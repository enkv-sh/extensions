package awssm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"sync"
	"time"

	"enkv.sh/plugins/outputs/aws-secrets-manager/profile"
	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Implementation discovers one standard credential snapshot before preparing
// a direct Secrets Manager JSON request. Mutations have no retry stack. The
// zero value is invalid; use NewImplementation to bind production callbacks.
type Implementation struct {
	output.Binding
	transport http.RoundTripper
	endpoint  string // Empty in production; test-only controlled endpoint.
	signTime  func() time.Time
}

// New creates a production transport without a descriptor binding. It is an
// internal construction step; NewImplementation supplies the usable binding.
func New() Implementation {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return Implementation{transport: &http.Transport{Proxy: nil, DisableKeepAlives: true,
		DisableCompression: true, Protocols: protocols, MaxConnsPerHost: 1}, signTime: time.Now}
}

func (i Implementation) sendCaptured(ctx context.Context, command output.Preparation, policy protocol.Policy, payload, credentialBytes []byte, accountQualified bool) (output.Outcome, error) {
	if ctx == nil || ctx.Err() != nil || !policy.Valid() || int(command.PayloadLength) != len(payload) ||
		i.transport == nil || i.signTime == nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	target, err := validateConsumer(command, policy)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	if command.Action == protocol.ActionWriteValue {
		if len(payload) < 1 || len(payload) > MaximumRawValueBytes {
			return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
		}
	} else if len(payload) != 0 {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	credential, err := parseCredential(credentialBytes)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	// Copy the received credential fields once before any provider request. The
	// same immutable snapshot signs qualification and mutation.
	credentials := aws.Credentials{AccessKeyID: string(credential.access), SecretAccessKey: string(credential.secret), SessionToken: string(credential.token)}
	if !credential.expiry.IsZero() {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, credential.expiry)
		defer cancel()
	}
	if ctx.Err() != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	if !accountQualified && requiresAccountQualification(command.Action) {
		if !i.qualifyAccount(ctx, target, credentials) || ctx.Err() != nil {
			return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
		}
	}
	operation, body, err := actionBody(command, target, payload)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	contentHash := sha256.Sum256(body)
	// Transfer the full allocation so the HTTP body owner can clear it after
	// transport reads finish. Disabling GetBody removes the replay body factory.
	owner := output.TakeRequestBody(body)
	handed := false
	defer func() {
		if !handed {
			_ = owner.Close()
		}
	}()
	endpoint := target.Endpoint
	if i.endpoint != "" {
		endpoint = i.endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", owner)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	req.ContentLength = int64(len(body))
	req.GetBody = nil
	req.Close = true
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager."+operation)
	if err := v4.NewSigner().SignHTTP(ctx, credentials, req, hex.EncodeToString(contentHash[:]), "secretsmanager", target.Region, i.signTime()); err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	req.GetBody = nil
	guard := &operationTransport{base: i.transport, endpoint: endpoint, operation: operation}
	client := &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	handed = true
	response, err := client.Do(req)
	if err != nil {
		if !guard.didEnter() {
			return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
		}
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	responseBytes, readErr := io.ReadAll(io.LimitReader(response.Body, maximumReplyBytes+1))
	closeErr := response.Body.Close()
	defer clear(responseBytes)
	if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || len(responseBytes) > maximumReplyBytes {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	resource, ok := qualifiedResponse(command, target, responseBytes)
	if !ok {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	locator := ""
	if command.Action == protocol.ActionCreateEmpty {
		locator = resource + "?stage=AWSCURRENT"
	}
	return output.Acknowledged(http.StatusOK, "", resource, locator)
}

func actionBody(command output.Preparation, target profile.Target, payload []byte) (string, []byte, error) {
	switch command.Action {
	case protocol.ActionCreateEmpty:
		body := []byte(`{"ClientRequestToken":"` + hex.EncodeToString(command.AttemptID[:]) + `","Name":"` + target.Name + `"}`)
		return "CreateSecret", body, nil
	case protocol.ActionWriteValue:
		body, err := putBody(target.ARN, command.AttemptID, payload)
		return "PutSecretValue", body, err
	case protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		secretID := target.ARN
		if command.Action == protocol.ActionDeleteReservedSlot {
			secretID = target.Name
		}
		return "DeleteSecret", []byte(`{"RecoveryWindowInDays":7,"SecretId":"` + secretID + `"}`), nil
	default:
		return "", nil, profile.ErrProfile
	}
}

func qualifiedResponse(command output.Preparation, target profile.Target, body []byte) (string, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	switch command.Action {
	case protocol.ActionCreateEmpty:
		var reply struct {
			ARN               string `json:"ARN"`
			Name              string `json:"Name"`
			VersionID         string `json:"VersionId"`
			ReplicationStatus []any  `json:"ReplicationStatus"`
		}
		if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF || reply.Name != target.Name ||
			reply.VersionID != "" || len(reply.ReplicationStatus) != 0 {
			return "", false
		}
		owned, err := profile.ParseOwnedInstance(reply.ARN)
		return reply.ARN, err == nil && owned.Slot == target.Slot
	case protocol.ActionWriteValue:
		var reply struct {
			ARN           string   `json:"ARN"`
			Name          string   `json:"Name"`
			VersionID     string   `json:"VersionId"`
			VersionStages []string `json:"VersionStages"`
		}
		if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF || reply.ARN != target.ARN || reply.Name != target.Name ||
			reply.VersionID != hex.EncodeToString(command.AttemptID[:]) || len(reply.VersionStages) != 1 || reply.VersionStages[0] != "AWSCURRENT" {
			return "", false
		}
		return reply.VersionID, true
	case protocol.ActionDeleteOwned, protocol.ActionDeleteReservedSlot:
		var reply struct {
			ARN          string      `json:"ARN"`
			Name         string      `json:"Name"`
			DeletionDate json.Number `json:"DeletionDate"`
		}
		decoder.UseNumber()
		if decoder.Decode(&reply) != nil || decoder.Decode(new(any)) != io.EOF || reply.Name != target.Name {
			return "", false
		}
		owned, err := profile.ParseOwnedInstance(reply.ARN)
		if err != nil || owned.Slot != target.Slot || command.Action == protocol.ActionDeleteOwned && reply.ARN != target.ARN {
			return "", false
		}
		stamp, err := reply.DeletionDate.Float64()
		return reply.ARN, err == nil && stamp > 0 && !math.IsInf(stamp, 0) && !math.IsNaN(stamp)
	default:
		return "", false
	}
}

func putBody(arn string, attempt protocol.ID, payload []byte) ([]byte, error) {
	if _, err := profile.ParseOwnedInstance(arn); err != nil || attempt.IsZero() || len(payload) < 1 || len(payload) > MaximumRawValueBytes {
		return nil, profile.ErrProfile
	}
	encodedLength := base64.StdEncoding.EncodedLen(len(payload))
	result := make([]byte, 0, encodedLength+len(arn)+160)
	result = append(result, `{"ClientRequestToken":"`...)
	result = hex.AppendEncode(result, attempt[:])
	result = append(result, `","SecretBinary":"`...)
	start := len(result)
	result = result[:start+encodedLength]
	base64.StdEncoding.Encode(result[start:], payload)
	result = append(result, `","SecretId":"`...)
	result = append(result, arn...)
	result = append(result, `","VersionStages":["AWSCURRENT"]}`...)
	if len(result) > maximumBodyBytes {
		clear(result)
		return nil, profile.ErrProfile
	}
	return result, nil
}

// The guard advances before entering the base transport. Even a failed call
// can have reached the service; no subsequent request may repeat that mutation.
type operationTransport struct {
	mu        sync.Mutex
	base      http.RoundTripper
	endpoint  string
	operation string
	entered   bool
}

func (o *operationTransport) didEnter() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.entered
}

// RoundTrip admits only the next fixed request and marks mutation entry before
// the base call. It closes refused request bodies and never grants replay after
// entry, including when the base transport returns an error.
func (o *operationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	o.mu.Lock()
	allowed := !o.entered && req.Method == http.MethodPost && req.URL.Scheme+"://"+req.URL.Host == o.endpoint &&
		req.URL.EscapedPath() == "/" && req.URL.RawQuery == "" && req.GetBody == nil && req.Close && req.ProtoMajor == 1 &&
		req.Header.Get("X-Amz-Target") == "secretsmanager."+o.operation &&
		req.Header.Get("Content-Type") == "application/x-amz-json-1.1" &&
		req.Header.Get("Authorization") != "" && req.Header.Get("X-Amz-Date") != "" &&
		req.ContentLength >= 0 && req.ContentLength <= maximumBodyBytes
	if allowed {
		o.entered = true
	}
	o.mu.Unlock()
	if !allowed {
		if req.Body != nil {
			return nil, errors.Join(errors.New("unapproved AWS output request"), req.Body.Close())
		}
		return nil, errors.New("unapproved AWS output request")
	}
	return o.base.RoundTrip(req)
}
