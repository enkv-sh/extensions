package awssm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"

	"enkv.sh/plugins/outputs/aws-secrets-manager/profile"
	protocol "enkv.sh/sdk/protocols/output"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

const identityRequest = "Action=GetCallerIdentity&Version=2011-06-15"

func requiresAccountQualification(action protocol.Action) bool {
	return action == protocol.ActionCreateEmpty || action == protocol.ActionDeleteReservedSlot
}

// qualifyAccount makes one bounded, read-only STS call. It neither resolves
// credentials nor retries, and it receives the same snapshot as the mutation.
func (i Implementation) qualifyAccount(ctx context.Context, target profile.Target, credentials aws.Credentials) bool {
	endpoint := "https://sts." + target.Region + ".amazonaws.com"
	if i.endpoint != "" {
		endpoint = i.endpoint
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", strings.NewReader(identityRequest))
	if err != nil {
		return false
	}
	req.GetBody = nil
	req.Close = true
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hash := sha256.Sum256([]byte(identityRequest))
	if v4.NewSigner().SignHTTP(ctx, credentials, req, hex.EncodeToString(hash[:]), "sts", target.Region, i.signTime()) != nil {
		_ = req.Body.Close()
		return false
	}
	guard := &identityTransport{base: i.transport, endpoint: endpoint}
	client := &http.Client{Transport: guard, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return false
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumReplyBytes+1))
	closeErr := response.Body.Close()
	defer clear(body)
	if ctx.Err() != nil || response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || len(body) > maximumReplyBytes {
		return false
	}
	var reply struct {
		XMLName xml.Name `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
		Results []struct {
			Accounts []string `xml:"Account"`
			ARNs     []string `xml:"Arn"`
			UserIDs  []string `xml:"UserId"`
		} `xml:"GetCallerIdentityResult"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(body))
	return decoder.Decode(&reply) == nil && decoder.Decode(new(any)) == io.EOF &&
		len(reply.Results) == 1 && len(reply.Results[0].Accounts) == 1 && reply.Results[0].Accounts[0] == target.Account &&
		len(reply.Results[0].ARNs) == 1 && reply.Results[0].ARNs[0] != "" && len(reply.Results[0].UserIDs) == 1 && reply.Results[0].UserIDs[0] != ""
}

type identityTransport struct {
	mu       sync.Mutex
	base     http.RoundTripper
	endpoint string
	entered  bool
}

// RoundTrip admits one signed STS identity request at the fixed regional
// endpoint. It closes refused bodies and permits no redirect or replay body.
func (t *identityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	allowed := !t.entered && req.Method == http.MethodPost && req.URL.Scheme+"://"+req.URL.Host == t.endpoint &&
		req.URL.EscapedPath() == "/" && req.URL.RawQuery == "" && req.GetBody == nil && req.Close && req.ProtoMajor == 1 &&
		req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" && req.Header.Get("X-Amz-Target") == "" &&
		req.Header.Get("Authorization") != "" && req.Header.Get("X-Amz-Date") != "" && req.ContentLength == int64(len(identityRequest))
	if allowed {
		t.entered = true
	}
	t.mu.Unlock()
	if !allowed {
		if req.Body != nil {
			return nil, errors.Join(errors.New("unapproved AWS identity request"), req.Body.Close())
		}
		return nil, errors.New("unapproved AWS identity request")
	}
	return t.base.RoundTrip(req)
}
