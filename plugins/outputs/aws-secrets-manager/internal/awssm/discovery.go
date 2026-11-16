package awssm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	outputcredential "enkv.sh/plugins/outputs/aws-secrets-manager/credential"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/endpointcreds"
	"github.com/aws/smithy-go/logging"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
)

const (
	endpointCredentialResponseLimit   = 64 << 10
	imdsCredentialResponseLimit       = 64 << 10
	endpointCredentialResponseTimeout = 5 * time.Second
)

// loadCredentialSource uses the pinned SDK's standard credential provider chain.
// Each operation captures one credential value before its first request.
func loadCredentialSource(ctx context.Context, region string) (aws.CredentialsProvider, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, outputcredential.ErrCredential
	}
	installed, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithLogger(logging.NewStandardLogger(io.Discard)), config.WithClientLogMode(0), config.WithEndpointCredentialOptions(func(o *endpointcreds.Options) {
		transport := awshttp.NewBuildableClient().GetTransport()
		transport.MaxResponseHeaderBytes = 16 << 10
		transport.DisableCompression = true
		transport.DisableKeepAlives = true
		o.HTTPClient = endpointCredentialClient{client: &http.Client{
			Transport:     transport,
			Timeout:       endpointCredentialResponseTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}}
	}), config.WithAPIOptions([]func(*middleware.Stack) error{boundIMDSResponses}))
	if err != nil || installed.Credentials == nil {
		return nil, outputcredential.ErrCredential
	}

	return installed.Credentials, nil
}

func boundIMDSResponses(stack *middleware.Stack) error {
	// Pinned IMDS metadata stacks carry APITokenProvider; its token stack
	// instead carries tokenTTLRequestHeader. Bound both before SDK body reads.
	_, metadata := stack.Finalize.Get("APITokenProvider")
	_, token := stack.Serialize.Get("tokenTTLRequestHeader")
	if !metadata && !token {
		return nil
	}
	return stack.Deserialize.Add(imdsResponseBoundary{}, middleware.After)
}

type imdsResponseBoundary struct{}

func (imdsResponseBoundary) ID() string { return "EnkvIMDSResponseBoundary" }

func (imdsResponseBoundary) HandleDeserialize(ctx context.Context, input middleware.DeserializeInput, next middleware.DeserializeHandler) (out middleware.DeserializeOutput, metadata middleware.Metadata, resultErr error) {
	out, metadata, resultErr = next.HandleDeserialize(ctx, input)
	response, ok := out.RawResponse.(*smithyhttp.Response)
	if resultErr != nil {
		return out, metadata, resultErr
	}
	if !ok || response == nil || response.Response == nil {
		return out, metadata, endpointCredentialRefusal{}
	}
	raw, readErr := readCredentialResponse(response.Response, imdsCredentialResponseLimit)
	if readErr != nil {
		return out, metadata, readErr
	}
	response.Body = &endpointCredentialBody{Reader: bytes.NewReader(raw), raw: raw}
	return out, metadata, nil
}

type endpointCredentialClient struct{ client *http.Client }

// Do bounds and validates endpoint-credential responses before the pinned SDK
// decodes them. Accepted bytes transfer to a body that clears them on close.
func (c endpointCredentialClient) Do(request *http.Request) (result *http.Response, resultErr error) {
	response, err := c.client.Do(request)
	if err != nil {
		return nil, endpointCredentialTransferError{cause: err}
	}
	raw, readErr := readCredentialResponse(response, endpointCredentialResponseLimit)
	if readErr != nil {
		return nil, readErr
	}
	if !validEndpointCredentialResponse(response, raw) {
		clear(raw)
		return nil, endpointCredentialRefusal{}
	}
	response.Body = &endpointCredentialBody{Reader: bytes.NewReader(raw), raw: raw}
	return response, nil
}

func readCredentialResponse(response *http.Response, limit int64) ([]byte, error) {
	if response.Body == nil {
		return nil, endpointCredentialRefusal{}
	}
	if response.StatusCode == http.StatusSwitchingProtocols {
		_ = response.Body.Close()
		return nil, endpointCredentialRefusal{}
	}
	raw, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		clear(raw)
		return nil, endpointCredentialReadError{endpointCredentialTransferError{cause: readErr}}
	}
	if closeErr != nil || int64(len(raw)) > limit {
		clear(raw)
		return nil, endpointCredentialRefusal{}
	}
	return raw, nil
}

// The pinned SDK decodes pointer shapes and dereferences them. Validate the
// complete object first; unknown fields retain the SDK's standard meaning.
func validEndpointCredentialResponse(response *http.Response, raw []byte) bool {
	success := response.StatusCode >= 200 && response.StatusCode < 300
	if !success && response.Header.Get("Content-Type") != "application/json" {
		return true
	}
	object := bytes.TrimSpace(raw)
	if len(object) == 0 || object[0] != '{' {
		return false
	}
	if success {
		var shape struct {
			AccessKeyID     string
			SecretAccessKey string
			Token           string
			AccountID       string
			Expiration      *time.Time
		}
		return json.Unmarshal(raw, &shape) == nil && shape.AccessKeyID != "" && shape.SecretAccessKey != ""
	}
	var shape struct {
		Code    string
		Message string
	}
	return json.Unmarshal(raw, &shape) == nil
}

type endpointCredentialBody struct {
	*bytes.Reader
	raw []byte
}

// Close clears the captured endpoint response after the SDK has consumed it.
func (b *endpointCredentialBody) Close() error { clear(b.raw); b.raw = nil; return nil }

// Smithy wraps HTTP client errors as connection failures. A local response
// refusal must stop before that generic classification can schedule a retry.
type endpointCredentialRefusal struct{}

// Error exposes only the safe credential-refusal classification.
func (endpointCredentialRefusal) Error() string { return outputcredential.ErrCredential.Error() }

// Unwrap preserves errors.Is with the public credential sentinel.
func (endpointCredentialRefusal) Unwrap() error { return outputcredential.ErrCredential }

// RetryableError prevents SDK retry of a local response-shape refusal.
func (endpointCredentialRefusal) RetryableError() bool { return false }

type endpointCredentialTransferError struct{ cause error }

// Error suppresses the raw transport diagnostic from public error text.
func (e endpointCredentialTransferError) Error() string {
	return outputcredential.ErrCredential.Error()
}

// Unwrap retains the cause for SDK retry classification and programmatic checks.
func (e endpointCredentialTransferError) Unwrap() error { return e.cause }

type endpointCredentialReadError struct {
	endpointCredentialTransferError
}

// RetryableError classifies the read cause before Smithy wraps it as a
// request-send error. This applies to credential discovery, not mutations.
func (e endpointCredentialReadError) RetryableError() bool {
	return retry.IsErrorRetryables(retry.DefaultRetryables).IsErrorRetryable(e.cause) == aws.TrueTernary
}

func captureCredential(ctx context.Context, region string) ([]byte, time.Time, error) {
	source, err := loadCredentialSource(ctx, region)
	if err != nil {
		return nil, time.Time{}, err
	}
	return captureCredentialSource(ctx, source)
}
func captureCredentialSource(ctx context.Context, source aws.CredentialsProvider) ([]byte, time.Time, error) {
	if ctx == nil || ctx.Err() != nil || source == nil {
		return nil, time.Time{}, outputcredential.ErrCredential
	}
	value, err := source.Retrieve(ctx)
	if err != nil || ctx.Err() != nil || value.CanExpire && (value.Expires.IsZero() || !time.Now().Before(value.Expires)) {
		return nil, time.Time{}, outputcredential.ErrCredential
	}
	expiry := time.Time{}
	if value.CanExpire {
		expiry = value.Expires
	}
	wire, err := outputcredential.Encode(value.AccessKeyID, value.SecretAccessKey, value.SessionToken, expiry)
	return wire, expiry, err
}
