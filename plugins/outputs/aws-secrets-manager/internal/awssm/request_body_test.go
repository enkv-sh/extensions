package awssm

import (
	"bytes"
	"net/http"
	"testing"

	"enkv.sh/sdk/output"
)

// full_only: false
func TestRequestGuardRefusalClosesOwnedBody(t *testing.T) {
	wire := []byte("private wire rejected before handoff")
	owner := output.TakeRequestBody(wire)
	req, err := http.NewRequest(http.MethodPost, "https://unapproved.invalid/", owner)
	if err != nil {
		t.Fatal(err)
	}
	guard := &operationTransport{endpoint: "https://secretsmanager.ap-southeast-2.amazonaws.com", operation: "PutSecretValue"}
	if reply, err := guard.RoundTrip(req); reply != nil || err == nil {
		t.Fatal("unapproved request passed")
	}
	if !bytes.Equal(wire, make([]byte, len(wire))) {
		t.Fatal("guard retained rejected storage")
	}
}
