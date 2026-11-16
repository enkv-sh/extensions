package gcpsm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"hash/crc32"
	"io"
	"net/http"
	"strconv"

	"enkv.sh/sdk/output"
	protocol "enkv.sh/sdk/protocols/output"
	"google.golang.org/api/googleapi"
	secretmanager "google.golang.org/api/secretmanager/v1"
)

// valueBody writes the API's Base64 transport representation directly into one
// owned allocation. The generated SecretPayload.Data string cannot be cleared.
func valueBody(payload []byte) []byte {
	encodedLength := base64.StdEncoding.EncodedLen(len(payload))
	body := make([]byte, 0, encodedLength+80)
	body = append(body, `{"payload":{"data":"`...)
	start := len(body)
	body = body[:start+encodedLength]
	base64.StdEncoding.Encode(body[start:], payload)
	body = append(body, `","dataCrc32c":"`...)
	body = strconv.AppendUint(body, uint64(crc32.Checksum(payload, crc32.MakeTable(crc32.Castagnoli))), 10)
	return append(body, `"}}`...)
}

func (i Implementation) writeValue(ctx context.Context, command output.Preparation, payload []byte,
	base string, guard *operationTransport, client *http.Client) (output.Outcome, error) {
	body := valueBody(payload)
	owner := output.TakeRequestBody(body)
	handed := false
	defer func() {
		if !handed {
			_ = owner.Close()
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/v1/"+command.Target.CanonicalTarget+":addVersion?alt=json&prettyPrint=false", owner)
	if err != nil {
		return output.QualifiedNoEffect(protocol.EntryNotEntered, 0, "", "")
	}
	req.ContentLength = int64(len(body))
	req.GetBody = nil
	req.Close = true
	req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/1.1", 1, 1
	req.Header.Set("Authorization", guard.bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", googleapi.UserAgent)
	handed = true
	response, err := client.Do(req)
	if err != nil {
		return guard.failure()
	}
	responseBody, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
	closeErr := response.Body.Close()
	defer clear(responseBody)
	if response.StatusCode != http.StatusOK || readErr != nil || closeErr != nil || len(responseBody) > 4096 {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	var version secretmanager.SecretVersion
	if json.Unmarshal(responseBody, &version) != nil || !version.ClientSpecifiedPayloadChecksum ||
		!canonicalVersion(command.Target.CanonicalTarget, version.Name) {
		return output.Unknown(protocol.EntryMayHaveEntered)
	}
	return output.Acknowledged(http.StatusOK, "", version.Name, "")
}
