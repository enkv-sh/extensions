package cloudflare_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	cloudflare "enkv.sh/plugins/generators/cloudflare-account-token/internal/cloudflare"
	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"enkv.sh/plugins/generators/cloudflare-account-token/profile"
)

// These vectors bind provider classification to its complete opaque facts and
// value with independent correlation and length framing.
// full_only: false
func TestCloudflareResponseClassificationAndExactProviderFactVectors(t *testing.T) {
	intentBody, account := independentIntent()
	intent, err := profile.ParseIntent(intentBody, account)
	if err != nil {
		t.Fatal(err)
	}
	requestDigest := independentTag(9)
	target := independentTag(3)
	create := func(status int, body []byte) (provider.SafeFacts, []byte) {
		return cloudflare.NormalizeCreate(status, body, intent, requestDigest)
	}
	deleteResult := func(status int, body []byte) (provider.SafeFacts, []byte) {
		return cloudflare.NormalizeDelete(status, body, account, target, intent.Digest, requestDigest), nil
	}
	vectors := []struct {
		name            string
		normalize       func() (provider.SafeFacts, []byte)
		wantDisposition uint8
		wantReason      uint8
		wantSHA256      string
	}{
		{
			name: "complete-create",
			normalize: func() (provider.SafeFacts, []byte) {
				return create(200, independentCreateResponse("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN"))
			},
			wantDisposition: 1,
			wantReason:      0,
			wantSHA256:      "854fbb88b8812e7309ed83b8b5786c7be49632540eb012a2c58e514b39c57aec",
		},
		{
			name: "complete-create-discards-creator-annotation",
			normalize: func() (provider.SafeFacts, []byte) {
				body := independentCreateResponse("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN")
				body = bytes.Replace(body, []byte(`"status":"active"`), []byte(`"status":"active","creator_email_at_creation":"creator-annotation@example.invalid"`), 1)
				return create(200, body)
			},
			wantDisposition: 1,
			wantReason:      0,
			wantSHA256:      "854fbb88b8812e7309ed83b8b5786c7be49632540eb012a2c58e514b39c57aec",
		},
		{
			name: "owned-unusable-create",
			normalize: func() (provider.SafeFacts, []byte) {
				return create(200, independentCreateResponse("short-secret"))
			},
			wantDisposition: 2,
			wantReason:      2,
			wantSHA256:      "f83de22d6fcb1f14c742be54acca8a688da9aac1058a59d6ecd380fcd06c6466",
		},
		{
			name: "provider-rejection",
			normalize: func() (provider.SafeFacts, []byte) {
				return create(403, []byte(`{"success":false,"errors":[{"code":9109,"message":"denied"}],"messages":[],"result":null}`))
			},
			wantDisposition: 4,
			wantReason:      7,
			wantSHA256:      "9bb948d45be86981a9d53f4a80f4d379e0185b62e05732f310fe27b52e8ce3fc",
		},
		{
			name: "delete-acknowledged",
			normalize: func() (provider.SafeFacts, []byte) {
				return deleteResult(200, []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s"}}`, target)))
			},
			wantDisposition: 3,
			wantReason:      0,
			wantSHA256:      "55b5c191045ed1127508b6a63dc839d2dd78ccbb3ad15508604fb5b851177195",
		},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			facts, value := vector.normalize()
			defer clear(value)
			if facts.Disposition != vector.wantDisposition || facts.Reason != vector.wantReason {
				t.Fatalf("classification differs: %+v", facts)
			}
			factsBody, err := provider.EncodeFacts(facts)
			body := make([]byte, 0, 136+len(factsBody)+len(value))
			for _, id := range []provider.ID{independentProtocolID(1), independentProtocolID(2), independentProtocolID(3), independentProtocolID(4)} {
				body = append(body, id[:]...)
			}
			body = binary.BigEndian.AppendUint32(body, uint32(len(factsBody)))
			body = append(body, factsBody...)
			body = binary.BigEndian.AppendUint32(body, uint32(len(value)))
			body = append(body, value...)
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(body)
			if got := hex.EncodeToString(sum[:]); got != vector.wantSHA256 {
				t.Fatalf("result vector SHA-256 = %s, want %s", got, vector.wantSHA256)
			}
		})
	}
}

func independentIntent() ([]byte, [32]byte) {
	account := independentTag(0)
	permission := independentTag(1)
	zone := independentTag(2)
	name := []byte("edge-\"token\\one")
	body := binary.BigEndian.AppendUint16(nil, 1)
	body = append(body, account[:]...)
	body = binary.BigEndian.AppendUint32(body, uint32(len(name)))
	body = append(body, name...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, permission[:]...)
	body = binary.BigEndian.AppendUint16(body, 2)
	body = append(body, 1)
	body = append(body, account[:]...)
	body = append(body, 2)
	body = append(body, zone[:]...)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 4)
	body = append(body, make([]byte, 12)...)
	body = append(body, 192, 0, 2, 0, 24)
	body = binary.BigEndian.AppendUint16(body, 1)
	body = append(body, 6, 0x20, 0x01, 0x0d, 0xb8)
	body = append(body, make([]byte, 12)...)
	body = append(body, 32, 1)
	body = binary.BigEndian.AppendUint64(body, 1704067200)
	body = append(body, 1)
	body = binary.BigEndian.AppendUint64(body, 1735689600)
	return body, account
}

func independentCreateResponse(value string) []byte {
	account, permission, zone, token := independentTag(0), independentTag(1), independentTag(2), independentTag(3)
	return []byte(fmt.Sprintf(`{"success":true,"errors":[],"messages":[],"result":{"id":"%s","value":"%s","status":"active","name":"edge-\"token\\one","policies":[{"id":"server-policy","effect":"allow","permission_groups":[{"id":"%s","name":"read","meta":{"scope":"account"}}],"resources":{"com.cloudflare.api.account.%s":"*","com.cloudflare.api.account.zone.%s":"*"}}],"condition":{"request.ip":{"in":["192.0.2.0/24"],"not_in":["2001:db8::/32"]}},"not_before":"2024-01-01T00:00:00Z","expires_on":"2025-01-01T00:00:00Z","issued_on":"2025-01-01T00:00:00Z","modified_on":null,"last_used_on":""}}`, token, value, permission, account, zone))
}

func independentTag(value byte) [32]byte {
	var out [32]byte
	for i := range out {
		out[i] = "0123456789abcdef"[int(value+byte(i))%16]
	}
	return out
}

func independentProtocolID(value byte) provider.ID {
	var out provider.ID
	for i := range out {
		out[i] = value
	}
	return out
}
