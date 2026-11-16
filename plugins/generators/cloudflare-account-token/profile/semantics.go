package profile

import (
	"crypto/sha256"
	"encoding/binary"
	protocol "enkv.sh/sdk/protocols/generator"
)

// ProductionOrigin is the fixed API origin; production has no endpoint setting.
const ProductionOrigin = "https://api.cloudflare.com/client/v4"

// ConfigContractID binds settings semantics to origin. Use ProductionOrigin for
// production; a different origin has a different contract identity.
func ConfigContractID(origin string) protocol.ID {
	return sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/CONFIG/v1\x00" + origin))
}

// ResourceContractID binds account/token resource interpretation to origin.
func ResourceContractID(origin string) protocol.ID {
	return sha256.Sum256([]byte("ENKV/CLOUDFLARE-ACCOUNT-TOKEN/RESOURCE/v1\x00" + origin))
}

func appendBlob(dst, body []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(body)))
	return append(dst, body...)
}
