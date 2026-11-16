package profile

import provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"

// HTTPRequestDigest commits the normalized body and exact fixed target. The
// caller obtains create bodies from Intent.RequestJSON; delete has no body.
// It borrows body only for the call and returns zero for invalid shapes.
func HTTPRequestDigest(action uint8, account, target [32]byte, body []byte) [32]byte {
	_, path, contentType, ok := HTTPRequestParts(action, account, target)
	if !ok || len(body) > provider.CloudflareMaxRequestBytes ||
		action == provider.ActionCreate && len(body) == 0 || action == provider.ActionDelete && len(body) != 0 {
		return [32]byte{}
	}
	preimage := []byte{action}
	preimage = appendBlob(preimage, []byte(path))
	preimage = appendBlob(preimage, []byte(contentType))
	preimage = appendBlob(preimage, body)
	return digest("http-request", preimage)
}

// HTTPRequestParts fixes the method, relative path and content type used both
// by the installed request commitment and by the provider client. Invalid action
// or tag combinations return ok=false; create requires a zero target.
func HTTPRequestParts(action uint8, account, target [32]byte) (method, path, contentType string, ok bool) {
	if !ValidTag(account) {
		return "", "", "", false
	}
	switch action {
	case provider.ActionCreate:
		if target != [32]byte{} {
			return "", "", "", false
		}
		return "POST", "/accounts/" + string(account[:]) + "/tokens", "application/json", true
	case provider.ActionDelete:
		if !ValidTag(target) {
			return "", "", "", false
		}
		return "DELETE", "/accounts/" + string(account[:]) + "/tokens/" + string(target[:]), "", true
	default:
		return "", "", "", false
	}
}
