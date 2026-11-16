//go:build enkv_cloudflare_testartifact

package cloudflare

import (
	"crypto/tls"
	provider "enkv.sh/plugins/generators/cloudflare-account-token/internal/provider"
	"net/http"
	"time"
)

// This origin exists only in the explicitly unqualified hermetic artifact.
var unqualifiedTestArtifactOrigin string

// NewTestClient returns nil unless the dedicated fixture origin was linked in.
// Its TLS verification is disabled and it must never qualify production behavior.
func NewTestClient() *Client {
	if unqualifiedTestArtifactOrigin == "" {
		return nil
	}
	return &Client{origin: unqualifiedTestArtifactOrigin, unqualifiedTestOrigin: true, requestTimeout: 5 * time.Second, transport: func() ownedTransport { return unqualifiedTestTransport() }}
}

func unqualifiedTestTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	return &http.Transport{Proxy: nil, ForceAttemptHTTP2: false, TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}, // explicitly unqualified fixture only
		TLSHandshakeTimeout: provider.CloudflareTLSTimeoutSeconds * time.Second, ResponseHeaderTimeout: provider.CloudflareHeaderTimeoutSeconds * time.Second, MaxResponseHeaderBytes: provider.CloudflareMaxHeaderBytes, DisableCompression: true, DisableKeepAlives: true, Protocols: protocols}
}
