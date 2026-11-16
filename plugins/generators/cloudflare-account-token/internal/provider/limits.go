package provider

// These are local parser, transport and time bounds. They do not assert live
// service quotas or permission for a request.
const (
	CloudflareMaxNameLength         = 120
	CloudflareMaxPolicies           = 32
	CloudflareMaxPermissionGroups   = 64
	CloudflareMaxResources          = 256
	CloudflareMaxPrefixesPerList    = 128
	CloudflareMinSecretLength       = 40
	CloudflareMaxDiagnosticRows     = 16
	CloudflareMaxResponseDepth      = 16
	CloudflareMaxResponseNodes      = 131072
	CloudflareDialTimeoutSeconds    = 10
	CloudflareTLSTimeoutSeconds     = 10
	CloudflareHeaderTimeoutSeconds  = 20
	CloudflareRequestTimeoutSeconds = 60
	CloudflareCommandTimeoutSeconds = 90
	CloudflareMaxRequestBytes       = 1 << 20
	CloudflareMaxHeaderBytes        = 16 << 10
	CloudflareMaxResponseBytes      = 1 << 20
)
