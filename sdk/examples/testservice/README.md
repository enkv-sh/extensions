# Local example service

This package supplies a small HTTP service for the independent generator and
output examples. It uses memory only. Its deterministic binary tokens are test
values, not production credentials.

This module provides a Go handler, not a standalone service command. Import
`enkv.sh/sdk/examples/testservice` in a local Go application. Call
`testservice.New(testservice.Config{Token: "example-token", Namespace: "workshop"})`,
check the error, and use the returned handler with an HTTP server on loopback.
Use the same namespace in the plugin's settings and the same token in
`ENKV_EXAMPLE_TOKEN`. Stop and join the HTTP server
before calling the service's `Close` method. A test can use `httptest.NewServer`.

Every request requires `Authorization: Bearer <token>`. `GET /session` returns
the configured namespace. Plugins check this namespace before an effect.

| Request | Result |
|---|---|
| `POST /tokens` with JSON `namespace` and `subject` | 201 JSON `id` and `value_base64` |
| `GET /tokens/{id}` | 200 with the same token record |
| `DELETE /tokens/{id}` | 204; a subsequent read returns 404 |
| `POST /values/{namespace}/{key}` with raw bytes and `If-None-Match: *` | 201, `X-Resource-ID` and quoted `ETag` |
| `PUT /values/{namespace}/{key}` with raw bytes and `If-Match: "<id>"` | 204 with the same identity headers |
| `GET /values/{namespace}/{key}` | Raw value and identity headers |
| `DELETE /values/{namespace}/{key}` with `If-Match: "<id>"` | 204 |

The value key is the entry name encoded as unpadded base64url. Values can be
empty and are at most 65,536 bytes. Existing names and incorrect ownership
conditions return 412. Namespace names contain 1–64 lowercase letters, digits
or hyphens.

The first token for namespace `workshop` and subject `api` is `t1`, with bytes
`00 ff` followed by `workshop/api/t1`. Value resources receive `v1`, `v2`, and so
on. Updating a value preserves its resource identity; deleting and creating it
again assigns a new identity.

`LoseNextTokenReply` and `LoseNextValueReply` close the next successful create
or value-write response after the effect. These controls let the examples test
unknown outcomes. `Counts` is a test observation; it grants no ENKV ownership,
adoption, retry or cleanup authority.

From this module, run `GOWORK=off go test ./...`.
