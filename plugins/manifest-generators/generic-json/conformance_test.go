package genericjson

import (
	"bytes"
	"context"
	manifest "enkv.sh/sdk/manifest-generator"
	"enkv.sh/sdk/manifest-generator/conformance"
	"enkv.sh/sdk/manifest-generator/native"
	"os"
	"path/filepath"
	"testing"
)

func exactArtifactForTest(body []byte) []byte {
	owned := make([]byte, len(body))
	copy(owned, body)
	return owned
}
func authorArtifactCheck(t *testing.T, p *manifest.Projection, want string, renderer manifest.Renderer) error {
	t.Helper()
	implementation := implementationForTest(t)
	implementation.Render = renderer
	return conformance.CheckImplementation(t.Context(), native.Serve, implementation, conformance.Fixture{Projection: p, ExpectedArtifact: []byte(want)})
}

// full_only: false
func TestPublicConformance(t *testing.T) {
	p, want := manifestJSONLiteralFixture()
	if err := authorArtifactCheck(t, p, want, Render); err != nil {
		t.Fatal(err)
	}
	for _, damage := range []struct{ name, from, to string }{{"changed-destination", "orgs/owner/actions/secrets/TOKEN", "orgs/owner/actions/secrets/OTHER"}, {"changed-policy", `"data_base64": "AQf/"`, `"data_base64": "AQj/"`}} {
		t.Run(damage.name, func(t *testing.T) {
			changed := 0
			err := authorArtifactCheck(t, p, want, func(ctx context.Context, v manifest.View) manifest.Result {
				r := Render(ctx, v)
				if r.Failure == "" {
					next := bytes.Replace(r.Artifact, []byte(damage.from), []byte(damage.to), 1)
					if !bytes.Equal(next, r.Artifact) {
						changed++
					}
					clear(r.Artifact)
					r.Artifact = exactArtifactForTest(next)
					clear(next)
				}
				return r
			})
			if changed != 1 || err == nil {
				t.Fatal("author check did not reject changed mixed vector", changed, err)
			}
		})
	}
}

func implementationForTest(t *testing.T) native.Implementation {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("cmd", "enkv-manifest-generic-json", "plugin.json"))
	if err != nil {
		t.Fatal(err)
	}
	implementation, err := native.Bind(body, ConfigContractID, FormatContractID, manifest.Implementation{ValidateFormatSettings: ValidateFormatSettings, Render: Render})
	if err != nil {
		t.Fatal(err)
	}
	return implementation
}
