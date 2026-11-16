package artifact

import "testing"

// full_only: false
func TestReleaseIndexAcceptsUnlistedPlugin(t *testing.T) {
	want := ReleaseIndex{Schema: "enkv/plugin-index/v1", Name: "private-local-inventory", Releases: []Release{{Version: "1.0.0", Platform: "linux/amd64", Artifact: Digest{1}}}}
	body, err := EncodeReleaseIndex(want)
	if err != nil {
		t.Fatal("unlisted safe local plugin refused", err)
	}
	got, err := DecodeReleaseIndex(body)
	if err != nil || got.Name != want.Name || len(got.Releases) != 1 || got.Releases[0] != want.Releases[0] {
		t.Fatal("unlisted local plugin identity changed", got, err)
	}
}
