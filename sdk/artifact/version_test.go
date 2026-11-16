package artifact

import "testing"

// full_only: false
func TestSemanticVersionOrderAndGrammar(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1", "2.0.0", "100000000000000000000000000000000000000.0.0"}
	for i, v := range ordered {
		if !ValidVersion(v) {
			t.Fatal(v)
		}
		if i > 0 {
			c, err := CompareVersions(ordered[i-1], v)
			if err != nil || c >= 0 {
				t.Fatalf("order %q: %d %v", v, c, err)
			}
		}
	}
	for _, v := range []string{"", "v1.2.3", "1.2", "01.2.3", "1.02.3", "1.2.03", "1.2.3-01", "1.2.3-", "1.2.3+", "1.2.3-a..b", "1.2.3+bad+again", "1.2.3-a_1"} {
		if ValidVersion(v) {
			t.Fatal("accepted", v)
		}
	}
	if c, err := CompareVersions("1.2.3+one", "1.2.3+two"); err != nil || c != 0 {
		t.Fatal("build metadata precedence", c, err)
	}
	if !StableVersion("1.2.3+build") || StableVersion("1.2.3-rc.1") {
		t.Fatal("stable policy")
	}
}

// full_only: false
func TestDigestCanonicalHex(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	d, err := ParseDigest(want)
	if err != nil || d.String() != want || Hash([]byte("abc")) != d || d.IsZero() {
		t.Fatal("digest", err)
	}
	for _, s := range []string{want[:63], "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD", want + "0"} {
		if _, err := ParseDigest(s); err != ErrRecord {
			t.Fatal("noncanonical digest accepted")
		}
	}
}

// full_only: false
func TestPluginIdentityUsesPortableGrammar(t *testing.T) {
	for _, name := range []string{"private-plugin", "modified.official_2", "unknown-plugin"} {
		if !ValidPluginID(name) {
			t.Fatal("valid private identity refused", name)
		}
	}
	for _, name := range []string{"", ".", "..", "plugin/child", "/plugin", "bad space"} {
		if ValidPluginID(name) {
			t.Fatal("unsafe plugin identity admitted", name)
		}
	}
}
