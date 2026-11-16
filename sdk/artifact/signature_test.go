package artifact

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"
)

// full_only: false
func TestChecksumsCanonicalAndClosed(t *testing.T) {
	const digest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	const fixture = digest + "  enkv-linux-amd64.tar.gz\n"
	rows, err := DecodeChecksums([]byte(fixture))
	if err != nil || len(rows) != 1 || rows[0].Name != "enkv-linux-amd64.tar.gz" || rows[0].Digest.String() != digest {
		t.Fatalf("decode fixture: %v %#v", err, rows)
	}
	encoded, err := EncodeChecksums(rows)
	if err != nil || string(encoded) != fixture {
		t.Fatalf("encode fixture: %v %q", err, encoded)
	}
	empty, err := DecodeChecksums(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty list: %v", err)
	}
	if encoded, err := EncodeChecksums(empty); err != nil || len(encoded) != 0 {
		t.Fatalf("empty encoding: %v", err)
	}
	for _, body := range []string{fixture[:len(fixture)-1], fixture + fixture, digest + " enkv-linux-amd64.tar.gz\n", digest + "  ../enkv.tar.gz\n", digest + "  bad.zip\n"} {
		if _, err := DecodeChecksums([]byte(body)); !errors.Is(err, ErrRecord) {
			t.Fatalf("accepted malformed checksum %q: %v", body, err)
		}
	}
}

// full_only: false
func TestSignExactBytesAndPurpose(t *testing.T) {
	// RFC 8032 section 7.1 seed; checksum SHA-256 is the published SHA-256("abc") vector.
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	key := ed25519.NewKeyFromSeed(seed)
	body := []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  enkv.tar.gz\n")
	sig, err := Sign("cli-checksums", body, key)
	if err != nil || len(sig) != ed25519.SignatureSize {
		t.Fatalf("sign: %v", err)
	}
	// Independently signed with OpenSSL 3.5.9 pkeyutl -sign -rawin using
	// the RFC 8032 seed in PKCS8. The message is the checksum literal above.
	expectedSignature, err := hex.DecodeString("29cc54b459bae27bd5958e6b587d4157c2f189eab4b02093e0c75ac133908add36f6503ee13d3e83b307ff504777edb6016f58d1150e704a75fd2d066345d00c")
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := hex.DecodeString("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, expectedSignature) {
		t.Fatalf("signature differs from independent fixture: %x", sig)
	}
	if err := VerifySignature("cli-checksums", body, expectedSignature, ed25519.PublicKey(publicKey)); err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(key.Public().(ed25519.PublicKey), body, sig) {
		t.Fatal("signature does not cover exact input")
	}
	if err := VerifySignature("cli-checksums", body, sig, key.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	badKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	cases := []struct {
		purpose   string
		body, sig []byte
		key       ed25519.PublicKey
	}{
		{"cli-checksums", body, sig, badKey},
		{"plugin-index", body, sig, key.Public().(ed25519.PublicKey)},
		{"unknown", body, sig, key.Public().(ed25519.PublicKey)},
		{"cli-checksums", body, sig[:63], key.Public().(ed25519.PublicKey)},
		{"cli-checksums", append(append([]byte{}, body...), '\n'), sig, key.Public().(ed25519.PublicKey)},
		{"cli-checksums", bytes.Replace(body, []byte("enkv.tar.gz"), []byte("other.tar.gz"), 1), sig, key.Public().(ed25519.PublicKey)},
		{"cli-checksums", body, sig, key.Public().(ed25519.PublicKey)[:31]},
	}
	for i, c := range cases {
		if err := VerifySignature(c.purpose, c.body, c.sig, c.key); !errors.Is(err, ErrSignature) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	if _, err := Sign("cli-checksums", body, key[:31]); !errors.Is(err, ErrSignature) {
		t.Fatalf("bad private key: %v", err)
	}
}

// full_only: false
func TestSignaturePEMStrictTypesAndTrailingData(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	private, err := EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ParsePrivateKeyPEM(private)
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatalf("private roundtrip: %v", err)
	}
	public, err := EncodePublicKeyPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParsePublicKeyPEM(public)
	if err != nil || !bytes.Equal(pub, key.Public().(ed25519.PublicKey)) {
		t.Fatalf("public roundtrip: %v", err)
	}
	for _, bad := range [][]byte{public, append(append([]byte{}, private...), private...), append(append([]byte{}, private...), 'x')} {
		if _, err := ParsePrivateKeyPEM(bad); !errors.Is(err, ErrSignature) {
			t.Fatalf("private accepted: %v", err)
		}
	}
	if _, err := ParsePublicKeyPEM(private); !errors.Is(err, ErrSignature) {
		t.Fatalf("private as public: %v", err)
	}
}
