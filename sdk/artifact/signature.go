package artifact

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrSignature identifies a refused signature, purpose, signing key or key encoding.
// Use errors.Is because record and key-parser errors can be wrapped.
var ErrSignature = errors.New("artifact signature refused")

// Checksum binds a portable .tar.gz filename to its exact SHA-256 digest.
type Checksum struct {
	Name   string
	Digest Digest
}

func safeArchiveFilename(name string) bool {
	return safeBasename(name) && strings.HasSuffix(name, ".tar.gz")
}

// EncodeChecksums encodes up to 256 rows sorted by unique filename as lowercase
// hex, two spaces, filename and newline. An empty set encodes to an empty body.
func EncodeChecksums(rows []Checksum) ([]byte, error) {
	if len(rows) > 256 {
		return nil, ErrRecord
	}
	var b strings.Builder
	for i, row := range rows {
		if !safeArchiveFilename(row.Name) || i > 0 && rows[i-1].Name >= row.Name {
			return nil, ErrRecord
		}
		b.WriteString(row.Digest.String())
		b.WriteString("  ")
		b.WriteString(row.Name)
		b.WriteByte('\n')
	}
	if b.Len() > MaxRecordBytes {
		return nil, ErrRecord
	}
	return []byte(b.String()), nil
}

// DecodeChecksums requires the exact canonical checksum encoding, including each
// final newline. It returns owned rows or an error matching ErrRecord.
func DecodeChecksums(body []byte) ([]Checksum, error) {
	if len(body) == 0 {
		return []Checksum{}, nil
	}
	if len(body) > MaxRecordBytes || body[len(body)-1] != '\n' {
		return nil, ErrRecord
	}
	lines := bytes.Split(body[:len(body)-1], []byte{'\n'})
	if len(lines) > 256 {
		return nil, ErrRecord
	}
	rows := make([]Checksum, 0, len(lines))
	for _, line := range lines {
		if len(line) < 67 || line[64] != ' ' || line[65] != ' ' {
			return nil, ErrRecord
		}
		digest, err := ParseDigest(string(line[:64]))
		if err != nil {
			return nil, err
		}
		rows = append(rows, Checksum{Name: string(line[66:]), Digest: digest})
	}
	canonical, err := EncodeChecksums(rows)
	if err != nil || !bytes.Equal(canonical, body) {
		return nil, ErrRecord
	}
	return rows, nil
}

func validateSignatureBody(purpose string, body []byte) error {
	var err error
	switch purpose {
	case "plugin-executable":
		_, err = DecodeMetadata(body)
	case "plugin-archive":
		_, err = DecodeArchiveRecord(body)
	case "plugin-index":
		_, err = DecodeReleaseIndex(body)
	case "cli-checksums":
		_, err = DecodeChecksums(body)
	default:
		err = ErrRecord
	}
	if err != nil {
		return fmt.Errorf("%w: selected purpose or record: %w", ErrSignature, err)
	}
	return nil
}

// Sign validates purpose and exact canonical record bytes, then returns a new
// 64-byte pure Ed25519 signature. Purpose is "plugin-executable", "plugin-archive",
// "plugin-index" or "cli-checksums"; the signature covers body itself. The caller
// supplies the private key and retains ownership of key and body. Refusals match
// ErrSignature and can also match ErrRecord for invalid records.
func Sign(purpose string, body []byte, key ed25519.PrivateKey) ([]byte, error) {
	if err := validateSignatureBody(purpose, body); err != nil {
		return nil, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, ErrSignature
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, ErrSignature
	}
	return ed25519.Sign(key, body), nil
}

// VerifySignature validates the selected purpose and record, then checks the
// exact body with a caller-trusted Ed25519 public key. It selects no trust root
// from the record. Refusals support errors.Is(err, ErrSignature); success grants
// no permission to install or execute a plugin.
func VerifySignature(purpose string, body, signature []byte, key ed25519.PublicKey) error {
	if err := validateSignatureBody(purpose, body); err != nil {
		return err
	}
	if len(key) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, body, signature) {
		return ErrSignature
	}
	return nil
}

// ParsePrivateKeyPEM accepts one unencrypted PKCS8 Ed25519 PRIVATE KEY block,
// without PEM headers, leading data or trailing bytes. The caller owns the returned
// private key and must clear private buffers when no longer used. It assigns no trust.
func ParsePrivateKeyPEM(body []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.HasPrefix(body, []byte("-----BEGIN PRIVATE KEY-----")) {
		return nil, ErrSignature
	}
	value, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS8: %w", ErrSignature, err)
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, ErrSignature
	}
	return key, nil
}

// ParsePublicKeyPEM accepts one SPKI Ed25519 PUBLIC KEY block without PEM headers,
// leading data or trailing bytes. The caller must establish trust independently.
func ParsePublicKeyPEM(body []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(body)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.HasPrefix(body, []byte("-----BEGIN PUBLIC KEY-----")) {
		return nil, ErrSignature
	}
	value, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: SPKI: %w", ErrSignature, err)
	}
	key, ok := value.(ed25519.PublicKey)
	if !ok {
		return nil, ErrSignature
	}
	return key, nil
}

// EncodePrivateKeyPEM validates the full Ed25519 private key and returns a new
// unencrypted PKCS8 PEM buffer. The caller must protect and clear private buffers.
func EncodePrivateKeyPEM(key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, ErrSignature
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: PKCS8: %w", ErrSignature, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// EncodePublicKeyPEM returns a new SPKI PEM buffer for a correctly sized Ed25519 key.
func EncodePublicKeyPEM(key ed25519.PublicKey) ([]byte, error) {
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrSignature
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("%w: SPKI: %w", ErrSignature, err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}
