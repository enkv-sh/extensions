package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"enkv.sh/sdk/artifact"
)

// full_only: false
func TestCommandSignsVerifiesAndPreservesExistingOutput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "checksums")
	privatePath := filepath.Join(dir, "private.pem")
	publicPath := filepath.Join(dir, "public.pem")
	sigPath := filepath.Join(dir, "checksums.sig")
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, 32))
	private, err := artifact.EncodePrivateKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	public, err := artifact.EncodePublicKeyPEM(key.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{input: []byte("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  enkv.tar.gz\n"), privatePath: private, publicPath: public} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-purpose", "cli-checksums", "-input", input, "-key", privatePath, "-output", sigPath}
	if err := run(args, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	signature, err := os.ReadFile(sigPath)
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature: %v", err)
	}
	if err := run(args, &bytes.Buffer{}); err == nil {
		t.Fatal("overwrote existing signature")
	}
	after, err := os.ReadFile(sigPath)
	if err != nil || !bytes.Equal(signature, after) {
		t.Fatalf("existing signature changed: %v", err)
	}
	if err := run([]string{"-verify", "-purpose", "cli-checksums", "-input", input, "-key", publicPath, "-signature", sigPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-verify", "-purpose", "plugin-index", "-input", input, "-key", publicPath, "-signature", sigPath}, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted wrong purpose")
	}
}

// full_only: false
func TestCommandHelpAndArgumentFailures(t *testing.T) {
	for _, option := range []string{"-h", "-help"} {
		t.Run(option, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "new-signature")
			var diagnostic bytes.Buffer
			args := []string{"-input", "unreadable-record", "-key", "unreadable-key", "-output", output, option}
			if err := run(args, &diagnostic); err != nil || !strings.HasPrefix(diagnostic.String(), "Usage of enkv-artifact-sign:\n") {
				t.Fatal("help did not succeed before reading input", err, diagnostic.String())
			}
			if _, err := os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("help created a signature", err)
			}
		})
	}
	for _, test := range []struct {
		name          string
		args          []string
		field, reason string
	}{
		{"purpose", []string{"-input", "unreadable-record", "-key", "unreadable-key", "-output", "new-output"}, "purpose", "required"},
		{"input", []string{"-purpose", "cli-checksums", "-key", "unreadable-key", "-output", "new-output"}, "input", "required"},
		{"key", []string{"-purpose", "cli-checksums", "-input", "unreadable-record", "-output", "new-output"}, "key", "required"},
		{"output", []string{"-purpose", "cli-checksums", "-input", "unreadable-record", "-key", "unreadable-key"}, "output", "required"},
		{"signature", []string{"-verify", "-purpose", "cli-checksums", "-input", "unreadable-record", "-key", "unreadable-key"}, "signature", "required"},
		{"verify-output", []string{"-verify", "-purpose", "cli-checksums", "-input", "unreadable-record", "-key", "unreadable-key", "-signature", "unreadable-signature", "-output", "new-output"}, "output", "forbidden with verify"},
		{"sign-signature", []string{"-purpose", "cli-checksums", "-input", "unreadable-record", "-key", "unreadable-key", "-output", "new-output", "-signature", "unreadable-signature"}, "signature", "requires verify"},
		{"positional", []string{"supplied-private-value"}, "positional", "unexpected arguments"},
		{"flag", []string{"-supplied-private-value"}, "flags", "invalid"},
	} {
		t.Run(test.name, func(t *testing.T) {
			var diagnostic bytes.Buffer
			err := run(test.args, &diagnostic)
			if err == nil || err.Error() != "signer arguments: "+test.field+": "+test.reason || strings.Contains(diagnostic.String(), "supplied-private-value") {
				t.Fatal("argument failure lost its safe field", err, diagnostic.String())
			}
		})
	}
	for _, short := range []bool{false, true} {
		t.Run(map[bool]string{false: "write-error", true: "short-write"}[short], func(t *testing.T) {
			cause := errors.New("private writer details")
			writer := &diagnosticWriter{cause: cause}
			want := cause
			if short {
				writer.cause = nil
				want = io.ErrShortWrite
			}
			err := run([]string{"-help"}, writer)
			if !errors.Is(err, want) || err.Error() != "signer arguments: diagnostic: write failed" || writer.calls != 1 || writer.bytes != 7 {
				t.Fatal("failed help delivery was not a safe operational failure", err, writer.calls, writer.bytes)
			}
		})
	}
}

type diagnosticWriter struct {
	cause        error
	calls, bytes int
}

func (w *diagnosticWriter) Write(b []byte) (int, error) {
	w.calls++
	n := min(7, len(b))
	w.bytes += n
	return n, w.cause
}
