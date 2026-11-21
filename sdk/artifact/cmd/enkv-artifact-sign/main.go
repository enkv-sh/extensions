// Command enkv-artifact-sign signs or verifies exact bounded artifact records
// with caller-selected Ed25519 keys. Signing requires a new output file and an
// unencrypted PKCS8 private key; verification requires a detached signature and an
// independently trusted SPKI public key. It neither creates keys nor publishes records.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"enkv.sh/sdk/artifact"
)

func readBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	if int64(len(body)) > limit {
		return nil, artifact.ErrRecord
	}
	return body, nil
}
func run(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("enkv-artifact-sign", flag.ContinueOnError)
	var diagnostic bytes.Buffer
	flags.SetOutput(&diagnostic)
	purpose := flags.String("purpose", "", "plugin-executable, plugin-archive, plugin-index, or cli-checksums")
	input := flags.String("input", "", "exact canonical record file")
	keyPath := flags.String("key", "", "caller-trusted PKCS8 private or SPKI public PEM key")
	output := flags.String("output", "", "new detached signature file")
	verify := flags.Bool("verify", false, "verify an existing detached signature with a public key")
	signaturePath := flags.String("signature", "", "detached signature file for verification")
	if err := flags.Parse(args); err != nil {
		if !errors.Is(err, flag.ErrHelp) {
			return errors.New("signer arguments: flags: invalid")
		}
		n, writeErr := io.WriteString(stderr, diagnostic.String())
		if writeErr == nil && n != diagnostic.Len() {
			writeErr = io.ErrShortWrite
		}
		if writeErr != nil {
			return signerFailure{"signer arguments: diagnostic", "write failed", writeErr}
		}
		return nil
	}
	if flags.NArg() != 0 {
		return errors.New("signer arguments: positional: unexpected arguments")
	}
	for _, field := range []struct{ name, value string }{
		{"purpose", *purpose}, {"input", *input}, {"key", *keyPath},
	} {
		if field.value == "" {
			return fmt.Errorf("signer arguments: %s: required", field.name)
		}
	}
	if *verify {
		if *output != "" {
			return errors.New("signer arguments: output: forbidden with verify")
		}
		if *signaturePath == "" {
			return errors.New("signer arguments: signature: required")
		}
	} else {
		if *signaturePath != "" {
			return errors.New("signer arguments: signature: requires verify")
		}
		if *output == "" {
			return errors.New("signer arguments: output: required")
		}
	}
	body, err := readBounded(*input, artifact.MaxRecordBytes)
	if err != nil {
		return signerError("read record", err)
	}
	keyBytes, err := readBounded(*keyPath, 16384)
	if err != nil {
		return signerError("read key", err)
	}
	if *verify {
		key, err := artifact.ParsePublicKeyPEM(keyBytes)
		if err != nil {
			return signerError("parse public key", err)
		}
		signature, err := readBounded(*signaturePath, 64)
		if err != nil {
			return signerError("read signature", err)
		}
		return signerError("verify signature", artifact.VerifySignature(*purpose, body, signature, key))
	}
	key, err := artifact.ParsePrivateKeyPEM(keyBytes)
	if err != nil {
		return signerError("parse private key", err)
	}
	signature, err := artifact.Sign(*purpose, body, key)
	if err != nil {
		return signerError("sign record", err)
	}
	file, err := os.OpenFile(*output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return signerError("create signature", err)
	}
	n, writeErr := file.Write(signature)
	if writeErr == nil && n != len(signature) {
		writeErr = io.ErrShortWrite
	}
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		return errors.Join(signerError("write signature", writeErr), signerError("close signature", closeErr), signerError("remove incomplete signature", os.Remove(*output)))
	}
	return nil
}

// Keep raw causes available for identity checks without publishing their paths
// or parser messages through the command's printable error chain.
type signerFailure struct {
	operation, reason string
	cause             error
}

func (e signerFailure) Error() string        { return e.operation + ": " + e.reason }
func (e signerFailure) GoString() string     { return e.Error() }
func (e signerFailure) Is(target error) bool { return errors.Is(e.cause, target) }

func signerError(operation string, err error) error {
	if err == nil {
		return nil
	}
	reason := "operation failed"
	switch {
	case errors.Is(err, os.ErrNotExist):
		reason = "file not found"
	case errors.Is(err, os.ErrExist):
		reason = "file exists"
	case errors.Is(err, os.ErrPermission):
		reason = "permission denied"
	case errors.Is(err, io.ErrShortWrite):
		reason = "short write"
	case errors.Is(err, artifact.ErrRecord):
		reason = "invalid record"
	case errors.Is(err, artifact.ErrSignature):
		reason = "invalid signature or key"
	}
	return signerFailure{operation, reason, err}
}

func main() {
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
