package main

import (
	"bytes"
	"errors"
	"testing"
)

type cliDeliveryFailureWriter struct {
	body             bytes.Buffer
	calls, attempted int
	failure          error
}

func (w *cliDeliveryFailureWriter) Write(body []byte) (int, error) {
	w.calls++
	w.attempted += len(body)
	n, err := w.body.Write(body[:min(len(body), max(0, 7-w.body.Len()))])
	if err != nil {
		return n, err
	}
	return n, w.failure
}

// full_only: false
func TestRunDiagnosticDeliveryFailureIsOperational(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, tc := range []struct {
		name       string
		args       []string
		diagnostic string
	}{
		{"help", []string{"-help"}, "Usage of enkv-plugin-build:\n"},
		{"unknown", []string{"-unknown"}, "flag provided but not defined: -unknown\n"},
		{"positional", []string{"unexpected"}, "unexpected positional arguments\n"},
		{"verify-conflict", []string{"-verify", "build", "-descriptor", "enkv-plugin.json"}, "verify cannot be combined with build flags\n"},
		{"archive-missing-signature", []string{"-archive", "build"}, "archive requires -metadata-signature\n"},
		{"archive-missing-output", []string{"-archive", "build", "-metadata-signature", "metadata.sig"}, "archive requires -output\n"},
		{"archive-descriptor-conflict", []string{"-archive", "build", "-metadata-signature", "metadata.sig", "-output", "archive", "-descriptor", "enkv-plugin.json"}, "archive uses the existing build descriptor\n"},
		{"signature-without-archive", []string{"-metadata-signature", "metadata.sig"}, "metadata-signature requires -archive\n"},
		{"default-build-missing-output", nil, "plugin build: output: required\n"},
	} {
		for _, mode := range []string{"error-after-prefix", "nil-error-short"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				stderr := &cliDeliveryFailureWriter{}
				if mode == "error-after-prefix" {
					stderr.failure = errors.New("controlled diagnostic delivery failure")
				}
				var stdout bytes.Buffer
				code := run(t.Context(), tc.args, &stdout, stderr)
				if stdout.Len() != 0 || stderr.calls == 0 || stderr.attempted <= 7 || stderr.body.String() != tc.diagnostic[:7] {
					t.Fatalf("required diagnostic delivery: stdout=%q body=%q calls=%d attempted=%d", stdout.String(), stderr.body.String(), stderr.calls, stderr.attempted)
				}
				if code != 1 {
					t.Fatalf("failed diagnostic returned exit code %d; want operational failure 1", code)
				}
			})
		}
	}
}
