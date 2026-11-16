package main

import (
	"bytes"
	"context"
	"encoding/binary"
	plugin "enkv.sh/plugins/manifest-generators/generic-json"
	"enkv.sh/plugins/manifest-generators/generic-json/execution"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"
)

func commandRequestLiteral(t *testing.T) []byte {
	t.Helper()
	implementation, err := execution.NewImplementation(descriptorJSON)
	if err != nil {
		t.Fatal(err)
	}
	b := []byte("ENKV/MANIFEST/v2\x00")
	b = append(b, 2)
	b = append(b, 0x55)
	b = append(b, make([]byte, 31)...)
	identity := implementation.Identity()
	b = append(b, identity.DescriptorID[:]...)
	for _, value := range []string{"ENKV/CONSUMPTION-PROJECTION/v1", plugin.FormatContractID, plugin.ConfigContractID, "{}"} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(value)))
		b = append(b, value...)
	}
	b = append(b, 1, 2, 0)
	for _, first := range []byte{1, 2, 3, 4} {
		b = append(b, first)
		b = append(b, make([]byte, 31)...)
	}
	return append(b, make([]byte, 8)...)
}
func commandPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, f := range []*os.File{r, w} {
			if err := f.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				t.Error(err)
			}
		}
	})
	return r, w
}

// full_only: false
func TestManifestCommandUsesNativeEntryAndRefusesInvalidShape(t *testing.T) {
	for _, condition := range []string{"complete", "argument", "environment", "descriptor"} {
		t.Run(condition, func(t *testing.T) {
			requestR, requestW := commandPipe(t)
			artifactR, artifactW := commandPipe(t)
			statusR, statusW := commandPipe(t)
			b := commandRequestLiteral(t)
			if n, err := requestW.Write(b); err != nil || n != len(b) {
				t.Fatal(n, err)
			}
			if err := requestW.Close(); err != nil {
				t.Fatal(err)
			}
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := null.Close(); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestManifestCommandEntryHelper$", "--", condition)
			child.Env = []string{}
			child.Stdin, child.Stdout, child.Stderr = null, null, null
			child.ExtraFiles = []*os.File{requestR, artifactW, statusW}
			if condition == "descriptor" {
				child.ExtraFiles[0] = null
			}
			err = child.Run()
			if ctx.Err() != nil {
				t.Fatal("command child did not join", ctx.Err())
			}
			if err := artifactW.Close(); err != nil {
				t.Fatal(err)
			}
			if err := statusW.Close(); err != nil {
				t.Fatal(err)
			}
			code := 0
			if err != nil {
				var exit *exec.ExitError
				if !errors.As(err, &exit) {
					t.Fatal(err)
				}
				code = exit.ExitCode()
			}
			status, err := io.ReadAll(io.LimitReader(statusR, 4097))
			if err != nil {
				t.Fatal(err)
			}
			artifact, err := io.ReadAll(io.LimitReader(artifactR, 4097))
			if err != nil {
				t.Fatal(err)
			}
			if condition != "complete" {
				if code != 2 || len(status) != 0 || len(artifact) != 0 {
					t.Fatal("invalid command shape accepted", code, len(status), len(artifact))
				}
				return
			}
			expected := `{
  "schema": "ENKV/CONSUMPTION-MANIFEST/v3",
  "format_contract_id": "ENKV/CONSUMPTION-MANIFEST/v3",
  "config_contract_id": "ENKV/CONSUMPTION-MANIFEST-CONFIG/v1",
  "observation": {
    "domain_id": "0100000000000000000000000000000000000000000000000000000000000000",
    "head_revision_id": "0200000000000000000000000000000000000000000000000000000000000000",
    "snapshot_id": "0300000000000000000000000000000000000000000000000000000000000000"
  },
  "target_recipient_id": "0400000000000000000000000000000000000000000000000000000000000000",
  "selection": {
    "target_mode": "current-authority",
    "entry_mode": "exact-names"
  },
  "service_filter": null,
  "entries": [],
  "excluded_entries": [],
  "evidence_limit": "authorized-input-and-exact-bytes"
}
`
			want := []byte("ENKV/MANIFEST/v2\x00")
			want = append(want, 0x55)
			want = append(want, make([]byte, 31)...)
			want = append(want, 0)
			want = binary.BigEndian.AppendUint64(want, uint64(len(expected)))
			if code != 0 || !bytes.Equal(status, want) || string(artifact) != expected {
				t.Fatal("native command did not emit exact complete exchange", code, len(status), len(artifact))
			}
		})
	}
}

// full_only: false
func TestManifestCommandEntryHelper(t *testing.T) {
	if len(os.Args) < 3 || os.Args[len(os.Args)-2] != "--" {
		return
	}
	condition := os.Args[len(os.Args)-1]
	os.Args = []string{os.Args[0], "manifest-wire-v2"}
	os.Clearenv()
	if condition == "argument" {
		os.Args[1] = "unknown"
	}
	if condition == "environment" {
		if err := os.Setenv("UNEXPECTED", "present"); err != nil {
			os.Exit(90)
		}
	}
	main()
	os.Exit(91)
}
