package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func archiveWriterFixture(t *testing.T) (string, Metadata, map[string][]byte) {
	t.Helper()
	directory := t.TempDir()
	metadata, err := DecodeMetadata([]byte(packageMetadata))
	if err != nil {
		t.Fatal(err)
	}
	members := map[string][]byte{"LICENSE": []byte("author license\n"), "THIRD_PARTY_NOTICES.md": []byte("Go license\n"), "dependencies.bin": packageDependency(), "metadata.json": []byte(packageMetadata), "metadata.sig": bytes.Repeat([]byte{7}, 64), "plugin": []byte("abc")}
	for name, body := range members {
		mode := os.FileMode(0600)
		if name == "plugin" {
			mode = 0700
		}
		if err := os.WriteFile(filepath.Join(directory, name), body, mode); err != nil {
			t.Fatal(err)
		}
	}
	return directory, metadata, members
}

// full_only: false
func TestWriteArchiveProducesDeterministicClosedPackage(t *testing.T) {
	directory, metadata, members := archiveWriterFixture(t)
	var first, second bytes.Buffer
	record, err := WriteArchive(t.Context(), &first, "generic-json.tar.gz", directory, metadata)
	if err != nil {
		t.Fatal(err)
	}
	again, err := WriteArchive(t.Context(), &second, "generic-json.tar.gz", directory, metadata)
	if err != nil || !bytes.Equal(first.Bytes(), second.Bytes()) || !reflect.DeepEqual(record, again) {
		t.Fatalf("archive is not deterministic: %v", err)
	}
	if record.Artifact != sha256.Sum256([]byte(packageMetadata)) || record.Archive.SHA256 != sha256.Sum256(first.Bytes()) || record.Archive.Length != uint64(first.Len()) {
		t.Fatal("archive record differs from independent byte measurements")
	}
	compressed := bytes.NewReader(first.Bytes())
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		t.Fatal(err)
	}
	gz.Multistream(false)
	if !gz.ModTime.IsZero() || gz.Name != "" || gz.Comment != "" || len(gz.Extra) != 0 || gz.OS != 255 {
		t.Fatal("gzip has variable or platform-specific metadata", gz.Header)
	}
	reader := tar.NewReader(gz)
	wantNames := []string{"LICENSE", "THIRD_PARTY_NOTICES.md", "dependencies.bin", "metadata.json", "metadata.sig", "plugin"}
	var expected []ArchiveMember
	for _, name := range wantNames {
		header, err := reader.Next()
		if err != nil {
			t.Fatal(err)
		}
		mode := int64(0644)
		if name == "plugin" {
			mode = 0755
		}
		if header.Name != name || header.Mode != mode || header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(time.Unix(0, 0)) {
			t.Fatalf("unexpected archive header: %#v", header)
		}
		body, err := io.ReadAll(reader)
		if err != nil || !bytes.Equal(body, members[name]) {
			t.Fatalf("member %s differs: %v", name, err)
		}
		expected = append(expected, ArchiveMember{Name: name, Length: uint64(len(body)), SHA256: sha256.Sum256(body)})
	}
	if _, err := reader.Next(); err != io.EOF {
		t.Fatal("archive has extra members or lacks a complete terminator", err)
	}
	if tail, err := io.ReadAll(gz); err != nil || len(tail) != 0 {
		t.Fatal("archive has extra expanded data", err)
	}
	if err := gz.Close(); err != nil || compressed.Len() != 0 || !reflect.DeepEqual(record.Members, expected) {
		t.Fatalf("archive has trailing bytes or incorrect member facts: %v", err)
	}
	extracted := t.TempDir()
	if err := ExtractArchive(t.Context(), bytes.NewReader(first.Bytes()), record, extracted); err != nil {
		t.Fatal("existing extraction refused produced archive", err)
	}
	if err := VerifyPackage(t.Context(), extracted, record); err != nil {
		t.Fatal("existing package verification refused produced archive", err)
	}
}

// full_only: false
func TestWriteArchiveRefusesInvalidMembersAndWriteFailures(t *testing.T) {
	for _, damage := range []string{"extra", "missing signature", "short signature", "missing license", "executable license", "symlink license", "changed metadata", "changed plugin", "missing dependency", "changed dependency", "oversized legal file"} {
		t.Run(damage, func(t *testing.T) {
			directory, metadata, _ := archiveWriterFixture(t)
			path := func(name string) string { return filepath.Join(directory, name) }
			var err error
			switch damage {
			case "extra":
				err = os.WriteFile(path("extra"), []byte("extra"), 0600)
			case "missing signature":
				err = os.Remove(path("metadata.sig"))
			case "short signature":
				err = os.Truncate(path("metadata.sig"), 63)
			case "missing license":
				err = os.Remove(path("LICENSE"))
			case "executable license":
				err = os.Chmod(path("LICENSE"), 0700)
			case "symlink license":
				if err = os.Remove(path("LICENSE")); err == nil {
					err = os.Symlink(path("THIRD_PARTY_NOTICES.md"), path("LICENSE"))
				}
			case "changed metadata":
				err = os.WriteFile(path("metadata.json"), []byte("{}"), 0600)
			case "changed plugin":
				err = os.WriteFile(path("plugin"), []byte("abd"), 0700)
			case "missing dependency":
				err = os.Remove(path("dependencies.bin"))
			case "changed dependency":
				err = os.WriteFile(path("dependencies.bin"), []byte("unexpected"), 0600)
			case "oversized legal file":
				err = os.Truncate(path("LICENSE"), MaxArchiveBytes)
			}
			if err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			record, err := WriteArchive(t.Context(), &output, "generic-json.tar.gz", directory, metadata)
			if !errors.Is(err, ErrArchive) || !reflect.DeepEqual(record, ArchiveRecord{}) || output.Len() != 0 {
				t.Fatalf("invalid members produced archive output or facts: record=%#v bytes=%d err=%v", record, output.Len(), err)
			}
		})
	}
	directory, metadata, _ := archiveWriterFixture(t)
	for _, filename := range []string{"../plugin.tar.gz", "plugin.zip"} {
		if _, err := WriteArchive(t.Context(), io.Discard, filename, directory, metadata); !errors.Is(err, ErrArchive) {
			t.Fatal("unsafe archive filename accepted", filename, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := WriteArchive(ctx, io.Discard, "plugin.tar.gz", directory, metadata); !errors.Is(err, context.Canceled) {
		t.Fatal("archive ignored cancellation", err)
	}
	for _, writer := range []io.Writer{archiveFailWriter{}, archiveShortWriter{}} {
		record, err := WriteArchive(t.Context(), writer, "plugin.tar.gz", directory, metadata)
		if !errors.Is(err, ErrArchive) || !reflect.DeepEqual(record, ArchiveRecord{}) {
			t.Fatal("failed output produced complete archive facts", record, err)
		}
	}
	bounded := &archiveOutput{writer: io.Discard, length: MaxArchiveBytes - 1}
	if n, err := bounded.Write([]byte{1, 2}); n != 0 || !errors.Is(err, ErrArchive) {
		t.Fatal("compressed output exceeded archive limit", n, err)
	}
}

type archiveFailWriter struct{}

func (archiveFailWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type archiveShortWriter struct{}

func (archiveShortWriter) Write([]byte) (int, error) { return 0, nil }
