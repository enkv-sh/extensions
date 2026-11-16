package artifact

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// full_only: false
func TestPackageDirectoryEnumerationIsBounded(t *testing.T) {
	body, record := archiveFixture(t, packageEntries(), nil, nil)
	directory := t.TempDir()
	for _, entry := range packageEntries() {
		if err := os.WriteFile(filepath.Join(directory, entry.header.Name), entry.body, os.FileMode(entry.header.Mode)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ReadPackageBytes(t.Context(), directory, record); err != nil {
		t.Fatalf("valid package: %v", err)
	}
	for i := range 8192 {
		if err := os.WriteFile(filepath.Join(directory, fmt.Sprintf("extra-%04d", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	checkAllocations := func(t *testing.T, read func()) {
		t.Helper()
		// A fixed member refusal must not allocate one entry per extra file.
		if allocations := testing.AllocsPerRun(3, read); allocations > 2048 {
			t.Fatalf("directory refusal allocated %.0f objects; maximum 2048", allocations)
		}
	}
	t.Run("extract", func(t *testing.T) {
		checkAllocations(t, func() {
			contents, err := ExtractArchiveBytes(t.Context(), bytes.NewReader(body), record, directory, nil)
			if !errors.Is(err, ErrArchive) || !errors.Is(err, ErrRecord) || !reflect.DeepEqual(contents, PackageContents{}) {
				t.Fatalf("nonempty extraction: contents %#v, error %v", contents, err)
			}
		})
	})
	t.Run("package", func(t *testing.T) {
		checkAllocations(t, func() {
			contents, err := ReadPackageBytes(t.Context(), directory, record)
			if !errors.Is(err, ErrArchive) || !errors.Is(err, ErrRecord) || !reflect.DeepEqual(contents, PackageContents{}) {
				t.Fatalf("extra package members: contents %#v, error %v", contents, err)
			}
		})
	})
	t.Run("build", func(t *testing.T) {
		identity := sha256.Sum256([]byte(packageMetadata))
		checkAllocations(t, func() {
			metadata, err := verifyBuildFolder(t.Context(), directory, identity)
			if err == nil || err.Error() != "build member set differs" || !reflect.DeepEqual(metadata, Metadata{}) {
				t.Fatalf("extra build members: metadata %#v, error %v", metadata, err)
			}
		})
	})
}
