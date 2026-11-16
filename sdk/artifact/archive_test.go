package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// full_only: false
func TestExtractArchiveRefusesBeforeExistingFilesChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keep")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := ExtractArchive(context.Background(), bytes.NewReader(nil), ArchiveRecord{}, dir); !errors.Is(err, ErrArchive) {
		t.Fatalf("extract invalid record: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "unchanged" {
		t.Fatalf("changed existing file: %v %q", err, got)
	}
}

// These literals use SHA-256("abc") and independently framed Python JSON,
// big-endian dependency framing and the documented identity preimages.
const packageMetadata = `{"schema":"enkv/plugin-artifact/v2","purpose":"plugin-executable","name":"generic-json","role":"manifest-generator","version":"1.0.0","main_module":"example.test/plugin","command":"example.test/plugin","platform":"linux/amd64","toolchain":"go1.27.0","build_options":[],"contracts":[{"kind":"wire","identity":"0100000000000000000000000000000000000000000000000000000000000000","version":9}],"family":{"schema":2,"facts":{"schema":2,"descriptor":{"schema":1,"name":"generic-json","role":"manifest-generator","version":"1.0.0","wire":{"kind":"wire","identity":"0100000000000000000000000000000000000000000000000000000000000000","version":9},"generator":null,"output":null,"manifest":{"config_contract_id":"private-settings/v1","format_contract_id":"private-reference/v1"}},"descriptor_id":"cf3309d300871e9a325a766504b5ee08c16a945ab1fd172701ae3e7f0f16c368","executor_id":"2d69c1f99a3b8187fb7649d5b3d925eefb91a92e5fd0f3c575a7fec6f9df44d4","artifact_contract_id":"bc44c21e3a4a4d95537e9e25c3231502a7dfab00b521eea344bbc02e45e6d54e","dependency_manifest_id":"b1581dd698f9775616dd523619bdc4ec9ae1b86ee97e40606ec89098ef7fcdac","artifact_sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","artifact_length":3,"module":"example.test/plugin","command":"example.test/plugin","go_version":"go1.27.0","native_tuple":"linux/amd64"},"dependency":{"sha256":"202dcc7ed3a82e524d4d72e691dd1c4c5884da41f6a8c8e2aa1ae4936e1385f7","length":588}},"executable":{"sha256":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","length":3},"sources":[{"module":"example.test/plugin","digest":"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}],"resolved":[{"path":"example.test/plugin","version":"","sum":"","replacement":null}],"compiled":[{"path":"example.test/plugin","version":"(devel)","sum":"","replacement":null}]}`
const packageMetadataIdentity = "f7915747143933a0d1b7f81f5ff025d324c84bf3c9d7accb9394e76558d9c0e2"
const packageDependencyHex = "0003000002467b22726f6c65223a226d616e69666573742d67656e657261746f72222c226d61696e5f6d6f64756c65223a226578616d706c652e746573742f706c7567696e222c22636f6d6d616e64223a226578616d706c652e746573742f706c7567696e222c22706c6174666f726d223a226c696e75782f616d643634222c22746f6f6c636861696e223a22676f312e32372e30222c226275696c645f6f7074696f6e73223a5b5d2c22636f6e747261637473223a5b7b226b696e64223a2277697265222c226964656e74697479223a2230313030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030222c2276657273696f6e223a397d5d2c22736f7572636573223a5b7b226d6f64756c65223a226578616d706c652e746573742f706c7567696e222c22646967657374223a2262613738313662663866303163666561343134313430646535646165323232336230303336316133393631373761396362343130666636316632303031356164227d5d2c227265736f6c766564223a5b7b2270617468223a226578616d706c652e746573742f706c7567696e222c2276657273696f6e223a22222c2273756d223a22222c227265706c6163656d656e74223a6e756c6c7d5d2c22636f6d70696c6564223a5b7b2270617468223a226578616d706c652e746573742f706c7567696e222c2276657273696f6e223a2228646576656c29222c2273756d223a22222c227265706c6163656d656e74223a6e756c6c7d5d7d"

func packageDependency() []byte {
	body, err := hex.DecodeString(packageDependencyHex)
	if err != nil {
		panic(err)
	}
	return body
}

type testArchiveEntry struct {
	header tar.Header
	body   []byte
}

func packageEntries() []testArchiveEntry {
	return []testArchiveEntry{
		{tar.Header{Name: "metadata.json", Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, []byte(packageMetadata)},
		{tar.Header{Name: "plugin", Mode: 0700, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, []byte("abc")},
		{tar.Header{Name: "dependencies.bin", Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, packageDependency()},
	}
}
func archiveBytes(t *testing.T, entries []testArchiveEntry, tarSuffix, gzipSuffix []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	writer := tar.NewWriter(&raw)
	for _, entry := range entries {
		header := entry.header
		header.Size = int64(len(entry.body))
		if header.Typeflag == tar.TypeSymlink {
			header.Size = 0
		}
		if err := writer.WriteHeader(&header); err != nil {
			t.Fatal(err)
		}
		if header.Size > 0 {
			if _, err := writer.Write(entry.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	raw.Write(tarSuffix)
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	if _, err := gz.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	compressed.Write(gzipSuffix)
	return compressed.Bytes()
}

func archiveFixture(t *testing.T, entries []testArchiveEntry, tarSuffix, gzipSuffix []byte) ([]byte, ArchiveRecord) {
	t.Helper()
	body := archiveBytes(t, entries, tarSuffix, gzipSuffix)
	record := ArchiveRecord{Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: sha256.Sum256([]byte(packageMetadata)), Name: "generic-json", Version: "1.0.0", Platform: "linux/amd64", Archive: ArchiveFile{Filename: "generic-json.tar.gz", SHA256: sha256.Sum256(body), Length: uint64(len(body))}, Members: []ArchiveMember{
		{Name: "dependencies.bin", Length: uint64(len(packageDependency())), SHA256: sha256.Sum256(packageDependency())},
		{Name: "metadata.json", Length: uint64(len(packageMetadata)), SHA256: sha256.Sum256([]byte(packageMetadata))},
		{Name: "plugin", Length: 3, SHA256: sha256.Sum256([]byte("abc"))},
	}}
	return body, record
}

// full_only: false
func TestExtractArchiveAndOfflineExactPackage(t *testing.T) {
	body, record := archiveFixture(t, packageEntries(), nil, nil)
	dir := t.TempDir()
	if err := ExtractArchive(context.Background(), bytes.NewReader(body), record, dir); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(context.Background(), dir, record); err != nil {
		t.Fatal(err)
	}
	// Offline verification makes no compressed-byte observation or claim.
	offline := record
	offline.Archive.SHA256 = sha256.Sum256([]byte("unobserved"))
	offline.Archive.Length++
	if err := VerifyPackage(context.Background(), dir, offline); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "NOTICE"), []byte("extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(context.Background(), dir, record); !errors.Is(err, ErrArchive) {
		t.Fatalf("accepted unlisted member: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "NOTICE")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugin"), []byte("abd"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPackage(context.Background(), dir, record); !errors.Is(err, ErrArchive) {
		t.Fatalf("accepted changed executable: %v", err)
	}
}

// full_only: false
func TestExtractArchiveRejectsUnsafeOrDamagedStreamsAndCleansFiles(t *testing.T) {
	cases := []struct {
		name                  string
		mutate                func([]testArchiveEntry) []testArchiveEntry
		tarSuffix, gzipSuffix []byte
		record                func(*ArchiveRecord)
	}{
		{name: "duplicate", mutate: func(e []testArchiveEntry) []testArchiveEntry { return append(e, e[1]) }},
		{name: "traversal", mutate: func(e []testArchiveEntry) []testArchiveEntry { e[1].header.Name = "../plugin"; return e }},
		{name: "absolute", mutate: func(e []testArchiveEntry) []testArchiveEntry { e[1].header.Name = "/plugin"; return e }},
		{name: "link", mutate: func(e []testArchiveEntry) []testArchiveEntry {
			e[1].header.Typeflag = tar.TypeSymlink
			e[1].header.Linkname = "elsewhere"
			return e
		}},
		{name: "extra", mutate: func(e []testArchiveEntry) []testArchiveEntry {
			return append(e, testArchiveEntry{tar.Header{Name: "other", Mode: 0700, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, []byte("abc")})
		}},
		{name: "extra-executable-mode", mutate: func(e []testArchiveEntry) []testArchiveEntry { e[0].header.Mode = 0700; return e }},
		{name: "pax", mutate: func(e []testArchiveEntry) []testArchiveEntry {
			e[0].header.Format = tar.FormatPAX
			e[0].header.PAXRecords = map[string]string{"comment": "forbidden"}
			return e
		}},
		{name: "missing", mutate: func(e []testArchiveEntry) []testArchiveEntry { return e[:1] }},
		{name: "member-hash", mutate: func(e []testArchiveEntry) []testArchiveEntry { e[1].body = []byte("abd"); return e }},
		{name: "member-length", mutate: func(e []testArchiveEntry) []testArchiveEntry { e[1].body = []byte("abcd"); return e }},
		{name: "tar-trailing", tarSuffix: []byte("trailing")},
		{name: "gzip-trailing", gzipSuffix: []byte("trailing")},
		{name: "compressed-length", record: func(r *ArchiveRecord) { r.Archive.Length++ }},
		{name: "compressed-hash", record: func(r *ArchiveRecord) { r.Archive.SHA256 = sha256.Sum256([]byte("wrong")) }},
		{name: "metadata-identity", record: func(r *ArchiveRecord) { r.Version = "1.0.1" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			entries := packageEntries()
			if c.mutate != nil {
				entries = c.mutate(entries)
			}
			body, record := archiveFixture(t, entries, c.tarSuffix, c.gzipSuffix)
			if c.record != nil {
				c.record(&record)
			}
			dir := t.TempDir()
			if err := ExtractArchive(context.Background(), bytes.NewReader(body), record, dir); !errors.Is(err, ErrArchive) {
				t.Fatalf("accepted damaged archive: %v", err)
			}
			files, err := os.ReadDir(dir)
			if err != nil || len(files) != 0 {
				t.Fatalf("left extracted files: %v %v", files, err)
			}
		})
	}
	body, record := archiveFixture(t, packageEntries(), nil, nil)
	gzReader, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := io.ReadAll(gzReader)
	if err != nil {
		t.Fatal(err)
	}
	if err := gzReader.Close(); err != nil {
		t.Fatal(err)
	}
	var missingTerminator bytes.Buffer
	gzWriter := gzip.NewWriter(&missingTerminator)
	if _, err := gzWriter.Write(raw[:len(raw)-1024]); err != nil {
		t.Fatal(err)
	}
	if err := gzWriter.Close(); err != nil {
		t.Fatal(err)
	}
	terminatedRecord := record
	terminatedRecord.Archive.SHA256 = sha256.Sum256(missingTerminator.Bytes())
	terminatedRecord.Archive.Length = uint64(missingTerminator.Len())
	if err := ExtractArchive(context.Background(), bytes.NewReader(missingTerminator.Bytes()), terminatedRecord, t.TempDir()); !errors.Is(err, ErrArchive) {
		t.Fatalf("accepted missing tar terminator: %v", err)
	}
	for _, damaged := range [][]byte{body[:len(body)-1], append(append([]byte{}, body...), body...)} {
		r := record
		r.Archive.SHA256 = sha256.Sum256(damaged)
		r.Archive.Length = uint64(len(damaged))
		if err := ExtractArchive(context.Background(), bytes.NewReader(damaged), r, t.TempDir()); !errors.Is(err, ErrArchive) {
			t.Fatalf("accepted truncated/concatenated gzip: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ExtractArchive(ctx, bytes.NewReader(body), record, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("lost cancellation cause: %v", err)
	}
}

// Parent-derived original output schema-2 bytes: Python struct framing and
// hashlib, with no production codec. The body is 668 bytes and its original
// family identity is 0f648984a9e267ba5dfa394e4c10793b862bdd0f4dacfe33073ac878ae3d364f.
const retainedPackageDependencyHex = "000200000008676f312e32372e300000000c64617277696e2f61726d3634000000386769746875622e636f6d2f44657269756c2f656e6b762d696d706c2f706c7567696e732f6f75747075742d636f6e74726163742d74657374000000566769746875622e636f6d2f44657269756c2f656e6b762d696d706c2f706c7567696e732f6f75747075742d636f6e74726163742d746573742f636d642f656e6b762d6f75747075742d636f6e74726163742d74657374002ea88c7a30351b12a4dcfc06cdce2af6eab18416176466c2500cb6ef74f745bfa9d0df1873a041a6e38e2c461ffc6b53d216fd7cfab9bece3e9b5bc5c69b42035e689e2b01672bf33996e75d5e372ff60c536ce1599a1458e867cd8f4bef51600000000300000012656e6b762e73682f73646b2f6f75747075740000000676302e302e30000000386769746875622e636f6d2f44657269756c2f656e6b762d696d706c2f706c7567696e732f6f75747075742d636f6e74726163742d74657374000000056c6f63616c0000002c6769746875622e636f6d2f44657269756c2f656e6b762d696d706c2f70726f746f636f6c732f6f75747075740000000676302e302e300000000200000012656e6b762e73682f73646b2f6f75747075740000000676302e302e3000000000000000272e2e2f2e2e2f2e2e2f2e2e2f64657269756c2d656e6b762d646f63732f73646b2f6f75747075740000000728646576656c29000000000000002c6769746875622e636f6d2f44657269756c2f656e6b762d696d706c2f70726f746f636f6c732f6f75747075740000000676302e302e3000000000000000312e2e2f2e2e2f2e2e2f2e2e2f64657269756c2d656e6b762d646f63732f73646b2f70726f746f636f6c732f6f75747075740000000728646576656c2900000000"

func retainedPackageFixture(t *testing.T) (Metadata, []byte) {
	t.Helper()
	dependency, err := hex.DecodeString(retainedPackageDependencyHex)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(dependency)
	if len(dependency) != 668 || hex.EncodeToString(digest[:]) != "0cf005b5ec7831aa6a607752e05ebaed7c10941783f696befee793df2f2f640d" {
		t.Fatal("independent dependency fixture differs")
	}
	// This synthetic outer package makes no source or admission claim. The raw
	// package owner binds the original bytes; their semantic owner checks them.
	m := codecMetadata()
	m.Name = "aws-secrets-manager"
	m.Role = "output"
	m.Platform = "darwin/arm64"
	m.Executable = DigestLength{SHA256: sha256.Sum256([]byte("abc")), Length: 3}
	identity, err := ParseDigest("0f648984a9e267ba5dfa394e4c10793b862bdd0f4dacfe33073ac878ae3d364f")
	if err != nil {
		t.Fatal(err)
	}
	descriptor := authorDescriptor("output")
	descriptor.Name = m.Name
	facts, err := BindOutputFacts(OutputFacts{Schema: FamilySchema, Descriptor: descriptor, ExecutionFacts: ExecutionFacts{Module: m.MainModule, Command: m.Command, GoVersion: m.Toolchain, NativeTuple: m.Platform}}, m.Executable.SHA256, m.Executable.Length, identity)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	m.Family = &Family{Schema: FamilySchema, Facts: body, Dependency: DigestLength{SHA256: digest, Length: uint64(len(dependency))}}
	m.Contracts = []Contract{descriptor.Wire}
	return m, dependency
}

func packageArchiveFixture(t *testing.T, m Metadata, dependency []byte) ([]byte, ArchiveRecord, []byte) {
	t.Helper()
	metadata, err := EncodeMetadata(m)
	if err != nil {
		t.Fatal(err)
	}
	entries := []testArchiveEntry{
		{tar.Header{Name: "dependencies.bin", Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, dependency},
		{tar.Header{Name: "metadata.json", Mode: 0600, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, metadata},
		{tar.Header{Name: "plugin", Mode: 0700, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}, []byte("abc")},
	}
	body := archiveBytes(t, entries, nil, nil)
	record := ArchiveRecord{Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: sha256.Sum256(metadata), Name: m.Name, Version: m.Version, Platform: m.Platform, Archive: ArchiveFile{Filename: "retained-fixture.tar.gz", SHA256: sha256.Sum256(body), Length: uint64(len(body))}, Members: []ArchiveMember{}}
	for _, entry := range entries {
		record.Members = append(record.Members, ArchiveMember{Name: entry.header.Name, Length: uint64(len(entry.body)), SHA256: sha256.Sum256(entry.body)})
	}
	return body, record, metadata
}

// full_only: false
func TestPackageBytesRetainExactLegacyMembersWithoutCurrentAdmission(t *testing.T) {
	m, dependency := retainedPackageFixture(t)
	body, record, metadata := packageArchiveFixture(t, m, dependency)
	directory := t.TempDir()
	contents, err := ExtractArchiveBytes(t.Context(), bytes.NewReader(body), record, directory, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents.MetadataBytes, metadata) || !bytes.Equal(contents.DependencyBytes, dependency) || !reflect.DeepEqual(contents.Metadata, m) {
		t.Fatal("captured package bytes differ")
	}
	read, err := ReadPackageBytes(t.Context(), directory, record)
	if err != nil || !reflect.DeepEqual(read, contents) {
		t.Fatalf("offline captured bytes differ: %v", err)
	}
	if err := VerifyPackage(t.Context(), directory, record); !errors.Is(err, ErrArchive) || !errors.Is(err, ErrRecord) {
		t.Fatalf("current verifier admitted retained schema2: %v", err)
	}
	strictDirectory := t.TempDir()
	if err := ExtractArchive(t.Context(), bytes.NewReader(body), record, strictDirectory); !errors.Is(err, ErrArchive) || !errors.Is(err, ErrRecord) {
		t.Fatalf("current extraction admitted retained schema2: %v", err)
	}
	files, err := os.ReadDir(strictDirectory)
	if err != nil || len(files) != 0 {
		t.Fatalf("strict refusal left created members: %v %v", files, err)
	}
	// Signature verification can use the exact captured metadata after the source
	// directory changes. The capture is independent caller-owned memory.
	if err := os.WriteFile(filepath.Join(directory, "metadata.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(contents.MetadataBytes, metadata) {
		t.Fatal("captured metadata changed with disk")
	}
	failed, err := ReadPackageBytes(t.Context(), directory, record)
	if !errors.Is(err, ErrArchive) || !reflect.DeepEqual(failed, PackageContents{}) {
		t.Fatalf("damaged read returned partial contents: %#v %v", failed, err)
	}
}

// full_only: false
func TestPackageBytesCheckRawDependencyBindingWithoutSelectingItsDomain(t *testing.T) {
	for _, condition := range []string{"family-hash", "family-length", "inner-identity"} {
		t.Run(condition, func(t *testing.T) {
			m, dependency := retainedPackageFixture(t)
			switch condition {
			case "family-hash":
				m.Family.Dependency.SHA256 = Digest{99}
			case "family-length":
				m.Family.Dependency.Length++
			case "inner-identity":
				facts, err := m.OutputFacts()
				if err != nil {
					t.Fatal(err)
				}
				facts, err = BindOutputFacts(facts, facts.ArtifactSHA256, facts.ArtifactLength, Digest{99})
				if err != nil {
					t.Fatal(err)
				}
				m.Family.Facts, err = json.Marshal(facts)
				if err != nil {
					t.Fatal(err)
				}
			}
			body, record, metadata := packageArchiveFixture(t, m, dependency)
			directory := t.TempDir()
			contents, err := ExtractArchiveBytes(t.Context(), bytes.NewReader(body), record, directory, nil)
			if condition == "inner-identity" {
				if err != nil || !bytes.Equal(contents.MetadataBytes, metadata) || !bytes.Equal(contents.DependencyBytes, dependency) {
					t.Fatalf("raw layer interpreted inner dependency identity: %v", err)
				}
				if err := VerifyPackage(t.Context(), directory, record); !errors.Is(err, ErrRecord) {
					t.Fatalf("strict verifier admitted wrong construction: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrArchive) || !reflect.DeepEqual(contents, PackageContents{}) {
				t.Fatalf("accepted damaged family byte binding: %#v %v", contents, err)
			}
			files, readErr := os.ReadDir(directory)
			if readErr != nil || len(files) != 0 {
				t.Fatalf("raw refusal left members: %v %v", files, readErr)
			}
		})
	}
}

type archiveEOFAction struct {
	source io.Reader
	action func() error
	done   bool
}

func (r *archiveEOFAction) Read(p []byte) (int, error) {
	n, err := r.source.Read(p)
	if err == io.EOF && !r.done {
		r.done = true
		if actionErr := r.action(); actionErr != nil {
			return n, actionErr
		}
	}
	return n, err
}

// full_only: false
func TestArchiveFailurePreservesForeignFilesAndCleanupCauses(t *testing.T) {
	body, record := archiveFixture(t, packageEntries(), nil, nil)
	directory := t.TempDir()
	sourceFailure := errors.New("archive source failed")
	reader := &archiveEOFAction{source: bytes.NewReader(body), action: func() error {
		if err := os.Remove(filepath.Join(directory, "plugin")); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, "plugin"), []byte("foreign replacement"), 0700); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(directory, "foreign"), []byte("foreign member"), 0600); err != nil {
			return err
		}
		return sourceFailure
	}}
	contents, err := ExtractArchiveBytes(t.Context(), reader, record, directory, nil)
	if !errors.Is(err, sourceFailure) || !reflect.DeepEqual(contents, PackageContents{}) {
		t.Fatalf("lost read cause or returned partial contents: %#v %v", contents, err)
	}
	for name, want := range map[string]string{"plugin": "foreign replacement", "foreign": "foreign member"} {
		got, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil || string(got) != want {
			t.Fatalf("foreign file changed: %s %q %v", name, got, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "metadata.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned member survived failure: %v", err)
	}
	for _, test := range []struct {
		name                    string
		preclosed, knownFailure bool
	}{
		{"live_owned_failure", false, true},
		{"preclosed_known_failure", true, true},
		{"preclosed_close_only", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "owned")
			file, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.WriteString("owned bytes"); err != nil {
				t.Fatal(err)
			}
			identity, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			if test.preclosed {
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			var original error
			if test.knownFailure {
				original = sourceFailure
			}
			err = finishArchiveFiles([]extractedArchiveFile{{path: path, file: file, identity: identity}}, original)
			if errors.Is(err, sourceFailure) != test.knownFailure {
				t.Fatalf("original failure cause differs: %v", err)
			}
			if _, statErr := file.Stat(); !errors.Is(statErr, os.ErrClosed) {
				t.Fatalf("ownership handle remains open: %v", statErr)
			}
			if !test.preclosed {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("live-owned member survived known failure: %v", err)
				}
				return
			}
			var pathFailure *os.PathError
			if !errors.As(err, &pathFailure) || !strings.Contains(err.Error(), "close "+path+":") {
				t.Errorf("final close failure cause was not retained: %v", err)
			}
			if test.knownFailure && !strings.Contains(err.Error(), "ownership unavailable") {
				t.Errorf("missing live ownership was not reported: %v", err)
			}
			body, readErr := os.ReadFile(path)
			if readErr != nil || string(body) != "owned bytes" {
				t.Errorf("released ownership was used to remove a pathname: %q %v", body, readErr)
			}
		})
	}
}

type observedArchiveMember struct {
	*os.File
	name                      string
	syncFailure, closeFailure error
	events                    *[]string
}

func (f *observedArchiveMember) Sync() error {
	*f.events = append(*f.events, "sync "+f.name)
	if f.syncFailure != nil {
		return f.syncFailure
	}
	return f.File.Sync()
}
func (f *observedArchiveMember) Close() error {
	*f.events = append(*f.events, "close "+f.name)
	return errors.Join(f.File.Close(), f.closeFailure)
}

// full_only: false
func TestArchiveMemberSyncAndCloseFailuresPreventSuccessfulHandoff(t *testing.T) {
	body, record := archiveFixture(t, packageEntries(), nil, nil)
	for _, condition := range []string{"success", "sync metadata.json", "sync plugin", "sync dependencies.bin", "close plugin", "retain plugin"} {
		t.Run(condition, func(t *testing.T) {
			directory := t.TempDir()
			failure := errors.New("member operation failed")
			var events []string
			var created []*observedArchiveMember
			var retained []extractedArchiveFile
			opener := func(path string, flags int, mode os.FileMode) (archiveMemberFile, error) {
				file, err := os.OpenFile(path, flags, mode)
				if err != nil {
					return nil, err
				}
				member := &observedArchiveMember{File: file, name: filepath.Base(path), events: &events}
				if condition == "sync "+member.name {
					member.syncFailure = failure
				}
				if condition == "close "+member.name {
					member.closeFailure = failure
				}
				created = append(created, member)
				return member, nil
			}
			retain := func(name string, identity os.FileInfo) error {
				if condition == "retain "+name {
					return failure
				}
				path := filepath.Join(directory, name)
				file, err := os.Open(path)
				if err != nil {
					return err
				}
				held, statErr := file.Stat()
				if statErr != nil || !os.SameFile(identity, held) {
					return errors.Join(ErrRecord, statErr, file.Close())
				}
				retained = append(retained, extractedArchiveFile{path: path, file: file, identity: identity})
				return nil
			}
			contents, err := extractArchiveBytesWithOpener(t.Context(), bytes.NewReader(body), record, directory, retain, opener)
			if condition == "success" {
				if err != nil {
					t.Fatal(err)
				}
				wantMetadata, decodeErr := DecodeMetadata([]byte(packageMetadata))
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				if !reflect.DeepEqual(contents, PackageContents{Metadata: wantMetadata, MetadataBytes: []byte(packageMetadata), DependencyBytes: packageDependency()}) {
					t.Error("successful extraction changed exact captured contents")
				}
			} else if !errors.Is(err, failure) || !reflect.DeepEqual(contents, PackageContents{}) {
				t.Errorf("member failure did not prevent successful handoff: contents=%#v error=%v", contents, err)
			}
			if condition == "success" || strings.HasPrefix(condition, "close ") {
				want := []string{"sync metadata.json", "sync plugin", "sync dependencies.bin", "close metadata.json", "close plugin", "close dependencies.bin"}
				if !reflect.DeepEqual(events, want) {
					t.Errorf("member sync/close ordering differs: got=%v want=%v", events, want)
				}
			}
			for _, file := range created {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Errorf("member %s handle not settled: %v", file.name, err)
				}
			}
			expectedRetained := len(created)
			if condition == "retain plugin" {
				expectedRetained--
			}
			if len(retained) != expectedRetained {
				t.Errorf("creation ownership not retained: held=%d expected=%d", len(retained), expectedRetained)
			}
			for _, member := range retained {
				if _, err := member.file.Stat(); err != nil {
					t.Errorf("caller ownership lost after extraction close: %v", err)
				}
			}
			if condition != "success" {
				cleanupErr := finishArchiveFiles(retained, failure)
				if !errors.Is(cleanupErr, failure) || cleanupErr.Error() != failure.Error() {
					t.Errorf("caller cleanup failed: %v", cleanupErr)
				}
				entries, readErr := os.ReadDir(directory)
				if readErr != nil || len(entries) != 0 {
					t.Errorf("failed member handoff left staging entries: %v %v", entries, readErr)
				}
			} else {
				if err := finishArchiveFiles(retained, nil); err != nil {
					t.Error(err)
				}
			}
		})
	}
}
