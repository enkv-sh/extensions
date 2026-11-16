package artifact

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ErrArchive identifies archive production, extraction or package-verification
// failures. Use errors.Is; wrapped errors preserve record, context and I/O causes.
var ErrArchive = errors.New("artifact archive refused")

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

// Read checks cancellation between bounded artifact reads; it does not cancel an
// underlying Read already in progress.
func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

type countedReader struct {
	reader io.Reader
	count  uint64
}

// Read counts bytes actually supplied, including bytes returned with an error.
// Archive validation uses this count to reject missing terminators and extra data.
func (r *countedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.count += uint64(n)
	return n, err
}

func archiveError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrArchive, err)
}

func archiveMembers(record ArchiveRecord) (map[string]ArchiveMember, error) {
	if _, err := EncodeArchiveRecord(record); err != nil {
		return nil, err
	}
	members := make(map[string]ArchiveMember, len(record.Members))
	for _, member := range record.Members {
		members[member.Name] = member
	}
	return members, nil
}

func readPackageDirectory(path string, maximum int) ([]os.DirEntry, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.IsDir() {
		return nil, ErrRecord
	}
	directory, err := openObservedFile(path, before)
	if err != nil {
		return nil, err
	}
	entries, readErr := directory.ReadDir(maximum + 1)
	if errors.Is(readErr, io.EOF) {
		readErr = nil
	}
	if err := errors.Join(readErr, checkObservedPath(path, before), directory.Close()); err != nil {
		return nil, err
	}
	slices.SortFunc(entries, func(a, b os.DirEntry) int {
		return strings.Compare(a.Name(), b.Name())
	})
	return entries, nil
}

// PackageContents contains structurally verified bytes. MetadataBytes and
// DependencyBytes are owned captures; decoded Metadata owns separate record data.
// It does not grant source, signature, semantic compatibility or execution trust.
type PackageContents struct {
	Metadata        Metadata
	MetadataBytes   []byte
	DependencyBytes []byte
}

type archiveMemberFile interface {
	io.Writer
	Stat() (os.FileInfo, error)
	Sync() error
	Close() error
}

type archiveMemberOpener func(string, int, os.FileMode) (archiveMemberFile, error)

func openArchiveMember(path string, flags int, mode os.FileMode) (archiveMemberFile, error) {
	return os.OpenFile(path, flags, mode)
}

type extractedArchiveFile struct {
	path string
	// Holding the file through validation prevents inode reuse after replacement.
	file     archiveMemberFile
	identity os.FileInfo
}

func finishArchiveFiles(files []extractedArchiveFile, result error) error {
	result = cleanupArchiveFiles(files, result)
	for _, file := range files {
		if file.file != nil {
			if err := file.file.Close(); err != nil {
				result = errors.Join(result, archiveError(err))
			}
		}
	}
	return result
}

func cleanupArchiveFiles(files []extractedArchiveFile, result error) error {
	if result == nil {
		return nil
	}
	for _, file := range files {
		if file.file == nil || file.identity == nil {
			result = errors.Join(result, archiveError(errors.New("extracted file ownership unavailable")))
			continue
		}
		held, err := file.file.Stat()
		if err != nil {
			result = errors.Join(result, archiveError(fmt.Errorf("extracted file ownership unavailable: %w", err)))
			continue
		}
		if !os.SameFile(file.identity, held) {
			result = errors.Join(result, archiveError(errors.New("extracted file ownership unavailable")))
			continue
		}
		current, err := os.Lstat(file.path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result = errors.Join(result, archiveError(err))
			continue
		}
		if !os.SameFile(held, current) {
			continue
		}
		if err := os.Remove(file.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, archiveError(err))
		}
	}
	return result
}

// ExtractArchive requires current dependency facts and writes into a caller-owned
// private empty directory. Failure cleanup removes only files with proven live
// ownership. Lost ownership or final close errors can leave staging entries.
func ExtractArchive(ctx context.Context, reader io.Reader, record ArchiveRecord, directory string) (result error) {
	var created []extractedArchiveFile
	defer func() { result = finishArchiveFiles(created, result) }()
	contents, err := extractArchiveBytes(ctx, reader, record, directory, &created, openArchiveMember, nil)
	if err != nil {
		return err
	}
	return archiveError(verifyDependency(contents.Metadata, contents.DependencyBytes))
}

// ExtractArchiveBytes writes into a caller-owned private empty directory and
// returns exact metadata and dependency bytes from bounded members. Callers
// authenticate and interpret those bytes separately.
// retain, when nonnil, receives each created basename and its identity while the
// creation descriptor is still open. It can retain an independent ownership
// handle for caller cleanup, including after a final member-close failure.
// A retain error refuses extraction. A failure returns no contents and removes
// only files with proven live ownership. Remaining staging belongs to the caller.
func ExtractArchiveBytes(ctx context.Context, reader io.Reader, record ArchiveRecord, directory string, retain func(string, os.FileInfo) error) (contents PackageContents, result error) {
	return extractArchiveBytesWithOpener(ctx, reader, record, directory, retain, openArchiveMember)
}

func extractArchiveBytesWithOpener(ctx context.Context, reader io.Reader, record ArchiveRecord, directory string, retain func(string, os.FileInfo) error, openMember archiveMemberOpener) (contents PackageContents, result error) {
	var created []extractedArchiveFile
	defer func() {
		result = finishArchiveFiles(created, result)
		if result != nil {
			contents = PackageContents{}
		}
	}()
	return extractArchiveBytes(ctx, reader, record, directory, &created, openMember, retain)
}

func extractArchiveBytes(ctx context.Context, reader io.Reader, record ArchiveRecord, directory string, created *[]extractedArchiveFile, openMember archiveMemberOpener, retain func(string, os.FileInfo) error) (contents PackageContents, result error) {
	members, err := archiveMembers(record)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if err := ctx.Err(); err != nil {
		return PackageContents{}, archiveError(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if !info.IsDir() {
		return PackageContents{}, archiveError(ErrRecord)
	}
	entries, err := readPackageDirectory(directory, 0)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if len(entries) != 0 {
		return PackageContents{}, archiveError(ErrRecord)
	}
	compressedHash := sha256.New()
	compressed := &countedReader{reader: io.TeeReader(io.LimitReader(contextReader{ctx, reader}, MaxArchiveBytes+1), compressedHash)}
	buffered := bufio.NewReader(compressed)
	gz, err := gzip.NewReader(buffered)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	defer func() {
		if err := gz.Close(); err != nil {
			result = errors.Join(result, archiveError(err))
		}
	}()
	gz.Multistream(false)
	expanded := &countedReader{reader: io.LimitReader(contextReader{ctx, gz}, MaxArchiveBytes+1)}
	tarReader := tar.NewReader(expanded)
	seen := make(map[string]bool, len(members))
	expectedTarLength := uint64(1024)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return PackageContents{}, archiveError(err)
		}
		member, ok := members[header.Name]
		if !ok || seen[header.Name] || header.Format != tar.FormatUSTAR || header.Typeflag != tar.TypeReg || header.Linkname != "" || header.Size < 0 || uint64(header.Size) != member.Length || header.Name != "plugin" && header.Mode&0111 != 0 || header.Name == "plugin" && header.Mode&0111 == 0 {
			return PackageContents{}, archiveError(ErrRecord)
		}
		seen[header.Name] = true
		expectedTarLength += 512 + (member.Length+511)/512*512
		if expectedTarLength > MaxArchiveBytes {
			return PackageContents{}, archiveError(ErrRecord)
		}
		path := filepath.Join(directory, header.Name)
		mode := os.FileMode(0600)
		if header.Name == "plugin" {
			mode = 0700
		}
		file, err := openMember(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return PackageContents{}, archiveError(err)
		}
		identity, statErr := file.Stat()
		*created = append(*created, extractedArchiveFile{path: path, file: file, identity: identity})
		if statErr != nil {
			return PackageContents{}, archiveError(statErr)
		}
		if retain != nil {
			if err := retain(header.Name, identity); err != nil {
				return PackageContents{}, archiveError(err)
			}
		}
		hash := sha256.New()
		n, copyErr := io.Copy(io.MultiWriter(file, hash), tarReader)
		if copyErr != nil {
			return PackageContents{}, archiveError(copyErr)
		}
		if uint64(n) != member.Length || !bytes.Equal(hash.Sum(nil), member.SHA256[:]) || expanded.count > MaxArchiveBytes {
			return PackageContents{}, archiveError(ErrRecord)
		}
		if err := file.Sync(); err != nil {
			return PackageContents{}, archiveError(err)
		}
	}
	// tar.Reader accepts missing terminators. The exact structural length requires
	// both zero blocks, and the following read also validates gzip CRC and length.
	if len(seen) != len(members) || expanded.count != expectedTarLength {
		return PackageContents{}, archiveError(ErrRecord)
	}
	var extra [1]byte
	if n, err := expanded.Read(extra[:]); n != 0 || err != io.EOF {
		if err == nil || err == io.EOF {
			err = ErrRecord
		}
		return PackageContents{}, archiveError(err)
	}
	if n, err := buffered.Read(extra[:]); n != 0 || err != io.EOF {
		if err == nil || err == io.EOF {
			err = ErrRecord
		}
		return PackageContents{}, archiveError(err)
	}
	if compressed.count != record.Archive.Length || compressed.count > MaxArchiveBytes || !bytes.Equal(compressedHash.Sum(nil), record.Archive.SHA256[:]) {
		return PackageContents{}, archiveError(ErrRecord)
	}
	return ReadPackageBytes(ctx, directory, record)
}

// VerifyPackage verifies current installed members and current dependency facts.
// It makes no claim about observed compressed bytes or source authentication.
func VerifyPackage(ctx context.Context, directory string, record ArchiveRecord) error {
	contents, err := ReadPackageBytes(ctx, directory, record)
	if err != nil {
		return err
	}
	return archiveError(verifyDependency(contents.Metadata, contents.DependencyBytes))
}

// ReadPackageBytes checks the exact current member set and raw byte bindings.
// It returns captured canonical metadata for separate signature verification and
// leaves inner dependency interpretation to its owner.
func ReadPackageBytes(ctx context.Context, directory string, record ArchiveRecord) (PackageContents, error) {
	members, err := archiveMembers(record)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if err := ctx.Err(); err != nil {
		return PackageContents{}, archiveError(err)
	}
	root, err := os.Lstat(directory)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if !root.IsDir() {
		return PackageContents{}, archiveError(ErrRecord)
	}
	entries, err := readPackageDirectory(directory, len(members))
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if len(entries) != len(members) {
		return PackageContents{}, archiveError(ErrRecord)
	}
	var metadataBytes, dependencyBytes []byte
	for _, entry := range entries {
		member, ok := members[entry.Name()]
		if !ok {
			return PackageContents{}, archiveError(ErrRecord)
		}
		path := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return PackageContents{}, archiveError(err)
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != member.Length || entry.Name() != "plugin" && info.Mode().Perm()&0111 != 0 || entry.Name() == "plugin" && info.Mode().Perm()&0111 == 0 {
			return PackageContents{}, archiveError(ErrRecord)
		}
		file, err := openObservedFile(path, info)
		if err != nil {
			return PackageContents{}, archiveError(err)
		}
		hash := sha256.New()
		var retained bytes.Buffer
		var target io.Writer = hash
		if entry.Name() == "metadata.json" || entry.Name() == "dependencies.bin" {
			target = io.MultiWriter(hash, &retained)
		}
		n, copyErr := io.Copy(target, io.LimitReader(contextReader{ctx, file}, int64(member.Length)+1))
		pathErr := checkObservedPath(path, info)
		closeErr := file.Close()
		if err := errors.Join(copyErr, pathErr, closeErr); err != nil {
			return PackageContents{}, archiveError(err)
		}
		if uint64(n) != member.Length || !bytes.Equal(hash.Sum(nil), member.SHA256[:]) {
			return PackageContents{}, archiveError(ErrRecord)
		}
		switch entry.Name() {
		case "metadata.json":
			metadataBytes = retained.Bytes()
		case "dependencies.bin":
			dependencyBytes = retained.Bytes()
		}
	}
	metadata, err := DecodeMetadata(metadataBytes)
	if err != nil {
		return PackageContents{}, archiveError(err)
	}
	if Hash(metadataBytes) != record.Artifact || metadata.Name != record.Name || metadata.Version != record.Version || metadata.Platform != record.Platform {
		return PackageContents{}, archiveError(ErrRecord)
	}
	executable, ok := members["plugin"]
	if !ok || metadata.Executable.SHA256 != executable.SHA256 || metadata.Executable.Length != executable.Length {
		return PackageContents{}, archiveError(ErrRecord)
	}
	if metadata.Family == nil || dependencyBytes == nil || uint64(len(dependencyBytes)) != metadata.Family.Dependency.Length || Hash(dependencyBytes) != metadata.Family.Dependency.SHA256 {
		return PackageContents{}, archiveError(ErrRecord)
	}
	return PackageContents{Metadata: metadata, MetadataBytes: metadataBytes, DependencyBytes: dependencyBytes}, nil
}
