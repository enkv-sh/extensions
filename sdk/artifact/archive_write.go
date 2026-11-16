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
)

type archiveOutput struct {
	writer io.Writer
	length uint64
}

// Write enforces the compressed-byte ceiling before forwarding and counts actual
// output. A nil-error short write is still a failed archive.
func (w *archiveOutput) Write(body []byte) (int, error) {
	if uint64(len(body)) > MaxArchiveBytes-w.length {
		return 0, ErrArchive
	}
	n, err := w.writer.Write(body)
	w.length += uint64(n)
	if err == nil && n != len(body) {
		err = io.ErrShortWrite
	}
	return n, err
}

// WriteArchive writes an official-package candidate with an external metadata
// signature. It borrows output and never closes it. A failed write can leave
// partial bytes; only a successful record describes a complete archive.
// Signature authentication and host admission remain the consumer's work.
func WriteArchive(ctx context.Context, output io.Writer, filename, directory string, metadata Metadata) (record ArchiveRecord, result error) {
	defer func() {
		if result != nil {
			record = ArchiveRecord{}
			result = archiveError(result)
		}
	}()
	if !safeArchiveFilename(filename) || output == nil {
		return record, ErrRecord
	}
	canonical, err := EncodeMetadata(metadata)
	if err != nil {
		return record, err
	}
	if err := plainDirectory(directory); err != nil {
		return record, err
	}
	entries, err := readPackageDirectory(directory, 8)
	if err != nil {
		return record, err
	}
	if len(entries) > 8 {
		return record, ErrRecord
	}
	files := make([]*os.File, 0, len(entries))
	defer func() {
		for _, file := range files {
			result = errors.Join(result, file.Close())
		}
	}()
	record = ArchiveRecord{Schema: "enkv/plugin-archive/v1", Purpose: "plugin-archive", Artifact: Hash(canonical), Name: metadata.Name, Version: metadata.Version, Platform: metadata.Platform, Archive: ArchiveFile{Filename: filename, SHA256: Hash([]byte("pending archive")), Length: 1}, Members: []ArchiveMember{}}
	total := uint64(1024)
	seen := map[string]bool{}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return record, err
		}
		if !validMemberName(entry.Name()) || !entry.Type().IsRegular() {
			return record, ErrRecord
		}
		path := filepath.Join(directory, entry.Name())
		before, err := os.Lstat(path)
		if err != nil {
			return record, err
		}
		if !before.Mode().IsRegular() || before.Size() < 0 || uint64(before.Size()) > MaxArchiveBytes || entry.Name() != "plugin" && before.Mode().Perm()&0111 != 0 || entry.Name() == "plugin" && before.Mode().Perm()&0111 == 0 {
			return record, ErrRecord
		}
		total += 512 + (uint64(before.Size())+511)/512*512
		if total > MaxArchiveBytes {
			return record, ErrRecord
		}
		file, err := openObservedFile(path, before)
		if err != nil {
			return record, err
		}
		files = append(files, file)
		hash := sha256.New()
		n, err := io.Copy(hash, io.LimitReader(contextReader{ctx, file}, before.Size()+1))
		if pathErr := checkObservedPath(path, before); err != nil || pathErr != nil || n != before.Size() {
			return record, errors.Join(ErrRecord, err, pathErr)
		}
		var digest Digest
		copy(digest[:], hash.Sum(nil))
		record.Members = append(record.Members, ArchiveMember{Name: entry.Name(), Length: uint64(n), SHA256: digest})
		seen[entry.Name()] = true
	}
	if !seen["metadata.sig"] || !seen["LICENSE"] {
		return record, ErrRecord
	}
	contents, err := ReadPackageBytes(ctx, directory, record)
	if err != nil || !bytes.Equal(contents.MetadataBytes, canonical) {
		return record, errors.Join(ErrRecord, err)
	}
	if err := verifyDependency(metadata, contents.DependencyBytes); err != nil {
		return record, err
	}
	hash := sha256.New()
	compressed := &archiveOutput{writer: io.MultiWriter(output, hash)}
	gz := gzip.NewWriter(compressed)
	tarWriter := tar.NewWriter(gz)
	for i, member := range record.Members {
		if _, err := files[i].Seek(0, io.SeekStart); err != nil {
			return record, errors.Join(err, tarWriter.Close(), gz.Close())
		}
		mode := int64(0644)
		if member.Name == "plugin" {
			mode = 0755
		}
		header := &tar.Header{Name: member.Name, Mode: mode, Size: int64(member.Length), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}
		if err := tarWriter.WriteHeader(header); err != nil {
			return record, errors.Join(err, tarWriter.Close(), gz.Close())
		}
		memberHash := sha256.New()
		n, err := io.Copy(io.MultiWriter(tarWriter, memberHash), io.LimitReader(contextReader{ctx, files[i]}, int64(member.Length)+1))
		if err != nil || uint64(n) != member.Length || !bytes.Equal(memberHash.Sum(nil), member.SHA256[:]) {
			return record, errors.Join(ErrRecord, err, tarWriter.Close(), gz.Close())
		}
	}
	if err := errors.Join(tarWriter.Close(), gz.Close(), ctx.Err()); err != nil {
		return record, err
	}
	record.Archive.Length = compressed.length
	copy(record.Archive.SHA256[:], hash.Sum(nil))
	if _, err := EncodeArchiveRecord(record); err != nil {
		return record, err
	}
	return record, nil
}
