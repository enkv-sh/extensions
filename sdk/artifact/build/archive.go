package build

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"enkv.sh/sdk/artifact"
)

// ArchiveConfig selects a verified local Build and the original Directory, Command
// and dependency mode needed to recapture its source facts. MetadataSignature is
// an external detached 64-byte signature file; this operation checks its shape,
// not its trust. Output must be a new directory outside Build with an existing
// parent. Workspace and Versioned follow Config; no library defaults are supplied.
type ArchiveConfig struct {
	Build, Directory, Command, Output, Workspace, MetadataSignature string
	Versioned                                                       bool
}

// Archive packages a verified build without changing its immutable folder.
// The caller signs metadata before this operation and archive.json afterward.
// Archive checks source/build stability and signature size, not signature trust.
// It never executes a plugin or reads a private signing key. Supply a nonnil context.
// On error the record is zero; a final write failure can leave an incomplete output
// directory. Use a fresh output path for another attempt.
func Archive(ctx context.Context, config ArchiveConfig) (record artifact.ArchiveRecord, result error) {
	defer func() {
		if result != nil {
			record = artifact.ArchiveRecord{}
		}
	}()
	if config.Build == "" || config.Directory == "" || config.Command == "" || config.Output == "" || config.MetadataSignature == "" || strings.Contains(config.Command, "...") || strings.HasPrefix(config.Command, "-") {
		return record, errors.New("archive requires build, directory, command, output and metadata signature")
	}
	directory, err := filepath.Abs(config.Directory)
	if err != nil {
		return record, err
	}
	output, err := filepath.Abs(config.Output)
	if err != nil {
		return record, err
	}
	if _, err := os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return record, fmt.Errorf("archive output must not exist: %w", errors.Join(os.ErrExist, err))
	}
	environment, err := buildEnvironment(Config{Workspace: config.Workspace, Versioned: config.Versioned})
	if err != nil {
		return record, err
	}
	metadata, err := artifact.VerifyBuild(ctx, config.Build)
	if err != nil {
		return record, err
	}
	if metadata.Platform != runtime.GOOS+"/"+runtime.GOARCH {
		return record, errors.New("archive requires the build's native platform")
	}
	identity, err := metadata.Identity()
	if err != nil {
		return record, err
	}
	outputParent, err := openArchiveOutputParent(config.Build, output, identity)
	if err != nil {
		return record, err
	}
	defer func() { result = errors.Join(result, outputParent.Close()) }()
	version, err := goCommand(ctx, directory, environment, "env", "GOVERSION")
	if err != nil {
		return record, err
	}
	if strings.TrimSpace(string(version)) != "go1.27.3" || metadata.Toolchain != "go1.27.3" {
		return record, errors.New("go 1.27.3 is required")
	}
	goRoot, err := goCommand(ctx, directory, environment, "env", "GOROOT")
	if err != nil {
		return record, err
	}
	before, modules, err := selectedInputs(ctx, directory, environment, config.Command, config.Versioned)
	if err != nil {
		return record, err
	}
	if err := archiveSourceFacts(ctx, before, modules, metadata); err != nil {
		return record, err
	}
	legal, err := artifact.CollectLegalFiles(ctx, before, metadata.MainModule, strings.TrimSpace(string(goRoot)))
	if err != nil {
		return record, err
	}
	temporary, err := os.MkdirTemp("", "enkv-plugin-archive-")
	if err != nil {
		return record, err
	}
	defer func() { result = errors.Join(result, os.RemoveAll(temporary)) }()
	stage := filepath.Join(temporary, "members")
	if err := os.Mkdir(stage, 0700); err != nil {
		return record, err
	}
	build := filepath.Join(config.Build, "builds", identity.String())
	for _, name := range []string{"plugin", "metadata.json", "dependencies.bin"} {
		mode := os.FileMode(0600)
		limit := int64(artifact.MaxRecordBytes)
		if name == "plugin" {
			mode, limit = 0700, artifact.MaxExecutableBytes
		}
		if err := copyArchiveFile(ctx, filepath.Join(build, name), filepath.Join(stage, name), mode, limit); err != nil {
			return record, err
		}
	}
	if err := copyArchiveFile(ctx, config.MetadataSignature, filepath.Join(stage, "metadata.sig"), 0600, 64); err != nil {
		return record, err
	}
	for name, body := range legal {
		if err := os.WriteFile(filepath.Join(stage, name), body, 0600); err != nil {
			return record, err
		}
	}
	filename := "enkv-plugin-" + identity.String() + ".tar.gz"
	archivePath := filepath.Join(temporary, filename)
	archive, err := os.OpenFile(archivePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return record, err
	}
	record, writeErr := artifact.WriteArchive(ctx, archive, filename, stage, metadata)
	if err := errors.Join(writeErr, archive.Close()); err != nil {
		return record, err
	}
	after, afterModules, err := selectedInputs(ctx, directory, environment, config.Command, config.Versioned)
	if err != nil {
		return record, err
	}
	if err := archiveSourceFacts(ctx, after, afterModules, metadata); err != nil {
		return record, err
	}
	afterLegal, err := artifact.CollectLegalFiles(ctx, after, metadata.MainModule, strings.TrimSpace(string(goRoot)))
	if err != nil {
		return record, err
	}
	afterBuild, err := artifact.VerifyBuild(ctx, config.Build)
	if err != nil {
		return record, err
	}
	if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(modules, afterModules) || !reflect.DeepEqual(legal, afterLegal) || !reflect.DeepEqual(metadata, afterBuild) {
		return record, errors.New("selected sources or build changed during archive creation")
	}
	body, err := artifact.EncodeArchiveRecord(record)
	if err != nil {
		return record, err
	}
	if err := outputParent.Mkdir(filepath.Base(output), 0755); err != nil {
		return record, err
	}
	outputDirectory, err := outputParent.OpenRoot(filepath.Base(output))
	if err != nil {
		return record, err
	}
	defer func() { result = errors.Join(result, outputDirectory.Close()) }()
	file, err := outputDirectory.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return record, err
	}
	if err := errors.Join(copyArchiveFileTo(ctx, archivePath, file, artifact.MaxArchiveBytes), file.Close()); err != nil {
		return record, err
	}
	if err := writeArchiveRecord(outputDirectory, body); err != nil {
		return record, err
	}
	return record, nil
}

func openArchiveOutputParent(build, output string, identity artifact.Digest) (parent *os.Root, result error) {
	build, err := filepath.Abs(build)
	if err != nil {
		return nil, err
	}
	build, err = filepath.EvalSymlinks(build)
	if err != nil {
		return nil, err
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, root.Close())
		}
	}()
	held, err := root.Stat(".")
	if err != nil {
		return nil, err
	}
	parentPath, err = filepath.EvalSymlinks(parentPath)
	if err != nil {
		return nil, err
	}
	current, err := os.Stat(parentPath)
	if err != nil || !os.SameFile(held, current) {
		return nil, errors.Join(errors.New("archive output parent changed"), err)
	}
	relative, err := filepath.Rel(build, parentPath)
	if err != nil {
		return nil, err
	}
	if relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return nil, errors.New("archive output must be outside the build directory")
	}
	selected, err := os.Stat(filepath.Join(build, "builds", identity.String()))
	if err != nil {
		return nil, err
	}
	if os.SameFile(held, selected) {
		return nil, errors.New("archive output parent is the immutable build directory")
	}
	return root, nil
}

func archiveSourceFacts(ctx context.Context, packages []artifact.SourcePackage, modules []artifact.SourceModule, metadata artifact.Metadata) error {
	if err := requireModuleMetadata(ctx, packages, modules); err != nil {
		return err
	}
	mainCount := 0
	for _, pkg := range packages {
		if pkg.Name == "main" && pkg.ImportPath == metadata.Command && pkg.Module != nil && pkg.Module.Path == metadata.MainModule {
			mainCount++
		}
	}
	if mainCount != 1 {
		return errors.New("selected archive main differs from build metadata")
	}
	sources, err := artifact.CaptureSourcesForModules(ctx, metadata.Role, packages, modules)
	if err != nil {
		return err
	}
	resolved, err := resolvedDependencies(modules, sources)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(sources, metadata.Sources) || !reflect.DeepEqual(resolved, metadata.Resolved) {
		return errors.New("selected archive source facts differ from build metadata")
	}
	return nil
}

type archiveReader struct {
	ctx    context.Context
	reader io.Reader
}

// Read checks caller cancellation before each source read. It cannot interrupt
// a source already blocked in Read; archive sources here are opened regular files.
func (r archiveReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(body)
}

func copyArchiveFile(ctx context.Context, source, destination string, mode os.FileMode, limit int64) error {
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	return errors.Join(copyArchiveFileTo(ctx, source, output, limit), output.Close())
}

func copyArchiveFileTo(ctx context.Context, source string, output io.Writer, limit int64) error {
	before, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > limit {
		return errors.New("archive input type or size refused")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	opened, err := input.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return errors.Join(artifact.ErrRecord, err, input.Close())
	}
	n, copyErr := io.Copy(output, io.LimitReader(archiveReader{ctx, input}, limit+1))
	if n != before.Size() || n > limit {
		copyErr = errors.Join(copyErr, errors.New("archive input changed or exceeds limit"))
	}
	return errors.Join(copyErr, input.Close())
}

func writeArchiveRecord(directory *os.Root, body []byte) error {
	file, err := directory.OpenFile("archive.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return err
	}
	n, err := io.Copy(file, bytes.NewReader(body))
	if n != int64(len(body)) {
		err = errors.Join(err, io.ErrShortWrite)
	}
	return errors.Join(err, file.Close())
}
