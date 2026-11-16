package artifact

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

// PublishBuild validates metadata, dependency bytes and the executable, then
// publishes complete build bytes before atomically replacing build.json. It borrows
// inputs through return and requires a nonnil context. Cleanup removes only paths
// whose ownership is still proven. A failure can leave a complete build or an
// already replaced marker if a later sync/close fails; it is not proof of no effect.
func PublishBuild(ctx context.Context, output string, metadata Metadata, executable string, dependency []byte) (marker BuildMarker, err error) {
	return publishBuild(ctx, output, metadata, executable, dependency, openBuildDirectoryFile)
}

func publishBuild(ctx context.Context, output string, metadata Metadata, executable string, dependency []byte, openDirectory buildDirectoryOpener) (marker BuildMarker, err error) {
	body, err := EncodeMetadata(metadata)
	if err != nil {
		return marker, err
	}
	if err = verifyDependency(metadata, dependency); err != nil {
		return marker, err
	}
	if err = VerifyExecutable(ctx, executable, metadata); err != nil {
		return marker, err
	}
	if err = os.MkdirAll(output, 0755); err != nil {
		return marker, err
	}
	if err = plainDirectory(output); err != nil {
		return marker, err
	}
	builds := filepath.Join(output, "builds")
	if err = os.MkdirAll(builds, 0755); err != nil {
		return marker, err
	}
	if err = plainDirectory(builds); err != nil {
		return marker, err
	}

	outputRoot, err := os.OpenRoot(output)
	if err != nil {
		return BuildMarker{}, err
	}
	defer func() { err = errors.Join(err, outputRoot.Close()) }()
	outputDirectory, err := outputRoot.Open(".")
	if err != nil {
		return BuildMarker{}, err
	}
	defer func() { err = errors.Join(err, outputDirectory.Close()) }()
	buildsRoot, err := outputRoot.OpenRoot("builds")
	if err != nil {
		return BuildMarker{}, err
	}
	defer func() { err = errors.Join(err, buildsRoot.Close()) }()
	buildsDirectory, err := openDirectory(buildsRoot)
	if err != nil {
		return BuildMarker{}, err
	}
	defer func() { err = errors.Join(err, buildsDirectory.Close()) }()
	stableParents := func() error {
		if err := sameOpenDirectory(output, outputDirectory); err != nil {
			return err
		}
		info, err := outputRoot.Lstat("builds")
		if err != nil {
			return err
		}
		held, err := buildsDirectory.Stat()
		if err != nil {
			return err
		}
		if !info.IsDir() || !os.SameFile(info, held) {
			return errors.New("builds directory changed")
		}
		return nil
	}
	identity := Hash(body)
	marker = BuildMarker{Schema: "enkv/plugin-build/v1", Artifact: identity, Directory: "builds/" + identity.String()}
	targetName := identity.String()
	target := filepath.Join(builds, targetName)
	if err = stableParents(); err != nil {
		return BuildMarker{}, err
	}
	if _, statErr := buildsRoot.Lstat(targetName); statErr == nil {
		if _, err = verifyBuildFolder(ctx, target, identity); err != nil {
			return BuildMarker{}, err
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return BuildMarker{}, statErr
	} else {
		stagePath, makeErr := os.MkdirTemp(builds, ".build-")
		if makeErr != nil {
			return BuildMarker{}, makeErr
		}
		stage, openErr := openBuildDirectory(buildsRoot, filepath.Base(stagePath), openDirectory)
		if openErr != nil {
			return BuildMarker{}, openErr
		}
		published := false
		defer func() { err = errors.Join(err, stage.finish(!published)) }()
		if err = stage.write(ctx, "metadata.json", body, 0444); err != nil {
			return BuildMarker{}, err
		}
		if err = stage.write(ctx, "dependencies.bin", dependency, 0444); err != nil {
			return BuildMarker{}, err
		}
		if err = stage.copyPlugin(ctx, executable); err != nil {
			return BuildMarker{}, err
		}
		if _, err = verifyBuildFolder(ctx, stagePath, identity); err != nil {
			return BuildMarker{}, err
		}
		if err = stage.check(); err != nil {
			return BuildMarker{}, err
		}
		if err = stage.directory.Chmod(0555); err != nil {
			return BuildMarker{}, err
		}
		if err = stage.directory.Sync(); err != nil {
			return BuildMarker{}, err
		}
		if err = errors.Join(ctx.Err(), stableParents()); err != nil {
			return BuildMarker{}, err
		}
		if _, statErr := buildsRoot.Lstat(targetName); statErr == nil {
			if _, err = verifyBuildFolder(ctx, target, identity); err != nil {
				return BuildMarker{}, err
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return BuildMarker{}, statErr
		} else if renameErr := buildsRoot.Rename(stage.name, targetName); renameErr != nil {
			if _, err = verifyBuildFolder(ctx, target, identity); err != nil {
				return BuildMarker{}, errors.Join(renameErr, err)
			}
		} else {
			published = true
			if err = buildsDirectory.Sync(); err != nil {
				return BuildMarker{}, err
			}
		}
	}
	if err = errors.Join(ctx.Err(), stableParents()); err != nil {
		return BuildMarker{}, err
	}
	if _, err = verifyBuildFolder(ctx, target, identity); err != nil {
		return BuildMarker{}, err
	}
	markerBody, err := EncodeBuildMarker(marker)
	if err != nil {
		return BuildMarker{}, err
	}
	file, err := os.CreateTemp(output, ".build-marker-")
	if err != nil {
		return BuildMarker{}, err
	}
	temporary := filepath.Base(file.Name())
	defer func() { err = errors.Join(err, removeSameFile(outputRoot, temporary, file), file.Close()) }()
	if err = file.Chmod(0644); err != nil {
		return BuildMarker{}, err
	}
	_, writeErr := file.Write(markerBody)
	if err = errors.Join(writeErr, file.Sync()); err != nil {
		return BuildMarker{}, err
	}
	if err = errors.Join(ctx.Err(), stableParents(), checkSameFile(outputRoot, temporary, file)); err != nil {
		return BuildMarker{}, err
	}
	if err = outputRoot.Rename(temporary, "build.json"); err != nil {
		return BuildMarker{}, err
	}
	if err = outputDirectory.Sync(); err != nil {
		return BuildMarker{}, err
	}

	return marker, nil
}

// VerifyBuild verifies one complete immutable folder selected by a stable marker.
// It never executes the mutable output path.
func VerifyBuild(ctx context.Context, directory string) (Metadata, error) {
	if err := plainDirectory(directory); err != nil {
		return Metadata{}, err
	}
	before, err := readBounded(ctx, filepath.Join(directory, "build.json"), MaxMarkerBytes)
	if err != nil {
		return Metadata{}, err
	}
	marker, err := DecodeBuildMarker(before)
	if err != nil {
		return Metadata{}, err
	}
	if err := plainDirectory(filepath.Join(directory, "builds")); err != nil {
		return Metadata{}, err
	}
	metadata, err := verifyBuildFolder(ctx, filepath.Join(directory, filepath.FromSlash(marker.Directory)), marker.Artifact)
	if err != nil {
		return Metadata{}, err
	}
	after, err := readBounded(ctx, filepath.Join(directory, "build.json"), MaxMarkerBytes)
	if err != nil {
		return Metadata{}, err
	}
	if !bytes.Equal(before, after) {
		return Metadata{}, errors.New("build marker changed during verification")
	}
	return metadata, nil
}
func verifyBuildFolder(ctx context.Context, directory string, identity Digest) (Metadata, error) {
	if err := plainDirectory(directory); err != nil {
		return Metadata{}, err
	}
	body, err := readBounded(ctx, filepath.Join(directory, "metadata.json"), MaxMetadataBytes)
	if err != nil {
		return Metadata{}, err
	}
	if Hash(body) != identity {
		return Metadata{}, errors.New("build metadata identity differs")
	}
	metadata, err := DecodeMetadata(body)
	if err != nil {
		return Metadata{}, err
	}
	allowed := map[string]bool{"metadata.json": true, "plugin": true, "dependencies.bin": true}
	entries, err := readPackageDirectory(directory, len(allowed))
	if err != nil {
		return Metadata{}, err
	}
	if len(entries) != len(allowed) {
		return Metadata{}, errors.New("build member set differs")
	}
	for _, entry := range entries {
		if !allowed[entry.Name()] || !entry.Type().IsRegular() {
			return Metadata{}, errors.New("build member refused")
		}
	}
	dependency, err := readBounded(ctx, filepath.Join(directory, "dependencies.bin"), MaxDependencyBytes)
	if err != nil {
		return Metadata{}, err
	}
	if err := verifyDependency(metadata, dependency); err != nil {
		return Metadata{}, err
	}
	if err := VerifyExecutable(ctx, filepath.Join(directory, "plugin"), metadata); err != nil {
		return Metadata{}, err
	}
	return metadata, nil
}
func verifyDependency(metadata Metadata, body []byte) error {
	if metadata.Family == nil {
		return ErrRecord
	}
	if Hash(body) != metadata.Family.Dependency.SHA256 || uint64(len(body)) != metadata.Family.Dependency.Length {
		return errors.New("dependency member digest or length differs")
	}
	facts, err := DecodeDependency(body)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(facts, metadata.BuildFacts()) {
		return errors.New("dependency build facts differ")
	}
	identity, err := DependencyID(metadata.Role, body)
	if err != nil {
		return err
	}
	execution, err := metadata.ExecutionFacts()
	if err != nil {
		return err
	}
	if execution.DependencyManifestID != identity {
		return errors.New("dependency identity differs")
	}
	return nil
}
func plainDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("build directory type refused")
	}
	return nil
}
func readBounded(ctx context.Context, path string, limit int) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > int64(limit) {
		return nil, errors.New("build record type or size refused")
	}
	file, err := openObservedFile(path, info)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(contextReader{ctx, file}, int64(limit)+1))
	pathErr := checkObservedPath(path, info)
	closeErr := file.Close()
	if err := errors.Join(readErr, pathErr, closeErr, ctx.Err()); err != nil {
		return nil, err
	}
	if len(body) > limit || int64(len(body)) != info.Size() {
		return nil, errors.New("build record changed or exceeds limit")
	}
	return body, nil
}

type buildMember struct {
	name string
	file *os.File
}
type buildDirectoryFile interface {
	Stat() (os.FileInfo, error)
	Chmod(os.FileMode) error
	Sync() error
	Close() error
}
type buildDirectoryOpener func(*os.Root) (buildDirectoryFile, error)

func openBuildDirectoryFile(root *os.Root) (buildDirectoryFile, error) {
	return root.Open(".")
}

type buildDirectory struct {
	parent, root *os.Root
	name         string
	directory    buildDirectoryFile
	members      []buildMember
}

func openBuildDirectory(parent *os.Root, name string, openDirectory buildDirectoryOpener) (*buildDirectory, error) {
	root, err := parent.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	directory, err := openDirectory(root)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	result := &buildDirectory{parent: parent, root: root, name: name, directory: directory}
	if err := result.check(); err != nil {
		return nil, errors.Join(err, directory.Close(), root.Close())
	}
	return result, nil
}
func sameOpenDirectory(path string, directory *os.File) error {
	actual, err := os.Lstat(path)
	if err != nil {
		return err
	}
	held, err := directory.Stat()
	if err != nil {
		return err
	}
	if !actual.IsDir() || !os.SameFile(actual, held) {
		return errors.New("build directory changed")
	}
	return nil
}
func (d *buildDirectory) check() error {
	actual, err := d.parent.Lstat(d.name)
	if err != nil {
		return err
	}
	held, err := d.directory.Stat()
	if err != nil {
		return err
	}
	if !actual.IsDir() || !os.SameFile(actual, held) {
		return errors.New("owned build directory changed")
	}
	return nil
}
func checkSameFile(root *os.Root, name string, file *os.File) error {
	actual, err := root.Lstat(name)
	if err != nil {
		return err
	}
	held, err := file.Stat()
	if err != nil {
		return err
	}
	if !actual.Mode().IsRegular() || !os.SameFile(actual, held) {
		return errors.New("owned build file changed")
	}
	return nil
}
func (d *buildDirectory) create(name string, mode os.FileMode) (*os.File, error) {
	if err := d.check(); err != nil {
		return nil, err
	}
	file, err := d.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return nil, err
	}
	d.members = append(d.members, buildMember{name: name, file: file})
	if err := checkSameFile(d.root, name, file); err != nil {
		return nil, err
	}
	return file, nil
}
func (d *buildDirectory) write(ctx context.Context, name string, body []byte, mode os.FileMode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := d.create(name, mode)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(body)
	return errors.Join(writeErr, file.Sync(), ctx.Err())
}
func (d *buildDirectory) copyPlugin(ctx context.Context, source string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	output, err := d.create("plugin", 0555)
	if err != nil {
		return errors.Join(err, input.Close())
	}
	buffer := make([]byte, 64<<10)
	var count int64
	var copyErr error
	for {
		if copyErr = ctx.Err(); copyErr != nil {
			break
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			count += int64(n)
			if count > MaxExecutableBytes {
				copyErr = errors.New("executable exceeds limit")
				break
			}
			written, err := output.Write(buffer[:n])
			if err != nil {
				copyErr = err
				break
			}
			if written != n {
				copyErr = io.ErrShortWrite
				break
			}
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				copyErr = readErr
			}
			break
		}
	}
	return errors.Join(copyErr, input.Close(), output.Sync())
}
func removeSameFile(root *os.Root, name string, file *os.File) error {
	if err := checkSameFile(root, name, file); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return root.Remove(name)
}
func (d *buildDirectory) finish(remove bool) error {
	var result error
	if remove {
		if err := d.check(); err != nil {
			result = errors.Join(result, err)
		} else {
			result = errors.Join(result, d.directory.Chmod(0700))
			for _, member := range d.members {
				result = errors.Join(result, removeSameFile(d.root, member.name, member.file))
			}
			if err := d.check(); err != nil {
				result = errors.Join(result, err)
			} else {
				result = errors.Join(result, d.parent.Remove(d.name))
			}
		}
	}
	for _, member := range d.members {
		result = errors.Join(result, member.file.Close())
	}
	return errors.Join(result, d.directory.Close(), d.root.Close())
}
