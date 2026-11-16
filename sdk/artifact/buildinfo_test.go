package artifact

import (
	"runtime/debug"
	"testing"
)

// full_only: false
func TestBuildInfoRequiresExactCompiledSet(t *testing.T) {
	info := &debug.BuildInfo{GoVersion: "go1.27.0", Path: "example.test/author/cmd/plugin", Main: debug.Module{Path: "example.test/author", Version: "(devel)"}, Deps: []*debug.Module{{Path: "example.test/helper", Version: "(devel)"}}, Settings: []debug.BuildSetting{{Key: "-buildmode", Value: "exe"}, {Key: "-compiler", Value: "gc"}, {Key: "-trimpath", Value: "true"}, {Key: "CGO_ENABLED", Value: "0"}, {Key: "GOARCH", Value: "arm64"}, {Key: "GOOS", Value: "darwin"}, {Key: "GOARM64", Value: "v8.0"}}}
	sources := []Source{{Module: "example.test/author", Digest: Hash([]byte("author"))}, {Module: "example.test/helper", Digest: Hash([]byte("helper"))}}
	facts := BuildFacts{MainModule: info.Main.Path, Command: info.Path, Toolchain: info.GoVersion, Platform: "darwin/arm64", Sources: sources, Resolved: []Dependency{{Path: info.Main.Path}, {Path: "example.test/helper"}}, Compiled: []Dependency{{Path: info.Main.Path, Version: "(devel)"}, {Path: "example.test/helper", Version: "(devel)"}}}
	options, err := BuildOptions(info)
	if err != nil {
		t.Fatal(err)
	}
	facts.BuildOptions = options
	if err := VerifyBuildInfo(info, facts); err != nil {
		t.Fatal(err)
	}
	info.Deps = append(info.Deps, &debug.Module{Path: "example.test/extra", Version: "v1.0.0"})
	if err := VerifyBuildInfo(info, facts); err == nil {
		t.Fatal("extra compiled module accepted")
	}
	info.Deps = info.Deps[:1]
	info.Main.Version = ""
	if err := VerifyBuildInfo(info, facts); err == nil {
		t.Fatal("actual main representation was normalized")
	}
}
