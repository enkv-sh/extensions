package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/buildinfo"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"enkv.sh/sdk/artifact"
)

func inspectCLI(path, platform string, cliKey, pluginKey []byte, environment string) (result error) {
	body, e := read(path, artifact.MaxArchiveBytes)
	if e != nil {
		return e
	}
	gz, e := gzip.NewReader(bytes.NewReader(body))
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, gz.Close()) }()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	scratch, e := os.MkdirTemp("", "enkv-release-cli-")
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, os.RemoveAll(scratch)) }()
	var total int64
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
		if h.Name != "enkv" && h.Name != "LICENSE" && h.Name != "NOTICE" && h.Name != "THIRD_PARTY_NOTICES.md" || seen[h.Name] || h.Typeflag != tar.TypeReg || h.Size <= 0 || h.Size > artifact.MaxExecutableBytes {
			return errors.New("invalid CLI archive member")
		}
		total += h.Size
		if total > artifact.MaxArchiveBytes {
			return errors.New("CLI archive exceeds limit")
		}
		seen[h.Name] = true
		if h.Name == "enkv" {
			if h.Mode != 0755 {
				return errors.New("CLI member is not executable")
			}
			f, e := os.Create(filepath.Join(scratch, "enkv"))
			if e != nil {
				return e
			}
			_, copyErr := io.CopyN(f, tr, h.Size)
			if e := errors.Join(copyErr, f.Close()); e != nil {
				return e
			}
		}
	}
	if !seen["enkv"] || !seen["LICENSE"] || !seen["THIRD_PARTY_NOTICES.md"] {
		return errors.New("CLI archive is incomplete")
	}
	binary := filepath.Join(scratch, "enkv")
	info, e := buildinfo.ReadFile(binary)
	if e != nil {
		return e
	}
	if info.Path != "enkv.sh/compositions/full/cmd/enkv" || info.GoVersion != "go1.27.3" {
		return errors.New("CLI executable identity differs")
	}
	settings := map[string]string{}
	for _, s := range info.Settings {
		settings[s.Key] = s.Value
	}
	if settings["GOOS"]+"/"+settings["GOARCH"] != platform {
		return errors.New("CLI native platform differs")
	}
	values := map[string]string{"installedCLIVerificationKey": hex.EncodeToString(cliKey), "installedPluginKeys": hex.EncodeToString(pluginKey)}
	if environment == "production" {
		values["installedPluginOrigin"] = "https://enkv.sh/releases/"
		values["installedPluginRedirectHosts"] = "github.com,release-assets.githubusercontent.com"
		values["installedPluginTLSRoots"] = ""
		for _, dep := range info.Deps {
			if dep.Version == "" || dep.Version == "(devel)" || dep.Replace != nil && (dep.Replace.Version == "" || dep.Replace.Version == "(devel)") {
				return errors.New("CLI has unversioned dependencies")
			}
		}
	}
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	embedded, e := readAssembly(binary, names)
	if e != nil {
		return e
	}
	for name, value := range values {
		if embedded[name] != value {
			return fmt.Errorf("CLI assembly root differs: %s", name)
		}
	}

	return checkFloor(binary, io.Discard)
}
func trustedRoots(dir, cliPath, pluginPath string) error {
	if cliPath == "" || pluginPath == "" {
		return errors.New("independently trusted CLI and plugin public key paths are required")
	}
	for rel, trust := range map[string]string{"keys/cli-public.pem": cliPath, "keys/plugin-public.pem": pluginPath} {
		a, e := publicKey(filepath.Join(dir, rel))
		if e != nil {
			return e
		}
		b, e := publicKey(trust)
		if e != nil {
			return e
		}
		if !bytes.Equal(a, b) {
			return errors.New("candidate key differs from trusted root")
		}
	}
	return nil
}
