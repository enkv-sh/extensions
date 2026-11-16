// Command enkv-plugin-build builds one author-declared plugin, verifies a local
// build, or creates an archive candidate. Build defaults are directory ".",
// descriptor "plugin.json" and command "."; output and an explicit dependency mode
// are required. It prints the result as JSON and never runs the plugin.
// Use -help for mode-specific flags.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/signal"
	"syscall"

	"enkv.sh/sdk/artifact"
	"enkv.sh/sdk/artifact/build"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var config build.Config
	var verify, archive, metadataSignature string
	flags := flag.NewFlagSet("enkv-plugin-build", flag.ContinueOnError)
	var flagOutput bytes.Buffer
	flags.SetOutput(&flagOutput)
	flags.StringVar(&config.Directory, "directory", ".", "author module directory")
	flags.StringVar(&config.Descriptor, "descriptor", "plugin.json", "author descriptor JSON file")
	flags.StringVar(&config.Command, "command", ".", "one main package")
	flags.StringVar(&config.Output, "output", "", "local build output directory or new archive output directory")
	flags.StringVar(&config.Workspace, "workspace", "", "absolute coordinated go.work file")
	flags.BoolVar(&config.Versioned, "versioned", false, "disable workspace and require versioned dependencies")
	flags.StringVar(&verify, "verify", "", "verify an existing local build output directory")
	flags.StringVar(&archive, "archive", "", "package an existing local build output directory")
	flags.StringVar(&metadataSignature, "metadata-signature", "", "external detached metadata signature for archive creation")
	parseErr := flags.Parse(args)
	if err := writeText(stderr, flagOutput.String()); err != nil {
		return 1
	}
	if parseErr != nil {
		if errors.Is(parseErr, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		return diagnosticExit(stderr, "unexpected positional arguments", 2)
	}
	if verify != "" {
		count := 0
		flags.Visit(func(*flag.Flag) { count++ })
		if count != 1 {
			return diagnosticExit(stderr, "verify cannot be combined with build flags", 2)
		}
	}
	if archive != "" {
		if metadataSignature == "" {
			return diagnosticExit(stderr, "archive requires -metadata-signature", 2)
		}
		if config.Output == "" {
			return diagnosticExit(stderr, "archive requires -output", 2)
		}
		invalid := false
		flags.Visit(func(f *flag.Flag) {
			if f.Name == "descriptor" {
				invalid = true
			}
		})
		if invalid {
			return diagnosticExit(stderr, "archive uses the existing build descriptor", 2)
		}
	} else if metadataSignature != "" {
		return diagnosticExit(stderr, "metadata-signature requires -archive", 2)
	}
	var result any
	var err error
	if verify != "" {
		result, err = artifact.VerifyBuild(ctx, verify)
	} else if archive != "" {
		result, err = build.Archive(ctx, build.ArchiveConfig{Build: archive, Directory: config.Directory, Command: config.Command, Output: config.Output, Workspace: config.Workspace, Versioned: config.Versioned, MetadataSignature: metadataSignature})
	} else {
		result, err = build.Run(ctx, config)
	}
	if err != nil {
		return diagnosticExit(stderr, err.Error(), 1)
	}
	var output bytes.Buffer
	if err := json.NewEncoder(&output).Encode(result); err != nil {
		return diagnosticExit(stderr, err.Error(), 1)
	}
	if err := writeText(stdout, output.String()); err != nil {
		return diagnosticExit(stderr, err.Error(), 1)
	}
	return 0
}

func diagnosticExit(output io.Writer, message string, code int) int {
	if err := writeText(output, message+"\n"); err != nil {
		return 1
	}
	return code
}

func writeText(output io.Writer, text string) error {
	if text == "" {
		return nil
	}
	n, err := io.WriteString(output, text)
	if err != nil {
		return err
	}
	if n != len(text) {
		return io.ErrShortWrite
	}
	return nil
}
