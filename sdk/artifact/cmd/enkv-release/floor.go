package main

import (
	"debug/elf"
	"debug/macho"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

func glibcMaximum(symbols []elf.ImportedSymbol) (string, error) {
	maximum := ""
	maximumMajor, maximumMinor := -1, -1
	for _, symbol := range symbols {
		if !strings.HasPrefix(symbol.Version, "GLIBC_") {
			continue
		}
		v := strings.TrimPrefix(symbol.Version, "GLIBC_")
		parts := strings.Split(v, ".")
		if len(parts) < 2 {
			return "", errors.New("unknown glibc requirement")
		}
		major, e := strconv.Atoi(parts[0])
		if e != nil {
			return "", e
		}
		minor, e := strconv.Atoi(parts[1])
		if e != nil {
			return "", e
		}
		if major > 2 || major == 2 && minor > 34 {
			return "", fmt.Errorf("binary requires %s above glibc 2.34", symbol.Version)
		}
		if major > maximumMajor || major == maximumMajor && minor > maximumMinor {
			maximum = symbol.Version
			maximumMajor, maximumMinor = major, minor
		}
	}
	return maximum, nil
}
func checkFloor(path string, output io.Writer) (result error) {
	if f, e := elf.Open(path); e == nil {
		defer func() { result = errors.Join(result, f.Close()) }()
		if f.Machine != elf.EM_X86_64 {
			return errors.New("linux executable is not amd64")
		}
		symbols, e := f.ImportedSymbols()
		if e != nil {
			if !errors.Is(e, elf.ErrNoSymbols) || f.SectionByType(elf.SHT_DYNSYM) != nil {
				return e
			}
			hasLoad := false
			for _, p := range f.Progs {
				if p.Type == elf.PT_LOAD && p.Filesz > 0 {
					hasLoad = true
				}
				if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
					return errors.New("dynamic ELF has no dynamic symbol table")
				}
			}
			if f.Type != elf.ET_EXEC || !hasLoad {
				return errors.New("static ELF has no executable load image")
			}
			_, e = fmt.Fprintln(output, "native=linux/amd64 linkage=static glibc_max=none")
			return e
		}
		maximum, e := glibcMaximum(symbols)
		if e != nil {
			return e
		}
		_, e = fmt.Fprintf(output, "native=linux/amd64 glibc_max=%s ceiling=GLIBC_2.34\n", maximum)
		return e
	}
	f, e := macho.Open(path)
	if e != nil {
		return e
	}
	defer func() { result = errors.Join(result, f.Close()) }()
	if f.Cpu != macho.CpuArm64 {
		return errors.New("macOS executable is not arm64")
	}
	for _, load := range f.Loads {
		raw := load.Raw()
		if len(raw) < 16 {
			continue
		}
		cmd := f.ByteOrder.Uint32(raw)
		offset := 8
		if cmd == 0x32 {
			offset = 12
		} else if cmd != 0x24 {
			continue
		}
		v := f.ByteOrder.Uint32(raw[offset:])
		if v == 0 {
			return errors.New("empty macOS deployment target")
		}
		_, e = fmt.Fprintf(output, "native=darwin/arm64 minimum_macos=%d.%d.%d\n", v>>16, (v>>8)&255, v&255)
		return e
	}
	return errors.New("macOS minimum load command missing")
}
