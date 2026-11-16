package main

import (
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"

	"enkv.sh/sdk/artifact"
)

// Release builds retain their symbol table; trimpath omits linker flags from Go build info.
func readAssembly(path string, names []string) (map[string]string, error) {
	type section struct {
		address, size uint64
		readAt        func([]byte, int64) (int, error)
		zero          bool
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > artifact.MaxExecutableBytes {
		return nil, errors.New("CLI executable exceeds assembly inspection bound")
	}
	var sections []section
	symbols := map[string]uint64{}
	var order binary.ByteOrder
	var closeFile func() error
	if f, e := elf.Open(path); e == nil {
		closeFile = f.Close
		order = f.ByteOrder
		for _, s := range f.Sections {
			if s.Type != elf.SHT_NOBITS && (s.Offset > uint64(info.Size()) || s.FileSize > uint64(info.Size())-s.Offset) {
				return nil, errors.Join(errors.New("CLI section bounds refused"), f.Close())
			}
			if s.Type == elf.SHT_SYMTAB {
				if s.Flags&elf.SHF_COMPRESSED != 0 || s.Link >= uint32(len(f.Sections)) || f.Sections[s.Link].Type != elf.SHT_STRTAB || f.Sections[s.Link].Flags&elf.SHF_COMPRESSED != 0 {
					return nil, errors.Join(errors.New("CLI symbol table bounds refused"), f.Close())
				}
			}
		}

		rows, e := f.Symbols()
		if e != nil {
			return nil, errors.Join(e, f.Close())
		}
		for _, s := range rows {
			symbols[s.Name] = s.Value
		}
		for _, s := range f.Sections {
			var readAt func([]byte, int64) (int, error)
			if s.ReaderAt != nil {
				readAt = s.ReadAt
			}
			sections = append(sections, section{s.Addr, s.Size, readAt, s.Type == elf.SHT_NOBITS})
		}
	} else {
		f, e := macho.Open(path)
		if e != nil {
			return nil, e
		}
		closeFile = f.Close
		order = f.ByteOrder
		if f.Symtab == nil {
			return nil, errors.Join(errors.New("CLI symbol table is missing"), f.Close())
		}
		for _, s := range f.Symtab.Syms {
			symbols[s.Name] = s.Value
		}
		for _, s := range f.Sections {
			var readAt func([]byte, int64) (int, error)
			if s.ReaderAt != nil {
				readAt = s.ReadAt
			}
			sections = append(sections, section{s.Addr, s.Size, readAt, s.Flags&0xff == 1})
		}
	}
	values, readErr := func() (map[string]string, error) {
		memory := func(address, length uint64) ([]byte, error) {
			if length > 4096 {
				return nil, errors.New("assembly string exceeds limit")
			}
			for _, s := range sections {
				if address < s.address || address-s.address > s.size || length > s.size-(address-s.address) {
					continue
				}
				if s.zero {
					return make([]byte, int(length)), nil
				}
				data := make([]byte, int(length))
				if s.readAt == nil {
					return nil, errors.New("CLI section is unreadable")
				}
				n, e := s.readAt(data, int64(address-s.address))
				if e != nil || n != len(data) {
					return nil, errors.Join(e, io.ErrUnexpectedEOF)
				}
				return data, nil
			}
			return nil, errors.New("assembly address is outside file sections")
		}
		values := map[string]string{}
		for _, name := range names {
			symbol := "enkv.sh/compositions/full." + name
			address, ok := symbols[symbol]
			if !ok {
				address, ok = symbols["_"+symbol]
			}
			if !ok {
				return nil, fmt.Errorf("CLI assembly symbol missing: %s", name)
			}
			header, e := memory(address, 16)
			if e != nil {
				return nil, e
			}
			length := order.Uint64(header[8:])
			if length == 0 {
				values[name] = ""
				continue
			}
			stringAddress, ok := symbols[symbol+".str"]
			if !ok {
				stringAddress, ok = symbols["_"+symbol+".str"]
			}
			if !ok {
				return nil, fmt.Errorf("CLI linker string symbol missing: %s", name)
			}
			body, e := memory(stringAddress, length)
			if e != nil {
				return nil, e
			}
			values[name] = string(body)
		}
		return values, nil
	}()
	return values, errors.Join(readErr, closeFile())
}
