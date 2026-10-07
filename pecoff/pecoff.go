// Package pecoff 解析 PE/COFF 文件。
package pecoff

import (
	"errors"
	"strings"
)

// Counter 记录比较次数。
type Counter struct {
	Scanned int
}

// Section 是一个节。
type Section struct {
	Name             string
	VirtualAddress   uint32
	VirtualSize      uint32
	PointerToRawData uint32
	SizeOfRawData    uint32
}

// File 是解析结果。
type File struct {
	Machine     int
	Sections    []Section
	Imports     []string
	importIndex map[string]struct{}
}

func u16(b []byte) int {
	return int(b[0]) | int(b[1])<<8
}

func u32(b []byte) int {
	return int(b[0]) | int(b[1])<<8 | int(b[2])<<16 | int(b[3])<<24
}

// Parse 解析一份 PE 文件。
func Parse(data []byte, c *Counter) (*File, error) {
	c.Scanned++
	if len(data) < 64 || string(data[:2]) != "MZ" {
		return nil, errors.New("bad-dos")
	}
	peOff := u32(data[0x3c:])
	if peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, errors.New("bad-signature")
	}
	file := &File{}
	file.Machine = u16(data[peOff+4:])
	numSections := u16(data[peOff+6:])
	sizeOptional := u16(data[peOff+20:])
	opt := peOff + 24
	magic := u16(data[opt:])
	var dirs int
	switch magic {
	case 0x10b:
		dirs = opt + 96
	case 0x20b, 0xb20:
		dirs = opt + 112
	default:
		return nil, errors.New("bad-magic")
	}
	importRVA := u32(data[dirs+8:])
	sectionTable := opt + sizeOptional
	for i := 0; i < numSections; i++ {
		base := sectionTable + i*40
		if base+40 > len(data) {
			return nil, errors.New("bad-section-table")
		}
		file.Sections = append(file.Sections, Section{
			Name:             strings.TrimRight(string(data[base:base+8]), "\x00"),
			VirtualSize:      uint32(u32(data[base+8:])),
			VirtualAddress:   uint32(u32(data[base+12:])),
			SizeOfRawData:    uint32(u32(data[base+16:])),
			PointerToRawData: uint32(u32(data[base+20:])),
		})
	}
	for pos := importRVA; ; pos += 20 {
		c.Scanned++
		descOff, ok := file.rvaToOffset(uint32(pos))
		if !ok || descOff+20 > len(data) {
			return nil, errors.New("bad-import-table")
		}
		nameRVA := u32(data[descOff+12:])
		if nameRVA == 0 {
			break
		}
		nameOff, ok := file.rvaToOffset(uint32(nameRVA))
		if !ok {
			return nil, errors.New("bad-import-name")
		}
		file.Imports = append(file.Imports, readCString(data, nameOff))
	}
	return file, nil
}

func (f *File) rvaToOffset(rva uint32) (int, bool) {
	for _, sect := range f.Sections {
		size := sect.VirtualSize
		if size == 0 {
			size = sect.SizeOfRawData
		}
		if rva >= sect.VirtualAddress && rva < sect.VirtualAddress+size {
			return int(rva - sect.VirtualAddress + sect.PointerToRawData), true
		}
	}
	return 0, false
}

func readCString(data []byte, offset int) string {
	if offset < 0 || offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

// HasImport 判断是否导入了某个 DLL。
func (f *File) HasImport(name string, c *Counter) bool {
	if f.importIndex == nil {
		f.importIndex = make(map[string]struct{}, len(f.Imports))
		for _, item := range f.Imports {
			f.importIndex[item] = struct{}{}
		}
	}
	c.Scanned++
	_, ok := f.importIndex[name]
	return ok
}
