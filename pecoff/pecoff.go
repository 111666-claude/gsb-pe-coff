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
	Machine  int
	Sections []Section
	Imports  []string

	importIndex map[string]struct{}
	indexedLen  int
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
	if opt+2 > len(data) {
		return nil, errors.New("bad-optional")
	}
	var dirBase int
	switch u16(data[opt:]) {
	case 0x10b:
		dirBase = 96
	case 0x20b, 0x0b20:
		dirBase = 112
	default:
		return nil, errors.New("bad-magic")
	}
	importRVA := 0
	if sizeOptional >= dirBase+16 && opt+dirBase+16 <= len(data) {
		importRVA = u32(data[opt+dirBase+8:])
	}
	sectionTable := opt + sizeOptional
	for i := 0; i < numSections; i++ {
		base := sectionTable + i*40
		if base+40 > len(data) {
			break
		}
		file.Sections = append(file.Sections, Section{
			Name:             strings.TrimRight(string(data[base:base+8]), "\x00"),
			VirtualSize:      uint32(u32(data[base+8:])),
			VirtualAddress:   uint32(u32(data[base+12:])),
			SizeOfRawData:    uint32(u32(data[base+16:])),
			PointerToRawData: uint32(u32(data[base+20:])),
		})
	}
	if importRVA != 0 {
		pos := file.rvaToOffset(uint32(importRVA))
		for pos >= 0 && pos+20 <= len(data) {
			c.Scanned++
			nameRVA := u32(data[pos+12:])
			if nameRVA == 0 {
				break
			}
			if nameOff := file.rvaToOffset(uint32(nameRVA)); nameOff >= 0 {
				file.Imports = append(file.Imports, readCString(data, nameOff))
			}
			pos += 20
		}
	}
	return file, nil
}

// rvaToOffset 把 RVA 映射成文件偏移，失败返回 -1。
func (f *File) rvaToOffset(rva uint32) int {
	for _, s := range f.Sections {
		size := s.VirtualSize
		if size == 0 {
			size = s.SizeOfRawData
		}
		if rva >= s.VirtualAddress && rva < s.VirtualAddress+size {
			return int(rva-s.VirtualAddress) + int(s.PointerToRawData)
		}
	}
	return -1
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
	if f.importIndex == nil || f.indexedLen != len(f.Imports) {
		f.importIndex = make(map[string]struct{}, len(f.Imports))
		for _, item := range f.Imports {
			c.Scanned++
			f.importIndex[item] = struct{}{}
		}
		f.indexedLen = len(f.Imports)
	}
	c.Scanned++
	_, ok := f.importIndex[name]
	return ok
}
