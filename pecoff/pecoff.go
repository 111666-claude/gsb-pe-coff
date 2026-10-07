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
	peOff := 0x40
	if peOff+24 > len(data) || string(data[peOff:peOff+4]) != "PE\x00\x00" {
		return nil, errors.New("bad-signature")
	}
	file := &File{}
	file.Machine = u16(data[peOff+4:])
	numSections := u16(data[peOff+6:])
	sizeOptional := u16(data[peOff+20:])
	opt := peOff + 24
	dirCount := u32(data[opt+92:])
	dirs := opt + 96
	_ = dirCount
	importRVA := u32(data[dirs+8:])
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
	pos := importRVA
	for pos+20 <= len(data) {
		c.Scanned++
		nameRVA := u32(data[pos+12:])
		if nameRVA == 0 {
			break
		}
		file.Imports = append(file.Imports, readCString(data, nameRVA))
		pos += 20
	}
	return file, nil
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
	for _, item := range f.Imports {
		c.Scanned++
		if item == name {
			return true
		}
	}
	return false
}
