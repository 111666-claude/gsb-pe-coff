package pecoff

import "fmt"

// Scenario 是一个固定场景。
type Scenario struct {
	Name string
	Run  func() map[string]any
}

func put32(b []byte, off, value int) {
	b[off] = byte(value)
	b[off+1] = byte(value >> 8)
	b[off+2] = byte(value >> 16)
	b[off+3] = byte(value >> 24)
}

// Build 拼一份 PE32 文件，导入 KERNEL32.dll。
func Build(peOff int) []byte {
	data := make([]byte, 0x600)
	copy(data, []byte("MZ"))
	put32(data, 0x3c, peOff)
	copy(data[peOff:], []byte("PE\x00\x00"))
	data[peOff+4] = 0x4c
	data[peOff+5] = 0x01
	data[peOff+6] = 1
	data[peOff+20] = 0xe0
	opt := peOff + 24
	data[opt] = 0x0b
	data[opt+1] = 0x01
	put32(data, opt+92, 16)
	put32(data, opt+104, 0x1000)
	put32(data, opt+108, 40)
	sect := opt + 0xe0
	copy(data[sect:], []byte(".rdata"))
	put32(data, sect+8, 0x200)
	put32(data, sect+12, 0x1000)
	put32(data, sect+16, 0x200)
	put32(data, sect+20, 0x200)
	put32(data, 0x200+12, 0x1030)
	put32(data, 0x200+16, 0x1040)
	copy(data[0x230:], []byte("KERNEL32.dll"))
	return data
}

// Samples 返回全部场景。
func Samples() []Scenario {
	return []Scenario{
		{Name: "lfanew", Run: func() map[string]any {
			file, err := Parse(Build(0x80), &Counter{})
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			return map[string]any{"sections": len(file.Sections)}
		}},
		{Name: "magic", Run: func() map[string]any {
			data := Build(0x40)
			data[0x58] = 0x20
			data[0x59] = 0x0b
			put32(data, 0x58+104, 0)
			put32(data, 0x58+108, 0)
			put32(data, 0x58+120, 0x1000)
			put32(data, 0x58+124, 40)
			file, err := Parse(data, &Counter{})
			if err != nil {
				return map[string]any{"error": err.Error()}
			}
			return map[string]any{"imports": len(file.Imports)}
		}},
		{Name: "rva", Run: func() map[string]any {
			file, _ := Parse(Build(0x40), &Counter{})
			if len(file.Imports) == 0 {
				return map[string]any{"dll": ""}
			}
			return map[string]any{"dll": file.Imports[0]}
		}},
		{Name: "imports", Run: func() map[string]any {
			file, _ := Parse(Build(0x40), &Counter{})
			return map[string]any{"imports": len(file.Imports)}
		}},
	}
}

// Work 跑规模线场景。
func Work(n int) map[string]any {
	file := &File{}
	for i := 0; i < n; i++ {
		file.Imports = append(file.Imports, fmt.Sprintf("D%04d.dll", i))
	}
	c := &Counter{}
	for i := 0; i < n; i++ {
		file.HasImport(fmt.Sprintf("D%04d.dll", i), c)
	}
	return map[string]any{"imports": n, "scanned": c.Scanned}
}
