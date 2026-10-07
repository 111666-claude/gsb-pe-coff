package pecoff

import "testing"

func TestParseSections(t *testing.T) {
	file, err := Parse(Build(0x40), &Counter{})
	if err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(file.Sections) != 1 {
		t.Fatalf("应有一个节：%d", len(file.Sections))
	}
}

func TestSectionName(t *testing.T) {
	file, _ := Parse(Build(0x40), &Counter{})
	if file.Sections[0].Name != ".rdata" {
		t.Fatalf("节名不对：%q", file.Sections[0].Name)
	}
}

func TestMachine(t *testing.T) {
	file, _ := Parse(Build(0x40), &Counter{})
	if file.Machine != 0x14c {
		t.Fatalf("机器码不对：%x", file.Machine)
	}
}

func TestBadDos(t *testing.T) {
	if _, err := Parse([]byte("XX"), &Counter{}); err == nil {
		t.Fatal("DOS 头不对应报错")
	}
}

func TestHasImportMissing(t *testing.T) {
	file, _ := Parse(Build(0x40), &Counter{})
	if file.HasImport("NOPE.dll", &Counter{}) {
		t.Fatal("不该命中缺失的导入")
	}
}

func TestCounterCounts(t *testing.T) {
	c := &Counter{}
	Parse(Build(0x40), c)
	if c.Scanned == 0 {
		t.Fatal("应统计比较次数")
	}
}
