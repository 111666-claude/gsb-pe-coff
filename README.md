# pe-coff

解析 PE/COFF：DOS 头的 PE 偏移、可选头魔数、数据目录、节表与 RVA 到文件偏移的映射、导入表 DLL 列表。只用标准库。

```
go test ./...
go vet ./...
go run ./cmd/pecoff --sample=lfanew
go run ./cmd/pecoff --sample=magic
go run ./cmd/pecoff --sample=rva
go run ./cmd/pecoff --sample=imports
go run ./cmd/pecoff --sample=work
```

## 口径

- **PE 偏移**：DOS 头 `0x3C` 处的 4 字节小端给出 `PE\0\0` 的位置。
- **可选头**：魔数 `0x10B` 是 PE32、`0x20B` 是 PE32+；数据目录个数在可选头偏移 92 处，目录从偏移 96 开始。
- **导入目录**：数据目录第 1 项是导入表（RVA 与大小）；导入描述符 20 字节一组，全零结束。
- **RVA 映射**：RVA 落在某个节的虚拟地址范围内时，文件偏移等于 `RVA - 虚拟地址 + 原始指针`。
- **查找**：按 DLL 名查找走索引。

## 不变量

- 段表条数与 COFF 头声明一致。
- 导入 DLL 名一定来自 RVA 映射后的文件偏移。
- `scanned` 不随导入数乘查询次数放大：八百个导入查八百次的 `scanned` 不超过 6000。

## 输出契约

`File` 含机器、节列表与导入 DLL 列表。场景打印一行 JSON。
`--sample=work` 打印 `{"imports": N, "scanned": N}`。
