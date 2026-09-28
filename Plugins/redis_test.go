package Plugins

import (
	"net"
	"testing"
)

// TestReadReplyLimit 验证 readreply 单次最多读取 16KB，
// 防止对端在 1 秒读超时窗口内灌入大量数据把内存吃满。
// 参数：无。
// 返回值：无（断言失败时 t.Fatal）。
func TestReadReplyLimit(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	// 持续写入超过 16KB 的数据，模拟对端灌数据
	go func() {
		defer c2.Close()
		chunk := make([]byte, 1024)
		for {
			if _, err := c2.Write(chunk); err != nil {
				return
			}
		}
	}()

	got, err := readreply(c1)
	if err != nil {
		t.Fatalf("readreply 返回错误: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("应至少读到部分数据")
	}
	if len(got) > 16*1024 {
		t.Fatalf("读取 %d 字节，超过 16KB 上限", len(got))
	}
}
