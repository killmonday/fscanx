package Plugins

import (
	"testing"
)

// TestName qqwry IP 归属地查询测试。
// qqwry.dat 是可选的运行时资源且位于仓库根目录，包目录下加载失败时跳过而不是 panic。
func TestName(t *testing.T) {
	db, err := NewQQwry("qqwry.dat")
	if err != nil {
		t.Skipf("跳过：无法加载 qqwry.dat: %v", err)
	}
	res, err := db.Find("211.149.157.245")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	t.Log(res.String())
}
