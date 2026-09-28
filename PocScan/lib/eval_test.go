package lib

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetRespBodyLimitRaw 验证原始响应体读取被限制在 maxPocBodyBytes 内：
// 10MB 响应只读入 4MB，不再全量进内存。
// 参数：无。
// 返回值：无（断言失败时 t.Fatal）。
func TestGetRespBodyLimitRaw(t *testing.T) {
	big := bytes.Repeat([]byte("A"), 10<<20)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := getRespBody(resp)
	if err != nil {
		t.Fatalf("getRespBody 返回错误: %v", err)
	}
	if len(body) != maxPocBodyBytes {
		t.Fatalf("期望截断到 %d 字节，实际 %d 字节", maxPocBodyBytes, len(body))
	}
}

// TestGetRespBodyLimitGzip 验证 gzip 解压后的内容同样受限（解压炸弹防护）：
// 64MB 零字节压缩后很小，解压读取不得超过 maxPocBodyBytes。
// 参数：无。
// 返回值：无（断言失败时 t.Fatal）。
func TestGetRespBodyLimitGzip(t *testing.T) {
	var raw bytes.Buffer
	zw := gzip.NewWriter(&raw)
	_, _ = zw.Write(bytes.Repeat([]byte{0}, 64<<20))
	_ = zw.Close()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(raw.Bytes())
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := getRespBody(resp)
	if err != nil {
		t.Fatalf("getRespBody 返回错误: %v", err)
	}
	if len(body) != maxPocBodyBytes {
		t.Fatalf("期望解压截断到 %d 字节，实际 %d 字节", maxPocBodyBytes, len(body))
	}
}
