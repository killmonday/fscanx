package Plugins

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/killmonday/fscanx/common"
)

// withWebTimeout 临时设置 common.WebTimeout 并在测试结束后恢复原值。
// 参数 v：模拟的 WebTimeout 秒数。
// 返回值：无。
func withWebTimeout(t *testing.T, v int64) {
	t.Helper()
	orig := common.WebTimeout
	common.WebTimeout = v
	t.Cleanup(func() { common.WebTimeout = orig })
}

// TestReadRawWithSizeConcurrentIsolation 池污染回归测试：
// 多 goroutine 并发调用 ReadRawWithSize，各自返回的数据不得因 buffer 池复用而互相覆盖。
// 服务端回显每个请求的唯一 id，若返回切片与池化 buffer 共享底层数组，
// 内容校验会失败，且 -race 下竞态探测器会直接报数据竞争。
// 参数：无。
// 返回值：无（断言失败时 t.Error）。
func TestReadRawWithSizeConcurrentIsolation(t *testing.T) {
	withWebTimeout(t, 10)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 回显请求方唯一 id + 足量填充，池污染时返回内容会被其他请求的数据覆盖
		fmt.Fprintf(w, "UNIQUE-PAYLOAD-%s-%s", r.URL.Query().Get("id"), strings.Repeat("x", 4096))
	}))
	defer srv.Close()

	const workers = 16
	const rounds = 8
	var wg sync.WaitGroup
	errCh := make(chan error, workers*rounds)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for r := 0; r < rounds; r++ {
				reqID := strconv.Itoa(id) + "-" + strconv.Itoa(r)
				resp, err := http.Get(srv.URL + "?id=" + reqID)
				if err != nil {
					errCh <- err
					continue
				}
				body, err := ReadRawWithSize(resp, 192*1024)
				if err != nil {
					errCh <- err
					continue
				}
				// 让出调度，给其他 goroutine 机会取走同一池化 buffer 并写入
				runtime.Gosched()
				if !strings.Contains(string(body), "UNIQUE-PAYLOAD-"+reqID+"-") {
					errCh <- fmt.Errorf("返回数据与本请求不匹配，疑似被池污染: want UNIQUE-PAYLOAD-%s got %.80q", reqID, string(body))
				}
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestReadRawWithSizeErrorPath 错误路径（读取超时）测试：
// 错误路径同样必须返回拷贝副本，且调用方在忽略错误继续使用 body 时拿到的是头部数据。
// TimeoutReader 只在两次 Read 之间检查 ctx，因此服务端周期性发块（永不发完），
// 使某次 Read 在 ctx 到期后进入 select 且数据未就绪，确定性地触发超时分支。
// 参数：无。
// 返回值：无（断言失败时 t.Fatal）。
func TestReadRawWithSizeErrorPath(t *testing.T) {
	withWebTimeout(t, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 每 500ms 发 1KB，共 3 秒，始终发不满 192KB 且在 1 秒超时后仍持续有后续读取点
		chunk := strings.Repeat("A", 1024)
		for i := 0; i < 6; i++ {
			fmt.Fprint(w, chunk)
			w.(http.Flusher).Flush()
			time.Sleep(500 * time.Millisecond)
		}
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, err := ReadRawWithSize(resp, 192*1024)
	if err == nil {
		t.Fatal("预期读取超时报错，实际 err 为 nil")
	}
	if !strings.Contains(string(body), "HTTP/1.1 200 OK") {
		t.Fatalf("错误路径返回的 body 应包含状态行: %.80q", string(body))
	}

	// 验证错误路径返回的 body 不与池共享底层数组：
	// 再次调用 ReadRawWithSize 使池化 buffer 被复用后，首次返回的 body 内容必须保持不变
	snapshot := append([]byte(nil), body...)
	resp2, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = ReadRawWithSize(resp2, 192*1024)
	if !bytes.Equal(snapshot, body) {
		t.Fatal("错误路径返回的 body 被后续池复用覆盖，说明与池共享底层数组")
	}
}
