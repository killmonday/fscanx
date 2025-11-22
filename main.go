package main

import (
	"net/http"
	"time"

	"github.com/killmonday/fscanx/Plugins"
	"github.com/killmonday/fscanx/common"
	//"net/http"
	_ "net/http/pprof"
)

func main() {
	go func() {
		http.ListenAndServe("localhost:6060", nil)
	}()

	//go func() {
	//	time.Sleep(time.Second * 5)
	//	for {
	//		var m runtime.MemStats
	//		runtime.ReadMemStats(&m)
	//		fmt.Println("\n\n===============================================================================================")
	//		fmt.Printf("Alloc    堆内存正在使用的 = %.2f MB\n", float64(m.Alloc)/1024/1024)
	//		fmt.Printf("StackSys 所有协程的栈内存 = %.2f MB\n", float64(m.StackSys)/1024/1024)
	//		fmt.Printf("HeapSys 栈内存正在使用+预留内存  = %.2f MB\n", float64(m.HeapSys)/1024/1024)
	//		fmt.Printf("Sys 总内存占用 = %.2f MB\n", float64(m.Sys)/1024/1024)
	//		fmt.Printf("TotalAlloc = %.2f MB\n", float64(m.TotalAlloc)/1024/1024)
	//		fmt.Printf("HeapAlloc = %.2f MB\n", float64(m.HeapAlloc)/1024/1024)
	//		fmt.Printf("HeapReleased = %.2f MB\n", float64(m.HeapReleased)/1024/1024)
	//		fmt.Printf("OtherSys = %.2f MB\n", float64(m.OtherSys)/1024/1024)
	//		fmt.Println("当前 Goroutine 数量:", runtime.NumGoroutine())
	//		fmt.Println("===============================================================================================\n\n")
	//		//lib.Client.CloseIdleConnections()
	//		//lib.ClientNoRedirect.CloseIdleConnections()
	//		time.Sleep(time.Second * 8)
	//	}
	//
	//}()

	var Info common.HostInfo
	start := time.Now()
	common.Flag(&Info)
	common.Parse(&Info)

	// 检查是否有 --std 参数（通过flag）
	if common.ScanWithStdInput {
		Plugins.ScanFromStdin()
		common.LogSuccess("[*] scan done! cost: %s\n", time.Since(start))
		common.LogWG.Wait() //等待所有日志打印和写入文件等等事件
		close(common.Results)
		return
	}
	Plugins.Scan(Info)
	common.LogSuccess("[*] scan done! cost: %s\n", time.Since(start))
	common.LogWG.Wait() //等待所有日志打印和写入文件等等事件
	close(common.Results)
}
