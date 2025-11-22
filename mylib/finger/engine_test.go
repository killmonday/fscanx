package fingers

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"
	"testing"
	"time"

	"github.com/chainreactors/utils/httputils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/ehole"
	"github.com/killmonday/fscanx/mylib/finger/fingerprinthub"
	"github.com/killmonday/fscanx/mylib/finger/fingers"
	"github.com/killmonday/fscanx/mylib/finger/goby"
	"github.com/killmonday/fscanx/mylib/finger/wappalyzer"
)

func TestEngine(t *testing.T) {
	// 创建内存分析文件
	memProfileFile, err := os.Create("memprofile.out")
	if err != nil {
		t.Fatal("could not create memory profile: ", err)
	}
	defer memProfileFile.Close()

	// 在检测 `DetectContent` 前进行内存分析

	// Your test code
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	fmt.Println(engine.String())

	//client := &http.Client{
	//	Transport: &http.Transport{
	//		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//	},
	//}
	//resp, err := client.Get("https://boce.aliyun.com/detect/http")
	//if err != nil {
	//	panic(err)
	//}
	//start := time.Now()
	//content := httputils.ReadRaw(resp)

	// 调用 DetectContent

	content, err := os.ReadFile("1.raw")
	if err != nil {
		return
	}
	frames, err := engine.DetectContent(content)
	if err != nil {
		return
	}

	// 打印执行时间
	//println("耗时: " + time.Since(start).String())
	fmt.Println(frames.String())

	// 在检测 `DetectContent` 后进行内存分析
	pprof.WriteHeapProfile(memProfileFile)

	// 打印内存分配
	for _, f := range frames {
		fmt.Println("cpe: ", f.CPE(), "||||", f.String())
	}
}

func TestEngine_Match(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://127.0.0.1:8089")
	if err != nil {
		panic(err)
	}
	frames := engine.Match(resp)
	fmt.Println(frames.String())
}

func TestFavicon(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://baidu.com/favicon.ico")
	if err != nil {
		return
	}
	content := httputils.ReadRaw(resp)
	body, _, _ := httputils.SplitHttpRaw(content)
	frame := engine.DetectFavicon(body)
	fmt.Println(frame)
}

func TestFingersEngine(t *testing.T) {
	engine, err := fingers.NewFingersEngine()
	if err != nil {
		t.Error(err)
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get("https://218.94.127.25:443")
	if err != nil {
		t.Log(err)
		return
	}
	fmt.Println("math")

	content := httputils.ReadRaw(resp)
	frames := engine.WebMatch(content)
	for _, frame := range frames {
		t.Log(frame)
	}
}

func TestEngine_MatchWithEngines(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	need := []string{FingersEngine, FingerPrintEngine}
	frames := engine.MatchWithEngines(resp, need...)
	for _, frame := range frames {
		t.Log(frame)
	}
}

func TestFingerPrintHubsEngine(t *testing.T) {
	engine, err := fingerprinthub.NewFingerPrintHubEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	_, body, ok := httputils.SplitHttpRaw(content)
	if ok {
		frames := engine.MatchWithHttpAndBody(resp.Header, string(body))
		for _, frame := range frames {
			t.Log(frame)
		}
	}
}

func TestEHoleEngine(t *testing.T) {
	engine, err := ehole.NewEHoleEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1:8089")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	header, body, ok := httputils.SplitHttpRaw(content)
	if ok {
		frames := engine.MatchWithHeaderAndBody(string(header), string(body))
		for _, frame := range frames {
			t.Log(frame)
		}
	}
}

func TestGobyEngine(t *testing.T) {
	engine, err := goby.NewGobyEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("https://baidu.com")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	content = bytes.ToLower(content)
	start := time.Now()
	frames := engine.WebMatch(content)
	fmt.Println(frames)
	fmt.Println(time.Since(start).String())
}

func TestEngine_Wappalyzer(t *testing.T) {
	engine, err := wappalyzer.NewWappalyzeEngine()
	if err != nil {
		t.Error(err)
		return
	}
	resp, err := http.Get("http://127.0.0.1:8000")
	if err != nil {
		return
	}

	content := httputils.ReadBody(resp)
	start := time.Now()
	frames := engine.Fingerprint(resp.Header, content)
	fmt.Println(frames)
	fmt.Println(time.Since(start).String())
}

func TestAlias(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Error()
		return
	}
	fmt.Println(engine.FindAny("cdncache_server"))
	fmt.Println(engine.Aliases.Aliases["cdn-cache-server"])
	fmt.Println(engine.Aliases.Map["fingers"]["cdn-cache-server"])
}

func TestNmapEngine(t *testing.T) {
	engine, err := NewEngine(NmapEngine)
	if err != nil {
		t.Error(err)
		return
	}

	nmapEngine := engine.Nmap()
	if nmapEngine == nil {
		t.Error("nmap engine not found")
		return
	}

	fmt.Printf("nmap engine loaded with %d fingerprints\n", nmapEngine.Len())

	// 测试Service指纹匹配 - 使用common包的默认实现
	testServiceSender := common.NewServiceSender(3 * time.Second)

	testServiceCallback := func(result *common.ServiceResult) {
		if result.Framework != nil {
			t.Logf("detected service: %s", result.Framework.String())
		}
	}

	result := nmapEngine.ServiceMatch("127.0.0.1", 80, 1, testServiceSender, testServiceCallback)
	if result != nil && result.Framework != nil {
		t.Logf("service result: %s", result.Framework.String())
	}

	// 测试引擎能力
	capability := nmapEngine.Capability()
	if !capability.SupportService {
		t.Error("nmap engine should support service fingerprinting")
	}
	if capability.SupportWeb {
		t.Error("nmap engine should not support web fingerprinting")
	}

	// 测试WebMatch应该返回空结果
	webFrames := nmapEngine.WebMatch([]byte("test"))
	if len(webFrames) != 0 {
		t.Error("nmap engine WebMatch should return empty results")
	}
}

// TestServiceEngine 测试Service引擎的能力
func TestServiceEngine(t *testing.T) {
	engine, err := NewEngine(NmapEngine)
	if err != nil {
		t.Error(err)
		return
	}

	// 测试获取支持Service的引擎
	serviceEngines := engine.GetEnginesByType(common.ServiceFingerprint)
	expectedServiceEngines := []string{NmapEngine}

	if len(serviceEngines) != len(expectedServiceEngines) {
		t.Errorf("Expected %d service engines, got %d", len(expectedServiceEngines), len(serviceEngines))
	}

	for _, expected := range expectedServiceEngines {
		found := false
		for _, actual := range serviceEngines {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected service engine %s not found", expected)
		}
	}

	// 测试DetectService API
	testSender := common.NewServiceSender(3 * time.Second)

	ports := []int{80, 443, 445, 135, 1080, 3306, 1433, 1521}
	for _, port := range ports {
		results, err := engine.DetectService("127.0.0.1", port, 9, testSender, nil)
		if err != nil {
			t.Logf("DetectService error: %v", err)
		}
		if len(results) > 0 && results[0].Framework != nil {
			fmt.Printf("DetectService result: %s\n", results[0].Framework.String())
		}
	}
}
