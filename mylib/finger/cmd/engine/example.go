package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/chainreactors/utils/encode"
	"github.com/chainreactors/utils/httputils"
	"github.com/jessevdk/go-flags"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
	"gopkg.in/yaml.v3"
)

var opts struct {
	// 指定要使用的引擎，多个引擎用逗号分隔
	Engines string `short:"e" long:"engines" description:"Specify engines to use (comma separated)" default:"fingers,fingerprinthub,wappalyzer,ehole,goby"`

	// 是否忽略SSL证书验证
	InsecureSSL bool `short:"k" long:"insecure" description:"Skip SSL certificate verification"`

	// 目标URL
	URL string `short:"u" long:"url" description:"Target URL to fingerprint" required:"true"`

	// 是否显示详细信息
	Verbose bool `short:"v" long:"verbose" description:"Show verbose debug information"`

	// 是否只检测favicon
	FaviconOnly bool `short:"f" long:"favicon" description:"Only detect favicon"`

	// 资源文件覆盖
	GobyFile           string `long:"goby" description:"Override goby.json.gz with custom file"`
	FingerprintHubFile string `long:"fingerprinthub" description:"Override fingerprinthub_v3.json.gz with custom file"`
	EholeFile          string `long:"ehole" description:"Override ehole.json.gz with custom file"`
	FingersFile        string `long:"fingers" description:"Override fingers_http.json.gz with custom file"`
	WappalyzerFile     string `long:"wappalyzer" description:"Override wappalyzer.json.gz with custom file"`
	AliasesFile        string `long:"aliases" description:"Override aliases.yaml with custom file"`
}

// 处理资源文件覆盖
func processResourceFile(filePath string) ([]byte, error) {
	if filePath == "" {
		return nil, nil
	}

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %v", filePath, err)
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	// 如果是JSON文件，转换为YAML
	if ext == ".json" {
		var jsonData interface{}
		if err := json.Unmarshal(data, &jsonData); err != nil {
			return nil, fmt.Errorf("failed to parse JSON file %s: %v", filePath, err)
		}

		data, err = yaml.Marshal(jsonData)
		if err != nil {
			return nil, fmt.Errorf("failed to convert JSON to YAML for file %s: %v", filePath, err)
		}
	}

	// 如果文件不是.gz结尾，进行gzip压缩
	if !strings.HasSuffix(filePath, ".gz") {
		compressedData, err := encode.GzipCompress(data)
		if err != nil {
			return nil, fmt.Errorf("failed to compress file %s: %v", filePath, err)
		}
		data = compressedData
	}

	return data, nil
}

func main() {
	// 解析命令行参数
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(1)
	}

	// 处理资源文件覆盖
	if opts.GobyFile != "" {
		if data, err := processResourceFile(opts.GobyFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.GobyData = data
		}
	}

	if opts.FingerprintHubFile != "" {
		if data, err := processResourceFile(opts.FingerprintHubFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.Fingerprinthubdata = data
		}
	}

	if opts.EholeFile != "" {
		if data, err := processResourceFile(opts.EholeFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.EholeData = data
		}
	}

	if opts.FingersFile != "" {
		if data, err := processResourceFile(opts.FingersFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.FingersHTTPData = data
		}
	}

	if opts.WappalyzerFile != "" {
		if data, err := processResourceFile(opts.WappalyzerFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.WappalyzerData = data
		}
	}

	if opts.AliasesFile != "" {
		if data, err := processResourceFile(opts.AliasesFile); err != nil {
			fmt.Println(err)
			os.Exit(1)
		} else {
			resources.AliasesData = data
		}
	}

	// 创建HTTP客户端
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: opts.InsecureSSL,
			},
		},
	}

	// 创建引擎实例
	var engineNames []string
	if opts.Engines != "" {
		engineNames = strings.Split(opts.Engines, ",")
	}

	engine, err := fingers.NewEngine(engineNames...)
	if err != nil {
		fmt.Printf("Failed to create engine: %v\n", err)
		os.Exit(1)
	}

	if opts.Verbose {
		fmt.Printf("Loaded engines: %s\n", engine.String())
	}

	// 发送HTTP请求
	resp, err := client.Get(opts.URL)
	if err != nil {
		fmt.Printf("Failed to request URL %s: %v\n", opts.URL, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	// 检测指纹
	var frames common.Frameworks
	if opts.FaviconOnly {
		content := httputils.ReadBody(resp)
		frame := engine.DetectFavicon(content)
		if frame != nil {
			frames.Add(frame)
		}
	} else {
		frames = engine.Match(resp)
	}

	// 输出结果
	if opts.Verbose {
		fmt.Printf("\nDetected frameworks for %s:\n", opts.URL)
		for _, frame := range frames {
			fmt.Printf("Name: %s\n", frame.Name)
			fmt.Printf("Vendor: %s\n", frame.Vendor)
			fmt.Printf("Product: %s\n", frame.Product)
			fmt.Printf("Version: %s\n", frame.Version)
			fmt.Printf("CPE: %s\n", frame.CPE())
			fmt.Printf("---\n")
		}
	} else {
		fmt.Println(frames.String())
	}
}
