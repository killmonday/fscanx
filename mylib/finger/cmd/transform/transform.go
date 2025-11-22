package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	gonmap "github.com/killmonday/fscanx/mylib/finger/nmap"
)

// DataSource 定义数据源接口
type DataSource interface {
	Name() string                       // 数据源名称
	URL() string                        // 下载URL
	CacheFileName() string              // 本地缓存文件名
	OutputFileName() string             // 输出JSON文件名
	Download(client *http.Client) error // 下载逻辑
	Transform() error                   // 转换逻辑
}

// ProbesDataSource nmap-service-probes数据源
type ProbesDataSource struct{}

func (p *ProbesDataSource) Name() string { return "probes" }
func (p *ProbesDataSource) URL() string {
	return "https://raw.githubusercontent.com/nmap/nmap/master/nmap-service-probes"
}
func (p *ProbesDataSource) CacheFileName() string  { return "nmap-service-probes.txt" }
func (p *ProbesDataSource) OutputFileName() string { return "resources/nmap-service-probes.json.gz" }

func (p *ProbesDataSource) Download(client *http.Client) error {
	return downloadFile(client, p.URL(), p.CacheFileName())
}

func (p *ProbesDataSource) Transform() error {
	return transformProbes(p.CacheFileName(), p.OutputFileName())
}

// ServicesDataSource nmap-services数据源
type ServicesDataSource struct{}

func (s *ServicesDataSource) Name() string { return "services" }
func (s *ServicesDataSource) URL() string {
	return "https://raw.githubusercontent.com/nmap/nmap/master/nmap-services"
}
func (s *ServicesDataSource) CacheFileName() string  { return "nmap-services.txt" }
func (s *ServicesDataSource) OutputFileName() string { return "resources/nmap-services.json.gz" }

func (s *ServicesDataSource) Download(client *http.Client) error {
	return downloadFile(client, s.URL(), s.CacheFileName())
}

func (s *ServicesDataSource) Transform() error {
	return transformServices(s.CacheFileName(), s.OutputFileName())
}

// DataManager 数据管理器
type DataManager struct {
	sources map[string]DataSource
	client  *http.Client
}

// NewDataManager 创建数据管理器
func NewDataManager(proxyURL string) *DataManager {
	dm := &DataManager{
		sources: make(map[string]DataSource),
		client:  createHTTPClientWithProxy(proxyURL),
	}

	// 注册数据源
	dm.RegisterSource(&ProbesDataSource{})
	dm.RegisterSource(&ServicesDataSource{})

	return dm
}

// RegisterSource 注册数据源
func (dm *DataManager) RegisterSource(source DataSource) {
	dm.sources[source.Name()] = source
}

// GetSource 获取数据源
func (dm *DataManager) GetSource(name string) (DataSource, bool) {
	source, exists := dm.sources[name]
	return source, exists
}

// ListSources 列出所有数据源
func (dm *DataManager) ListSources() []string {
	var names []string
	for name := range dm.sources {
		names = append(names, name)
	}
	return names
}

// Download 下载数据源
func (dm *DataManager) Download(sourceName string) error {
	source, exists := dm.GetSource(sourceName)
	if !exists {
		return fmt.Errorf("数据源 '%s' 不存在", sourceName)
	}

	fmt.Printf("正在下载 %s 从 %s...\n", source.Name(), source.URL())
	return source.Download(dm.client)
}

// Transform 转换数据源
func (dm *DataManager) Transform(sourceName string) error {
	source, exists := dm.GetSource(sourceName)
	if !exists {
		return fmt.Errorf("数据源 '%s' 不存在", sourceName)
	}

	fmt.Printf("正在转换 %s 数据为 JSON 格式...\n", source.Name())
	return source.Transform()
}

// Update 更新数据源（下载+转换）
func (dm *DataManager) Update(sourceName string) error {
	if err := dm.Download(sourceName); err != nil {
		return err
	}
	return dm.Transform(sourceName)
}

// DownloadAll 下载所有数据源
func (dm *DataManager) DownloadAll() error {
	for name := range dm.sources {
		if err := dm.Download(name); err != nil {
			return fmt.Errorf("下载 %s 失败: %v", name, err)
		}
	}
	return nil
}

// TransformAll 转换所有数据源
func (dm *DataManager) TransformAll() error {
	for name := range dm.sources {
		if err := dm.Transform(name); err != nil {
			return fmt.Errorf("转换 %s 失败: %v", name, err)
		}
	}
	return nil
}

// UpdateAll 更新所有数据源
func (dm *DataManager) UpdateAll() error {
	if err := dm.DownloadAll(); err != nil {
		return err
	}
	return dm.TransformAll()
}

func main() {
	var proxyURL string
	flag.StringVar(&proxyURL, "proxy", "", "HTTP代理地址 (例如: http://127.0.0.1:1080)")
	flag.Parse()

	args := flag.Args()
	if len(args) < 1 {
		printUsage()
		return
	}

	dm := NewDataManager(proxyURL)
	command := args[0]

	switch command {
	case "download":
		if len(args) == 1 {
			// 下载所有
			if err := dm.DownloadAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 下载指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Download(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "transform":
		if len(args) == 1 {
			// 转换所有
			if err := dm.TransformAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 转换指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Transform(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "update":
		if len(args) == 1 {
			// 更新所有
			if err := dm.UpdateAll(); err != nil {
				log.Fatal(err)
			}
		} else {
			// 更新指定数据源
			for _, sourceName := range args[1:] {
				if err := dm.Update(sourceName); err != nil {
					log.Fatal(err)
				}
			}
		}

	case "list":
		fmt.Println("可用的数据源:")
		for _, name := range dm.ListSources() {
			source, _ := dm.GetSource(name)
			fmt.Printf("  %-10s - %s\n", name, source.URL())
		}

	default:
		printUsage()
	}
}

func printUsage() {
	fmt.Println("数据转换工具")
	fmt.Println()
	fmt.Println("用法:")
	fmt.Println("  go run cmd/transform/transform.go [flags] <command> [sources...]")
	fmt.Println()
	fmt.Println("标志:")
	fmt.Println("  -proxy string    HTTP代理地址 (例如: http://127.0.0.1:1080)")
	fmt.Println()
	fmt.Println("命令:")
	fmt.Println("  download [sources...]  下载指定数据源（不指定则下载所有）")
	fmt.Println("  transform [sources...] 转换指定数据源（不指定则转换所有）")
	fmt.Println("  update [sources...]    更新指定数据源（不指定则更新所有）")
	fmt.Println("  list                   列出所有可用数据源")
	fmt.Println()
	fmt.Println("可用数据源: probes, services")
	fmt.Println()
	fmt.Println("示例:")
	fmt.Println("  go run cmd/transform/transform.go list")
	fmt.Println("  go run cmd/transform/transform.go -proxy http://127.0.0.1:1080 download probes")
	fmt.Println("  go run cmd/transform/transform.go update services")
	fmt.Println("  go run cmd/transform/transform.go -proxy http://127.0.0.1:1080 update")
}

// createHTTPClientWithProxy 创建支持代理的HTTP客户端
func createHTTPClientWithProxy(proxyURL string) *http.Client {
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// 如果提供了代理URL，使用代理
	if proxyURL != "" {
		parsedProxyURL, err := url.Parse(proxyURL)
		if err != nil {
			fmt.Printf("代理URL解析失败: %v，将使用直连\n", err)
		} else {
			transport := &http.Transport{
				Proxy: http.ProxyURL(parsedProxyURL),
			}
			client.Transport = transport
			fmt.Printf("使用代理: %s\n", proxyURL)
		}
	}

	return client
}

// downloadFile 通用文件下载函数
func downloadFile(client *http.Client, url, filename string) error {
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("下载失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("下载失败，状态码: %d", resp.StatusCode)
	}

	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建本地文件失败: %v", err)
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return fmt.Errorf("保存文件失败: %v", err)
	}

	fmt.Printf("✓ 下载完成: %s\n", filename)
	return nil
}

// writeGzipJSON 写入gzip压缩的JSON文件
func writeGzipJSON(data interface{}, filename string) error {
	// 确保输出目录存在
	if err := os.MkdirAll(filepath.Dir(filename), 0755); err != nil {
		return fmt.Errorf("创建输出目录失败: %v", err)
	}

	// 转换为 JSON
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON 序列化失败: %v", err)
	}

	// 创建gzip压缩文件
	outputFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("创建输出文件失败: %v", err)
	}
	defer outputFile.Close()

	// 创建gzip写入器
	gzipWriter := gzip.NewWriter(outputFile)
	defer gzipWriter.Close()

	// 写入压缩数据
	_, err = gzipWriter.Write(jsonData)
	if err != nil {
		return fmt.Errorf("写入压缩数据失败: %v", err)
	}

	fmt.Printf("✓ 转换完成: %s\n", filename)

	// 显示文件大小
	if outputStat, err := os.Stat(filename); err == nil {
		fmt.Printf("  - 文件大小: %d bytes (%.2f KB)\n", outputStat.Size(), float64(outputStat.Size())/1024)
	}

	return nil
}

// fileExists 检查文件是否存在
func fileExists(filename string) bool {
	_, err := os.Stat(filename)
	return !os.IsNotExist(err)
}

// Service 代表一个服务条目
type Service struct {
	Name        string  `json:"name"`
	Port        int     `json:"port"`
	Protocol    string  `json:"protocol"`
	Probability float64 `json:"probability"`
	Comments    string  `json:"comments,omitempty"`
}

// ServicesData 代表解析后的services数据结构
type ServicesData struct {
	Services []Service `json:"services"`
}

// transformServices 转换services数据
func transformServices(cacheFile, outputFile string) error {
	if !fileExists(cacheFile) {
		return fmt.Errorf("找不到文件: %s，请先下载", cacheFile)
	}

	fmt.Printf("使用本地缓存文件: %s\n", cacheFile)
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	fmt.Printf("解析服务数据...\n")
	data := parseNmapServices(string(content))

	if err := writeGzipJSON(data, outputFile); err != nil {
		return err
	}

	fmt.Printf("  - 服务数量: %d\n", len(data.Services))
	fmt.Println()
	fmt.Println("转换后的 JSON 文件可以用于:")
	fmt.Println("1. 快速加载服务数据，避免每次解析原始文件")
	fmt.Println("2. 定期自动更新服务库")
	fmt.Println("3. 在嵌入式资源中使用")

	return nil
}

// transformProbes 转换probes数据
func transformProbes(cacheFile, outputFile string) error {
	if !fileExists(cacheFile) {
		return fmt.Errorf("找不到文件: %s，请先下载", cacheFile)
	}

	fmt.Printf("使用本地缓存文件: %s\n", cacheFile)
	content, err := os.ReadFile(cacheFile)
	if err != nil {
		return fmt.Errorf("读取本地文件失败: %v", err)
	}

	fmt.Printf("解析探针数据...\n")
	data := parseAndExportProbes(string(content))

	fmt.Printf("应用自定义匹配规则...\n")
	applyCustomNMAPMatch(data)

	probeCount := len(data.Probes)
	totalMatches := 0
	for _, probe := range data.Probes {
		totalMatches += len(probe.MatchGroup)
	}

	if err := writeGzipJSON(data, outputFile); err != nil {
		return err
	}

	fmt.Printf("  - 探针数量: %d\n", probeCount)
	fmt.Printf("  - 指纹数量: %d\n", totalMatches)
	fmt.Println()
	fmt.Println("转换后的 JSON 文件可以用于:")
	fmt.Println("1. 快速加载探针数据，避免每次解析原始文件")
	fmt.Println("2. 定期自动更新指纹库")
	fmt.Println("3. 在嵌入式资源中使用")

	return nil
}

// parseNmapServices 解析nmap-services内容
func parseNmapServices(content string) *ServicesData {
	lines := strings.Split(content, "\n")
	var services []Service

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// 跳过空行和注释行
		if len(line) == 0 || strings.HasPrefix(line, "#") {
			continue
		}

		// 解析格式: service-name port/protocol probability [comments]
		// 例如: http 80/tcp 0.484143 # World Wide Web HTTP
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		serviceName := parts[0]
		portProtocol := parts[1]

		// 解析端口和协议
		portProtocolParts := strings.Split(portProtocol, "/")
		if len(portProtocolParts) != 2 {
			continue
		}

		port, err := strconv.Atoi(portProtocolParts[0])
		if err != nil {
			continue
		}

		protocol := portProtocolParts[1]

		// 解析概率值
		var probability float64 = 0.0
		if len(parts) >= 3 {
			if prob, err := strconv.ParseFloat(parts[2], 64); err == nil {
				probability = prob
			}
		}

		// 解析注释（如果存在）
		var comments string
		if commentIndex := strings.Index(line, "#"); commentIndex != -1 {
			comments = strings.TrimSpace(line[commentIndex+1:])
		}

		service := Service{
			Name:        serviceName,
			Port:        port,
			Protocol:    protocol,
			Probability: probability,
			Comments:    comments,
		}

		services = append(services, service)
	}

	return &ServicesData{
		Services: services,
	}
}

// parseAndExportProbes 解析探针内容并导出为数据结构
func parseAndExportProbes(content string) *gonmap.NmapProbesData {
	tempNmap := gonmap.NewTempParser(content)

	probes := make([]*gonmap.Probe, 0, len(tempNmap.GetProbes()))
	for _, probe := range tempNmap.GetProbes() {
		probeCopy := *probe
		probes = append(probes, &probeCopy)
	}

	return &gonmap.NmapProbesData{
		Probes:   probes,
		Services: make(map[string]string),
	}
}

// applyCustomNMAPMatch 应用自定义匹配规则
func applyCustomNMAPMatch(data *gonmap.NmapProbesData) {
	probeMap := make(map[string]*gonmap.Probe)
	for _, probe := range data.Probes {
		probeMap[probe.Name] = probe
	}

	addCustomMatch := func(probeName, matchExpr string) {
		if probe, exists := probeMap[probeName]; exists {
			probe.LoadMatch(matchExpr, false)
		}
	}

	// 新增自定义指纹信息
	addCustomMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	addCustomMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	addCustomMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	addCustomMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	addCustomMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	addCustomMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	addCustomMatch("TCP_NULL", `telnet m|^Username: ??|`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	addCustomMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	addCustomMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	addCustomMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	addCustomMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	addCustomMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
}
