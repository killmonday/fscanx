package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chainreactors/utils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
)

// 扫描统计信息
type ScanStats struct {
	TotalTargets    int64
	ScannedTargets  int64
	OpenPorts       int64
	IdentifiedPorts int64
	StartTime       time.Time
}

// 扫描结果
type ScanResult struct {
	Host      string
	Port      string
	Open      bool
	Framework *common.Framework
	Error     error
}

func main() {
	// 命令行参数
	var (
		cidrFlag    = flag.String("cidr", "127.0.0.1/32", "目标CIDR范围，例如: 192.168.1.0/24")
		portFlag    = flag.String("port", "1000-2000", "端口范围，例如: 80,443,1000-2000")
		threadsFlag = flag.Int("threads", 100, "并发线程数")
		timeoutFlag = flag.Int("timeout", 3, "扫描超时时间(秒)")
		levelFlag   = flag.Int("level", 1, "扫描深度级别(1-9)")
		verboseFlag = flag.Bool("v", false, "详细输出模式")
		outputFlag  = flag.String("o", "", "输出文件路径")
	)
	flag.Parse()

	if *cidrFlag == "" || *portFlag == "" {
		fmt.Println("使用方法:")
		fmt.Println("  nmap -cidr 192.168.1.0/24 -port 22,80,443,1000-2000")
		fmt.Println("  nmap -cidr 10.0.0.1 -port 80 -threads 200 -timeout 5")
		flag.PrintDefaults()
		return
	}

	fmt.Printf("🚀 启动nmap指纹扫描器\n")
	fmt.Printf("目标: %s\n", *cidrFlag)
	fmt.Printf("端口: %s\n", *portFlag)
	fmt.Printf("线程: %d\n", *threadsFlag)
	fmt.Printf("超时: %ds\n", *timeoutFlag)
	fmt.Printf("级别: %d\n", *levelFlag)

	// 解析CIDR和端口
	ips, err := parseCIDR(*cidrFlag)
	if err != nil {
		log.Fatalf("解析CIDR失败: %v", err)
	}

	// 使用utils包解析端口
	utils.PrePort, err = resources.LoadPorts()
	if err != nil {
		log.Fatalf("加载端口资源失败: %v", err)
	}
	var portList []string
	portList = utils.ParsePortsString(*portFlag)

	fmt.Printf("📊 目标统计: %d个IP, %d个端口, 共%d个扫描目标\n",
		ips.Len(), len(portList), ips.Len()*len(portList))

	// 创建fingers引擎（只使用nmap引擎）
	engine, err := fingers.NewEngine(fingers.NmapEngine)
	if err != nil {
		log.Fatalf("创建引擎失败: %v", err)
	}

	// 创建网络发送器
	sender := common.NewServiceSender(time.Duration(*timeoutFlag) * time.Second)

	// 初始化统计信息
	stats := &ScanStats{
		TotalTargets: int64(ips.Len() * len(portList)),
		StartTime:    time.Now(),
	}

	// 创建任务通道和结果通道
	taskChan := make(chan scanTask, *threadsFlag*2)
	resultChan := make(chan ScanResult, *threadsFlag)

	// 启动工作协程
	var wg sync.WaitGroup
	for i := 0; i < *threadsFlag; i++ {
		wg.Add(1)
		go worker(engine, sender, taskChan, resultChan, &wg, *levelFlag)
	}

	// 启动结果处理协程
	go resultHandler(resultChan, stats, *verboseFlag, *outputFlag)

	// 生成扫描任务
	go func() {
		defer close(taskChan)
		for ip := range ips.Range() {
			for _, port := range portList {
				portStr := strings.TrimSpace(port)
				taskChan <- scanTask{Host: ip.String(), Port: portStr}
			}
		}
	}()

	// 等待所有工作协程完成
	wg.Wait()
	close(resultChan)

	// 输出最终统计
	duration := time.Since(stats.StartTime)
	fmt.Printf("\n✅ 扫描完成!\n")
	fmt.Printf("总耗时: %v\n", duration)
	fmt.Printf("扫描目标: %d\n", atomic.LoadInt64(&stats.ScannedTargets))
	fmt.Printf("开放端口: %d\n", atomic.LoadInt64(&stats.OpenPorts))
	fmt.Printf("识别服务: %d\n", atomic.LoadInt64(&stats.IdentifiedPorts))
	fmt.Printf("扫描速度: %.2f targets/sec\n",
		float64(atomic.LoadInt64(&stats.ScannedTargets))/duration.Seconds())
}

// 扫描任务
type scanTask struct {
	Host string
	Port string
}

// 工作协程
func worker(engine *fingers.Engine, sender common.ServiceSender, taskChan <-chan scanTask, resultChan chan<- ScanResult, wg *sync.WaitGroup, level int) {
	defer wg.Done()

	for task := range taskChan {
		// 使用DetectService进行扫描
		serviceResults, err := engine.DetectService(task.Host, task.Port, level, sender, nil)

		result := ScanResult{
			Host:      task.Host,
			Port:      task.Port,
			Open:      len(serviceResults) > 0,
			Framework: nil,
			Error:     err,
		}

		// 如果有识别到的服务，取第一个
		if len(serviceResults) > 0 && serviceResults[0].Framework != nil {
			result.Framework = serviceResults[0].Framework
		}

		select {
		case resultChan <- result:
		default:
			// 结果通道已满，丢弃结果（避免阻塞）
		}
	}
}

// 结果处理协程
func resultHandler(resultChan <-chan ScanResult, stats *ScanStats, verbose bool, outputFile string) {
	var results []ScanResult

	for result := range resultChan {
		atomic.AddInt64(&stats.ScannedTargets, 1)

		// 统计开放端口
		if result.Open {
			atomic.AddInt64(&stats.OpenPorts, 1)
		}

		// 统计识别的服务
		if result.Framework != nil {
			atomic.AddInt64(&stats.IdentifiedPorts, 1)
		}

		// 输出结果
		if result.Open {
			if verbose || result.Framework != nil {
				printResult(result)
			}
			results = append(results, result)
		}
	}

	// 保存到文件
	if outputFile != "" {
		saveResults(results, outputFile)
	}
}

// 打印扫描结果
func printResult(result ScanResult) {
	target := fmt.Sprintf("%s:%s", result.Host, result.Port)

	if result.Framework != nil {
		// 使用Framework.String()方法进行输出
		frameworkStr := result.Framework.String()

		// 添加guess标识
		guessIndicator := ""
		if result.Framework.IsGuess() {
			guessIndicator = " [guess]"
		}

		// 输出基本信息
		fmt.Printf("✅ %s -> %s%s", target, frameworkStr, guessIndicator)

		// 输出CPE信息（如果有的话）
		if result.Framework.Attributes != nil && result.Framework.Attributes.String() != "" {
			fmt.Printf(" | CPE: %s", result.Framework.CPE())
		}

		fmt.Printf("\n")
	} else if result.Open {
		// 只是端口开放，无法识别服务
		fmt.Printf("🔓 %s -> 端口开放\n", target)
	}
}

// 保存结果到文件
func saveResults(results []ScanResult, filename string) {
	// TODO: 实现结果保存功能
	fmt.Printf("📝 结果已保存到: %s (%d条记录)\n", filename, len(results))
}

// parseCIDR 解析CIDR网段，返回IP地址列表
func parseCIDR(cidr string) (*utils.CIDR, error) {

	// 解析CIDR
	ipnet := utils.ParseCIDR(cidr)
	if ipnet == nil {
		return nil, fmt.Errorf("无效的CIDR: %s, 错误: %v", cidr)
	}

	return ipnet, nil
}
