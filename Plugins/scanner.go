package Plugins

import (
	"bufio"
	"fmt"
	"github.com/killmonday/fscanx/PocScan/lib"
	"github.com/killmonday/fscanx/common"
	"github.com/killmonday/fscanx/mylib/gonmap"
	"github.com/remeh/sizedwaitgroup"
	"net"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Czdb *QQwry

func init() {
	for _, port := range common.PluginPortMap {
		common.PortsArrayHasPlugin = append(common.PortsArrayHasPlugin, strconv.Itoa(port))
	}
	Czdb, _ = NewQQwry("qqwry.dat")
}

// 从标准输入读取目标并探测。目前支持输入为url、ip:port、masscan输出文件内容、masscan屏幕输出内容、纯域名
func ScanFromStdin() {
	defer func() {
		gonmap.Clear()
		if r := recover(); r != nil {
			//debug.PrintStack()
			//os.Exit(-1)
		}
	}()
	if common.UseNmap {
		gonmap.SetFilter(9)
	}
	scanner := bufio.NewScanner(os.Stdin)
	targetInputCh := make(chan Addr, common.PortScanThreadNum)
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: stdin", nowStr, strings.Join(os.Args[1:], " ")))
	fmt.Println("start infoscan")
	lib.Inithttp()

	go func() {
		// 扫描工作协程。PortScanTaskWithStd中使用gopool启动n个工作协程
		PortScanTaskWithStd(targetInputCh)
	}()

	// 从标准输入读取每一行。目前支持url、ip:port、masscan输出文件、masscan屏幕输出内容、纯域名
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		target, port := "", ""
		if strings.HasPrefix(line, "http") {
			// 支持url输入
			target = line
			port = "-1"
		} else {
			// 支持 ip:port 输入
			matches := common.RegIPAndPort.FindAllStringSubmatch(line, -1)
			if len(matches) >= 1 && !strings.HasPrefix(line, "http") {
				match := matches[0]
				if len(match) == 3 {
					target = match[1]
					port = match[2]
				} else {
					continue
				}
			} else {
				// 支持 masscan输出文件的内容格式
				matchesMasscanRunning := common.RegMasscanRunningText.FindAllStringSubmatch(line, -1)
				if len(matchesMasscanRunning) >= 1 {
					match := matchesMasscanRunning[0]
					if len(match) == 3 {
						port = match[1]
						target = match[2]
					} else {
						continue
					}
				} else {
					// 支持 masscan运行时屏幕输出的格式
					matchesMasscanFileOutput := common.RegMasscanOutputText.FindAllStringSubmatch(line, -1)
					if len(matchesMasscanFileOutput) >= 1 {
						match := matchesMasscanFileOutput[0]
						if len(match) == 3 {
							port = match[1]
							target = match[2]
						} else {
							continue
						}
					} else {
						// 支持纯域名格式
						if common.Reg_domain.MatchString(line) {
							// 输入的是纯域名，只探测443、80端口
							common.LogWG.Add(2)
							targetInputCh <- Addr{"https://" + line, -1}
							targetInputCh <- Addr{"http://" + line, -1}
						}
						continue
					}
				}
			}
		}
		portInt, err := strconv.Atoi(port)
		if err != nil {
			portInt = 80
		}
		common.LogWG.Add(1)
		targetInputCh <- Addr{target, portInt}
	}
	common.LogWG.Wait()
	close(targetInputCh)
	common.PoolScan.StopAndWait()

	alivePortPrint := "[+] alive ports(%d): "
	count := 0
	common.AlivePortsMap.Range(func(key, value interface{}) bool {
		alivePort := key.(string)
		alivePortPrint += alivePort
		alivePortPrint += ","
		count++
		return true
	})
	alivePortPrint = fmt.Sprintf(alivePortPrint, count)
	alivePortPrint = strings.TrimRight(alivePortPrint, ",")

	common.LogSuccess(alivePortPrint)
	return
}

type PortScanRes struct {
	ip       string
	port     string
	protocol string
}

func AutoScanBigCidr(info common.HostInfo) []string {
	common.LogSuccess("[*] Auto pre scan init, target: %s", info.Host)
	probePortList := strings.Split(common.AutoScanPorts, ",")
	swg := sizedwaitgroup.New(common.PortScanThreadNum) //端口扫描的并发控制
	var ipNeedProbe []string

	if info.Host == "192" {
		info.Host = "192.168.0.0/16"
	} else if info.Host == "10" {
		info.Host = "10.0.0.0/8"
	}

	doTcp := false
	doIcmp := false
	taskType := strings.Split(common.AutoScanProtocols, ",")
	for _, t := range taskType {
		if t == "tcp" {
			doTcp = true
		}
		if t == "icmp" {
			doIcmp = true
		}
	}

	if info.Host == "172" {
		for i := 16; i < 32; i++ {
			bNet := fmt.Sprintf("172.%d.0.0/16", i)
			ipNeedProbe = append(ipNeedProbe, common.ParseIpBWithGuess(bNet)...)
		}
	} else if strings.HasSuffix(info.Host, "/16") {
		ipNeedProbe = common.ParseIpBWithGuess(info.Host)
	} else if strings.HasSuffix(info.Host, "/8") {
		ipNeedProbe = common.ParseIpAWithGuess(info.Host)
	} else {
		fmt.Println("-auto不支持的网段")
		return nil
	}
	if doTcp {
		timeout := time.Duration(common.AutoScanTcpTimeout) * time.Second
		for _, ip := range ipNeedProbe {
			// 依次扫描指定端口
			for _, port := range probePortList {
				swg.Add()
				ip := ip
				port := port
				common.PoolScan.Submit(func() {
					defer func() {
						swg.Done()
						if r := recover(); r != nil {
							//debug.PrintStack()
						}
					}()
					addrStr := fmt.Sprintf("%s:%s", ip, port)
					conn, err := common.GetConn("tcp4", addrStr, timeout)
					// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
					if _, ok := conn.(*net.TCPConn); ok {
						err = conn.(*net.TCPConn).SetLinger(0)
						if err != nil {
							//fmt.Println("set socket delay close fail:", err)
						}
					}
					if conn != nil {
						conn.Close()
					}
					if err == nil {
						index := strings.LastIndex(ip, ".")
						if index != -1 {
							ipc := ip[:index]
							num, ok := AliveIpCPrefix.Load(ipc)
							if ok {
								AliveIpCPrefix.Store(ipc, num.(uint16)+1)
							} else {
								AliveIpCPrefix.Store(ipc, uint16(1))
								common.LogSuccess("[*] alive net\t%s.0/24", ipc)
							}
						}
						//if common.Silent == false {
						//	common.LogSuccess("(tcp) Target %-15s is alive", ip)
						//}
					}
				})

			}
		}
		swg.Wait()
	}
	if doIcmp {
		IcmpTaskWorker(ipNeedProbe, common.UsePingExe)
		common.LogSuccess("[*] icmp/tcp check done.\n\n")
	}

	aliveCNets := CountAliveIPCidrWithGlobal()
	common.LogSuccess("[*] Auto pre scan done! start scan alive c net.\n############################################")
	return aliveCNets
}

func Scan(inputInfo common.HostInfo) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[ERROR] Goroutine Scan panic: %v\n", r)
			//debug.PrintStack()
		}
	}()
	var wg = sync.WaitGroup{}
	var alivePortResList []*PortScanRes
	isPrintIcmp := true
	//web := strconv.Itoa(common.PluginPortMap["web"])         //只是个标志 1000003
	//ms17010 := strconv.Itoa(common.PluginPortMap["ms17010"]) //只是个标志 1000001
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: %s", nowStr, strings.Join(os.Args[1:], " "), inputInfo.Host))
	fmt.Println("start infoscan")
	lib.Inithttp()

	// 解析-hf输入的文件。ReadInputFile函数会提取纯ip、ip:port、url、域名（处理为http[s]://域名）
	if common.HostFile != "" {
		// 如果输入是文件类型
		var ipListFromFile []string
		ipListFromFile, _ = common.ReadInputFile(common.HostFile)

		// 此处对纯ip目标做端口扫描
		PortScanBatchTaskWithList(ipListFromFile, common.PortsInput)
	}

	// 0.A段/B段 智能存活扫描
	if common.AutoScanBigCidr {
		aliveIpCNets := AutoScanBigCidr(inputInfo) //存活的c段列表
		if aliveIpCNets == nil {
			goto ScanIpContainPort
		}
		inputInfo.Host = strings.Join(aliveIpCNets, ",")
		if common.NoPing == false {
			//如果下面还需要ping扫描，清空布隆过滤器
			common.BloomFilter.ClearAll()
			common.LogSuccess("[*] 开始icmp扫描存活C段的所有IP，C段总数：%d\n......\n", len(aliveIpCNets))
			isPrintIcmp = false
		} else {
			common.BloomFilter = nil
		}
	}
	runtime.GC()

	// 1.1 icmp扫描+端口探测和协议识别
	if common.NoPing == false {
		targetInputCh, err := common.ParseIPsByChanMaster(inputInfo.Host, true)
		if err != nil {
			fmt.Println("parse ip err:", err)
			return
		}
		aliveIPList := []string{}
		aliveIpChan := make(chan string, common.PortScanThreadNum)
		icmpWg := sync.WaitGroup{}
		// 接收icmp探测结果到 []string
		go func() {
			icmpWg.Add(1)
			for aliveIP := range aliveIpChan {
				aliveIPList = append(aliveIPList, aliveIP)
			}
			icmpWg.Done()
		}()
		IcmpTaskWorkerByChan(targetInputCh, aliveIpChan, common.UsePingExe, isPrintIcmp) //阻塞
		icmpWg.Wait()
		if len(aliveIPList) == 0 {
			goto ScanIpContainPort
		}

		common.LogSuccess("\n[*] 所有存活C段的icmp扫描结束，统计如下")
		CountAliveIPCidrWithGlobal()
		common.LogSuccess("[*] Icmp alive hosts len is: %d\n\n############################################\n[*] 端口扫描", len(aliveIPList))
		if common.Scantype == "icmp" {
			common.LogWG.Wait()
			return
		}
		if common.BloomFilter != nil {
			common.BloomFilter = nil
		}
		runtime.GC()

		if common.UseNmap {
			gonmap.SetFilter(9)
		}

		// 做nmap扫描/端口存活/poc扫描。PortScanBatchTask里具体做哪一种扫描取决于 -nmap、-poc选项是否设置
		PortScanBatchTaskWithList(aliveIPList, common.PortsInput)
		if common.Scantype == "portscan" {
			common.LogWG.Wait()
			return
		}

	} else {
		// 1.2 跳过icmp扫描，直接做端口探测和协议识别
		//finalResChan := make(chan *PortScanRes, common.PortScanThreadNum)
		//portscanWg := sync.WaitGroup{}
		common.LogSuccess("[*] 端口扫描")

		if common.UseNmap {
			gonmap.SetFilter(9)
		}

		targetInputCh, err := common.ParseIPsByChanMaster(inputInfo.Host, false)
		if err != nil {
			fmt.Println("parse ip err:", err)
			return
		}

		PortScanBatchTaskWithChan(targetInputCh)
	}

ScanIpContainPort:
	// 2.1 扫描 ip:port 输入，做端口协议识别和特定插件扫描
	if len(common.HostAndPortList) != 0 {
		ipAndPortChan := make(chan Addr, common.PortScanThreadNum)
		go func() {
			for _, target := range common.HostAndPortList {
				s := strings.Split(target, ":")
				ip := s[0]
				port := s[1]
				portInt, _ := strconv.Atoi(port)
				common.LogWG.Add(1)
				ipAndPortChan <- Addr{ip, portInt}
			}
			close(ipAndPortChan)
		}()
		PortScanTaskWithStd(ipAndPortChan)
		common.PoolScan.StopAndWait()
	}

	gonmap.Clear()
	runtime.GC() //回收gonmap对象等

	if len(alivePortResList) == 0 {
		goto ScanUrl
	}

ScanUrl:
	// 3.对于url目标，直接web扫描
	for _, url := range common.Urls {
		targetInfo := common.HostInfo{
			Host:    inputInfo.Host,
			Ports:   inputInfo.Ports,
			Url:     url,
			PocName: inputInfo.PocName,
		}
		CallScanTaskByProtocolAsync("http", &targetInfo, &wg)
	}

	wg.Wait()

	//统计和打印存活的端口
	alivePortPrint := "[+] alive ports(%d): "
	count := 0
	common.AlivePortsMap.Range(func(key, value interface{}) bool {
		alivePort := key.(string)
		alivePortPrint += alivePort
		alivePortPrint += ","
		count++
		return true
	})
	alivePortPrint = fmt.Sprintf(alivePortPrint, count)
	alivePortPrint = strings.TrimRight(alivePortPrint, ",")
	common.LogSuccess(alivePortPrint)
	fmt.Printf("\n[*] ok: 1/1\n")

	return
}

func CallScanTaskByPortAsync(scantype string, info *common.HostInfo, wg *sync.WaitGroup) {
	wg.Add(1)
	common.PluginTaskRateCtrlCh <- struct{}{}
	common.PoolScan.Submit(func() {
		defer func() {
			//Mutex.Lock()
			//common.End += 1
			//Mutex.Unlock()
			wg.Done()
			<-common.PluginTaskRateCtrlCh
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] Goroutine CallScanTaskByPortAsync panic: %v\n", r)
			}
		}()
		ScanFunc(&scantype, info)
	})
}

// 根据协议调用插件
func CallScanTaskByProtocolAsync(protocol string, info *common.HostInfo, wg *sync.WaitGroup) {
	wg.Add(1)
	common.PluginTaskRateCtrlCh <- struct{}{}
	common.PoolScan.Submit(func() {
		defer func() {
			wg.Done()
			<-common.PluginTaskRateCtrlCh
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] Goroutine CallScanTaskByProtocolAsync panic: %v\n", r)
				debug.PrintStack()
			}
		}()
		f := reflect.ValueOf(PluginListByProto[protocol])
		in := []reflect.Value{reflect.ValueOf(info)}
		f.Call(in)
	})

}

func CallScanTaskWithStd(scantype string, info *common.HostInfo) {
	defer func() {
		if r := recover(); r != nil {
			//debug.PrintStack()
		}
	}()
	ScanFunc(&scantype, info) //同步调用
}

func ScanFunc(name *string, info *common.HostInfo) {
	defer func() {
		if err := recover(); err != nil {
			fmt.Printf("[-] %v:%v scan error: %v\n", info.Host, info.Ports, err)
		}
	}()
	f := reflect.ValueOf(PluginList[*name])
	in := []reflect.Value{reflect.ValueOf(info)}
	f.Call(in)
}

func IsContain(items []string, item string) bool {
	for _, eachItem := range items {
		if eachItem == item {
			return true
		}
	}
	return false
}
