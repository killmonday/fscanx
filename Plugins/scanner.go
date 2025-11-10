package Plugins

import (
	"bufio"
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"github.com/xxx/wscan/PocScan/lib"
	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/gonmap"
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
		for _, ip := range ipNeedProbe {
			// 依次扫描指定端口
			for _, port := range probePortList {
				swg.Add()
				//go func(ip string, port string) {
				//	defer func() {
				//		swg.Done()
				//		if r := recover(); r != nil {
				//			//panicValue := r
				//			//stack := debug.Stack() // []byte，包含堆栈信息
				//			//file, err := os.OpenFile("panic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				//			//if err != nil {
				//			//	// 如果连日志文件都无法打开，打印到 stderr
				//			//	fmt.Fprintf(os.Stderr, "无法打开 panic 日志文件: %v\n", err)
				//			//	fmt.Fprintf(os.Stderr, "Panic: %v\n", panicValue)
				//			//	fmt.Fprintf(os.Stderr, "Stack Trace:\n%s\n", stack)
				//			//	return
				//			//}
				//			//defer file.Close()
				//			//errorMsg := fmt.Sprintf("[PANIC] Recovered from: %v\nStack Trace:\n%s\n", panicValue, string(stack))
				//			//if _, err := file.WriteString(errorMsg); err != nil {
				//			//	fmt.Fprintf(os.Stderr, "无法写入 panic 日志: %v\n", err)
				//			//}
				//		}
				//	}()
				//	addrStr := fmt.Sprintf("%s:%s", ip, port)
				//	conn, err := common.WrapperTcpWithTimeout("tcp4", addrStr, 3*time.Second)
				//	if conn != nil {
				//		conn.Close()
				//	}
				//	if err == nil {
				//		index := strings.LastIndex(ip, ".")
				//		if index != -1 {
				//			ipc := ip[:index]
				//			num, ok := AliveIpCPrefix.Load(ipc)
				//			if ok {
				//				AliveIpCPrefix.Store(ipc, num.(uint16)+1)
				//			} else {
				//				AliveIpCPrefix.Store(ipc, uint16(1))
				//			}
				//		}
				//		if common.Silent == false {
				//			common.LogSuccess("(tcp) Target %-15s is alive", ip)
				//		}
				//	}
				//}(ip, port)

				ip := ip
				port := port
				common.PoolScan.Submit(func() {
					defer func() {
						swg.Done()
						if r := recover(); r != nil {
							//panicValue := r
							//stack := debug.Stack() // []byte，包含堆栈信息
							//file, err := os.OpenFile("panic.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
							//if err != nil {
							//	// 如果连日志文件都无法打开，打印到 stderr
							//	fmt.Fprintf(os.Stderr, "无法打开 panic 日志文件: %v\n", err)
							//	fmt.Fprintf(os.Stderr, "Panic: %v\n", panicValue)
							//	fmt.Fprintf(os.Stderr, "Stack Trace:\n%s\n", stack)
							//	return
							//}
							//defer file.Close()
							//errorMsg := fmt.Sprintf("[PANIC] Recovered from: %v\nStack Trace:\n%s\n", panicValue, string(stack))
							//if _, err := file.WriteString(errorMsg); err != nil {
							//	fmt.Fprintf(os.Stderr, "无法写入 panic 日志: %v\n", err)
							//}
						}
					}()
					addrStr := fmt.Sprintf("%s:%s", ip, port)
					conn, err := common.WrapperTcpWithTimeout("tcp4", addrStr, 3*time.Second)
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
							}
						}
						if common.Silent == false {
							common.LogSuccess("(tcp) Target %-15s is alive", ip)
						}
					}
				})

			}
		}
		swg.Wait()
	}
	if doIcmp {
		IcmpTaskWorker(ipNeedProbe, common.UsePingExe)
	}

	aliveCNets := CountAliveIPCidrWithGlobal()
	common.LogSuccess("[*] Auto pre scan done!\n[*] start scan all alive c net...\n############################################")
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
	web := strconv.Itoa(common.PluginPortMap["web"])         //只是个标志 1000003
	ms17010 := strconv.Itoa(common.PluginPortMap["ms17010"]) //只是个标志 1000001
	nowStr := time.Now().Format("2006-01-02 15:04:05")
	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: %s", nowStr, strings.Join(os.Args[1:], " "), inputInfo.Host))
	fmt.Println("start infoscan")
	lib.Inithttp()

	// 0.A段/B段 智能存活扫描
	if common.AutoScanBigCidr {
		aliveIpCNets := AutoScanBigCidr(inputInfo) //存活的c段列表
		if aliveIpCNets == nil {
			goto ScanIpContainPort
		}
		inputInfo.Host = strings.Join(aliveIpCNets, ",")
		common.LogSuccess("[*] 存活C段所有IP做icmp扫描，C段总数：%d", len(aliveIpCNets))
		if common.NoPing == false {
			//如果下面还需要ping扫描，清空
			common.BloomFilter = common.BloomFilter.ClearAll()
		} else {
			common.BloomFilter = nil
		}
	}
	runtime.GC()

	// 1.1 icmp扫描+端口探测和协议识别
	if common.NoPing == false {
		////解析输入目标。icmp的监听扫描方式需要记录扫描过的ip来确认哪些属于目标，否则会打印出目标范围外的其他ip。所以这里只能解析所有ip并传入进去，另外
		//targetList, err := common.ParseIP(inputInfo.Host, common.HostFile)
		//if len(targetList) == 0 {
		//	goto ScanIpContainPort
		//}
		//if err != nil {
		//	fmt.Println("[-] parse ip error:", err)
		//	return
		//}
		//aliveIPList := IcmpTaskWorker(targetList, common.UsePingExe) //阻塞
		//common.LogSuccess("[*] 存活C段的icmp扫描结束，统计如下")
		//CountAliveIPCidrWithGlobal()
		//common.LogSuccess("[*] Icmp alive hosts len is: %d\n############################################\n[*] 端口扫描", len(aliveIPList))
		//if common.Scantype == "icmp" {
		//	common.LogWG.Wait()
		//	return
		//}
		//
		//// 做nmap扫描/端口存活/poc扫描。PortScanBatchTask里具体做哪一种扫描取决于 -nmap、-poc选项是否设置
		//alivePortResList = PortScanBatchTask(aliveIPList, common.PortsInput, common.TcpTimeout)
		//common.LogSuccess("\n[*] alive ports len is: %d\n", len(alivePortResList)) // 这是存活的总ip:port数，其实就是存活资产总数
		//if common.Scantype == "portscan" {
		//	common.LogWG.Wait()
		//	return
		//}

		///////////////////// 测试新 icmp+portscan
		// 解析输入目标。icmp的监听扫描方式需要记录扫描过的ip来确认哪些属于目标，否则会打印出目标范围外的其他ip。所以这里只能解析所有ip并传入进去，另外

		targetInputCh, err := common.ParseIPsByChanMaster(inputInfo.Host)
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
		IcmpTaskWorkerByChan(targetInputCh, aliveIpChan, common.UsePingExe) //阻塞
		icmpWg.Wait()

		if len(aliveIPList) == 0 {
			goto ScanIpContainPort
		}

		common.LogSuccess("[*] 存活C段的icmp扫描结束，统计如下")
		CountAliveIPCidrWithGlobal()
		common.LogSuccess("[*] Icmp alive hosts len is: %d\n############################################\n[*] 端口扫描", len(aliveIPList))
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
		alivePortResList = PortScanBatchTask(aliveIPList, common.PortsInput, common.TcpTimeout)
		common.LogSuccess("\n[*] alive ports len is: %d\n", len(alivePortResList)) // 这是存活的总ip:port数，其实就是存活资产总数
		if common.Scantype == "portscan" {
			common.LogWG.Wait()
			return
		}

	} else {
		// 1.2 跳过icmp扫描，直接做端口探测和协议识别
		needProbePorts := common.ParsePort(common.PortsInput)
		finalResChan := make(chan *PortScanRes, common.PortScanThreadNum)
		portscanWg := sync.WaitGroup{}
		if common.UseNmap {
			gonmap.SetFilter(9)
		}
		// 从通道获取gonmap端口探测结果
		go func() {
			portscanWg.Add(1)
			for portScanRes := range finalResChan {
				alivePortResList = append(alivePortResList, portScanRes)
			}
			portscanWg.Done()
		}()

		for _, p := range needProbePorts {
			// 依次探测每个端口
			targetInputCh, err := common.ParseIPsByChanMaster(inputInfo.Host)
			if err != nil {
				fmt.Println("parse ip err:", err)
				return
			}
			PortScanBatchTaskByChan(targetInputCh, p, common.TcpTimeout, finalResChan)
		}
		portscanWg.Wait()

		// 解析-hf输入的文件，此处需要解析是因为ParseIPByChan里不再解析输入文件
		if common.HostFile != "" {
			// 输入是文件类型，从文件读取目标
			var ipListFromFile []string
			ipListFromFile, _ = common.ReadInputFile(common.HostFile)
			alivePortResList = PortScanBatchTask(ipListFromFile, common.PortsInput, common.TcpTimeout)
			common.LogSuccess("\n[*] alive ports len is: %d\n", len(alivePortResList)) // 这是存活的总ip:port数，其实就是存活资产总数
		}
	}

ScanIpContainPort:
	// 2.1 扫描 ip:port 输入，做端口协议识别和特定插件扫描
	if len(common.HostAndPortList) != 0 {
		fmt.Println("[debug] HostAndPortList len:", len(common.HostAndPortList))
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

	if len(alivePortResList) == 0 {
		goto ScanUrl
	}

	// 2.2 对于之前探测的纯ip/ip段目标资产，其中开放了端口且特定协议/特定端口的，使用插件进一步扫描
	common.LogSuccess("############################################\n[*] 深度扫描")
	common.LogSuccess("============================================")
	runtime.GC() //回收gonmap对象等

	// 端口探测、协议识别结束后，从探测结果列表alivePortInfoSlice中获取 ip、port、识别出的协议，然后进一步对端口上的应用服务进行识别、提取更多有用信息，如http、smb、rdp等
	for _, targetInfoOfAlive := range alivePortResList {
		targetInfo := common.HostInfo{
			Host:    targetInfoOfAlive.ip,
			Ports:   targetInfoOfAlive.port,
			PocName: inputInfo.PocName,
		}
		protocol := targetInfoOfAlive.protocol
		if protocol == "" {
			protocol = "unkown"
		}
		_, exist := common.AlivePortsMap.Load(targetInfoOfAlive.port)
		if exist != true {
			common.AlivePortsMap.Store(targetInfoOfAlive.port, true)
		}
		// 遍历当前目标的端口是否是插件相关的端口
		switch {
		case targetInfo.Ports == "135":
			CallScanTaskByPort(targetInfo.Ports, &targetInfo, &wg) //findnet
			if common.IsWmi {
				CallScanTaskByPort("1000005", &inputInfo, &wg) //wmiexec
			}
		case targetInfo.Ports == "389":
			res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", protocol, targetInfo.Host, targetInfo.Ports, "[+]DC")
			common.LogSuccess(res)
		case targetInfo.Ports == "445":
			CallScanTaskByPort(targetInfo.Ports, &targetInfo, &wg) // smb信息探测
			CallScanTaskByPort(ms17010, &targetInfo, &wg)          // ms17010漏洞检测
			CallScanTaskByPort("1000002", &targetInfo, &wg)        // smbghost漏洞检测
		case targetInfo.Ports == "9000":
			CallScanTaskByPort(targetInfo.Ports, &targetInfo, &wg) // fcgiscan漏洞检测
		case IsContain(common.PortsHasPlugin, targetInfo.Ports):
			// 如果要探测的目标端口在本程序中有专用的探测方法，则使用专用探测方法(如445、21、3389、135等)。否则走入default使用http尝试探测
			CallScanTaskByPort(targetInfo.Ports, &targetInfo, &wg) // plugins scan
			fallthrough                                            // 继续执行下一个分支
		default:
			// 如果使用了 -nmap选项， 则端口探测后会识别到协议，可根据协议来启用对应插件进行深度利用
			if common.UseNmap {
				if PluginListByProto[protocol] != nil {
					CallScanTaskByProtocol(protocol, &targetInfo, &wg)
				} else {
					// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
					CallScanTaskByProtocol("http", &targetInfo, &wg) // plugins scan
				}
			} else {
				// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
				CallScanTaskByPort(web, &targetInfo, &wg)
			}
		} // switch end
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
		CallScanTaskByProtocol("http", &targetInfo, &wg)
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

func CallScanTaskByPort(scantype string, info *common.HostInfo, wg *sync.WaitGroup) {
	common.PluginTaskRateCtrlCh <- struct{}{}
	wg.Add(1)
	//go func() {
	//	defer func() {
	//		//Mutex.Lock()
	//		//common.End += 1
	//		//Mutex.Unlock()
	//		wg.Done()
	//		<-common.PluginTaskRateCtrlCh
	//		if r := recover(); r != nil {
	//			fmt.Printf("[ERROR] Goroutine CallScanTaskByPort panic: %v\n", r)
	//		}
	//	}()
	//	ScanFunc(&scantype, info)
	//}()

	common.PoolScan.Submit(func() {
		defer func() {
			//Mutex.Lock()
			//common.End += 1
			//Mutex.Unlock()
			wg.Done()
			<-common.PluginTaskRateCtrlCh
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] Goroutine CallScanTaskByPort panic: %v\n", r)
			}
		}()
		ScanFunc(&scantype, info)
	})

}

// 根据协议调用插件
func CallScanTaskByProtocol(protocol string, info *common.HostInfo, wg *sync.WaitGroup) {
	common.PluginTaskRateCtrlCh <- struct{}{}
	wg.Add(1)
	//go func() {
	//	defer func() {
	//		wg.Done()
	//		<-common.PluginTaskRateCtrlCh
	//		if r := recover(); r != nil {
	//			fmt.Printf("[ERROR] Goroutine CallScanTaskByProtocol panic: %v\n", r)
	//			debug.PrintStack()
	//		}
	//	}()
	//	f := reflect.ValueOf(PluginListByProto[protocol])
	//	in := []reflect.Value{reflect.ValueOf(info)}
	//	f.Call(in)
	//}()

	common.PoolScan.Submit(func() {
		defer func() {
			wg.Done()
			<-common.PluginTaskRateCtrlCh
			if r := recover(); r != nil {
				fmt.Printf("[ERROR] Goroutine CallScanTaskByProtocol panic: %v\n", r)
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
