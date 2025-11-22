package Plugins

import (
	"testing"
)

func TestScanByChan(t *testing.T) {
	//if common.AutoScanBigCidr {
	//	lib.Inithttp()
	//	fmt.Println("inputInfo.ports=", common.PortsInput)
	//	aliveIpCNets := AutoScanBigCidr(inputInfo)
	//	fmt.Println("AutoScanBigCidr函数返回后！")
	//
	//	inputInfo.Host = strings.Join(aliveIpCNets, ",")
	//	fmt.Println("存活c段个数：", len(aliveIpCNets))
	//
	//	//测试icmp
	//	inputCh, err := common.ParseIPsByChanMaster(inputInfo.Host)
	//	fmt.Println(err)
	//	aliveCh := make(chan string, common.PortScanThreadNum)
	//	go IcmpTaskWorkerByChan(inputCh, aliveCh, false)
	//
	//	//端口扫描
	//	needProbePorts := common.ParsePort(common.PortsInput)
	//	fmt.Println("探测端口组合：", needProbePorts)
	//	finalResChan := make(chan *PortScanRes, common.PortScanThreadNum)
	//	var wg2 = sync.WaitGroup{}
	//	go func() {
	//		defer func() {
	//			if r := recover(); r != nil {
	//				debug.PrintStack()
	//			}
	//		}()
	//		for portInfoOfAlive := range finalResChan {
	//			targetInfo := common.HostInfo{
	//				Host:  portInfoOfAlive.ip,
	//				Ports: portInfoOfAlive.port,
	//			}
	//			CallScanTaskByProtocolAsync("http", &targetInfo, &wg2)
	//
	//			fmt.Println(portInfoOfAlive.ip, portInfoOfAlive.port, portInfoOfAlive.protocol)
	//		}
	//	}()
	//	for _, p := range needProbePorts {
	//		targetInputCh, err := common.ParseIPsByChanMaster(inputInfo.Host)
	//		fmt.Println(err)
	//		PortScanBatchTaskByChan(targetInputCh, p, common.TcpTimeout, finalResChan)
	//	}
	//	close(finalResChan)
	//
	//	fmt.Println("test done!")
	//
	//	os.Exit(-1)
	//}
}

//func ScanOld(inputInfo common.HostInfo) {
//	defer func() {
//		if r := recover(); r != nil {
//			fmt.Printf("[ERROR] Goroutine Scan panic: %v\n", r)
//			debug.PrintStack()
//		}
//	}()
//	nowStr := time.Now().Format("2006-01-02 15:04:05")
//	common.LogSuccess(fmt.Sprintf("===================new task===================\n%s\nargs: %s\ntarget: %s", nowStr, strings.Join(os.Args[1:], " "), inputInfo.Host))
//
//	fmt.Println("start infoscan")
//
//	ipLists, err := common.ParseIP(inputInfo.Host, common.HostFile, common.NoHosts)
//	if err != nil {
//		return
//	}
//
//	fmt.Println("ParseIP后！")
//	fmt.Println("共需探测ip数量：", len(ipLists))
//
//	time.Sleep(5 * time.Second)
//
//	var wg = sync.WaitGroup{}
//	web := strconv.Itoa(common.PluginPortMap["web"])
//	ms17010 := strconv.Itoa(common.PluginPortMap["ms17010"])
//	//校验输入是否解析正确，然后进入扫描，有ping扫描、web扫描、poc扫描、全部等类型
//	if len(ipLists) > 0 || len(common.HostAndPortList) > 0 {
//		if common.NoPing == false && len(ipLists) > 1 || common.Scantype == "icmp" {
//			// 开始icmp扫描，获取存活ip
//			ipLists = IcmpTaskWorker(ipLists, common.UsePingExe)
//			CountAliveIPCidrWithGlobal()
//			fmt.Println("[*] Icmp alive hosts len is:", len(ipLists))
//		}
//		if common.Scantype == "icmp" {
//			//仅icmp扫描，等待所有结果打印结束就退出
//			common.LogWG.Wait()
//			return
//		}
//		var alivePortInfoSlice []*PortScanRes
//		if common.Scantype == "webonly" || common.Scantype == "webpoc" {
//			alivePortInfoSlice = ParseDisallowPort(ipLists, common.PortsInput)
//		} else if common.Scantype == "hostname" {
//			common.PortsInput = "139"
//			alivePortInfoSlice = ParseDisallowPort(ipLists, common.PortsInput)
//		} else if len(ipLists) > 0 {
//			// 做nmap扫描/端口存活/poc扫描。PortScanBatchTask里具体做哪一种扫描取决于 -nmap、-poc选项是否设置
//			alivePortInfoSlice = PortScanBatchTask(ipLists, common.PortsInput, common.TcpTimeout)
//			fmt.Println("[*] alive ports len is:", len(alivePortInfoSlice)) // 这是存活的总ip:port数，其实就是存活资产总数
//			gonmap.Clear()
//			if common.Scantype == "portscan" {
//				common.LogWG.Wait()
//				return
//			}
//		}
//
//		if len(common.HostAndPortList) > 0 {
//			//TODO: <ip:port> input format in input file with -hf
//		}
//
//		var portsHasProMethod []string // 有特殊插件的端口列表 []string{"21","22","135"."445","1433","3306","5432","6379","9200","11211","27017"...}
//		for _, port := range common.PluginPortMap {
//			portsHasProMethod = append(portsHasProMethod, strconv.Itoa(port))
//		}
//		// 针对开放且识别出协议的目标端口，进行进一步的扫描
//		fmt.Println("start vulscan")
//		fmt.Println("===============================")
//		runtime.GC() //回收gonmap对象
//
//		// 端口探测、协议识别结束后，从探测结果列表alivePortInfoSlice中获取 ip、port、识别出的协议，然后进一步对端口上的应用服务进行识别、提取更多有用信息，如http、smb、rdp等
//		for _, portInfoOfAlive := range alivePortInfoSlice {
//			targetInfo := common.HostInfo{
//				Host:    portInfoOfAlive.ip,
//				Ports:   portInfoOfAlive.port,
//				PocName: inputInfo.PocName,
//			}
//			protocol := portInfoOfAlive.protocol
//			if protocol == "" {
//				protocol = "unkown"
//			}
//			_, exist := common.AlivePortsMap.Load(portInfoOfAlive.port)
//			if exist != true {
//				common.AlivePortsMap.Store(portInfoOfAlive.port, true)
//			}
//			// 遍历当前目标的端口是否是插件相关的端口
//			switch {
//			case targetInfo.Ports == "135":
//				CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, &wg) //findnet
//				if common.IsWmi {
//					CallScanTaskByPortAsync("1000005", &inputInfo, &wg) //wmiexec
//				}
//			case targetInfo.Ports == "389":
//				res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", protocol, targetInfo.Host, targetInfo.Ports, "[+]DC")
//				common.LogSuccess(res)
//			case targetInfo.Ports == "445":
//				CallScanTaskByPortAsync(ms17010, &targetInfo, &wg)          // ms17010
//				CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, &wg) // smb
//				CallScanTaskByPortAsync("1000002", &targetInfo, &wg)        // smbghost
//			case targetInfo.Ports == "9000":
//				CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, &wg) // fcgiscan
//			case IsContain(portsHasProMethod, targetInfo.Ports):
//				// 如果要探测的目标端口在本程序中有专用的探测方法，则使用专用探测方法(如445、21、3389、135等)。否则走入default使用http尝试探测
//				CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, &wg) // plugins scan
//				fallthrough                                            // 继续执行下一个分支
//			default:
//				// 如果使用了 -nmap选项， 则端口探测后会识别到协议，可根据协议来启用对应插件进行深度利用
//				if common.UseNmap {
//					if PluginListByProto[protocol] != nil {
//						CallScanTaskByProtocolAsync(protocol, &targetInfo, &wg)
//					} else {
//						// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
//						CallScanTaskByPortAsync(web, &targetInfo, &wg) // plugins scan
//					}
//				} else {
//					// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
//					CallScanTaskByPortAsync(web, &targetInfo, &wg) //webtitle
//				}
//
//			} // switch end
//		}
//	}
//	//扫描纯url
//	for _, url := range common.Urls {
//		targetInfo := common.HostInfo{
//			Host:    inputInfo.Host,
//			Ports:   inputInfo.Ports,
//			Url:     url,
//			PocName: inputInfo.PocName,
//		}
//		CallScanTaskByProtocolAsync("http", &targetInfo, &wg)
//	}
//	wg.Wait()
//
//	//统计和打印存活的端口
//	alivePortPrint := "[+] alive ports(%d): "
//	count := 0
//	common.AlivePortsMap.Range(func(key, value interface{}) bool {
//		alivePort := key.(string)
//		alivePortPrint += alivePort
//		alivePortPrint += ","
//		count++
//		return true
//	})
//	alivePortPrint = fmt.Sprintf(alivePortPrint, count)
//	alivePortPrint = strings.TrimRight(alivePortPrint, ",")
//	common.LogSuccess(alivePortPrint)
//
//	common.LogWG.Wait()
//	close(common.Results)
//	fmt.Printf("\n[*] ok: 1/1\n") //fmt.Printf("\n[*] ok: %v/%v\n", common.End, common.Num)
//}
