package Plugins

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/killmonday/fscanx/common"
	"github.com/killmonday/fscanx/mylib/gonmap"
)

type Addr struct {
	ip   string
	port int
}

//func PortScanBatchTask(hostslist []string, ports string, timeout int64) []*PortScanRes {
//	var alivePortsInfoSlice []*PortScanRes
//	workers := common.PortScanThreadNum
//	Addrs := make(chan Addr, common.PortScanThreadNum)
//	alivePortResult := make(chan *PortScanRes, common.PortScanThreadNum)
//	var wg sync.WaitGroup
//
//	//获取待扫描的全部端口列表
//	needProbePorts := common.ParsePort(ports)
//	if len(needProbePorts) == 0 {
//		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
//		return alivePortsInfoSlice
//	}
//
//	// 处理探测的端口，从扫描的端口列表中 删除用户设置的禁止扫描的端口
//	notScanPorts := common.ParsePort(common.NotScanPorts)
//	if len(notScanPorts) > 0 {
//		temp := map[int]struct{}{}
//		for _, port := range needProbePorts {
//			temp[port] = struct{}{}
//		}
//
//		for _, port := range notScanPorts {
//			delete(temp, port)
//		}
//
//		var newDatas []int
//		for port := range temp {
//			newDatas = append(newDatas, port)
//		}
//		needProbePorts = newDatas
//		sort.Ints(needProbePorts)
//	}
//
//	// 接收探测结果的协程。从alivePortResult通道接收，添加到AlivePortsInfoSlice
//	go func() {
//		defer func() {
//			if r := recover(); r != nil {
//				//fmt.Println("[ERROR] Goroutine recv scan output panic: ", r)
//				//debug.PrintStack()
//			}
//		}()
//		for found := range alivePortResult {
//			alivePortsInfoSlice = append(alivePortsInfoSlice, found)
//			wg.Done()
//		}
//	}()
//
//	// 创建n个协程（消费者） 从Addrs通道接收ip和端口 进行端口扫描，识别开放状态和协议
//	for i := 0; i < workers; i++ {
//		go func() {
//			_addr := ""
//			defer func() {
//				if err := recover(); err != nil {
//					fmt.Printf("[-] scan %s error: %v\n", _addr, err)
//				}
//			}()
//			for addr := range Addrs {
//				_addr = addr.ip + ":" + strconv.Itoa(addr.port)
//				// 单个目标扫描
//				DoPortScan(addr, alivePortResult, timeout, &wg)
//				wg.Done()
//			}
//		}()
//	}
//
//	// 生产者，拼装ip和端口，发送到Addrs通道
//	for _, port := range needProbePorts {
//		for _, host := range hostslist {
//			wg.Add(1)
//			Addrs <- Addr{host, port}
//		}
//	}
//	wg.Wait()
//	close(Addrs)
//	close(alivePortResult)
//	return alivePortsInfoSlice
//}

func PortScanBatchTaskWithList(hostslist []string, ports string) {
	workers := common.PortScanThreadNum
	Addrs := make(chan Addr, common.PortScanThreadNum)
	var wg sync.WaitGroup

	//获取待扫描的 全部端口列表
	needProbePorts := common.ParsePort(ports)
	if len(needProbePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return
	}

	// 从端口列表删除用户设置的禁止扫描端口
	notScanPorts := common.ParsePort(common.NotScanPorts)
	if len(notScanPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range needProbePorts {
			temp[port] = struct{}{}
		}

		for _, port := range notScanPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port := range temp {
			newDatas = append(newDatas, port)
		}
		needProbePorts = newDatas
		sort.Ints(needProbePorts)
	}

	// 进行端口扫描。创建n个协程（消费者） 从Addrs通道接收ip和端口 ，然后调用DoPortScan 识别开放状态和协议
	for i := 0; i < workers; i++ {
		common.PoolScan.Submit(func() {
			_addr := ""
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("[-] scan %s error: %v\n", _addr, err)
				}
			}()
			for addr := range Addrs {
				// 单个目标扫描
				DoPortScan(addr.ip, addr.port, &wg)
				wg.Done()
			}
		})
	}

	// 生产者，拼装ip和端口，发送到Addrs通道
	for _, port := range needProbePorts {
		for _, host := range hostslist {
			wg.Add(1)
			Addrs <- Addr{host, port}
		}
	}
	wg.Wait()
	close(Addrs)
}

//func PortScanBatchTaskByChan(ipChan chan string, port int, timeout int64, returnCh chan *PortScanRes) {
//	workers := common.PortScanThreadNum
//	addrCh := make(chan Addr, common.PortScanThreadNum)
//	alivePortResult := make(chan *PortScanRes, common.PortScanThreadNum)
//	var wg sync.WaitGroup //记录addrCh和returnCh的使用
//
//	// 接收探测结果的协程。从alivePortResult通道接收，添加到AlivePortsInfoSlice
//	go func() {
//		defer func() {
//			if r := recover(); r != nil {
//				//fmt.Println("[ERROR] Goroutine recv scan output panic: ", r)
//				//debug.PrintStack()
//			}
//		}()
//		for found := range alivePortResult {
//			returnCh <- found
//			wg.Done()
//		}
//		close(returnCh)
//	}()
//
//	// 创建n个协程（消费者） 从Addrs通道接收ip和端口 进行端口扫描，识别开放状态和协议
//	for i := 0; i < workers; i++ {
//		go func() {
//			defer func() {
//				if err := recover(); err != nil {
//					fmt.Printf("[-] PortScanBatchTaskByChan error: %v\n", err)
//				}
//			}()
//			for addr := range addrCh {
//				// 单个目标扫描
//				DoPortScan(addr, alivePortResult, timeout, &wg) //阻塞调用
//				wg.Done()
//			}
//		}()
//	}
//
//	// 生产者，拼装ip和端口，发送到Addrs通道去做扫描
//	for host := range ipChan {
//		wg.Add(1)
//		addrCh <- Addr{host, port}
//	}
//	wg.Wait()
//	close(addrCh)
//	close(alivePortResult)
//}

func PortScanBatchTaskWithChan(ipWithPortChan chan string) {
	workers := common.PortScanThreadNum
	var wg sync.WaitGroup //记录addrCh和returnCh的使用

	// 创建n个协程（消费者） 从Addrs通道接收ip和端口 进行端口扫描，识别开放状态和协议
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer func() {
				wg.Done()
				if err := recover(); err != nil {
					fmt.Printf("[-] PortScanBatchTaskByChan error: %v\n", err)
				}
			}()
			for ipAndPort := range ipWithPortChan {
				// 单个目标扫描
				hostSlice := strings.Split(ipAndPort, ":")
				p, _ := strconv.Atoi(hostSlice[1])
				DoPortScan(hostSlice[0], p, &wg) //阻塞调用端口扫描。仅插件扫描部分为异步，依赖wg来同步
			}
		}()
	}

	wg.Wait()
}

func PortScanTaskWithStd(targetInput chan Addr) {
	for i := 0; i < common.PortScanThreadNum; i++ {
		// gopool开启n个工作协程
		common.PoolScan.Submit(func() {
			for addr := range targetInput {
				if strings.HasPrefix(addr.ip, "http") && addr.port == -1 {
					// url扫描
					WebScanSingle(&addr) //同步调用
				} else {
					PortProbeSingleOnStd(&addr) //同步调用
				}
			}
		})
	}
}

//func DoPortScan(addr Addr, alivePortResult chan<- *PortScanRes, adjustedTimeout int64, wg *sync.WaitGroup) {
//	// 调用gonmap进行端口探测。若未开启 -nmap，则只探测端口开放
//	defer func() {
//		if err := recover(); err != nil {
//			fmt.Printf("[-] DoPortScan error: %v\n", err)
//		}
//	}()
//
//	host, port := addr.ip, addr.port
//	if common.UseNmap {
//		nmap := gonmap.New()
//		status, response := nmap.ScanTimeout(host, port, common.NmapTotalTimeout, common.NmapSingleProbeTimeout)
//		res := &PortScanRes{
//			ip:       host,
//			port:     strconv.Itoa(port),
//			Response: response,
//		}
//		switch status {
//		case gonmap.Closed:
//			//fmt.Println("port ", port, "close")
//		case gonmap.Open:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			//alivePortResult <- address + "_unknow_"
//			alivePortResult <- res
//		case gonmap.NotMatched:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			alivePortResult <- res
//		case gonmap.Matched:
//			//fmt.Println("[debug] get cert info:", response.FingerPrint.Info)
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open %s", address, response.FingerPrint.Service)
//			common.LogSuccess(result)
//			wg.Add(1)
//			alivePortResult <- res
//		case gonmap.Unknown:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			alivePortResult <- res
//		}
//	} else {
//		conn, err := common.GetConn("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
//		if err == nil {
//			defer conn.Close()
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			res := &PortScanRes{
//				ip:   host,
//				port: strconv.Itoa(port),
//			}
//			alivePortResult <- res
//		}
//	}
//
//}

//func DoPortScan(addr Addr, alivePortResult chan<- *PortScanRes, adjustedTimeout int64, wg *sync.WaitGroup) {
//	fmt.Println("DoPortScan!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
//	// 如果使用了-nmap选项，调用gonmap进行端口探测。若未开启 -nmap，则只探测端口开放
//	defer func() {
//		if err := recover(); err != nil {
//			//fmt.Printf("[-] DoPortScan error: %v\n", err)
//			//debug.PrintStack()
//		}
//	}()
//
//	host, port := addr.ip, addr.port
//	if common.UseNmap {
//		nmap := gonmap.New()
//		status, response := nmap.ScanTimeout(host, port, common.NmapTotalTimeout, common.NmapSingleProbeTimeout)
//		res := &PortScanRes{
//			ip:       host,
//			port:     strconv.Itoa(port),
//			protocol: "",
//		}
//		switch status {
//		case gonmap.Closed:
//			//fmt.Println("port ", port, "close")
//		case gonmap.Open:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			//alivePortResult <- address + "_unknow_"
//			alivePortResult <- res
//		case gonmap.NotMatched:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			alivePortResult <- res
//		case gonmap.Matched:
//			//fmt.Println("[debug] get cert info:", response.FingerPrint.Info)
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open %s", address, response.FingerPrint.Service)
//			common.LogSuccess(result)
//			res.protocol = response.FingerPrint.Service
//			wg.Add(1)
//			alivePortResult <- res
//		case gonmap.Unknown:
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			wg.Add(1)
//			alivePortResult <- res
//		}
//	} else {
//		// 未开启-nmap选项，这里直接做端口存活探测，仅仅尝试tcp连接
//		conn, err := common.GetConn("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
//		if err == nil {
//			conn.(*net.TCPConn).SetLinger(0)
//			conn.Close()
//			address := host + ":" + strconv.Itoa(port)
//			result := fmt.Sprintf("%s open", address)
//			common.LogSuccess(result)
//			res := &PortScanRes{
//				ip:   host,
//				port: strconv.Itoa(port),
//			}
//			wg.Add(1)
//			alivePortResult <- res
//		}
//	}
//
//}

func DoPortScan(ip string, port int, wg *sync.WaitGroup) {
	wg.Add(1)
	// 如果使用了-nmap选项，调用gonmap进行端口探测。若未开启 -nmap，则只探测端口开放
	defer func() {
		wg.Done()
		if err := recover(); err != nil {
			//fmt.Printf("[-] DoPortScan error: %v\n", err)
			//debug.PrintStack()
		}
	}()

	host := ip
	portStr := strconv.Itoa(port)
	isOpen := false
	var protocol string

	if common.UseNmap {
		nmap := gonmap.New()
		status, response := nmap.ScanTimeout(host, port, common.NmapTotalTimeout, common.NmapSingleProbeTimeout)
		switch status {
		case gonmap.Closed:
			//fmt.Println("port ", port, "close")
		case gonmap.Open:
			if common.IsValidSocks5 == true {
				isOpen = true
				protocol = "tcp"
			}
		case gonmap.NotMatched:
			isOpen = true
			protocol = "tcp"
		case gonmap.Matched:
			//fmt.Println("[debug] gonamp recv:", host, port, response.FingerPrint.Service)
			isOpen = true
			protocol = response.FingerPrint.Service
		case gonmap.Unknown:
			isOpen = true
			protocol = "tcp"
		}
	} else {
		// 未开启-nmap选项，这里直接做端口存活探测，仅仅尝试tcp连接
		conn, err := common.GetConn("tcp4", fmt.Sprintf("%s:%s", host, portStr), common.NmapSingleProbeTimeout)
		if err == nil || conn != nil {
			if conn != nil {
				// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
				if _, ok := conn.(*net.TCPConn); ok {
					err = conn.(*net.TCPConn).SetLinger(0)
					if err != nil {
						//fmt.Println("set socket delay close fail:", err)
					}
				}
				conn.Close()
			}
			isOpen = true
		}
	}

	if isOpen {
		common.LogSuccess("[*] Port open\t%s:%s\t%s\n", ip, portStr, protocol)
		_, exist := common.AlivePortsMap.Load(portStr)
		if exist != true {
			common.AlivePortsMap.Store(portStr, true)
		}
		targetInfo := common.HostInfo{Host: host, Ports: portStr}
		switch {
		case portStr == "135":
			CallScanTaskByPortAsync(portStr, &targetInfo, wg) //findnet
			if common.IsWmi {
				CallScanTaskByPortAsync("1000005", &targetInfo, wg) //wmiexec
			}
		case portStr == "389":
			res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", protocol, targetInfo.Host, targetInfo.Ports, "[+]DC")
			common.LogSuccess(res)
		case portStr == "445":
			CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, wg) // smb信息探测
			CallScanTaskByPortAsync("1000001", &targetInfo, wg)        // ms17010漏洞检测
			CallScanTaskByPortAsync("1000002", &targetInfo, wg)        // smbghost漏洞检测
		case portStr == "9000":
			CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, wg) // fcgiscan漏洞检测
		case IsContain(common.PortsHasPlugin, targetInfo.Ports):
			// 如果要探测的目标端口在本程序中有专用的探测方法，则使用专用探测方法(如445、21、3389、135等)。否则走入default使用http尝试探测
			CallScanTaskByPortAsync(targetInfo.Ports, &targetInfo, wg) // plugins scan
			//fallthrough                                           // 继续执行下一个分支
		default:
			// 如果使用了 -nmap选项， 则端口探测后会识别到协议，可根据协议来启用对应插件进行深度利用
			if common.UseNmap {
				if PluginListByProto[protocol] != nil {
					CallScanTaskByProtocolAsync(protocol, &targetInfo, wg)
				} else {
					// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
					CallScanTaskByProtocolAsync("http", &targetInfo, wg) // plugins scan
				}
			} else {
				// 这里是插件未覆盖的协议，那么只进行http扫描识别就行
				CallScanTaskByProtocolAsync("http", &targetInfo, wg) // plugins scan
			}
		} // switch end
	}

}

func WebScanSingle(addr *Addr) {
	defer func() {
		if err := recover(); err != nil {
			//debug.PrintStack()
			//os.Exit(-1)
		}
		defer common.LogWG.Done()
	}()
	web := "1000003"
	res := &common.HostInfo{}
	host, port := addr.ip, addr.port
	if strings.HasPrefix(host, "http") && port == -1 {
		// 此处说明传入的是域名，直接调用web扫描，然后返回
		res.Url = host //设置HostInfo的Url字段，后续的扫描函数会知道这是Url扫描
		res.Host = host
		CallScanTaskWithStd(web, res) //同步调用
		return
	}

}

func PortProbeSingleOnStd(addr *Addr) {
	defer func() {
		if err := recover(); err != nil {
			//debug.PrintStack()
			//os.Exit(-1)
		}
		defer common.LogWG.Done()
	}()
	res := &common.HostInfo{}
	host, port := addr.ip, addr.port
	res.Host = host
	res.Ports = strconv.Itoa(port)
	var nmapResp *gonmap.Response
	var protocol = "tcp"

	if common.UseNmap {
		nmap := gonmap.New()
		status, response := nmap.ScanTimeout(host, port, common.NmapTotalTimeout, common.NmapSingleProbeTimeout)
		nmapResp = response
		switch status {
		case gonmap.Closed:
			return
		case gonmap.Open:
			if common.IsValidSocks5 == true {
				return
			}
		case gonmap.NotMatched:
		case gonmap.Matched:
			if response != nil {
				protocol = response.FingerPrint.Service
			}
		case gonmap.Unknown:
		}
	} else {
		// 未开启-nmap选项，这里直接做端口存活探测，仅仅尝试tcp连接
		conn, err := common.GetConn("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(common.TcpTimeout)*time.Second)
		if conn != nil {
			defer conn.Close()
			// 设置套接字延迟关闭选项，当调用 conn.Close() 时，立即关闭连接，不等待任何未发送或未确认的数据
			if _, ok := conn.(*net.TCPConn); ok {
				err = conn.(*net.TCPConn).SetLinger(0)
				if err != nil {
					//fmt.Println("set socket delay close fail:", err)
				}
			}
		}
		if err != nil {
			return
		}
	}

	_, exist := common.AlivePortsMap.Load(res.Ports)
	if exist != true {
		common.AlivePortsMap.Store(res.Ports, true)
	}
	if nmapResp != nil && nmapResp.FingerPrint != nil {
		protocol = nmapResp.FingerPrint.Service

	}

	common.LogSuccess("[*] Port open\t%s:%s\t%s\n", res.Host, res.Ports, protocol)

	switch {
	case res.Ports == "135":
		CallScanTaskWithStd(res.Ports, res)
		if common.IsWmi {
			CallScanTaskWithStd("1000005", res)
		}
	case res.Ports == "389":
		res := fmt.Sprintf("[+] Product %s://%s:%s\tbanner\t(%s)", "", res.Host, res.Ports, "[+]DC")
		common.LogSuccess(res)
	case res.Ports == "445":
		CallScanTaskWithStd(res.Ports, res) // smb信息探测
		CallScanTaskWithStd("1000001", res) // ms17010漏洞检测
		CallScanTaskWithStd("1000002", res) // smbghost漏洞检测
	case res.Ports == "9000":
		CallScanTaskWithStd(res.Ports, res)
	case IsContain(common.PortsArrayHasPlugin, res.Ports):
		CallScanTaskWithStd(res.Ports, res)
		//fallthrough
	default:
		wg := sync.WaitGroup{}
		if PluginListByProto[protocol] != nil {
			CallScanTaskByProtocolAsync(protocol, res, &wg)
		} else {
			CallScanTaskByProtocolAsync("http", res, &wg)
		}
		wg.Wait()
	}

}

func ParseDisallowPort(hostslist []string, ports string) (AliveAddress []*PortScanRes) {
	probePorts := common.ParsePort(ports)
	noPorts := common.ParsePort(common.NotScanPorts)
	if len(noPorts) > 0 {
		temp := map[int]struct{}{}
		for _, port := range probePorts {
			temp[port] = struct{}{}
		}

		for _, port := range noPorts {
			delete(temp, port)
		}

		var newDatas []int
		for port, _ := range temp {
			newDatas = append(newDatas, port)
		}
		probePorts = newDatas
		sort.Ints(probePorts)
	}
	for _, port := range probePorts {
		for _, host := range hostslist {
			//address := host + ":" + strconv.Itoa(port)
			AliveAddress = append(AliveAddress, &PortScanRes{
				ip:   host,
				port: strconv.Itoa(port),
			})
		}
	}
	return
}
