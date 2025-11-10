package Plugins

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xxx/wscan/common"
	"github.com/xxx/wscan/mylib/gonmap"
)

type Addr struct {
	ip   string
	port int
}

func PortScanBatchTask(hostslist []string, ports string, timeout int64) []*PortScanRes {
	var alivePortsInfoSlice []*PortScanRes
	workers := common.PortScanThreadNum
	Addrs := make(chan Addr, common.PortScanThreadNum)
	alivePortResult := make(chan *PortScanRes, common.PortScanThreadNum)
	var wg sync.WaitGroup

	//获取待扫描的全部端口列表
	needProbePorts := common.ParsePort(ports)
	if len(needProbePorts) == 0 {
		fmt.Printf("[-] parse port %s error, please check your port format\n", ports)
		return alivePortsInfoSlice
	}

	// 处理探测的端口，从扫描的端口列表中 删除用户设置的禁止扫描的端口
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

	// 接收探测结果的协程。从alivePortResult通道接收，添加到AlivePortsInfoSlice
	go func() {
		defer func() {
			if r := recover(); r != nil {
				//fmt.Println("[ERROR] Goroutine recv scan output panic: ", r)
				//debug.PrintStack()
			}
		}()
		for found := range alivePortResult {
			alivePortsInfoSlice = append(alivePortsInfoSlice, found)
			wg.Done()
		}
	}()

	// 创建n个协程（消费者） 从Addrs通道接收ip和端口 进行端口扫描，识别开放状态和协议
	for i := 0; i < workers; i++ {
		go func() {
			_addr := ""
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("[-] scan %s error: %v\n", _addr, err)
				}
			}()
			for addr := range Addrs {
				_addr = addr.ip + ":" + strconv.Itoa(addr.port)
				// 单个目标扫描
				DoPortScan(addr, alivePortResult, timeout, &wg)
				wg.Done()
			}
		}()
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
	close(alivePortResult)
	return alivePortsInfoSlice
}

func PortScanBatchTaskByChan(ipChan chan string, port int, timeout int64, returnCh chan *PortScanRes) {
	workers := common.PortScanThreadNum
	addrCh := make(chan Addr, common.PortScanThreadNum)
	alivePortResult := make(chan *PortScanRes, common.PortScanThreadNum)
	var wg sync.WaitGroup //记录addrCh和returnCh的使用

	// 接收探测结果的协程。从alivePortResult通道接收，添加到AlivePortsInfoSlice
	go func() {
		defer func() {
			if r := recover(); r != nil {
				//fmt.Println("[ERROR] Goroutine recv scan output panic: ", r)
				//debug.PrintStack()
			}
		}()
		for found := range alivePortResult {
			returnCh <- found
			wg.Done()
		}
		close(returnCh)
	}()

	// 创建n个协程（消费者） 从Addrs通道接收ip和端口 进行端口扫描，识别开放状态和协议
	for i := 0; i < workers; i++ {
		go func() {
			defer func() {
				if err := recover(); err != nil {
					fmt.Printf("[-] PortScanBatchTaskByChan error: %v\n", err)
				}
			}()
			for addr := range addrCh {
				// 单个目标扫描
				DoPortScan(addr, alivePortResult, timeout, &wg) //阻塞调用
				wg.Done()
			}
		}()
	}

	// 生产者，拼装ip和端口，发送到Addrs通道去做扫描
	for host := range ipChan {
		wg.Add(1)
		addrCh <- Addr{host, port}
	}
	wg.Wait()
	close(addrCh)
	close(alivePortResult)
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
					PortProbeSingle(&addr) //同步调用
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
//		status, response := nmap.ScanTimeout(host, port, time.Second*time.Duration(common.TcpTimeout*4), time.Second*time.Duration(common.TcpTimeout))
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
//		conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
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

func DoPortScan(addr Addr, alivePortResult chan<- *PortScanRes, adjustedTimeout int64, wg *sync.WaitGroup) {
	// 如果使用了-nmap选项，调用gonmap进行端口探测。若未开启 -nmap，则只探测端口开放
	defer func() {
		if err := recover(); err != nil {
			//fmt.Printf("[-] DoPortScan error: %v\n", err)
			//debug.PrintStack()
		}
	}()

	host, port := addr.ip, addr.port
	if common.UseNmap {
		nmap := gonmap.New()
		status, response := nmap.ScanTimeout(host, port, time.Second*time.Duration(common.TcpTimeout*4), time.Second*time.Duration(common.TcpTimeout))
		res := &PortScanRes{
			ip:       host,
			port:     strconv.Itoa(port),
			protocol: "",
		}
		switch status {
		case gonmap.Closed:
			//fmt.Println("port ", port, "close")
		case gonmap.Open:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			//alivePortResult <- address + "_unknow_"
			alivePortResult <- res
		case gonmap.NotMatched:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			alivePortResult <- res
		case gonmap.Matched:
			//fmt.Println("[debug] get cert info:", response.FingerPrint.Info)
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open %s", address, response.FingerPrint.Service)
			common.LogSuccess(result)
			res.protocol = response.FingerPrint.Service
			wg.Add(1)
			alivePortResult <- res
		case gonmap.Unknown:
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			wg.Add(1)
			alivePortResult <- res
		}
	} else {
		// 未开启-nmap选项，这里直接做端口存活探测，仅仅尝试tcp连接
		conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(adjustedTimeout)*time.Second)
		if err == nil {
			conn.Close()
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
			res := &PortScanRes{
				ip:   host,
				port: strconv.Itoa(port),
			}
			wg.Add(1)
			alivePortResult <- res
		}
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

func PortProbeSingle(addr *Addr) {
	defer func() {
		if err := recover(); err != nil {
			//debug.PrintStack()
			//os.Exit(-1)
		}
		defer common.LogWG.Done()
	}()
	fmt.Sprintf("call PortProbeSingle ！！！")
	ms17010 := "1000001"
	res := &common.HostInfo{}
	host, port := addr.ip, addr.port
	res.Host = host
	res.Ports = strconv.Itoa(port)
	var nmapResp *gonmap.Response

	if common.UseNmap {
		nmap := gonmap.New()
		status, response := nmap.ScanTimeout(host, port, time.Second*time.Duration(common.TcpTimeout*4), time.Second*time.Duration(common.TcpTimeout))
		nmapResp = response
		switch status {
		case gonmap.Closed:
			//fmt.Println("port ", port, "close")
			return
		case gonmap.Open:
			address := host + ":" + res.Ports
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
		case gonmap.NotMatched:
			address := host + ":" + res.Ports
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
		case gonmap.Matched:
			//fmt.Println("[debug] get cert info:", response.FingerPrint.Info)
			protocol := ""
			if response != nil {
				protocol = response.FingerPrint.Service
			}
			result := fmt.Sprintf("%s:%s open %s", host, res.Ports, protocol)
			if strings.HasPrefix(protocol, "http") == false {
				common.LogSuccess(result)
			}

		case gonmap.Unknown:
			address := host + ":" + res.Ports
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
		}
	} else {
		// 未开启-nmap选项，这里直接做端口存活探测，仅仅尝试tcp连接
		conn, err := common.WrapperTcpWithTimeout("tcp4", fmt.Sprintf("%s:%v", host, port), time.Duration(common.TcpTimeout)*time.Second)
		if conn != nil {
			defer conn.Close()
		}
		if err != nil {
			return
		} else {
			address := host + ":" + strconv.Itoa(port)
			result := fmt.Sprintf("%s open", address)
			common.LogSuccess(result)
		}
	}

	protocol := ""
	if nmapResp != nil && nmapResp.FingerPrint != nil {
		_, exist := common.AlivePortsMap.Load(res.Ports)
		if exist != true {
			common.AlivePortsMap.Store(res.Ports, true)
		}

		if nmapResp != nil {
			protocol = nmapResp.FingerPrint.Service
			if protocol == "" {
				protocol = "unkown"
			}
		}
	}
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
		CallScanTaskWithStd(ms17010, res)
		CallScanTaskWithStd(res.Ports, res)
	case res.Ports == "9000":
		CallScanTaskWithStd(res.Ports, res)
	case IsContain(common.PortsArrayHasPlugin, res.Ports):
		CallScanTaskWithStd(res.Ports, res)
		fallthrough
	default:
		wg := sync.WaitGroup{}
		if PluginListByProto[protocol] != nil {
			CallScanTaskByProtocol(protocol, res, &wg)
			wg.Wait()
		} else {
			CallScanTaskByProtocol("http", res, &wg)
			wg.Wait()
		}
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
