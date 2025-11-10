package Plugins

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/remeh/sizedwaitgroup"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/xxx/wscan/common"
	"golang.org/x/net/icmp"
)

var (
	AliveIpVerified sync.Map //存储存活的ip
	AliveIpCPrefix  sync.Map //存储存活的ip c段前缀 （例如 x.x.x）
	InputAllIpMap   sync.Map //存储所有用户输入的被解析出的ip
	livewg          sync.WaitGroup
)

// 返回存活的所有ip
func IcmpTaskWorker(hostslist []string, Ping bool) []string {
	aliveHostChan := make(chan string, common.Bucket_limit)
	var aliveSave []string
	// 接收存活结果
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("[ERROR] Goroutine IcmpTaskWorker panic: ", r)
			}
		}()
		for ip := range aliveHostChan {
			if common.BloomFilter.TestString(ip) {
				if common.Silent == false {
					if Ping == false {
						fmt.Printf("(icmp) Target %-15s is alive\n", ip)
					} else {
						fmt.Printf("(ping) Target %-15s is alive\n", ip)
					}
				}
				aliveSave = append(aliveSave, ip)
			}
			livewg.Done()
		}
	}()

	// 三种类型的icmp扫描
	if Ping == true {
		//方式一 使用本地系统的ping命令进行探测
		IcmpCheckWithExePing(hostslist, aliveHostChan)
	} else {
		var local_ip string = "0.0.0.0"
		if common.Iface != "" {
			local_ip = common.Iface
		}
		//方式二 尝试监听icmp报文，收发双工探测，最高效
		conn, err := icmp.ListenPacket("ip4:icmp", local_ip)
		if err == nil {
			for _, ip := range hostslist {
				InputAllIpMap.Store(ip, struct{}{}) // 监听报文会收到很多额外的杂包，需要确认源地址属于我们探测的目标，而不是其他报文
			}
			// 可以监听icmp报文，开始发包
			IcmpCheckWithListen(hostslist, conn, aliveHostChan)
			InputAllIpMap = sync.Map{} //扫描结束，置空，不需要了
		} else {
			//尝试无监听icmp探测
			common.LogError(err)
			fmt.Println("trying IcmpCheckWithoutListen")
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", time.Duration(common.PingTimeout)*time.Second)
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			if err == nil {
				//方式三 net.DialIP发送ICMP包，通过每个conn对象的发送/接收到报文来探测
				IcmpCheckWithoutListen(hostslist, aliveHostChan)
			} else {
				common.LogError(err)
				//使用ping探测
				fmt.Println("The current user permissions unable to send icmp packets")
				fmt.Println("start ping")
				IcmpCheckWithExePing(hostslist, aliveHostChan)
			}
		}
	}

	livewg.Wait()
	close(aliveHostChan)
	return aliveSave
}

func IcmpTaskWorkerByChan(inputChan chan string, returnChan chan string, Ping bool) {
	aliveHostChan := make(chan string, common.Bucket_limit)
	// 接收存活结果
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Println("[ERROR] Goroutine IcmpTaskWorker panic: ", r)
			}
		}()
		for ip := range aliveHostChan {
			returnChan <- ip
			if common.Silent == false {
				if Ping == false {
					fmt.Printf("(icmp) Target %-15s is alive\n", ip)
				} else {
					fmt.Printf("(ping) Target %-15s is alive\n", ip)
				}
			}

			livewg.Done()
		}
		close(returnChan)
	}()

	// 三种类型的icmp扫描
	if Ping == true {
		//方式一 使用本地系统的ping命令进行探测
		IcmpCheckWithExePingByChan(inputChan, aliveHostChan)
	} else {
		var local_ip string = "0.0.0.0"
		if common.Iface != "" {
			local_ip = common.Iface
		}
		//方式二 尝试监听icmp报文，收发双工探测，最高效
		conn, err := icmp.ListenPacket("ip4:icmp", local_ip)
		if err == nil {
			// 可以监听icmp报文，开始发包
			fmt.Println("[debug] icmp准备发包")
			IcmpCheckWithListenByChan(inputChan, conn, aliveHostChan)
		} else {
			//尝试无监听icmp探测
			common.LogError(err)
			fmt.Println("trying IcmpCheckWithoutListen")
			conn, err := net.DialTimeout("ip4:icmp", "127.0.0.1", time.Duration(common.PingTimeout)*time.Second)
			defer func() {
				if conn != nil {
					conn.Close()
				}
			}()
			if err == nil {
				//方式三 net.DialIP发送ICMP包，通过每个conn对象的发送/接收到报文来探测
				IcmpCheckWithoutListenByChan(inputChan, aliveHostChan)
			} else {
				common.LogError(err)
				//使用ping探测
				fmt.Println("The current user permissions unable to send icmp packets")
				fmt.Println("start ping")
				IcmpCheckWithExePingByChan(inputChan, aliveHostChan)
			}
		}
	}

	livewg.Wait()
	close(aliveHostChan)
	return
}

func IcmpCheckWithListen(hostslist []string, conn *icmp.PacketConn, chanHosts chan string) {
	endReceive := make(chan struct{}, 1)
	msg := make([]byte, 100)
	receiveWg := sync.WaitGroup{}
	var netErr net.Error
	go func() {
		//持续从通道中获取新报文，回传存活的ip。直到end信号
		receiveWg.Add(1)
		defer receiveWg.Done()
		for {
			select {
			case <-endReceive:
				conn.Close()
				return
			default:
				err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if err != nil {
					return
				}
				_, srcAddr, err := conn.ReadFrom(msg)
				if errors.As(err, &netErr) && netErr.Timeout() {
					// 预期的超时，继续循环
					continue
				}

				if srcAddr != nil {
					if msg[0] != 0 || msg[1] != 0 {
						continue
					}
					ipStr := srcAddr.String()[:]
					if common.BloomFilter.TestString(ipStr) {
						index := strings.LastIndex(ipStr, ".")
						if index != -1 {
							ipc := ipStr[:index]
							num, ok := AliveIpCPrefix.Load(ipc)
							if ok {
								AliveIpCPrefix.Store(ipc, num.(uint16)+1)
							} else {
								AliveIpCPrefix.Store(ipc, uint16(1))
								livewg.Add(1)
								chanHosts <- ipStr
							}
						}

					}
				}
			}
		}
	}()
	swg := sizedwaitgroup.New(int(common.Bucket_limit))
	for _, host := range hostslist {
		common.BloomFilter.AddString(host)
		common.Limiter.Wait(1) // 阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
		swg.Add()
		go func(host string) {
			dst, _ := net.ResolveIPAddr("ip", host)
			IcmpByte := makemsg(host)
			conn.WriteTo(IcmpByte, dst)
			swg.Done()
		}(host)
	}

	swg.Wait()
	time.Sleep(time.Duration(common.PingTimeout) * time.Second) // 等待最后可能收到的icmp包
	close(endReceive)                                           // 此处只是保险，实际依赖conn的关闭才能终止icmp监听
	conn.Close()                                                // close conn会结束阻塞的读写部分，让goroutine得以释放
	receiveWg.Wait()                                            // 避免函数返回后，chanHosts被立刻关闭，先阻塞等待goroutine释放
}

func IcmpCheckWithListenByChan(ipChan chan string, conn *icmp.PacketConn, aliveChan chan string) {
	fmt.Println("[debug] call IcmpCheckWithListenByChan !!!!")
	endReceive := make(chan struct{}, 1)
	msg := make([]byte, 100)
	receiveWg := sync.WaitGroup{}
	var netErr net.Error
	go func() {
		//持续从icmp监听中 获取新报文，回传存活的ip。直到end信号
		receiveWg.Add(1)
		defer receiveWg.Done()
		defer fmt.Println("icmp监听退出！！！！！！！！！！")
		for {
			select {
			case <-endReceive:
				return
			default:
				err := conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				if err != nil {
					return
				}
				_, srcAddr, err := conn.ReadFrom(msg)
				if errors.As(err, &netErr) && netErr.Timeout() {
					// 预期的超时，继续循环
					continue
				}
				if srcAddr != nil {
					if msg[0] != 0 || msg[1] != 0 {
						continue
					}
					//fmt.Println("XXXXXXXXXXXXXXXXX ", srcAddr.String(), msg)

					ipStr := srcAddr.String()
					if common.BloomFilter.TestString(ipStr) {
						index := strings.LastIndex(ipStr, ".")
						if index != -1 {
							ipc := ipStr[:index]
							num, ok := AliveIpCPrefix.Load(ipc)
							if ok {
								AliveIpCPrefix.Store(ipc, num.(uint16)+1)
							} else {
								AliveIpCPrefix.Store(ipc, uint16(1))

							}
						}
						livewg.Add(1)
						aliveChan <- ipStr
					}
				}
			}
		}
	}()
	swg := sizedwaitgroup.New(int(common.Bucket_limit))
	fmt.Println("[debug] xxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	// 发送icmp探测包
	for host := range ipChan {
		common.BloomFilter.AddString(host)
		common.Limiter.Wait(1) // 阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
		swg.Add()
		go func(host string) {
			dst, _ := net.ResolveIPAddr("ip", host)
			IcmpByte := makemsg(host)
			conn.WriteTo(IcmpByte, dst)
			swg.Done()
		}(host)
	}

	swg.Wait()
	time.Sleep(time.Duration(common.PingTimeout) * time.Second) // 等待最后可能收到的icmp包
	close(endReceive)                                           // 此处只是保险，实际依赖conn的关闭才能终止icmp监听
	conn.Close()                                                // close conn会结束阻塞的读写部分，让goroutine得以释放
	receiveWg.Wait()                                            // 避免函数返回后，chanHosts被立刻关闭，先阻塞等待goroutine释放
}

func IcmpCheckWithoutListen(hostslist []string, chanHosts chan string) {
	//num := 1000
	//if len(hostslist) < num {
	//	num = len(hostslist)
	//}
	var wg sync.WaitGroup
	for _, host := range hostslist {
		common.BloomFilter.AddString(host)
		wg.Add(1)
		common.Limiter.Wait(1) // 阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
		go func(host string) {
			if sendIcmp(host) {
				index := strings.LastIndex(host, ".")
				if index != -1 {
					ipc := host[:index]
					num, ok := AliveIpCPrefix.Load(ipc)
					if ok {
						AliveIpCPrefix.Store(ipc, num.(uint16)+1)
					} else {
						AliveIpCPrefix.Store(ipc, uint16(1))
						livewg.Add(1)
						chanHosts <- host
					}
				}

			}
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func IcmpCheckWithoutListenByChan(ipChan chan string, aliveChan chan string) {
	var wg sync.WaitGroup
	for host := range ipChan {
		common.BloomFilter.AddString(host)
		wg.Add(1)
		common.Limiter.Wait(1) // 并发控制。阻塞等待令牌桶中至少存在1个令牌,若存在则消耗掉1个令牌
		go func(host string) {
			if sendIcmp(host) {
				index := strings.LastIndex(host, ".")
				if index != -1 {
					ipc := host[:index]
					num, ok := AliveIpCPrefix.Load(ipc)
					if ok {
						AliveIpCPrefix.Store(ipc, num.(uint16)+1)
					} else {
						AliveIpCPrefix.Store(ipc, uint16(1))
						livewg.Add(1)
						aliveChan <- host
					}
				}

			}
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func sendIcmp(host string) bool {
	startTime := time.Now()

	// 使用net.DialIP发送ICMP包，并设置本地地址
	local_ip := &net.IPAddr{
		IP: net.ParseIP("0.0.0.0"), // 替换为你要指定的本机IP地址
	}
	if common.Iface != "" {
		use_ip := net.ParseIP(common.Iface)
		if use_ip == nil {
			return false
		}
		local_ip = &net.IPAddr{
			IP: use_ip, // 替换为你要指定的本机IP地址
		}
	}
	target_ip := net.ParseIP(host)
	if target_ip == nil {
		return false
	}
	conn, err := net.DialIP("ip4:icmp", local_ip, &net.IPAddr{IP: target_ip})
	if err != nil {
		fmt.Println("DialIP error, check iface:", err)
		return false
	}

	defer conn.Close()
	if err := conn.SetDeadline(startTime.Add(time.Duration(common.PingTimeout) * time.Second)); err != nil {
		return false
	}
	msg := makemsg(host)
	if _, err := conn.Write(msg); err != nil {
		return false
	}

	receive := make([]byte, 60)
	if _, err := conn.Read(receive); err != nil {
		return false
	}

	return true
}

func IcmpCheckWithExePing(hostslist []string, aliveHostChan chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for _, host := range hostslist {
		wg.Add(1)
		common.BloomFilter.AddString(host)
		limiter <- struct{}{}
		go func(host string) {
			if ExecCommandPing(host) {
				index := strings.LastIndex(host, ".")
				if index != -1 {
					ipc := host[:index]
					num, ok := AliveIpCPrefix.Load(ipc)
					if ok {
						AliveIpCPrefix.Store(ipc, num.(uint16)+1)
					} else {
						AliveIpCPrefix.Store(ipc, uint16(1))
						livewg.Add(1)
						aliveHostChan <- host
					}
				}

			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func IcmpCheckWithExePingByChan(ipChan chan string, aliveHostChan chan string) {
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 50)
	for host := range ipChan {
		wg.Add(1)
		common.BloomFilter.AddString(host)
		limiter <- struct{}{}
		go func(host string) {
			//执行ping
			if ExecCommandPing(host) {
				index := strings.LastIndex(host, ".")
				if index != -1 {
					ipc := host[:index]
					num, ok := AliveIpCPrefix.Load(ipc)
					if ok {
						AliveIpCPrefix.Store(ipc, num.(uint16)+1)
					} else {
						AliveIpCPrefix.Store(ipc, uint16(1))
						livewg.Add(1)
						aliveHostChan <- host
					}
				}

			}
			<-limiter
			wg.Done()
		}(host)
	}
	wg.Wait()
}

func ExecCommandPing(ip string) bool {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		command = exec.Command("cmd", "/c", "ping -n 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	case "darwin":
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -W 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	default: //linux
		command = exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 "+ip+" && echo true || echo false") //ping -c 1 -i 0.5 -t 4 -W 2 -w 5 "+ip+" >/dev/null && echo true || echo false"
	}
	outinfo := bytes.Buffer{}
	command.Stdout = &outinfo
	err := command.Start()
	if err != nil {
		return false
	}
	if err = command.Wait(); err != nil {
		return false
	} else {
		if strings.Contains(outinfo.String(), "true") && strings.Count(outinfo.String(), ip) > 2 {
			return true
		} else {
			return false
		}
	}
}

func makemsg(host string) []byte {
	msg := make([]byte, 40)
	id0, id1 := genIdentifier(host)
	msg[0] = 8
	msg[1] = 0
	msg[2] = 0
	msg[3] = 0
	msg[4], msg[5] = id0, id1
	msg[6], msg[7] = genSequence(1)
	check := checkSum(msg[0:40])
	msg[2] = byte(check >> 8)
	msg[3] = byte(check & 255)
	return msg
}

func checkSum(msg []byte) uint16 {
	sum := 0
	length := len(msg)
	for i := 0; i < length-1; i += 2 {
		sum += int(msg[i])*256 + int(msg[i+1])
	}
	if length%2 == 1 {
		sum += int(msg[length-1]) * 256
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum = sum + (sum >> 16)
	answer := uint16(^sum)
	return answer
}

func genSequence(v int16) (byte, byte) {
	ret1 := byte(v >> 8)
	ret2 := byte(v & 255)
	return ret1, ret2
}

func genIdentifier(host string) (byte, byte) {
	return host[0], host[1]
}

func CountAliveIPCidr(ipList []string) {
	//分别构建ip的b段和c段哈希表，键是纯B段或纯C段
	hash_ipb_map := make(map[string]int)
	hash_ipc_map := make(map[string]int)
	inputLen := len(ipList)
	if inputLen == 0 {
		return
	}

	for _, value := range ipList {
		ip_slice := strings.Split(value, ".")
		if len(ip_slice) == 4 {
			ip_b_key := fmt.Sprintf("%s.%s", ip_slice[0], ip_slice[1])
			ip_c_key := fmt.Sprintf("%s.%s.%s", ip_slice[0], ip_slice[1], ip_slice[2])

			if _, ok := hash_ipb_map[ip_b_key]; ok {
				hash_ipb_map[ip_b_key] += 1
			} else {
				hash_ipb_map[ip_b_key] = 1
			}

			if _, ok := hash_ipc_map[ip_c_key]; ok {
				hash_ipc_map[ip_c_key] += 1
			} else {
				hash_ipc_map[ip_c_key] = 1
			}
		} else {
			continue
		}
	}

	common.LogSuccess("--------------------IP_B--------------------\n--------------------------------------------")
	for ip_b, count := range hash_ipb_map {
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ip_b+".0.0/16", count)
		common.LogSuccess(output)
	}
	common.LogSuccess("--------------------IP_C--------------------")

	for ip_c, count := range hash_ipc_map {
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ip_c+".0/24", count)
		common.LogSuccess(output)
	}

}

// CountAliveIPCidrWithGlobal 统计展示存活网段，返回所有存活的c段列表
func CountAliveIPCidrWithGlobal() []string {
	//分别构建ip的b段和c段哈希表，键是纯B段或纯C段
	//hash_ipb_map := make(map[string]int)
	//hash_ipc_map := make(map[string]int)
	//aliveCNets := []string{}
	//
	//AliveIpVerified.Range(func(key, value interface{}) bool {
	//	ip := key.(string)
	//	ip_slice := strings.Split(ip, ".")
	//	if len(ip_slice) == 4 {
	//		ip_b_key := fmt.Sprintf("%s.%s", ip_slice[0], ip_slice[1])
	//		ip_c_key := fmt.Sprintf("%s.%s.%s", ip_slice[0], ip_slice[1], ip_slice[2])
	//
	//		if _, ok := hash_ipb_map[ip_b_key]; ok {
	//			hash_ipb_map[ip_b_key] += 1
	//		} else {
	//			hash_ipb_map[ip_b_key] = 1
	//		}
	//
	//		if _, ok := hash_ipc_map[ip_c_key]; ok {
	//			hash_ipc_map[ip_c_key] += 1
	//		} else {
	//			hash_ipc_map[ip_c_key] = 1
	//		}
	//	}
	//	return true
	//})

	//分别构建ip的b段和c段哈希表，键是纯B段或纯C段
	hashIpbMap := make(map[string]int)
	var aliveCNets []string

	common.LogSuccess("--------------------IP_C--------------------")
	AliveIpCPrefix.Range(func(key, value interface{}) bool {
		ip := key.(string)
		count := value.(uint16)
		ip_slice := strings.Split(ip, ".")
		if len(ip_slice) == 3 {
			ip_b_key := fmt.Sprintf("%s.%s", ip_slice[0], ip_slice[1])
			if _, ok := hashIpbMap[ip_b_key]; ok {
				hashIpbMap[ip_b_key] += 1
			} else {
				hashIpbMap[ip_b_key] = 1
			}
		}
		ipcStr := ip + ".0/24"
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ipcStr, count)
		common.LogSuccess(output)
		aliveCNets = append(aliveCNets, ipcStr)
		return true
	})

	common.LogSuccess("--------------------IP_B--------------------")
	for ip_b, count := range hashIpbMap {
		output := fmt.Sprintf("[*] LiveTop %-16s count: %d", ip_b+".0.0/16", count)
		common.LogSuccess(output)
	}
	common.LogSuccess("--------------------------------------------")

	return aliveCNets
}

func IsInIpMap(item string) bool {
	status := false
	InputAllIpMap.Range(func(key, value interface{}) bool {
		ip := key.(string)
		if ip == item {
			status = true
			return false
		}
		return true
	})
	return status
}

func IsInIpCMap(item string) bool {
	if _, ok := AliveIpCPrefix.Load(item); ok {
		return true
	}
	//AliveIpCPrefix.Range(func(key, value interface{}) bool {
	//	ipc := key.(string)
	//	if ipc == item {
	//		status = true
	//		return false
	//	}
	//	return true
	//})
	return false
}
