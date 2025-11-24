package common

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/bits-and-blooms/bloom/v3"
	"math/rand"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var Reg_domain = regexp.MustCompile(`^[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*\.[a-zA-Z]{2,}$`)
var RegIPAndPort = regexp.MustCompile(`^.*?(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5}).*?$`) // ?:表示该分组不进行捕获
var RegIP = regexp.MustCompile(`^\d{1,3}(\.\d{1,3}){3}$`)
var BloomFilter *bloom.BloomFilter
var ParseIPErr = errors.New(" host parsing error\n" +
	"format: \n" +
	"192.168.1.1\n" +
	"192.168.1.1/8\n" +
	"192.168.1.1/16\n" +
	"192.168.1.1/24\n" +
	"192.168.1.1,192.168.1.2\n" +
	"192.168.1.1-192.168.255.255\n" +
	"192.168.1.1-255")

func ParseIPsByChanMaster(host string, ipOnly bool) (targetInputCh chan string, err error) {
	targetInputCh = make(chan string)

	if strings.Contains(host, ":") {
		// example: 192.168.0.0/16:80
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			go ParseIPListByChan(host, targetInputCh, ipOnly)
		}
	} else {
		// 不含端口的
		go ParseIPListByChan(host, targetInputCh, ipOnly)
	}
	return
}

func ParseIP(host string, filename string, nohosts ...string) (hosts []string, err error) {
	if filename == "" && strings.Contains(host, ":") {
		// example: 192.168.0.0/16:80
		hostport := strings.Split(host, ":")
		if len(hostport) == 2 {
			host = hostport[0]
			hosts = ParseIPList(host)
		}
	} else {
		hosts = ParseIPList(host)
		if filename != "" {
			// 输入是文件类型，从文件读取目标
			var ipListFromFile []string
			ipListFromFile, _ = ReadInputFile(filename)
			hosts = append(hosts, ipListFromFile...) // -h 加上 -hf 的目标合并
		}
	}

	if len(nohosts) > 0 {
		nohost := nohosts[0]
		if nohost != "" {
			nohosts := ParseIPList(nohost)
			if len(nohosts) > 0 {
				temp := map[string]struct{}{}
				for _, host := range hosts {
					temp[host] = struct{}{}
				}

				for _, host := range nohosts {
					delete(temp, host)
				}

				var newDatas []string
				for host := range temp {
					newDatas = append(newDatas, host)
				}
				hosts = newDatas
				sort.Strings(hosts)
			}
		}
	}
	hosts = RemoveDuplicate(hosts)
	if len(hosts) == 0 && len(HostAndPortList) == 0 && host != "" && filename != "" {
		err = ParseIPErr
	}
	return
}

func ParseIPList(targetsInput string) (hosts []string) {
	if strings.Contains(targetsInput, ",") {
		targetSlice := strings.Split(targetsInput, ",")
		var ips []string
		for _, targetStr := range targetSlice {
			ips = parseIP(targetStr)
			hosts = append(hosts, ips...)
		}
	} else {
		hosts = parseIP(targetsInput)
	}
	return hosts
}

func ParseIPListByChan(targetsInput string, returnCh chan<- string, ipOnly bool) {
	defer close(returnCh)
	if strings.Contains(targetsInput, ",") {
		targetSlice := strings.Split(targetsInput, ",")
		for _, targetStr := range targetSlice {
			parseSingleIPWithChan(targetStr, returnCh, ipOnly)
		}
	} else {
		// 单个输入，不含逗号拼接
		parseSingleIPWithChan(targetsInput, returnCh, ipOnly)
	}
}

func LookupHost(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// 目前仅-hf使用
func parseIP(ip string) []string {
	switch {
	case ip == "192":
		return parseIP("192.168.0.0/16")
	case ip == "172":
		return parseIP("172.16.0.0/12")
	case ip == "10":
		return parseIP("10.0.0.0/8")
	//解析 /24 /16 /8 /xxx 等
	case strings.Contains(ip, "/"):
		return parseCidr2Range(ip)
	//可能是域名,用lookup获取ip
	case Reg_domain.MatchString(ip):
		if IsParseDomain {
			addrs, err := LookupHost(ip)
			if err != nil {
				return nil
			}
			for _, addr := range addrs {
				//只返回第一个ipv4地址
				if RegIP.MatchString(addr) {
					return []string{addr}
				}
			}
			return nil
		}
		return nil
	//192.168.1.1-192.168.1.100 或 192.168.111.1-255
	case strings.Contains(ip, "-"):
		return IpRange2Ips(ip)
	//处理单个ip
	default:
		testIP := net.ParseIP(ip)
		if testIP == nil {
			return nil
		}
		return []string{ip}
	}
}

// 针对-h
func parseSingleIPWithChan(hostStr string, returnCh chan<- string, ipOnly bool) {
	switch {
	case hostStr == "192":
		parseSingleIPWithChan("192.168.0.0/16", returnCh, ipOnly)
		return
	case hostStr == "172":
		parseSingleIPWithChan("172.16.0.0/12", returnCh, ipOnly)
		return
	case hostStr == "10":
		parseSingleIPWithChan("10.0.0.0/8", returnCh, ipOnly)
		return
	//解析 /24 /16 /8 /xxx 等
	case strings.Contains(hostStr, "/"):
		parseCidr2RangeByChan(hostStr, returnCh, ipOnly)
		return
	//纯域名,先用lookup获取ip，返回ip或ip:port
	case Reg_domain.MatchString(hostStr):
		addrs, err := LookupHost(hostStr)
		if err != nil {
			return
		}
		if ipOnly {
			for _, addr := range addrs {
				if RegIP.MatchString(addr) {
					returnCh <- addr
					return
				}
			}
		} else {
			needProbePorts := ParsePort(PortsInput)
			for _, p := range needProbePorts {
				for _, addr := range addrs {
					if RegIP.MatchString(addr) {
						returnCh <- fmt.Sprintf("%s:%d", addr, p)
						return
					}
				}
			}
		}

		return
	//192.168.1.1-192.168.1.100 或 192.168.111.1-255
	case strings.Contains(hostStr, "-"):
		IpRange2IpsByChan(hostStr, returnCh, ipOnly)
		return
	//处理单个ip
	default:
		testIP := net.ParseIP(hostStr)
		if testIP == nil {
			return
		}
		if ipOnly {
			returnCh <- hostStr
		} else {
			needProbePorts := ParsePort(PortsInput)
			for _, p := range needProbePorts {
				returnCh <- fmt.Sprintf("%s:%d", hostStr, p)
			}
		}
		return
	}
}

// 把 192.168.x.x/xx 转换成 192.168.x.x-192.168.x.x
func parseCidr2Range(host string) (hosts []string) {
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return
	}
	hosts = IpRange2Ips(IPRange(ipNet))
	return
}

func parseCidr2RangeByChan(host string, targetInputCh chan<- string, ipOnly bool) {
	// host = x.x.x.x/xx
	_, ipNet, err := net.ParseCIDR(host)
	if err != nil {
		return
	}
	IpRange2IpsByChan(IPRange(ipNet), targetInputCh, ipOnly)
	return
}

// 解析ip段到所有ip:
//
//	支持类型1：192.168.111.1-255
//	支持类型2：192.168.111.1-192.168.112.255
func IpRange2Ips(ip string) []string {
	IPRange := strings.Split(ip, "-")
	testIP := net.ParseIP(IPRange[0])
	var AllIP []string
	if len(IPRange[1]) < 4 {
		if IPRange[1] == "255" {
			IPRange[1] = "254"
		}
		Range, err := strconv.Atoi(IPRange[1])
		if testIP == nil || Range > 255 || err != nil {
			return nil
		}
		SplitIP := strings.Split(IPRange[0], ".")
		ip1, err1 := strconv.Atoi(SplitIP[3])
		ip2, err2 := strconv.Atoi(IPRange[1])
		PrefixIP := strings.Join(SplitIP[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return nil
		}
		for i := ip1; i <= ip2; i++ {
			AllIP = append(AllIP, PrefixIP+"."+strconv.Itoa(i))
		}
	} else {
		SplitIP1 := strings.Split(IPRange[0], ".")
		SplitIP2 := strings.Split(IPRange[1], ".")
		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
			return nil
		}
		if SplitIP2[3] == "255" {
			SplitIP2[3] = "254"
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(SplitIP1[i])
			ip2, err2 := strconv.Atoi(SplitIP2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return nil
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			AllIP = append(AllIP, ip)
		}
	}
	return AllIP
}

//func IpRange2IpsByChan(ip string, returnCh chan<- string) {
//	ipRange := strings.Split(ip, "-") //192.168.1.1-255
//	testIP := net.ParseIP(ipRange[0])
//	if len(ipRange[1]) < 4 {
//		//192.168.1.1-255
//		Range, err := strconv.Atoi(ipRange[1])
//		if testIP == nil || Range > 255 || err != nil {
//			return
//		}
//		SplitIP := strings.Split(ipRange[0], ".")
//		ip1, err1 := strconv.Atoi(SplitIP[3])
//		ip2, err2 := strconv.Atoi(ipRange[1])
//		PrefixIP := strings.Join(SplitIP[0:3], ".")
//		if ip1 > ip2 || err1 != nil || err2 != nil {
//			return
//		}
//		for i := ip1; i <= ip2; i++ {
//			returnCh <- PrefixIP + "." + strconv.Itoa(i)
//		}
//	} else {
//		//192.168.1.1-192.168.1.255
//		SplitIP1 := strings.Split(ipRange[0], ".")
//		SplitIP2 := strings.Split(ipRange[1], ".")
//		if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
//			return
//		}
//		start, end := [4]int{}, [4]int{}
//		for i := 0; i < 4; i++ {
//			ip1, err1 := strconv.Atoi(SplitIP1[i])
//			ip2, err2 := strconv.Atoi(SplitIP2[i])
//			if ip1 > ip2 || err1 != nil || err2 != nil {
//				return
//			}
//			start[i], end[i] = ip1, ip2
//		}
//
//		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
//		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
//
//		for num := startNum; num <= endNum; num++ {
//			_ip := fmt.Sprintf("%d.%d.%d.%d", (num>>24)&0xff, (num>>16)&0xff, (num>>8)&0xff, (num)&0xff)
//			//_ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
//			returnCh <- _ip
//		}
//	}
//}

func IpRange2IpsByChan(ip string, returnCh chan<- string, ipOnly bool) {
	ipRange := strings.Split(ip, "-") //192.168.1.1-255
	testIP := net.ParseIP(ipRange[0])
	if ipOnly {
		if len(ipRange[1]) < 4 {
			//处理192.168.1.1-255类型
			if ipRange[1] == "255" {
				ipRange[1] = "254"
			}
			Range, err := strconv.Atoi(ipRange[1])
			if testIP == nil || Range > 255 || err != nil {
				return
			}
			SplitIP := strings.Split(ipRange[0], ".")
			ip1, err1 := strconv.Atoi(SplitIP[3])
			ip2, err2 := strconv.Atoi(ipRange[1])
			PrefixIP := strings.Join(SplitIP[0:3], ".")
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return
			}
			for i := ip1; i <= ip2; i++ {
				_host := PrefixIP + "." + strconv.Itoa(i)
				returnCh <- _host
			}
		} else {
			//处理192.168.1.1-192.168.1.255类型
			SplitIP1 := strings.Split(ipRange[0], ".")
			SplitIP2 := strings.Split(ipRange[1], ".")
			if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
				return
			}
			if SplitIP2[3] == "255" {
				SplitIP2[3] = "254"
			}

			start, end := [4]int{}, [4]int{}
			for i := 0; i < 4; i++ {
				ip1, err1 := strconv.Atoi(SplitIP1[i])
				ip2, err2 := strconv.Atoi(SplitIP2[i])
				if ip1 > ip2 || err1 != nil || err2 != nil {
					return
				}
				start[i], end[i] = ip1, ip2
			}
			startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
			endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]

			for num := startNum; num <= endNum; num++ {
				_ip := fmt.Sprintf("%d.%d.%d.%d", (num>>24)&0xff, (num>>16)&0xff, (num>>8)&0xff, (num)&0xff)
				returnCh <- _ip
			}
		}
	} else {
		needProbePorts := ParsePort(PortsInput)
		for _, probePort := range needProbePorts {
			if len(ipRange[1]) < 4 {
				//192.168.1.1-255
				Range, err := strconv.Atoi(ipRange[1])
				if testIP == nil || Range > 255 || err != nil {
					return
				}
				SplitIP := strings.Split(ipRange[0], ".")
				ip1, err1 := strconv.Atoi(SplitIP[3])
				ip2, err2 := strconv.Atoi(ipRange[1])
				PrefixIP := strings.Join(SplitIP[0:3], ".")
				if ip1 > ip2 || err1 != nil || err2 != nil {
					return
				}
				for i := ip1; i <= ip2; i++ {
					_host := fmt.Sprintf("%s.%d:%d", PrefixIP, i, probePort)
					returnCh <- _host
				}
			} else {
				//192.168.1.1-192.168.1.255
				SplitIP1 := strings.Split(ipRange[0], ".")
				SplitIP2 := strings.Split(ipRange[1], ".")
				if len(SplitIP1) != 4 || len(SplitIP2) != 4 {
					return
				}
				start, end := [4]int{}, [4]int{}
				for i := 0; i < 4; i++ {
					ip1, err1 := strconv.Atoi(SplitIP1[i])
					ip2, err2 := strconv.Atoi(SplitIP2[i])
					if ip1 > ip2 || err1 != nil || err2 != nil {
						return
					}
					start[i], end[i] = ip1, ip2
				}

				startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
				endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]

				for num := startNum; num <= endNum; num++ {
					//_ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
					_ip := fmt.Sprintf("%d.%d.%d.%d:%d", (num>>24)&0xff, (num>>16)&0xff, (num>>8)&0xff, (num)&0xff, probePort)

					returnCh <- _ip

					//_host := "127.0.0.1"
					//returnCh <- _host
				}
			}
		}
	}

}

// 获取起始IP、结束IP
func IPRange(c *net.IPNet) string {
	start := c.IP.String()
	mask := c.Mask
	bcst := make(net.IP, len(c.IP))
	copy(bcst, c.IP)
	for i := 0; i < len(mask); i++ {
		ipIdx := len(bcst) - i - 1
		bcst[ipIdx] = c.IP[ipIdx] | ^mask[len(mask)-i-1]
	}
	end := bcst.String()
	return fmt.Sprintf("%s-%s", start, end) //返回 用-表示的ip段,192.168.1.0-192.168.255.255
}

// 文件内容去重。hashmap，不适合用于特大文件
func deduplicateFileContent(filename string) error {
	// 1. 打开输入文件
	inputFile, err := os.Open(filename)
	if err != nil {
		fmt.Println("无法打开输入文件:", err)
		return err
	}
	defer inputFile.Close()

	// 2. 创建一个 map 用于去重
	uniqueLines := make(map[string]struct{})

	// 3. 逐行读取文件内容
	scanner := bufio.NewScanner(inputFile)
	for scanner.Scan() {
		line := scanner.Text()
		uniqueLines[line] = struct{}{}
	}

	// 检查扫描过程中是否有错误
	if err := scanner.Err(); err != nil {
		fmt.Println("读取文件出错:", err)
		return err
	}
	inputFile.Close()

	// 4. 创建输出文件（也可以覆盖原文件）
	outputFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("无法创建输出文件:", err)
		return err
	}
	defer outputFile.Close()

	// 5. 将去重后的行写入输出文件
	writer := bufio.NewWriter(outputFile)
	for line := range uniqueLines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			fmt.Println("写入文件出错:", err)
			return err
		}
	}
	writer.Flush() // 确保所有数据都写入磁盘
	return nil
}

// 从输入文件-hf中按行读取目标
func ReadInputFile(filename string) ([]string, error) {
	fmt.Println("解析文件！！")
	// 对输入文件的内容去重，覆写输入文件
	if err := deduplicateFileContent(filename); err != nil {
		return []string{}, err
	}
	file, err := os.Open(filename)
	if err != nil {
		fmt.Printf("Open %s error, %v", filename, err)
		os.Exit(0)
	}
	defer file.Close()
	var content []string
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if strings.HasPrefix(line, "http") {
				// 支持url输入
				urlS, err := url.Parse(line)
				if err != nil {
					continue
				}
				Urls = append(Urls, line)
				if IsParseDomain {
					host := urlS.Host
					if index := strings.Index(host, ":"); index != -1 {
						host = host[:index]
						addrs, err := LookupHost(host)
						if err != nil {
						} else {
							for _, addr := range addrs {
								if RegIP.MatchString(addr) {
									// 只提取第一个ipv4地址，作为为c段
									content = append(content, ParseIPList(addr+"/24")...)
								}
							}
						}
					}
				}
			} else if text := strings.Split(line, ":"); len(text) == 2 {
				// ip:port 或 ipcidr:port 或 ip,ipcidr:port
				// 处理为 ip:port 存储到 common.HostAndPortList
				port := strings.Split(text[1], " ")[0]
				num, err := strconv.Atoi(port)
				if err != nil || (num < 1 || num > 65535) {
					continue
				}
				hosts := ParseIPList(text[0])
				for _, host := range hosts {
					HostAndPortList = append(HostAndPortList, fmt.Sprintf("%s:%s", host, port))
				}
			} else if Reg_domain.MatchString(line) {
				// 支持纯域名输入，只探测443、80端口
				Urls = append(Urls, "http://"+line)
				Urls = append(Urls, "https://"+line)
				if IsParseDomain {
					addrs, err := LookupHost(line)
					if err != nil {
					} else {
						for _, addr := range addrs {
							if RegIP.MatchString(addr) {
								content = append(content, ParseIPList(addr+"/24")...)
							}
						}
					}
				}

			} else {
				matchesMasscanRunning := RegMasscanRunningText.FindAllStringSubmatch(line, -1)
				if len(matchesMasscanRunning) >= 1 {
					match := matchesMasscanRunning[0]
					if len(match) == 3 {
						HostAndPortList = append(HostAndPortList, fmt.Sprintf("%s:%s", match[2], match[1]))
						continue
					}
				} else {
					matchesMasscanFileOutput := RegMasscanOutputText.FindAllStringSubmatch(line, -1)
					if len(matchesMasscanFileOutput) >= 1 {
						match := matchesMasscanFileOutput[0]
						if len(match) == 3 {
							HostAndPortList = append(HostAndPortList, fmt.Sprintf("%s:%s", match[2], match[1]))
							continue
						}
					}
				}
				// 还不击中，试试下面的格式，ip/ip段，或者多个ip和ip段以逗号拼接的格式
				// example: line = "ip1,ip2,ipCidr1,ip3"
				host := ParseIPList(line)
				content = append(content, host...)
			}
		}
	}
	// 返回 纯ip列表。其他的如url保存到全局Url，ip:port保存到全局的HostAndPortList
	return RemoveDuplicate(content), nil
}

// 去重
func RemoveDuplicate(old []string) []string {
	result := []string{}
	temp := map[string]struct{}{}
	for _, item := range old {
		if _, ok := temp[item]; !ok {
			temp[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

//func ParseIpA(ip string) []string {
//	realIP := ip[:len(ip)-2]
//	testIP := net.ParseIP(realIP)
//	if testIP == nil {
//		return nil
//	}
//
//	ipA := strings.Split(ip, ".")[0]
//	var AllIP []string
//	for b := 0; b <= 255; b++ {
//		for c := 0; c <= 255; c++ {
//			for d := 0; d <= 254; d++ {
//				AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%d", ipA, b, c, d))
//			}
//		}
//	}
//	return AllIP
//}

func ParseIpAWithGuess(ip string) []string {
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)
	if testIP == nil {
		return nil
	}

	ipLocationSlice := strings.Split(AUtoScanIPLocation, ",")

	ipA := strings.Split(ip, ".")[0]
	var AllIP []string
	for b := 0; b <= 255; b++ {
		for c := 0; c <= 255; c++ {
			for _, location := range ipLocationSlice {
				AllIP = append(AllIP, fmt.Sprintf("%s.%d.%d.%s", ipA, b, c, location))
			}
		}
	}
	return AllIP
}

func ParseIpAByChan(ip string, targetInputCh chan<- string) {
	realIP := ip[:len(ip)-2]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return
	}

	ipA := strings.Split(ip, ".")[0]
	for b := 0; b <= 255; b++ {
		for c := 0; c <= 255; c++ {
			for d := 0; d <= 254; d++ {
				targetInputCh <- fmt.Sprintf("%s.%d.%d.%d", ipA, b, c, d)
			}
		}
	}
}

func ParseIpBWithGuess(ip string) []string {
	realIP := ip[:len(ip)-3]
	testIP := net.ParseIP(realIP)
	if testIP == nil {
		return nil
	}

	ipLocationSlice := strings.Split(AUtoScanIPLocation, ",")

	slice := strings.Split(ip, ".")
	ipA := slice[0]
	ipB := slice[1]
	var AllIP []string
	for c := 0; c <= 255; c++ {
		for _, location := range ipLocationSlice {
			AllIP = append(AllIP, fmt.Sprintf("%s.%s.%d.%s", ipA, ipB, c, location))
		}
	}
	return AllIP
}

func ParseIpBWithGuessByChan(ip string, targetInputCh chan<- string) {
	realIP := ip[:len(ip)-3]
	testIP := net.ParseIP(realIP)

	if testIP == nil {
		return
	}

	slice := strings.Split(ip, ".")
	ipA := slice[0]
	ipB := slice[1]
	for c := 0; c <= 255; c++ {
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, 1)
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, 2)
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, 5)
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, RandInt(6, 55))
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, 253)
		targetInputCh <- fmt.Sprintf("%s.%s.%d.%d", ipA, ipB, c, 254)
	}
}

func RandInt(min, max int) int {
	if min >= max || min == 0 || max == 0 {
		return max
	}
	return rand.Intn(max-min) + min
}
