package gonmap

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/killmonday/fscanx/common"
	"github.com/miekg/dns"
)

type Nmap struct {
	exclude      PortList
	portProbeMap map[int]ProbeList
	probeNameMap map[string]*probe
	probeSort    ProbeList

	probeUsed ProbeList

	filter int

	//检测端口存活的超时时间
	timeout           time.Duration
	single_tz_timeout time.Duration

	bypassAllProbePort PortList
	sslSecondProbeMap  ProbeList
	allProbeMap        ProbeList
	sslProbeMap        ProbeList
}

//扫描类

func (n *Nmap) ScanTimeout(ip string, port int, timeout time.Duration, single_probe_timeout time.Duration) (status Status, response *Response) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	n.single_tz_timeout = single_probe_timeout
	var resChan = make(chan bool, 1)

	defer func() {
		if r := recover(); r != nil {
			//fmt.Println("[debug] ScanTimeout err: %v", r)
		}
		close(resChan)
		cancel()
	}()

	common.PoolScan.Submit(func() {
		defer func() {
			if r := recover(); r != nil {
				//debug.PrintStack()
			}
		}()
		scanRes := make(chan struct{}, 1)
		go func() {
			status, response = n.Scan(ip, port)
			scanRes <- struct{}{}
		}()

		select {
		case <-ctx.Done():
			return
		case <-scanRes:
			resChan <- true
		}
	})

	select {
	case <-ctx.Done():
		// 此处是达到了总体探测超时时间，由于之前的逻辑没有设计和回传中间探测的端口开放状态，所以这里重新探测一次tcp端口开放，未来有时间可以去掉这一步，把中间状态回传，就不用浪费一次tcp等待时间
		netloc := fmt.Sprintf("%s:%d", ip, port)
		conn, _ := common.GetConn("tcp", netloc, single_probe_timeout)
		if conn != nil {
			defer conn.Close()
			return Open, nil
		}
		return Closed, nil
	case <-resChan:
		if status == Open && common.IsValidSocks5 == false {
			// Open状态表示目标端口没有响应任何数据
			// 如果socks5代理非标准，首先说明①已经使用和配置了socks5代理；②走到此处说明使用了gonmap探测，基于第1点，gonmap在有限的前n个探针发送后依旧没有数据响应，可以认为是端口关闭，这是因为没办法尝试所有探针看是否有响应，并且这里获取到的tcp连接是与socks5服务器的，而非目标端口，所以又无法判断目标端口是否开放，因此如果直接判断为端口开放是武断的，故而判断为关闭，这是这种情况下必然损失的一些精度
			return Closed, nil
		}
		return status, response
	}
}

func (n *Nmap) Scan(ip string, port int) (status Status, response *Response) {
	defer func() {
		if r := recover(); r != nil {
			//debug.PrintStack()
			//if fmt.Sprint(r) != "send on closed channel" {
			//	panic(r)
			//}
			//fmt.Println("nmap scan err:", ip, port)
		}
	}()

	probeNames := n.portProbeMap[port]
	nextInx := 1
	//fmt.Println("去重后探针：", probeNames)

	firstProbe := probeNames[0]
	status, response = n.getRealResponse(ip, port, n.single_tz_timeout, firstProbe)

	//fmt.Println("[debug] [Scan()] 第一探针 探测结束，get resp ok , status：", status, "response:", response, "\n")
	if status == Closed || status == Matched {
		return status, response
	}
	otherProbes := probeNames[nextInx:]
	//剩余探针 探测
	return n.getRealResponse(ip, port, n.single_tz_timeout, otherProbes...)
}

func (n *Nmap) getRealResponse(host string, port int, timeout time.Duration, probes ...string) (status Status, response *Response) {
	status, response = n.getResponseByProbes(host, port, timeout, probes...)
	//fmt.Println("[debug] status, response: \n", status, "\n==============\n", response, "\n")
	if status != Matched {
		return status, response
	}
	if response != nil && response.FingerPrint.Service == "ssl" {
		//fmt.Println("[debug] start second ssl probe ..")
		status, response := n.getResponseBySSLSecondProbes(host, port, timeout)
		//fmt.Println("[debug] second ssl probe done,  status:", status, ", resp:", response) //"service:", response.FingerPrint.Service
		if status == Matched {
			return Matched, response
		}
	}
	return status, response
}

func (n *Nmap) getResponseBySSLSecondProbes(host string, port int, timeout time.Duration) (status Status, response *Response) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[CRITICAL] getResponseBySSLSecondProbes panic: %v\n", r)
		}
	}()

	//fmt.Println("[debug] send second ssl probe package..")
	status, response = n.getResponseByProbes(host, port, timeout, n.sslSecondProbeMap...)
	//fmt.Println("[debug] send second ssl probe package ok, status:", status, ", resp:", response, "\n\n")

	if status != Matched || response.FingerPrint.Service == "ssl" {
		//fmt.Println("[debug] send third ssl probe package..")
		status, response = n.getResponseByHTTPS(host, port, timeout)
	}
	if status == Matched && response != nil && response.FingerPrint.Service != "ssl" {
		if response.FingerPrint.Service == "http" {
			response.FingerPrint.Service = "https"
		}
		return Matched, response
	}
	return NotMatched, response
}

func (n *Nmap) getResponseByHTTPS(host string, port int, timeout time.Duration) (status Status, response *Response) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[CRITICAL] getResponseByHTTPS panic: %v\n", r)
		}
	}()
	var httpRequest = n.probeNameMap["TCP_GetRequest"]
	status, res := n.getResponse(host, port, true, timeout, httpRequest)
	return status, res
}

func (n *Nmap) getResponseByProbes(host string, port int, timeout time.Duration, probes ...string) (status Status, response *Response) {
	//var responseNotMatch *Response
	status = Closed
	hasNotMatchOnetime := false
	var currentStatu Status
	var currentRes *Response
	for index, requestName := range probes {
		if n.probeUsed.exist(requestName) {
			continue
		}
		//fmt.Printf("[debug] 当前探针 (%d): %s\n", index+1, requestName)

		n.probeUsed = append(n.probeUsed, requestName)
		p := n.probeNameMap[requestName]

		if index > 4 && status == Closed { //如果尝试了前4个探针依然没探测到端口开放，则退出
			break
		}

		currentStatu, currentRes = n.getResponse(host, port, p.sslports.exist(port), timeout, p)
		//logger.Printf("探测结果：Target:%s:%d,Probe:%s,Status:%v", host, port, requestName, currentStatu)

		if currentStatu == Matched {
			status = Matched
			response = currentRes
			break
		} else if currentStatu != Closed {
			if currentStatu == NotMatched {
				hasNotMatchOnetime = true
			}
			status = currentStatu
			response = currentRes
		}
	}
	//到达这里的，都不是Matched
	//如果曾经有一次探测是响应了内容，但没有匹配上指纹的，将最终返回状态设置为NotMatch。
	if hasNotMatchOnetime {
		status = NotMatched
	}
	//fmt.Println("返回：", status, response)
	return status, response
}

func (n *Nmap) getResponse(host string, port int, tls bool, timeout time.Duration, p *probe) (Status, *Response) {
	defer func() {
		if r := recover(); r != nil {
			//fmt.Printf("[CRITICAL] getResponse panic: %v\n", r)
		}
	}()
	if port == 53 {
		if DnsScan(host, port) {
			return Matched, &dnsResponse
		} else {
			return Closed, nil
		}
	}
	text, tls, isOpen := p.scan(host, port, tls, timeout)

	//fmt.Println("p.scan return text len:", len(text), "|| tls:", tls, "|| open:", isOpen)
	if isOpen == false {
		return Closed, nil
	}
	if len(text) == 0 {
		if isOpen {
			return Open, nil
		}
	}
	response := &Response{
		Raw:         text,
		TLS:         tls,
		FingerPrint: &FingerPrint{},
	}
	//若存在返回包，则开始做指纹匹配
	fingerPrint := n.getFinger(text, tls, p.name)
	response.FingerPrint = fingerPrint
	//fmt.Println("fingerPrint=", fingerPrint.Service)
	//如果成功匹配指纹，则直接返回指纹
	if fingerPrint.Service == "" {
		return NotMatched, response
	} else {
		return Matched, response
	}
}

func (n *Nmap) getFinger(responseRaw string, tls bool, requestName string) *FingerPrint {
	//fmt.Println("[debug] func getFinger, requestName=", requestName)
	data := n.convResponse(responseRaw)
	probe := n.probeNameMap[requestName]

	finger := probe.match(data)

	if tls == true {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.probeNameMap[requestName].fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.probeNameMap[requestName].fallback
	fallbackProbe := n.probeNameMap[fallback]
	for fallback != "" {
		// logger.Println(requestName, " fallback is :", fallback)
		finger = fallbackProbe.match(data)
		fallback = n.probeNameMap[fallback].fallback
		if finger.Service != "" {
			break
		}
	}
	//标记当前探针名称
	finger.ProbeName = requestName
	return finger
}

func (n *Nmap) convResponse(s1 string) string {
	//为了适配go语言的沙雕正则，只能讲二进制强行转换成UTF-8
	b1 := []byte(s1)
	var r1 []rune
	for _, i := range b1 {
		r1 = append(r1, rune(i))
	}
	s2 := string(r1)
	return s2
}

//配置类

func (n *Nmap) SetTimeout(timeout time.Duration) {
	n.timeout = timeout
}

func (n *Nmap) OpenDeepIdentify() {
	//-sV参数深度解析
	n.allProbeMap = n.probeSort
}

func (n *Nmap) AddMatch(probeName string, expr string) {
	var probe = n.probeNameMap[probeName]
	probe.loadMatch(expr, false)
}

//初始化类

func (n *Nmap) loads(s *string) {
	lines := strings.Split(*s, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		if !n.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			n.loadExclude(line)
			continue
		}
		if commandName == "Probe" {
			if len(probeLines) != 0 {
				probeGroups = append(probeGroups, probeLines)
				probeLines = []string{}
			}
		}
		probeLines = append(probeLines, line)
	}
	probeGroups = append(probeGroups, probeLines)

	for _, lines := range probeGroups {
		p := parseProbe(lines)
		n.pushProbe(*p)
	}
}

func (n *Nmap) loadExclude(expr string) {
	n.exclude = parsePortList(expr)
}

func (n *Nmap) pushProbe(p probe) {
	n.probeSort = append(n.probeSort, p.name)
	n.probeNameMap[p.name] = &p

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//如果端口列表为空，则为全端口
	if p.rarity > n.filter {
		return
	}
	//0记录所有使用的探针
	n.portProbeMap[0] = append(n.portProbeMap[0], p.name)

	//分别压入sslports,ports
	for _, i := range p.ports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.name)
	}

	for _, i := range p.sslports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.name)
	}

}

func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeNameMap {
		fallback := probeType.fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.probeNameMap["TCP_"+fallback]; ok {
			n.probeNameMap[probeName].fallback = "TCP_" + fallback
		} else {
			n.probeNameMap[probeName].fallback = "UDP_" + fallback
		}
	}
}

func (n *Nmap) isCommand(line string) bool {
	//删除注释行和空行
	if len(line) < 2 {
		return false
	}
	if line[:1] == "#" {
		return false
	}
	//删除异常命令
	commandName := line[:strings.Index(line, " ")]
	commandArr := []string{
		"Exclude", "Probe", "match", "softmatch", "ports", "sslports", "totalwaitms", "tcpwrappedms", "rarity", "fallback",
	}
	for _, item := range commandArr {
		if item == commandName {
			return true
		}
	}
	return false
}

// 根据所有探针的稀有度进行排序，得出一个探针发送的优先顺序。rarity值越高，越稀有，排在越后面
func (n *Nmap) sortOfRarity(list ProbeList) ProbeList {
	if len(list) == 0 {
		return list
	}
	var raritySplice []int
	for _, probeName := range list {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	for i := 0; i < len(raritySplice)-1; i++ {
		for j := 0; j < len(raritySplice)-i-1; j++ {
			if raritySplice[j] > raritySplice[j+1] {
				m := raritySplice[j+1]
				raritySplice[j+1] = raritySplice[j]
				raritySplice[j] = m
				mp := list[j+1]
				list[j+1] = list[j]
				list[j] = mp
			}
		}
	}

	for _, probeName := range list {
		rarity := n.probeNameMap[probeName].rarity
		raritySplice = append(raritySplice, rarity)
	}

	return list
}

// 工具函数
func DnsScan(host string, port int) bool {
	domainServer := fmt.Sprintf("%s:%d", host, port)
	c := dns.Client{
		Timeout: 2 * time.Second,
	}
	m := dns.Msg{}
	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
	m.SetQuestion("www.baidu.com.", dns.TypeA)
	_, _, err := c.Exchange(&m, domainServer)
	if err != nil {
		return false
	}
	return true
}
