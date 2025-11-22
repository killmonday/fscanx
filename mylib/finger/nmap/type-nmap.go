package gonmap

import (
	"compress/gzip"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/killmonday/fscanx/mylib/finger/resources"
)

type Nmap struct {
	exclude      PortList
	probeNameMap map[string]*Probe

	// 按稀有度分组的探针映射 map[Rarity][]*Probe
	rarityProbeMap map[int][]*Probe
	portProbeMap   map[int]ProbeList
	//bypassAllProbePort PortList
	sslSecondProbeMap ProbeList
	sslProbeMap       ProbeList

	// Services数据，用于端口服务识别
	servicesData *ServicesData
	nmapServices []string
}

// parsePortString 解析端口字符串，返回端口号、协议类型和是否为UDP
func (n *Nmap) parsePortString(portStr string) (port int, protocol string, isUDP bool) {
	portStr = strings.TrimSpace(portStr)

	// 检查UDP标记 (U:139)
	if strings.HasPrefix(strings.ToUpper(portStr), "U:") {
		portStr = portStr[2:] // 移除"U:"前缀
		isUDP = true
		protocol = "UDP"
	} else {
		// 默认为TCP
		isUDP = false
		protocol = "TCP"
	}

	// 解析端口号
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		// 如果解析失败，返回默认值
		return 0, protocol, isUDP
	}

	return portNum, protocol, isUDP
}

// shouldSkipUDPScan 判断是否应该跳过UDP扫描（未明确标记为UDP的情况下）
func (n *Nmap) shouldSkipUDPScan(port int) bool {
	// 这里暂时返回false，因为我们现在主要处理TCP
	// 将来可以根据需要添加更多逻辑
	return false
}

// scanUDPPort UDP端口扫描逻辑
func (n *Nmap) scanUDPPort(ip string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	localProbeUsed := make(ProbeList, 0)

	// 筛选适用的UDP探针
	udpProbes := n.getUDPProbes(port, level)
	if len(udpProbes) > 0 {
		return n.getResponseByProbes(ip, port, level, sender, &localProbeUsed, udpProbes...)
	}

	return NotMatched, nil
}

// getUDPProbes 获取UDP探针列表
func (n *Nmap) getUDPProbes(port, level int) ProbeList {
	var udpProbes ProbeList
	for _, probe := range n.probeNameMap {
		if probe.Protocol == "UDP" && probe.Rarity <= level {
			// 检查端口是否匹配
			if len(probe.Ports) == 0 || probe.Ports.exist(port) {
				udpProbes = append(udpProbes, probe.Name)
			}
		}
	}
	return udpProbes
}

// handleNetworkError 统一处理网络错误
func (n *Nmap) handleNetworkError(err error, protocol string) (Status, *Response) {
	errStr := err.Error()

	// 明确的连接拒绝错误，端口关闭
	connectionErrors := []string{"connection refused", "no route to host", "network is unreachable"}
	for _, errPattern := range connectionErrors {
		if strings.Contains(errStr, errPattern) {
			return Closed, nil
		}
	}

	// UDP特殊处理
	if protocol == "UDP" && strings.Contains(errStr, "refused") {
		return Closed, nil
	}

	// 超时和其他错误返回NotMatched，避免触发guess逻辑
	return NotMatched, nil
}

func (n *Nmap) Scan(ip string, portStr string, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	// 解析端口字符串
	port, _, isUDP := n.parsePortString(portStr)
	if port == 0 {
		return NotMatched, nil
	}

	// 如果没有明确标记为UDP，则只进行TCP扫描
	if isUDP {
		// UDP扫描逻辑（暂时简化，主要扫描UDP探针）
		return n.scanUDPPort(ip, port, level, sender)
	}

	// TCP扫描逻辑 - 分层扫描策略
	return n.scanTCPPort(ip, port, level, sender)
}

// scanTCPPort TCP端口扫描的分层策略
func (n *Nmap) scanTCPPort(ip string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	localProbeUsed := make(ProbeList, 0)

	// 定义扫描层次
	scanLayers := []struct {
		name   string
		probes func() ProbeList
	}{
		{"NULL", func() ProbeList {
			if nullProbe, exists := n.probeNameMap["TCP_NULL"]; exists {
				return ProbeList{nullProbe.Name}
			}
			return ProbeList{}
		}},
		{"Port-Specific", func() ProbeList {
			return n.getPortSpecificProbes(port)
		}},
		{"SSL", func() ProbeList {
			var sslProbes ProbeList
			for _, sslProbe := range n.sslProbeMap {
				if !localProbeUsed.exist(sslProbe) {
					sslProbes = append(sslProbes, sslProbe)
				}
			}
			return sslProbes
		}},
		{"Rarity", func() ProbeList {
			var rarityProbes ProbeList
			for rarity := 1; rarity <= level; rarity++ {
				if probes, exists := n.rarityProbeMap[rarity]; exists {
					for _, probe := range probes {
						if !localProbeUsed.exist(probe.Name) {
							rarityProbes = append(rarityProbes, probe.Name)
						}
					}
				}
			}
			return rarityProbes.removeDuplicate()
		}},
	}

	// 按层次依次执行扫描
	for _, layer := range scanLayers {
		probes := layer.probes()
		if len(probes) > 0 {
			status, response = n.getResponseByProbes(ip, port, level, sender, &localProbeUsed, probes...)
			if status == Closed || status == Matched {
				return status, response
			}
		}
	}

	return NotMatched, nil
}

// getPortSpecificProbes 获取端口特定的探针列表，从nmap-services配置自动选择
// 端口特定探针不受level限制，因为它们是最相关的探针
func (n *Nmap) getPortSpecificProbes(port int) ProbeList {
	var probes ProbeList

	// 优化1: 直接从portProbeMap获取该端口对应的探针，O(1)操作
	if portProbes, exists := n.portProbeMap[port]; exists && len(portProbes) > 0 {
		// 优化2: 使用probeNameMap直接获取探针信息，避免遍历
		probesByRarity := make(map[int][]string)
		maxRarity := 0

		for _, probeName := range portProbes {
			if probe, exists := n.probeNameMap[probeName]; exists {
				rarity := probe.Rarity
				probesByRarity[rarity] = append(probesByRarity[rarity], probeName)
				if rarity > maxRarity {
					maxRarity = rarity
				}
			}
		}

		// 优化3: 按稀有度排序，但不限制稀有度级别（因为是端口特定的）
		for rarity := 1; rarity <= maxRarity; rarity++ {
			probes = append(probes, probesByRarity[rarity]...)
		}

		// 不再限制探针数量，按分层逻辑执行
	}

	return probes.removeDuplicate()
}

// getPortCategoryProbes 获取端口分类特定探针，参考vscan的tcpPortsProbesScanTask
func (n *Nmap) getPortCategoryProbes(port int) ProbeList {
	var probes ProbeList

	switch port {
	case 3389: // RDP - Terminal探针组
		terminalProbes := []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"}
		for _, probeName := range terminalProbes {
			if _, exists := n.probeNameMap[probeName]; exists {
				probes = append(probes, probeName)
			}
		}

	case 443, 8433, 9433: // HTTPS - SSL探针组
		sslProbes := []string{"TCP_SSLSessionReq", "TCP_TLSSessionReq", "TCP_SSLv23SessionReq"}
		for _, probeName := range sslProbes {
			if _, exists := n.probeNameMap[probeName]; exists {
				probes = append(probes, probeName)
			}
		}

	case 80, 3000, 4567, 5000, 8000, 8001, 8080, 8081, 8888, 9001, 9080, 9090, 9100: // HTTP - FourOhFourRequest探针
		httpProbes := []string{"TCP_GetRequest", "TCP_HTTPOptions"}
		for _, probeName := range httpProbes {
			if _, exists := n.probeNameMap[probeName]; exists {
				probes = append(probes, probeName)
			}
		}
	}

	return probes.removeDuplicate()
}

// getResponseByProbes 使用外部sender和本地probeUsed进行扫描
func (n *Nmap) getResponseByProbes(host string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), localProbeUsed *ProbeList, probes ...string) (status Status, response *Response) {
	var responseNotMatch *Response
	for _, requestName := range probes {
		if localProbeUsed.exist(requestName) {
			continue
		}
		*localProbeUsed = append(*localProbeUsed, requestName)
		p := n.probeNameMap[requestName]

		status, response = n.getResponse(host, port, p.SSLPorts.exist(port), sender, p)
		if status == Closed {
			return Closed, nil
		}
		if status == Matched {
			// 如果匹配到ssl，需要进行二次扫描
			if response.FingerPrint.Service == "ssl" {
				sslStatus, sslResponse := n.getSSLSecondProbes(host, port, level, sender, localProbeUsed)
				if sslStatus == Matched {
					return Matched, sslResponse
				}
			}
			return Matched, response
		}
		if status == Open {
			responseNotMatch = response
		}
	}

	if responseNotMatch != nil {
		response = responseNotMatch
	}
	return status, response
}

// getSSLSecondProbes SSL二次探测
func (n *Nmap) getSSLSecondProbes(host string, port int, level int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), localProbeUsed *ProbeList) (status Status, response *Response) {
	// 直接使用SSL二次探测的探针（不需要额外过滤，已在主扫描中过滤）
	status, response = n.getResponseByProbes(host, port, level, sender, localProbeUsed, n.sslSecondProbeMap...)
	if status != Matched || response.FingerPrint.Service == "ssl" {
		status, response = n.getResponseByHTTPS(host, port, sender)
	}
	if status == Matched && response.FingerPrint.Service != "ssl" {
		if response.FingerPrint.Service == "http" {
			response.FingerPrint.Service = "https"
		}
		return Matched, response
	}
	return NotMatched, response
}

// getResponseByHTTPS 处理HTTPS
func (n *Nmap) getResponseByHTTPS(host string, port int, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error)) (status Status, response *Response) {
	var httpRequest = n.probeNameMap["TCP_GetRequest"]
	return n.getResponse(host, port, true, sender, httpRequest)
}

// getResponse 使用外部sender进行网络通信的核心方法
func (n *Nmap) getResponse(host string, port int, tls bool, sender func(host string, port int, data []byte, tls bool) ([]byte, bool, error), p *Probe) (Status, *Response) {
	//if port == 53 {
	//	if DnsScan(host, port) {
	//		return Matched, &dnsResponse
	//	} else {
	//		return Closed, nil
	//	}
	//}

	// 使用外部sender发送探测数据
	probeData := []byte(p.buildRequest(host)) // 构建探测请求数据
	responseData, actualTLS, err := sender(host, port, probeData, tls)

	// Debug output can be enabled here if needed for troubleshooting

	if err != nil {
		// 根据错误类型判断端口状态
		errStr := err.Error()

		// 明确的连接拒绝错误，端口关闭
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "no route to host") ||
			strings.Contains(errStr, "network is unreachable") {
			return Closed, nil
		}

		// UDP特殊处理
		if p.Protocol == "UDP" && strings.Contains(errStr, "refused") {
			return Closed, nil
		}

		// 超时错误通常意味着端口被过滤或服务不响应，但不一定意味着端口关闭
		// 这种情况下应该返回NotMatched而不是Open，避免触发guess逻辑
		if strings.Contains(errStr, "timeout") ||
			strings.Contains(errStr, "i/o timeout") ||
			strings.Contains(errStr, "deadline exceeded") {
			return NotMatched, nil
		}

		// 其他错误也返回NotMatched
		return NotMatched, nil
	}

	response := &Response{
		Raw:         string(responseData),
		TLS:         actualTLS,
		FingerPrint: &FingerPrint{},
	}

	//若存在返回包，则开始捕获指纹
	fingerPrint := n.getFinger(string(responseData), actualTLS, p.Name)
	response.FingerPrint = fingerPrint

	if fingerPrint.Service == "" {
		return NotMatched, response
	} else {
		return Matched, response
	}
}

func (n *Nmap) getFinger(responseRaw string, tls bool, requestName string) *FingerPrint {
	data := n.convResponse(responseRaw)
	probe := n.probeNameMap[requestName]

	finger := probe.match(data)

	if tls == true {
		if finger.Service == "http" {
			finger.Service = "https"
		}
	}

	if finger.Service != "" || n.probeNameMap[requestName].Fallback == "" {
		//标记当前探针名称
		finger.ProbeName = requestName
		return finger
	}

	fallback := n.probeNameMap[requestName].Fallback
	fallbackProbe := n.probeNameMap[fallback]
	for fallback != "" {
		finger = fallbackProbe.match(data)
		fallback = n.probeNameMap[fallback].Fallback
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

func (n *Nmap) AddMatch(probeName string, expr string) {
	var probe = n.probeNameMap[probeName]
	probe.loadMatch(expr, false)
}

// GetProbeMap 返回探针名称映射（用于调试）
func (n *Nmap) GetProbeMap() map[string]*Probe {
	return n.probeNameMap
}

// GetPortProbeMap 返回端口探针映射（用于调试）
func (n *Nmap) GetPortProbeMap() map[int]ProbeList {
	return n.portProbeMap
}

// GetRarityProbeMap 返回稀有度探针映射（用于调试）
func (n *Nmap) GetRarityProbeMap() map[int][]*Probe {
	return n.rarityProbeMap
}

// GetPortSpecificProbes 公开方法，用于调试
func (n *Nmap) GetPortSpecificProbes(port int) ProbeList {
	return n.getPortSpecificProbes(port)
}

// initServicesData 初始化ServicesData，参考loadFromEmbeddedJSON的简洁实现
func (n *Nmap) initServicesData() {
	// 从embedded资源加载nmap-services.json.gz
	reader, err := gzip.NewReader(strings.NewReader(string(resources.NmapServicesData)))
	if err != nil {
		return // 忽略错误，使用默认值
	}
	defer reader.Close()

	// 解析JSON数据
	decoder := json.NewDecoder(reader)
	var data ServicesData
	err = decoder.Decode(&data)
	if err != nil {
		return // 忽略错误，使用默认值
	}

	// 保存数据
	n.servicesData = &data

	// 构建nmapServices数组以保持兼容性
	n.nmapServices = n.buildNmapServicesArray(&data)
}

// buildNmapServicesArray 构建原有格式的services数组以保持兼容性
func (n *Nmap) buildNmapServicesArray(data *ServicesData) []string {
	// 找到最大端口号
	maxPort := 0
	for _, service := range data.Services {
		if service.Port > maxPort {
			maxPort = service.Port
		}
	}

	// 初始化数组，所有端口默认为"unknown"
	services := make([]string, maxPort+1)
	for i := range services {
		services[i] = "unknown"
	}

	// 填充已知服务
	for _, service := range data.Services {
		if service.Port >= 0 && service.Port < len(services) {
			services[service.Port] = n.fixServiceName(service.Name)
		}
	}

	return services
}

// fixServiceName 修复服务名称
func (n *Nmap) fixServiceName(serviceName string) string {
	serviceName = strings.ToLower(serviceName)
	if serviceName == "" {
		return "unknown"
	}

	// 处理一些特殊情况
	switch serviceName {
	case "www", "www-http":
		return "http"
	case "https", "http-ssl":
		return "https"
	case "domain":
		return "dns"
	case "nameserver":
		return "dns"
	default:
		serviceName = strings.ReplaceAll(serviceName, "_", "-")
		return serviceName
	}
}

//初始化类

func (n *Nmap) loadExclude(expr string) {
	n.exclude = parsePortList(expr)
}

func (n *Nmap) pushProbe(p Probe) {
	n.probeNameMap[p.Name] = &p

	// 按稀有度分组探针
	n.rarityProbeMap[p.Rarity] = append(n.rarityProbeMap[p.Rarity], &p)

	//建立端口扫描对应表，将根据端口号决定使用何种请求包
	//0记录所有使用的探针
	n.portProbeMap[0] = append(n.portProbeMap[0], p.Name)

	//分别压入sslports,ports
	for _, i := range p.Ports {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.Name)
	}

	for _, i := range p.SSLPorts {
		n.portProbeMap[i] = append(n.portProbeMap[i], p.Name)
	}
}

func (n *Nmap) fixFallback() {
	for probeName, probeType := range n.probeNameMap {
		fallback := probeType.Fallback
		if fallback == "" {
			continue
		}
		if _, ok := n.probeNameMap["TCP_"+fallback]; ok {
			n.probeNameMap[probeName].Fallback = "TCP_" + fallback
		} else {
			n.probeNameMap[probeName].Fallback = "UDP_" + fallback
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

// 工具函数
//func DnsScan(host string, port int) bool {
//	domainServer := fmt.Sprintf("%s:%d", host, port)
//	c := dns.Client{
//		Timeout: 2 * time.Second,
//	}
//	m := dns.Msg{}
//	// 最终都会指向一个ip 也就是typeA, 这样就可以返回所有层的cname.
//	m.SetQuestion("www.baidu.com.", dns.TypeA)
//	_, _, err := c.Exchange(&m, domainServer)
//	if err != nil {
//		return false
//	}
//	return true
//}
