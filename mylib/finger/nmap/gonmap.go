package gonmap

import (
	"compress/gzip"
	"encoding/json"
	"regexp"
	"strings"

	"github.com/killmonday/fscanx/mylib/finger/resources"
)

var nmap *Nmap

// r["PROBE"] 总探针数、r["MATCH"] 总指纹数 、r["USED_PROBE"] 已使用探针数、r["USED_MATCH"] 已使用指纹数
// init函数已移除，改为手动初始化

func initNmap() {
	//初始化NMAP探针库
	nmap = &Nmap{
		exclude:        emptyPortList,
		probeNameMap:   make(map[string]*Probe),
		rarityProbeMap: make(map[int][]*Probe),
		portProbeMap:   make(map[int]ProbeList),

		//bypassAllProbePort: []int{161, 137, 139, 135, 389, 443, 548, 1433, 6379, 1883, 5432, 1521, 3389, 3388, 3389, 33890, 33900},
		sslSecondProbeMap: []string{"TCP_TerminalServerCookie", "TCP_TerminalServer"},
		//allProbeMap:        []string{"TCP_GetRequest", "TCP_NULL"},
		sslProbeMap: []string{"TCP_TLSSessionReq", "TCP_SSLSessionReq", "TCP_SSLv23SessionReq"},
	}
	for i := 0; i <= 65535; i++ {
		nmap.portProbeMap[i] = []string{}
	}

	// 初始化ServicesData
	nmap.initServicesData()

	// 从预处理的JSON资源加载探针数据
	loadFromEmbeddedJSON()

	//修复fallback
	nmap.fixFallback()
	//新增自定义指纹信息
	customNMAPMatch() // 可能有问题，暂时禁用
	//优化检测逻辑，及端口对应的默认探针

	optimizeNMAPProbes() // 可能访问不存在的探针，暂时禁用
	//输出统计数据状态
}

// loadFromEmbeddedJSON 从嵌入的JSON资源加载探针数据
func loadFromEmbeddedJSON() bool {
	// 从resources包加载压缩的nmap数据
	data, err := loadNmapProbesFromEmbedded()
	if err != nil {
		return false
	}

	// 加载探针数据并重新编译正则表达式
	for _, probe := range data.Probes {
		// 重新编译每个Match中的正则表达式
		for _, match := range probe.MatchGroup {
			// 重新编译PatternRegexp，从JSON反序列化时不会保存正则对象
			match.PatternRegexp = match.getPatternRegexp(match.Pattern, "")
		}
		nmap.pushProbe(*probe)
	}

	// 加载服务映射数据
	for portStr, service := range data.Services {
		// 这里可以将服务映射数据加载到nmapServices中，如果需要的话
		_ = portStr
		_ = service
	}

	return true
}

// loadNmapProbesFromEmbedded 从嵌入的资源中加载nmap探针数据
func loadNmapProbesFromEmbedded() (*NmapProbesData, error) {
	// 创建gzip reader来解压数据
	reader, err := gzip.NewReader(strings.NewReader(string(resources.NmapServiceProbesData)))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	// 创建JSON解码器
	decoder := json.NewDecoder(reader)
	var data NmapProbesData

	// 解码JSON数据
	err = decoder.Decode(&data)
	if err != nil {
		return nil, err
	}

	return &data, nil
}

// loadCustomizeProbes 加载自定义探针数据（临时方案）

func customNMAPMatch() {
	//新增自定义指纹信息
	nmap.AddMatch("TCP_GetRequest", `echo m|^GET / HTTP/1.0\r\n\r\n$|s`)
	nmap.AddMatch("TCP_GetRequest", `mongodb m|.*It looks like you are trying to access MongoDB.*|s p/MongoDB/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d (?:[^\r\n]+\r\n)*?Server: ([^\r\n]+)| p/$1/`)
	nmap.AddMatch("TCP_GetRequest", `http m|^HTTP/1\.[01] \d\d\d|`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MariaDB server| p/MariaDB/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00..j\x04Host '.*' is not allowed to connect to this MySQL server| p/MySQL/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a(\d+\.\d+\.\d+)\x00.*caching_sha2_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `mysql m|.\x00\x00\x00\x0a([\d.-]+)-MariaDB\x00.*mysql_native_password\x00| p/MariaDB/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `redis m|-DENIED Redis is running in.*| p/Redis/ i/Protected mode/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome to visit (.*) series router!.*|s p/$1 Router/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Username: ??|`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet service is disabled or Your telnet session has expired due to inactivity.*|s i/Disabled/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Telnet connection from (.*) refused.*|s i/Refused/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Command line is locked now, please retry later.*\x0d\x0a\x0d\x0a|s i/Locked/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet.*|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^telnetd:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Quopin CLI for (.*)\x0d\x0a\x0d\x0a|s p/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0aHello, this is FRRouting \(version ([\d.]+)\).*|s p/FRRouting/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*User Access Verification.*Username:|s`)
	nmap.AddMatch("TCP_NULL", `telnet m|^Connection failed.  Windows CE Telnet Service cannot accept anymore concurrent users.|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^\x0d\x0a\x0d\x0aWelcome to the host.\x0d\x0a.*|s o/Windows/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^.*Welcome Visiting Huawei Home Gateway\x0d\x0aCopyright by Huawei Technologies Co., Ltd.*Login:|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `telnet m|^..\x01..\x03..\x18..\x1f|s p/Huawei/`)
	nmap.AddMatch("TCP_NULL", `smtp m|^220 ([a-z0-1.-]+).*| h/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220 H3C Small-FTP Server Version ([\d.]+).* | p/H3C Small-FTP/ v/$1/`)
	nmap.AddMatch("TCP_NULL", `ftp m|^421[- ]Service not available..*|`)
	nmap.AddMatch("TCP_NULL", `ftp m|^220[- ].*filezilla.*|i p/FileZilla/`)
	nmap.AddMatch("TCP_TerminalServerCookie", `ms-wbt-server m|^\x03\0\0\x13\x0e\xd0\0\0\x124\0\x02.*\0\x02\0\0\0| p/Microsoft Terminal Services/ o/Windows/ cpe:/o:microsoft:windows/a`)
	nmap.AddMatch("TCP_redis-server", `redis m|^.*redis_version:([.\d]+)\n|s p/Redis key-value store/ v/$1/ cpe:/a:redislabs:redis:$1/`)
	nmap.AddMatch("TCP_redis-server", `redis m|^-NOAUTH Authentication required.|s p/Redis key-value store/`)
}

func optimizeNMAPProbes() {
	nmap.probeNameMap["TCP_GenericLines"].SSLPorts = nmap.probeNameMap["TCP_GenericLines"].SSLPorts.append(993, 994, 456, 995)
	//优化检测逻辑，及端口对应的默认探针
	nmap.portProbeMap[993] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[993]...)
	nmap.portProbeMap[994] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[994]...)
	nmap.portProbeMap[995] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[995]...)
	nmap.portProbeMap[465] = append([]string{"TCP_GenericLines"}, nmap.portProbeMap[465]...)
	nmap.portProbeMap[3390] = append(nmap.portProbeMap[3390], "TCP_TerminalServer")
	nmap.portProbeMap[3390] = append(nmap.portProbeMap[3390], "TCP_TerminalServerCookie")
	nmap.portProbeMap[33890] = append(nmap.portProbeMap[33890], "TCP_TerminalServer")
	nmap.portProbeMap[33890] = append(nmap.portProbeMap[33890], "TCP_TerminalServerCookie")
	nmap.portProbeMap[33900] = append(nmap.portProbeMap[33900], "TCP_TerminalServer")
	nmap.portProbeMap[33900] = append(nmap.portProbeMap[33900], "TCP_TerminalServerCookie")
	nmap.portProbeMap[7890] = append(nmap.portProbeMap[7890], "TCP_Socks5")
	nmap.portProbeMap[7891] = append(nmap.portProbeMap[7891], "TCP_Socks5")
	nmap.portProbeMap[4000] = append(nmap.portProbeMap[4000], "TCP_Socks5")
	nmap.portProbeMap[2022] = append(nmap.portProbeMap[2022], "TCP_Socks5")
	nmap.portProbeMap[6000] = append(nmap.portProbeMap[6000], "TCP_Socks5")
	nmap.portProbeMap[7000] = append(nmap.portProbeMap[7000], "TCP_Socks5")
	//将TCP_GetRequest的fallback参数设置为NULL探针，避免漏资产
	nmap.probeNameMap["TCP_GenericLines"].Fallback = "TCP_NULL"
	nmap.probeNameMap["TCP_GetRequest"].Fallback = "TCP_NULL"
	nmap.probeNameMap["TCP_TerminalServerCookie"].Fallback = "TCP_GetRequest"
	nmap.probeNameMap["TCP_TerminalServer"].Fallback = "TCP_GetRequest"
}

// 功能类
func New() *Nmap {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}
	n := *nmap
	return &n
}

func GuessProtocol(port int) string {
	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}

	// 直接从nmap实例获取服务名称
	if port >= 0 && port < len(nmap.nmapServices) {
		return nmap.nmapServices[port]
	}
	return "unknown"
}

var regexpFirstNum = regexp.MustCompile(`^\d`)

func FixProtocol(oldProtocol string) string {
	//进行最后输出修饰
	if oldProtocol == "ssl/http" {
		return "https"
	}
	if oldProtocol == "http-proxy" {
		return "http"
	}
	if oldProtocol == "ms-wbt-server" {
		return "rdp"
	}
	if oldProtocol == "microsoft-ds" {
		return "smb"
	}
	if oldProtocol == "netbios-ssn" {
		return "netbios"
	}
	if oldProtocol == "oracle-tns" {
		return "oracle"
	}
	if oldProtocol == "msrpc" {
		return "rpc"
	}
	if oldProtocol == "ms-sql-s" {
		return "mssql"
	}
	if oldProtocol == "domain" {
		return "dns"
	}
	if oldProtocol == "svnserve" {
		return "svn"
	}
	if oldProtocol == "ibm-db2" {
		return "db2"
	}
	if oldProtocol == "socks-proxy" {
		return "socks5"
	}
	if len(oldProtocol) > 4 {
		if oldProtocol[:4] == "ssl/" {
			return oldProtocol[4:] + "-ssl"
		}
	}
	if regexpFirstNum.MatchString(oldProtocol) {
		oldProtocol = "S" + oldProtocol
	}
	oldProtocol = strings.ReplaceAll(oldProtocol, "_", "-")
	return oldProtocol
}
