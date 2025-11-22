package gonmap

import (
	"github.com/killmonday/fscanx/mylib/finger/common"
)

type NmapEngine struct {
	nmap *Nmap
}

// NewNmapEngine 创建新的 nmap 引擎实例
func NewNmapEngine() (*NmapEngine, error) {
	// 手动初始化nmap实例
	n := New()

	return &NmapEngine{
		nmap: n,
	}, nil
}

// Name 实现 EngineImpl 接口
func (e *NmapEngine) Name() string {
	return "nmap"
}

// Compile 实现 EngineImpl 接口
func (e *NmapEngine) Compile() error {
	// gonmap 在 init() 中已经完成编译，这里不需要额外操作
	return nil
}

// Len 实现 EngineImpl 接口
func (e *NmapEngine) Len() int {
	// 返回 nmap 指纹库的总指纹数
	return len(e.nmap.probeNameMap)
}

// WebMatch 实现Web指纹匹配 - nmap不支持Web指纹
func (e *NmapEngine) WebMatch(content []byte) common.Frameworks {
	// nmap不支持Web指纹识别
	return make(common.Frameworks)
}

// ServiceMatch 实现Service指纹匹配
func (e *NmapEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	if sender == nil || level <= 0 {
		return nil
	}

	// 创建适配器将common.ServiceSender转换为nmap内部sender格式
	nmapSender := func(host string, port int, data []byte, requestTLS bool) ([]byte, bool, error) {
		// 根据TLS需求和端口特性选择网络协议
		network := "tcp"
		if requestTLS || isHTTPSPort(port) {
			network = "tls"
		}

		// 直接使用端口字符串，让ServiceSender处理UDP等协议前缀
		response, err := sender.Send(host, portStr, data, network)
		if err != nil {
			// 如果TLS失败，尝试普通TCP
			if network == "tls" {
				response, err = sender.Send(host, portStr, data, "tcp")
				if err == nil {
					return response, false, nil // 成功但不是TLS
				}
			}
			return nil, false, err
		}

		// 返回响应和实际使用的协议类型
		actualTLS := (network == "tls")
		return response, actualTLS, nil
	}

	// 解析端口字符串获取端口号（用于其他逻辑）
	portNum, _, _ := e.nmap.parsePortString(portStr)

	// 使用nmap的完整扫描逻辑，但网络发送由外部sender控制
	status, response := e.nmap.Scan(host, portStr, level, nmapSender)

	var framework *common.Framework

	if status == Matched && response != nil && response.FingerPrint != nil {
		// 扫描成功，获取多个Framework（支持多个CPE app）
		frameworks := response.FingerPrint.ToFrameworks()
		if len(frameworks) > 0 {
			framework = frameworks[0] // 取第一个Framework作为主要结果
		}
	} else if status == Open {
		// 端口开放但无法识别服务，使用guess功能猜测服务
		guessedProtocol := GuessProtocol(portNum)
		if guessedProtocol != "" && guessedProtocol != "unknown" {
			// 创建基于猜测的Framework
			framework = common.NewFramework(FixProtocol(guessedProtocol), common.FrameFromGUESS)
			// 添加guess标记
			framework.Tags = append(framework.Tags, "guess")
		}
	}
	// 如果status是Closed或其他状态，framework保持为nil，表示端口未开放或无法连接

	if framework == nil {
		return nil
	}

	result := &common.ServiceResult{
		Framework: framework,
		Vuln:      nil, // nmap一般不直接返回漏洞信息
	}

	// 调用回调函数
	if callback != nil {
		callback(result)
	}

	return result
}

// matchResponse 使用nmap指纹库分析响应数据
func (e *NmapEngine) matchResponse(responseData []byte, host string, port int) *common.Framework {
	// 使用nmap的指纹匹配逻辑
	// 调用nmap的核心指纹识别函数，不涉及网络请求
	responseStr := string(responseData)
	fingerPrint := e.nmap.getFinger(responseStr, false, "")

	if fingerPrint != nil && fingerPrint.Service != "" {
		frameworks := fingerPrint.ToFrameworks()
		if len(frameworks) > 0 {
			return frameworks[0] // 返回第一个Framework
		}
	}
	return nil
}

// Capability 实现 EngineImpl 接口 - 返回引擎能力
func (e *NmapEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     false, // nmap不支持Web指纹
		SupportService: true,  // nmap支持Service指纹
	}
}

// isHTTPSPort 判断是否是常见的HTTPS端口
func isHTTPSPort(port int) bool {
	httpsports := []int{443, 8443, 993, 995, 465, 636, 989, 990, 992, 993, 994, 995, 5986}
	for _, p := range httpsports {
		if port == p {
			return true
		}
	}
	return false
}
