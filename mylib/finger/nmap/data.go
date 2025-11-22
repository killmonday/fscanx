package gonmap

import (
	"fmt"
	"strings"
)

// NmapProbesData 用于 JSON/YAML 序列化和反序列化的顶层数据结构
type NmapProbesData struct {
	Probes   []*Probe          `json:"probes" yaml:"probes"`
	Services map[string]string `json:"services,omitempty" yaml:"services,omitempty"`
}

// LoadFromJSON 从 JSON 数据加载探针数据
func (data *NmapProbesData) LoadFromJSON(jsonData []byte) error {
	// 这个方法将在后续实现，用于从预处理的 JSON 数据中加载探针
	// 避免每次都解析原始的 nmap-service-probes 文件
	return nil
}

// ExportProbes 导出当前加载的探针数据为可序列化的格式
func ExportProbes() *NmapProbesData {
	// 从全局nmap实例导出探针数据
	probes := make([]*Probe, 0, len(nmap.probeNameMap))

	// 将probeNameMap中的探针转换为数组
	for _, probe := range nmap.probeNameMap {
		// 创建探针副本，避免引用问题
		probeCopy := *probe
		probes = append(probes, &probeCopy)
	}

	return &NmapProbesData{
		Probes:   probes,
		Services: copyNmapServices(),
	}
}

// copyNmapServices 复制nmap服务映射
func copyNmapServices() map[string]string {
	services := make(map[string]string)

	// 确保nmap已经初始化
	if nmap == nil {
		initNmap()
	}

	// 将nmapServices数组转换为map格式
	if nmap.nmapServices != nil {
		for port, service := range nmap.nmapServices {
			if service != "" && service != "unknown" {
				services[fmt.Sprintf("%d", port)] = service
			}
		}
	}

	return services
}

// TempNmapParser 临时的nmap解析器，用于transform工具
type TempNmapParser struct {
	probeNameMap map[string]*Probe
}

// NewTempParser 创建临时解析器
func NewTempParser(content string) *TempNmapParser {
	parser := &TempNmapParser{
		probeNameMap: make(map[string]*Probe),
	}
	parser.loads(content)
	return parser
}

// GetProbes 获取解析的探针
func (t *TempNmapParser) GetProbes() map[string]*Probe {
	return t.probeNameMap
}

// loads 解析nmap-service-probes内容（从type-nmap.go复制）
func (t *TempNmapParser) loads(s string) {
	lines := strings.Split(s, "\n")
	var probeGroups [][]string
	var probeLines []string
	for _, line := range lines {
		if !t.isCommand(line) {
			continue
		}
		commandName := line[:strings.Index(line, " ")]
		if commandName == "Exclude" {
			continue // 忽略Exclude命令
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
		t.pushProbe(*p)
	}
}

// pushProbe 添加探针到映射中
func (t *TempNmapParser) pushProbe(p Probe) {
	t.probeNameMap[p.Name] = &p
}

// isCommand 检查是否是有效命令行（从type-nmap.go复制）
func (t *TempNmapParser) isCommand(line string) bool {
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
