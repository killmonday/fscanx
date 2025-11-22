package gonmap

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

type Probe struct {
	//探针级别
	Rarity int `json:"rarity"`
	//探针名称
	Name string `json:"name"`
	//探针适用默认端口号
	Ports PortList `json:"ports"`
	//探针适用SSL端口号
	SSLPorts PortList `json:"ssl_ports"`

	//totalwaitms  time.Duration
	//tcpwrappedms time.Duration

	//探针对应指纹库
	MatchGroup []*Match `json:"matches"`
	//探针指纹库若匹配失败，则会尝试使用fallback指定探针的指纹库
	Fallback string `json:"fallback,omitempty"`

	//探针发送协议类型
	Protocol string `json:"protocol"`
	//探针发送数据
	SendRaw string `json:"probe_string"`
}

// buildRequest 构建探测请求数据
func (p *Probe) buildRequest(host string) string {
	sendRaw := p.SendRaw
	// 替换模板变量
	sendRaw = strings.ReplaceAll(sendRaw, "{Host}", host)
	return sendRaw
}

// 原scan方法保留但现在不使用timeout
//func (p *Probe) scan(host string, port int, tls bool, timeout time.Duration, size int) (string, bool, error) {
//	uri := fmt.Sprintf("%s:%d", host, port)
//
//	sendRaw := strings.Replace(p.SendRaw, "{Host}", fmt.Sprintf("%s:%d", host, port), -1)
//
//	text, err := simplenet.Send(p.Protocol, tls, uri, sendRaw, timeout, size)
//	if err == nil {
//		return text, tls, nil
//	}
//	if strings.Contains(err.Error(), "STEP1") && tls == true {
//		text, err := simplenet.Send(p.Protocol, false, uri, p.SendRaw, timeout, size)
//		return text, false, err
//	}
//	return text, tls, err
//}

func (p *Probe) match(s string) *FingerPrint {
	var f = &FingerPrint{}
	var softFilter string

	for _, m := range p.MatchGroup {
		//实现软筛选
		if softFilter != "" {
			if m.Service != softFilter {
				continue
			}
		}
		//logger.Println("开始匹配正则：", m.service, m.patternRegexp.String())
		isMatch, _ := m.PatternRegexp.MatchString(s)
		if isMatch {
			//标记当前正则
			f.MatchRegexString = m.PatternRegexp.String()
			if m.Soft {
				//如果为软捕获，这设置筛选器
				f.Service = m.Service
				softFilter = m.Service
				continue
			} else {
				//如果为硬捕获则直接获取指纹信息
				m.makeVersionInfo(s, f)
				f.Service = m.Service
				return f
			}
		}
	}
	return f
}

var probeExprRegx = regexp.MustCompile("^(UDP|TCP) ([a-zA-Z0-9-_./]+) (?:q\\|([^|]*)\\|)(?:\\s+.*)?$")
var probeIntRegx = regexp.MustCompile(`^(\d+)$`)
var probeStrRegx = regexp.MustCompile(`^([a-zA-Z0-9-_./, ]+)$`)

func parseProbe(lines []string) *Probe {
	var p = &Probe{
		Ports:    emptyPortList,
		SSLPorts: emptyPortList,
	}

	for _, line := range lines {
		p.loadLine(line)
	}
	return p
}

func (p *Probe) loadLine(s string) {
	//分解命令
	i := strings.Index(s, " ")
	commandName := s[:i]
	commandArgs := s[i+1:]
	//逐行处理
	switch commandName {
	case "Probe":
		p.loadProbe(commandArgs)
	case "match":
		p.loadMatch(commandArgs, false)
	case "softmatch":
		p.loadMatch(commandArgs, true)
	case "ports":
		p.loadPorts(commandArgs, false)
	case "sslports":
		p.loadPorts(commandArgs, true)
	case "totalwaitms":
		//p.totalwaitms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "tcpwrappedms":
		//p.tcpwrappedms = time.Duration(p.getInt(commandArgs)) * time.Millisecond
	case "rarity":
		p.Rarity = p.getInt(commandArgs)
	case "fallback":
		p.Fallback = p.getString(commandArgs)
	}
}

func (p *Probe) loadProbe(s string) {
	//Probe <protocol> <probename> <probestring>
	if !probeExprRegx.MatchString(s) {
		panic(errors.New(s + " probe 语句格式不正确"))
	}
	args := probeExprRegx.FindStringSubmatch(s)
	if args[1] == "" || args[2] == "" {
		panic(errors.New("probe 参数格式不正确"))
	}
	p.Protocol = args[1]
	p.Name = args[1] + "_" + args[2]
	str := args[3]
	str = strings.ReplaceAll(str, `\0`, `\x00`)
	str = strings.ReplaceAll(str, `"`, `${double-quoted}`)
	str = `"` + str + `"`
	str, _ = strconv.Unquote(str)
	str = strings.ReplaceAll(str, `${double-quoted}`, `"`)
	p.SendRaw = str
}

func (p *Probe) loadMatch(s string, soft bool) {
	//"match": misc.MakeRegexpCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2}) (.*)$"),
	//match <Service> <pattern>|<patternopt> [<versioninfo>]
	//	"matchVersioninfoProductname": misc.MakeRegexpCompile("p/([^/]+)/"),
	//	"matchVersioninfoVersion":     misc.MakeRegexpCompile("v/([^/]+)/"),
	//	"matchVersioninfoInfo":        misc.MakeRegexpCompile("i/([^/]+)/"),
	//	"matchVersioninfoHostname":    misc.MakeRegexpCompile("h/([^/]+)/"),
	//	"matchVersioninfoOS":          misc.MakeRegexpCompile("o/([^/]+)/"),
	//	"matchVersioninfoDevice":      misc.MakeRegexpCompile("d/([^/]+)/"),

	p.MatchGroup = append(p.MatchGroup, parseMatch(s, soft))
}

func (p *Probe) loadPorts(expr string, ssl bool) {
	if ssl {
		p.SSLPorts = parsePortList(expr)
	} else {
		p.Ports = parsePortList(expr)
	}
}

func (p *Probe) getInt(expr string) int {
	if !probeIntRegx.MatchString(expr) {
		panic(errors.New("totalwaitms or tcpwrappedms 语句参数不正确"))
	}
	i, _ := strconv.Atoi(probeIntRegx.FindStringSubmatch(expr)[1])
	return i
}

func (p *Probe) getString(expr string) string {
	if !probeStrRegx.MatchString(expr) {
		panic(errors.New(expr + " fallback 语句参数不正确"))
	}

	// 获取匹配的字符串
	matched := probeStrRegx.FindStringSubmatch(expr)[1]

	// 如果有多个fallback值（逗号分隔），只取第一个
	if strings.Contains(matched, ",") {
		parts := strings.Split(matched, ",")
		return strings.TrimSpace(parts[0])
	}

	return matched
}

// LoadMatch 导出的loadMatch方法，供transform工具使用
func (p *Probe) LoadMatch(expr string, isExclude bool) {
	p.loadMatch(expr, isExclude)
}
