package gonmap

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/killmonday/fscanx/mylib/finger/common"
)

type Match struct {
	//match <Service> <pattern> <patternopt> [<versioninfo>]
	Soft          bool            `json:"soft"`
	Service       string          `json:"service"`
	Pattern       string          `json:"pattern"`
	PatternRegexp *regexp2.Regexp `json:"-"` // 不序列化正则对象
	VersionInfo   *FingerPrint    `json:"version_info,omitempty"`
}

var matchLoadRegexps = []*regexp.Regexp{
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m\\|([^|]+)\\|([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m=([^=]+)=([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m%([^%]+)%([is]{0,2})(?: (.*))?$"),
	regexp.MustCompile("^([a-zA-Z0-9-_./]+) m@([^@]+)@([is]{0,2})(?: (.*))?$"),
}

var matchVersionInfoRegexps = map[string]*regexp.Regexp{
	"PRODUCTNAME": regexp.MustCompile("p/([^/]+)/"),
	"VERSION":     regexp.MustCompile("v/([^/]+)/"),
	"INFO":        regexp.MustCompile("i/([^/]+)/"),
	"HOSTNAME":    regexp.MustCompile("h/([^/]+)/"),
	"OS":          regexp.MustCompile("o/([^/]+)/"),
	"DEVICE":      regexp.MustCompile("d/([^/]+)/"),
}

// CPE解析正则表达式，匹配 cpe:/ 格式的CPE条目
var matchCPERegexp = regexp.MustCompile(`cpe:/[^/\s]+/[^/\s]+/[^/\s\)]*(?:/[^/\s\)]*)*`)

var matchVersionInfoHelperRegxP = regexp.MustCompile(`\$P\((\d)\)`)
var matchVersionInfoHelperRegx = regexp.MustCompile(`\$(\d)`)

func parseMatch(s string, soft bool) *Match {
	var m = &Match{}
	var regx *regexp.Regexp

	for _, r := range matchLoadRegexps {
		if r.MatchString(s) {
			regx = r
		}
	}

	if regx == nil {
		panic(errors.New("match 语句参数不正确"))
	}

	args := regx.FindStringSubmatch(s)
	m.Soft = soft
	m.Service = args[1]
	m.Service = FixProtocol(m.Service)
	m.Pattern = args[2]
	m.PatternRegexp = m.getPatternRegexp(m.Pattern, args[3])
	m.VersionInfo = &FingerPrint{
		ProbeName:        "",
		MatchRegexString: "",
		Service:          m.Service,
		ProductName:      m.getVersionInfo(s, "PRODUCTNAME"),
		Version:          m.getVersionInfo(s, "VERSION"),
		Info:             m.getVersionInfo(s, "INFO"),
		Hostname:         m.getVersionInfo(s, "HOSTNAME"),
		OperatingSystem:  m.getVersionInfo(s, "OS"),
		DeviceType:       m.getVersionInfo(s, "DEVICE"),
		CPEs:             m.getCPEInfo(s),
		CPEAttributes:    m.getCPEAttributes(s),
	}
	return m
}

func (m *Match) getPatternRegexp(pattern string, opt string) *regexp2.Regexp {
	pattern = strings.ReplaceAll(pattern, `\0`, `\x00`)
	if opt != "" {
		if strings.Contains(opt, "i") == false {
			opt += "i"
		}
		if pattern[:1] == "^" {
			pattern = fmt.Sprintf("^(?%s:%s", opt, pattern[1:])
		} else {
			pattern = fmt.Sprintf("(?%s:%s", opt, pattern)
		}
		if pattern[len(pattern)-1:] == "$" {
			pattern = fmt.Sprintf("%s)$", pattern[:len(pattern)-1])
		} else {
			pattern = fmt.Sprintf("%s)", pattern)
		}
	}
	//pattern = regexp.MustCompile(`\\x[89a-f][0-9a-f]`).ReplaceAllString(pattern,".")
	regex, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		panic(err)
	}
	return regex
}

func (m *Match) getVersionInfo(s string, regID string) string {
	if matchVersionInfoRegexps[regID].MatchString(s) {
		return matchVersionInfoRegexps[regID].FindStringSubmatch(s)[1]
	} else {
		return ""
	}
}

// getCPEInfo 提取match语句中的所有CPE条目
func (m *Match) getCPEInfo(s string) []string {
	return matchCPERegexp.FindAllString(s, -1)
}

// getCPEAttributes 解析CPE条目为Attributes结构体
func (m *Match) getCPEAttributes(s string) []*common.Attributes {
	cpeStrings := m.getCPEInfo(s)
	var attributes []*common.Attributes

	for _, cpeStr := range cpeStrings {
		attr := common.NewAttributesWithCPE(cpeStr)
		if attr != nil {
			attributes = append(attributes, attr)
		}
	}

	return attributes
}

func (m *Match) makeVersionInfo(s string, f *FingerPrint) {
	f.Info = m.makeVersionInfoSubHelper(s, m.VersionInfo.Info)
	f.DeviceType = m.makeVersionInfoSubHelper(s, m.VersionInfo.DeviceType)
	f.Hostname = m.makeVersionInfoSubHelper(s, m.VersionInfo.Hostname)
	f.OperatingSystem = m.makeVersionInfoSubHelper(s, m.VersionInfo.OperatingSystem)
	f.ProductName = m.makeVersionInfoSubHelper(s, m.VersionInfo.ProductName)
	f.Version = m.makeVersionInfoSubHelper(s, m.VersionInfo.Version)
	f.Service = m.makeVersionInfoSubHelper(s, m.VersionInfo.Service)

	// 处理CPE信息，支持变量替换
	f.CPEs = m.makeVersionInfoCPEHelper(s, m.VersionInfo.CPEs)
	f.CPEAttributes = m.makeVersionInfoCPEAttributesHelper(s, f.CPEs)
}

func (m *Match) makeVersionInfoSubHelper(s string, pattern string) string {
	match, _ := m.PatternRegexp.FindStringMatch(s)
	if match == nil {
		return pattern
	}

	// 构建匹配组数组
	var sArr []string
	sArr = append(sArr, match.String()) // 完整匹配
	for i := 1; i < match.GroupCount(); i++ {
		group := match.GroupByNumber(i)
		if group != nil {
			sArr = append(sArr, group.String())
		} else {
			sArr = append(sArr, "")
		}
	}

	if len(sArr) == 1 {
		return pattern
	}
	if pattern == "" {
		return pattern
	}

	if matchVersionInfoHelperRegxP.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegxP.ReplaceAllStringFunc(pattern, func(repl string) string {
			a := matchVersionInfoHelperRegxP.FindStringSubmatch(repl)[1]
			return "$" + a
		})
	}

	if matchVersionInfoHelperRegx.MatchString(pattern) {
		pattern = matchVersionInfoHelperRegx.ReplaceAllStringFunc(pattern, func(repl string) string {
			i, _ := strconv.Atoi(matchVersionInfoHelperRegx.FindStringSubmatch(repl)[1])
			return sArr[i]
		})
	}
	pattern = strings.ReplaceAll(pattern, "\n", "")
	pattern = strings.ReplaceAll(pattern, "\r", "")
	return pattern
}

// makeVersionInfoCPEHelper 处理CPE列表，支持变量替换
func (m *Match) makeVersionInfoCPEHelper(s string, cpePatterns []string) []string {
	var processedCPEs []string

	for _, cpePattern := range cpePatterns {
		processedCPE := m.makeVersionInfoSubHelper(s, cpePattern)
		if processedCPE != "" {
			processedCPEs = append(processedCPEs, processedCPE)
		}
	}

	return processedCPEs
}

// makeVersionInfoCPEAttributesHelper 将处理后的CPE字符串转换为Attributes
func (m *Match) makeVersionInfoCPEAttributesHelper(s string, cpeStrings []string) []*common.Attributes {
	var attributes []*common.Attributes

	for _, cpeStr := range cpeStrings {
		attr := common.NewAttributesWithCPE(cpeStr)
		if attr != nil {
			attributes = append(attributes, attr)
		}
	}

	return attributes
}
