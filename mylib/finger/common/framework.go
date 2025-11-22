package common

import (
	"github.com/chainreactors/utils/iutils"
	"strings"
)

// 指纹类型定义
type FingerprintType int

const (
	WebFingerprint     FingerprintType = iota // Web应用指纹
	ServiceFingerprint                        // 服务指纹
)

// 引擎能力定义
type EngineCapability struct {
	SupportWeb     bool // 支持Web指纹
	SupportService bool // 支持Service指纹
}

// Service指纹检测结果
type ServiceResult struct {
	Framework *Framework
	Vuln      *Vuln // 可选，只有部分引擎（如fingers）会返回漏洞信息
}

var NoGuess bool

type From int

const (
	FrameFromDefault From = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
	FrameFromRedirect
	FrameFromFingers
	FrameFromFingerprintHub
	FrameFromWappalyzer
	FrameFromEhole
	FrameFromGoby
	FrameFromNmap
)

func (f From) String() string {
	return FrameFromMap[f]
}

var FrameFromMap = map[From]string{
	FrameFromDefault:        "default",
	FrameFromACTIVE:         "active",
	FrameFromICO:            "ico",
	FrameFromNOTFOUND:       "404",
	FrameFromGUESS:          "guess",
	FrameFromRedirect:       "redirect",
	FrameFromFingers:        "fingers",
	FrameFromFingerprintHub: "fingerprinthub",
	FrameFromWappalyzer:     "wappalyzer",
	FrameFromEhole:          "ehole",
	FrameFromGoby:           "goby",
	FrameFromNmap:           "nmap",
}

func GetFrameFrom(s string) From {
	switch s {
	case "active":
		return FrameFromACTIVE
	case "404":
		return FrameFromNOTFOUND
	case "ico":
		return FrameFromICO
	case "guess":
		return FrameFromGUESS
	case "redirect":
		return FrameFromRedirect
	case "fingerprinthub":
		return FrameFromFingerprintHub
	case "wappalyzer":
		return FrameFromWappalyzer
	case "ehole":
		return FrameFromEhole
	case "goby":
		return FrameFromGoby
	case "fingers":
		return FrameFromFingers
	case "nmap":
		return FrameFromNmap

	default:
		return FrameFromDefault
	}
}

func NewFramework(name string, from From) *Framework {
	frame := &Framework{
		Name:       name,
		From:       from,
		Froms:      map[From]bool{from: true},
		Tags:       make([]string, 0),
		Attributes: NewAttributesWithAny(),
	}
	frame.Attributes.Product = name
	frame.Attributes.Part = "a"
	if from >= FrameFromFingers {
		frame.AddTag(from.String())
	}
	return frame
}

func NewFrameworkWithVersion(name string, from From, version string) *Framework {
	frame := NewFramework(name, from)
	frame.Attributes.Version = version
	//frame.Version = version
	return frame
}

type Framework struct {
	Name        string        `json:"name"`
	From        From          `json:"-"` // 指纹可能会有多个来源, 指纹合并时会将多个来源记录到froms中
	Froms       map[From]bool `json:"froms,omitempty"`
	Tags        []string      `json:"tags,omitempty"`
	IsFocus     bool          `json:"is_focus,omitempty"`
	*Attributes `json:"attributes,omitempty"`
}

func (f *Framework) String() string {
	var s strings.Builder

	s.WriteString("[")
	if f.IsFocus {
		s.WriteString("⚠️") // 感叹符号 \x26\xA0
	}
	s.WriteString(f.Name)
	if f.Version != "" {
		s.WriteString(":" + strings.Replace(f.Version, ":", "_", -1))
	}
	s.WriteString("]")

	//if len(f.Froms) > 1 {
	//	s.WriteString(":(")
	//	var froms []string
	//	for from, _ := range f.Froms {
	//		froms = append(froms, FrameFromMap[from])
	//	}
	//	s.WriteString(strings.Join(froms, " "))
	//	s.WriteString(")")
	//} else {
	//	for from, _ := range f.Froms {
	//		if from != FrameFromFingers {
	//			s.WriteString(":")
	//			s.WriteString(FrameFromMap[from])
	//		}
	//	}
	//}
	return strings.TrimSpace(s.String())
}

func (f *Framework) UpdateAttributes(attrs *Attributes) {
	if f.Version != "" {
		attrs.Version = f.Version
	}
	f.Attributes = attrs
}

func (f *Framework) CPE() string {
	return f.Attributes.String()
}

func (f *Framework) URI() string {
	return f.Attributes.URI()
}

func (f *Framework) WFN() string {
	return f.Attributes.WFNString()
}

func (f *Framework) IsGuess() bool {
	var is bool
	for from, _ := range f.Froms {
		if from == FrameFromGUESS {
			is = true
		} else {
			return false
		}
	}
	return is
}

func (f *Framework) AddTag(tag string) {
	if !f.HasTag(tag) {
		f.Tags = append(f.Tags, tag)
	}
}

func (f *Framework) HasTag(tag string) bool {
	for _, t := range f.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

type Frameworks map[string]*Framework

func (fs Frameworks) One() *Framework {
	for _, f := range fs {
		return f
	}
	return nil
}

func (fs Frameworks) List() []*Framework {
	var frameworks []*Framework
	for _, f := range fs {
		frameworks = append(frameworks, f)
	}
	return frameworks
}

func (fs Frameworks) Add(other *Framework) bool {
	if other == nil {
		return false
	}
	other.Name = strings.ToLower(other.Name)
	if frame, ok := fs[other.Name]; ok {
		for from, _ := range other.Froms {
			frame.Froms[from] = true
		}
		frame.Tags = iutils.StringsUnique(append(frame.Tags, other.Tags...))
		frame.UpdateAttributes(other.Attributes)
		return false
	} else {
		fs[other.Name] = other
		return true
	}
}

func (fs Frameworks) Merge(other Frameworks) int {
	// name, tag 统一小写, 减少指纹库之间的差异
	var n int
	for _, f := range other {
		f.Name = strings.ToLower(f.Name)
		if fs.Add(f) {
			n += 1
		}
	}
	return n
}

func (fs Frameworks) String() string {
	if fs == nil {
		return ""
	}
	frameworkStrs := make([]string, len(fs))
	i := 0
	for _, f := range fs {
		if NoGuess && f.IsGuess() {
			continue
		}
		frameworkStrs[i] = f.String()
		i++
	}
	return strings.Join(frameworkStrs, "||")
}

func (fs Frameworks) GetNames() []string {
	if fs == nil {
		return nil
	}
	var titles []string
	for _, f := range fs {
		if !f.IsGuess() {
			titles = append(titles, f.Name)
		}
	}
	return titles
}

func (fs Frameworks) URI() []string {
	if fs == nil {
		return nil
	}
	var uris []string
	for _, f := range fs {
		uris = append(uris, f.URI())
	}
	return uris
}

func (fs Frameworks) CPE() []string {
	if fs == nil {
		return nil
	}
	var cpes []string
	for _, f := range fs {
		cpes = append(cpes, f.CPE())
	}
	return cpes
}

func (fs Frameworks) WFN() []string {
	if fs == nil {
		return nil
	}
	var wfns []string
	for _, f := range fs {
		wfns = append(wfns, f.WFN())
	}
	return wfns
}

func (fs Frameworks) IsFocus() bool {
	if fs == nil {
		return false
	}
	for _, f := range fs {
		if f.IsFocus {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasTag(tag string) bool {
	for _, f := range fs {
		if f.HasTag(tag) {
			return true
		}
	}
	return false
}

func (fs Frameworks) HasFrom(from string) bool {
	for _, f := range fs {
		if f.Froms[GetFrameFrom(from)] {
			return true
		}
	}
	return false
}
