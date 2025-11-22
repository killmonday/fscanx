package common

import (
	"fmt"
	"github.com/chainreactors/utils/iutils"
	"strings"
)

const (
	SeverityINFO int = iota + 1
	SeverityMEDIUM
	SeverityHIGH
	SeverityCRITICAL
	SeverityUnknown
)

func GetSeverityLevel(s string) int {
	switch s {
	case "info":
		return SeverityINFO
	case "medium":
		return SeverityMEDIUM
	case "high":
		return SeverityHIGH
	case "critical":
		return SeverityCRITICAL
	default:
		return SeverityUnknown
	}
}

var SeverityMap = map[int]string{
	SeverityINFO:     "info",
	SeverityMEDIUM:   "medium",
	SeverityHIGH:     "high",
	SeverityCRITICAL: "critical",
}

type Vuln struct {
	Name          string                 `json:"name"`
	Tags          []string               `json:"tags,omitempty"`
	Payload       map[string]interface{} `json:"payload,omitempty"`
	Detail        map[string][]string    `json:"detail,omitempty"`
	SeverityLevel int                    `json:"severity"`
	Framework     *Framework             `json:"-"`
}

func (v *Vuln) HasTag(tag string) bool {
	for _, t := range v.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (v *Vuln) GetPayload() string {
	return iutils.MapToString(v.Payload)
}

func (v *Vuln) GetDetail() string {
	var s strings.Builder
	for k, v := range v.Detail {
		s.WriteString(fmt.Sprintf(" %s:%s ", k, strings.Join(v, ",")))
	}
	return s.String()
}

func (v *Vuln) String() string {
	s := v.Name
	if payload := v.GetPayload(); payload != "" {
		s += fmt.Sprintf(" payloads:%s", iutils.AsciiEncode(payload))
	}
	if detail := v.GetDetail(); detail != "" {
		s += fmt.Sprintf(" payloads:%s", iutils.AsciiEncode(detail))
	}
	return s
}

type Vulns map[string]*Vuln

func (vs Vulns) One() *Vuln {
	for _, v := range vs {
		return v
	}
	return nil
}

func (vs Vulns) List() []*Vuln {
	var vulns []*Vuln
	for _, v := range vs {
		vulns = append(vulns, v)
	}
	return vulns
}

func (vs Vulns) Add(other *Vuln) bool {
	if _, ok := vs[other.Name]; !ok {
		vs[other.Name] = other
		return true
	}
	return false
}

func (vs Vulns) String() string {
	var s string

	for _, vuln := range vs {
		s += fmt.Sprintf("[ %s: %s ] ", SeverityMap[vuln.SeverityLevel], vuln.String())
	}
	return s
}

func (vs Vulns) Merge(other Vulns) int {
	// name, tag 统一小写, 减少指纹库之间的差异
	var n int
	for _, v := range other {
		v.Name = strings.ToLower(v.Name)
		if frame, ok := vs[v.Name]; ok {
			if len(v.Tags) > 0 {
				for i, tag := range v.Tags {
					v.Tags[i] = strings.ToLower(tag)
				}
				frame.Tags = iutils.StringsUnique(append(frame.Tags, v.Tags...))
			}
		} else {
			vs[v.Name] = v
			n += n
		}
	}
	return n
}

func (vs Vulns) HasTag(tag string) bool {
	for _, f := range vs {
		if f.HasTag(tag) {
			return true
		}
	}
	return false
}
