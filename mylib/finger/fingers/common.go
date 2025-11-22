package fingers

import (
	"bytes"
	"github.com/chainreactors/utils/iutils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
)

func NewContent(c []byte, cert string, ishttp bool) *Content {
	content := &Content{
		Cert: cert,
	}
	c = iutils.UTF8ConvertBytes(c)
	if ishttp {
		content.UpdateContent(c)
	} else {
		content.Content = c
	}
	return content
}

type Content struct {
	Content []byte `json:"content"`
	Header  []byte `json:"header"`
	Body    []byte `json:"body"`
	Cert    string `json:"cert"`
}

func (c *Content) UpdateContent(content []byte) {
	c.Content = bytes.ToLower(content)
	cs := bytes.Index(c.Content, []byte("\r\n\r\n"))
	if cs != -1 {
		c.Body = c.Content[cs+4:]
		c.Header = c.Content[:cs]
	}
}

// LoadFingers 加载指纹 迁移到fingers包, 允许其他服务调用
func LoadFingers(content []byte) (fingers Fingers, err error) {
	err = resources.UnmarshalData(content, &fingers)
	if err != nil {
		return nil, err
	}

	return fingers, nil
}

type FingerMapper map[string]Fingers

type Fingers []*Finger

func (fs Fingers) GroupByPort() FingerMapper {
	fingermap := make(FingerMapper)
	for _, f := range fs {
		if f.DefaultPort != nil {
			for _, port := range resources.PrePort.ParsePortSlice(f.DefaultPort) {
				fingermap[port] = append(fingermap[port], f)
			}
		} else {
			fingermap["0"] = append(fingermap["0"], f)
		}
	}
	return fingermap
}

func (fs Fingers) GroupByMod() (Fingers, Fingers) {
	var active, passive Fingers
	for _, f := range fs {
		if f.IsActive {
			active = append(active, f)
		} else {
			passive = append(passive, f)
		}
	}
	return active, passive
}

func (fs Fingers) PassiveMatch(input *Content, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		// sender置空, 所有的发包交给spray的pool
		frame, vuln, ok := finger.PassiveMatch(input)
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}

func (fs Fingers) ActiveMatch(level int, sender Sender, callback Callback, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		frame, vuln, ok := finger.ActiveMatch(level, sender)
		if callback != nil {
			callback(frame, vuln)
		}
		if ok {
			frames.Add(frame)
			if vuln != nil {
				vulns[vuln.Name] = vuln
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}

func (fs Fingers) Match(input *Content, level int, sender Sender, callback Callback, stopAtFirst bool) (common.Frameworks, common.Vulns) {
	frames := make(common.Frameworks)
	vulns := make(common.Vulns)
	for _, finger := range fs {
		frame, vuln, ok := finger.Match(input, level, sender)
		if callback != nil {
			callback(frame, vuln)
		}
		if ok {
			ok = true
			frames.Add(frame)
			if vuln != nil {
				vulns.Add(vuln)
			}
			if stopAtFirst {
				break
			}
		}
	}
	return frames, vulns
}
