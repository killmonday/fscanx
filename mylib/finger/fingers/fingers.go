package fingers

import (
	"github.com/chainreactors/logs"
	"github.com/chainreactors/utils"
	"github.com/killmonday/fscanx/mylib/finger/common"
)

var (
	OPSEC     = false
	FingerLog = logs.Log
)

type Finger struct {
	Name        string   `yaml:"name" json:"name" jsonschema:"required,title=Fingerprint Name,description=Unique identifier for the fingerprint,example=nginx"`
	Vendor      string   `yaml:"vendor,omitempty" json:"vendor,omitempty" jsonschema:"title=Vendor,description=Vendor or organization name,example=nginx"`
	Product     string   `yaml:"product,omitempty" json:"product,omitempty" jsonschema:"title=Product,description=Product or software name,example=nginx"`
	Protocol    string   `yaml:"protocol,omitempty" json:"protocol" jsonschema:"title=Protocol,description=Network protocol type,enum=http,enum=tcp,enum=udp,default=http,example=http"`
	Link        string   `yaml:"link,omitempty" json:"link,omitempty" jsonschema:"title=Link,description=Reference URL for the software,format=uri,example=https://nginx.org"`
	DefaultPort []string `yaml:"default_port,omitempty" json:"default_port,omitempty" jsonschema:"title=Default Ports,description=Default ports used by this service,example=80,example=443"`
	Focus       bool     `yaml:"focus,omitempty" json:"focus,omitempty" jsonschema:"title=Focus,description=Whether this is a high-priority fingerprint,default=false"`
	Rules       Rules    `yaml:"rule,omitempty" json:"rule,omitempty" jsonschema:"required,title=Rules,description=Matching rules for fingerprint detection"`
	Tags        []string `yaml:"tag,omitempty" json:"tag,omitempty" jsonschema:"title=Tags,description=Category tags for classification,example=web,example=server"`
	Opsec       bool     `yaml:"opsec,omitempty" json:"opsec,omitempty" jsonschema:"title=OPSEC,description=Whether this fingerprint uses operational security measures,default=false"`
	IsActive    bool     `yaml:"-" json:"-"`
}

func (finger *Finger) Compile(caseSensitive bool) error {
	if finger.Protocol == "" {
		finger.Protocol = HTTPProtocol
	}

	if len(finger.DefaultPort) == 0 {
		if finger.Protocol == HTTPProtocol {
			finger.DefaultPort = []string{"80"}
		}
	} else if utils.PrePort != nil {
		finger.DefaultPort = utils.ParsePortsSlice(finger.DefaultPort)
	}

	err := finger.Rules.Compile(finger.Name, caseSensitive)
	if err != nil {
		return err
	}

	for _, r := range finger.Rules {
		if r.IsActive {
			finger.IsActive = true
			break
		}
	}
	return nil
}

func (finger *Finger) ToResult(hasFrame, hasVuln bool, ver string, index int) (frame *common.Framework, vuln *common.Vuln) {
	if index >= len(finger.Rules) {
		return nil, nil
	}

	if hasFrame {
		if ver != "" {
			frame = common.NewFrameworkWithVersion(finger.Name, common.FrameFromFingers, ver)
		} else if finger.Rules[index].Version != "_" {
			frame = common.NewFrameworkWithVersion(finger.Name, common.FrameFromFingers, finger.Rules[index].Version)
		} else {
			frame = common.NewFramework(finger.Name, common.FrameFromFingers)
		}
	}

	if hasVuln {
		if finger.Rules[index].Vuln != "" {
			vuln = &common.Vuln{Name: finger.Rules[index].Vuln, SeverityLevel: HIGH, Framework: frame}
		} else if finger.Rules[index].Info != "" {
			vuln = &common.Vuln{Name: finger.Rules[index].Info, SeverityLevel: INFO, Framework: frame}
		} else {
			vuln = &common.Vuln{Name: finger.Name, SeverityLevel: INFO}
		}
		if finger.IsActive {
			vuln.Detail = map[string][]string{"path": []string{finger.Rules[index].SendDataStr}}
		}
	}

	frame.Vendor = finger.Vendor
	frame.Product = finger.Product
	return frame, vuln
}

func (finger *Finger) Match(content *Content, level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	// sender用来处理需要主动发包的场景, 因为不通工具中的传入指不相同, 因此采用闭包的方式自定义result进行处理, 并允许添加更多的功能.
	// 例如在spray中, sender可以用来配置header等, 也可以进行特定的path拼接
	// 如果sender留空只进行被动的指纹判断, 将无视rules中的senddata字段

	for i, rule := range finger.Rules {
		var ishttp bool
		var isactive bool
		if finger.Protocol == HTTPProtocol {
			ishttp = true
		}
		var c []byte
		var ok bool
		// 主动发包获取指纹
		if level >= rule.Level && rule.SendData != nil && sender != nil {
			if OPSEC == true && finger.Opsec == true {
				FingerLog.Debugf("(opsec!!!) skip active finger %s scan", finger.Name)
			} else {
				c, ok = sender(rule.SendData)
				if ok {
					isactive = true
					if ishttp {
						content.UpdateContent(c)
					} else {
						content.Content = c
					}
				}
			}
		}
		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &parsers.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			if isactive {
				frame.From = common.FrameFromFingers
				frame.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
			}
			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) PassiveMatch(content *Content) (*common.Framework, *common.Vuln, bool) {
	for i, rule := range finger.Rules {
		var ishttp bool
		if finger.Protocol == HTTPProtocol {
			ishttp = true
		}

		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &common.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}

func (finger *Finger) ActiveMatch(level int, sender Sender) (*common.Framework, *common.Vuln, bool) {
	if sender == nil {
		return nil, nil, false
	}

	for i, rule := range finger.Rules {
		var ishttp bool
		if finger.Protocol == HTTPProtocol {
			ishttp = true
		}
		// 主动发包获取指纹
		if !(level >= rule.Level && rule.SendData != nil) {
			return nil, nil, false
		}
		if OPSEC == true && finger.Opsec == true {
			FingerLog.Debugf("(opsec!!!) skip active finger %s scan", finger.Name)
			return nil, nil, false
		}
		content := &Content{}
		c, ok := sender(rule.SendData)
		if ok {
			if ishttp {
				content.UpdateContent(c)
			} else {
				content.Content = c
			}
		} else {
			return nil, nil, false
		}

		hasFrame, hasVuln, ver := RuleMatcher(rule, content, ishttp)
		if hasFrame {
			frame, vuln := finger.ToResult(hasFrame, hasVuln, ver, i)
			if finger.Focus {
				frame.IsFocus = true
			}
			//if vuln == nil && isactive {
			//	vuln = &common.Vuln{Name: finger.Name + " detect", SeverityLevel: INFO, Detail: map[string]interface{}{"path": rule.SendDataStr}}
			//}

			frame.From = common.FrameFromFingers
			frame.Froms = map[common.From]bool{common.FrameFromACTIVE: true}
			for _, tag := range finger.Tags {
				frame.AddTag(tag)
			}
			return frame, vuln, true
		}
	}
	return nil, nil, false
}
