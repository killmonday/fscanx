package fingers

import (
	"errors"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/favicon"
	"github.com/killmonday/fscanx/mylib/finger/resources"
)

const (
	HTTPProtocol = "http"
	TCPProtocol  = "tcp"
	UDPProtocol  = "udp"
)

func NewFingersEngineWithCustom(httpConfig, socketConfig []byte) (*FingersEngine, error) {
	if httpConfig != nil {
		resources.FingersHTTPData = httpConfig
	}
	if socketConfig != nil {
		resources.FingersSocketData = socketConfig
	}
	return NewFingersEngine()
}

func NewFingersEngine() (*FingersEngine, error) {
	// httpdata must be not nil
	// socketdata can be nil
	if resources.PrePort == nil && resources.PortData != nil {
		_, err := resources.LoadPorts()
		if err != nil {
			return nil, err
		}
	}

	httpfs, err := LoadFingers(resources.FingersHTTPData)
	if err != nil {
		return nil, err
	}

	engine := &FingersEngine{
		HTTPFingers: httpfs,
		Favicons:    favicon.NewFavicons(),
	}

	engine.SocketFingers, err = LoadFingers(resources.FingersSocketData)
	if err != nil {
		return nil, err
	}

	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type FingersEngine struct {
	HTTPFingers              Fingers
	HTTPFingersActiveFingers Fingers
	SocketFingers            Fingers
	SocketGroup              FingerMapper
	Favicons                 *favicon.FaviconsEngine
}

func (engine *FingersEngine) Name() string {
	return "fingers"
}

func (engine *FingersEngine) Len() int {
	return len(engine.HTTPFingers) + len(engine.SocketFingers)
}

func (engine *FingersEngine) Compile() error {
	var err error
	if engine.HTTPFingers == nil {
		return errors.New("fingers is nil")
	}
	for _, finger := range engine.HTTPFingers {
		err = finger.Compile(false)
		if err != nil {
			return err
		}
		if finger.IsActive {
			engine.HTTPFingersActiveFingers = append(engine.HTTPFingersActiveFingers, finger)
		}
	}

	//初始化favicon规则
	for _, finger := range engine.HTTPFingers {
		for _, rule := range finger.Rules {
			if rule.Favicon != nil {
				for _, mmh3 := range rule.Favicon.Mmh3 {
					engine.Favicons.Mmh3Fingers[mmh3] = finger.Name
				}
				for _, md5 := range rule.Favicon.Md5 {
					engine.Favicons.Md5Fingers[md5] = finger.Name
				}
			}
		}
	}

	if engine.SocketFingers != nil {
		for _, finger := range engine.SocketFingers {
			err = finger.Compile(true)
			if err != nil {
				return err
			}
		}
		engine.SocketGroup = engine.SocketFingers.GroupByPort()
	}
	return nil
}

func (engine *FingersEngine) Append(fingers Fingers) error {
	for _, f := range fingers {
		err := f.Compile(false)
		if err != nil {
			return err
		}
		if f.Protocol == HTTPProtocol {
			engine.HTTPFingers = append(engine.HTTPFingers, f)
			if f.IsActive {
				engine.HTTPFingersActiveFingers = append(engine.HTTPFingersActiveFingers, f)
			}
		} else if f.Protocol == TCPProtocol {
			engine.SocketFingers = append(engine.SocketFingers, f)
		}
	}
	return nil
}

func (engine *FingersEngine) SocketMatch(content []byte, port string, level int, sender Sender, callback Callback) (*common.Framework, *common.Vuln) {
	// socket service only match one fingerprint
	var alreadyFrameworks = make(map[string]bool)
	input := NewContent(content, "", false)
	var fs common.Frameworks
	var vs common.Vulns
	if port != "" {
		fs, vs = engine.SocketGroup[port].Match(input, level, sender, callback, true)
		if len(fs) > 0 {
			return fs.One(), vs.One()
		}
		for _, fs := range engine.SocketGroup[port] {
			alreadyFrameworks[fs.Name] = true
		}
	}

	fs, vs = engine.SocketGroup["0"].Match(input, level, sender, callback, true)
	if len(fs) > 0 {
		return fs.One(), vs.One()
	}
	for _, fs := range engine.SocketGroup["0"] {
		alreadyFrameworks[fs.Name] = true
	}

	for _, fs := range engine.SocketGroup {
		for _, finger := range fs {
			if _, ok := alreadyFrameworks[finger.Name]; ok {
				continue
			} else {
				alreadyFrameworks[finger.Name] = true
			}

			frame, vuln, ok := finger.Match(input, level, sender)
			if ok {
				if callback != nil {
					callback(frame, vuln)
				}
				return frame, vuln
			}
		}
	}
	return nil, nil
}

// WebMatch 实现Web指纹匹配
func (engine *FingersEngine) WebMatch(content []byte) common.Frameworks {
	fs, _ := engine.HTTPMatch(content, "")
	return fs
}

// ServiceMatch 实现Service指纹匹配
func (engine *FingersEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	if sender == nil {
		return nil
	}

	// 创建自适应的Callback
	fingersCallback := func(framework *common.Framework, vuln *common.Vuln) {
		if callback != nil {
			result := &common.ServiceResult{
				Framework: framework,
				Vuln:      vuln,
			}
			callback(result)
		}
	}

	// 创建适配器将common.ServiceSender转换为fingers.Sender
	// fingers.Sender: func([]byte) ([]byte, bool)
	// common.ServiceSender.Send(host, port, data) ([]byte, error)
	fingersSender := Sender(func(data []byte) ([]byte, bool) {
		response, err := sender.Send(host, portStr, data, "tcp")
		if err != nil {
			return nil, false
		}
		return response, true
	})

	framework, vuln := engine.SocketMatch(nil, portStr, level, fingersSender, fingersCallback)

	return &common.ServiceResult{
		Framework: framework,
		Vuln:      vuln,
	}
}

func (engine *FingersEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true, // fingers支持Web指纹
		SupportService: true, // fingers支持Service指纹
	}
}

func (engine *FingersEngine) HTTPMatch(content []byte, cert string) (common.Frameworks, common.Vulns) {
	// input map[string]interface{}
	// content: []byte
	// cert: string
	return engine.HTTPFingers.PassiveMatch(NewContent(content, cert, true), false)
}

func (engine *FingersEngine) HTTPActiveMatch(level int, sender Sender, callback Callback) (common.Frameworks, common.Vulns) {
	return engine.HTTPFingersActiveFingers.ActiveMatch(level, sender, callback, false)
}
