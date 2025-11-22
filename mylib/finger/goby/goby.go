package goby

import (
	"bytes"
	"github.com/chainreactors/words/logic"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
	"strings"
)

func NewGobyEngine() (*GobyEngine, error) {
	var fingers []*GobyFinger
	err := resources.UnmarshalData(resources.GobyData, &fingers)
	if err != nil {
		return nil, err
	}
	engine := &GobyEngine{
		Fingers: fingers,
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type GobyEngine struct {
	Fingers []*GobyFinger
}

func (engine *GobyEngine) Name() string {
	return "goby"
}

func (engine *GobyEngine) Len() int {
	return len(engine.Fingers)
}

func (engine *GobyEngine) Compile() error {
	for _, finger := range engine.Fingers {
		err := finger.Compile()
		if err != nil {
			return err
		}
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *GobyEngine) WebMatch(content []byte) common.Frameworks {
	return engine.MatchRaw(string(bytes.ToLower(content)))
}

// ServiceMatch 实现Service指纹匹配 - goby不支持Service指纹
func (engine *GobyEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// goby不支持Service指纹识别
	return nil
}

func (engine *GobyEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // goby支持Web指纹
		SupportService: false, // goby不支持Service指纹
	}
}

func (engine *GobyEngine) MatchRaw(raw string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.Fingers {
		frame := finger.Match(raw)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type gobyRule struct {
	Label   string `json:"label"`
	Feature string `json:"feature"`
	IsEquel bool   `json:"is_equal"` //是则判断条件相等，否则判断不等
}

type GobyFinger struct {
	Logic     string `json:"logic"`
	logicExpr *logic.Program
	Name      string     `json:"name"`
	Rule      []gobyRule `json:"rule"`
}

func (finger *GobyFinger) Compile() error {
	for i, r := range finger.Rule {
		// Fix bug: golang 不支持直接使用 `r.Feature` 的方式修改循环内的值
		//r.Feature = strings.ToLower(r.Feature)
		finger.Rule[i].Feature = strings.ToLower(r.Feature)
	}

	finger.logicExpr = logic.Compile(finger.Logic)
	return nil
}

func (finger *GobyFinger) Match(raw string) *common.Framework {
	env := make(map[string]bool)
	for _, r := range finger.Rule {
		match := strings.Contains(raw, r.Feature)
		env[r.Label] = match == r.IsEquel
	}

	matched := logic.EvalLogic(finger.logicExpr, env)

	if matched {
		return common.NewFramework(finger.Name, common.FrameFromGoby)
	}
	return nil
}
