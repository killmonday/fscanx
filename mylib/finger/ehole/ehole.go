package ehole

import (
	"bytes"
	"github.com/chainreactors/utils/httputils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
	"regexp"
	"strings"
)

const (
	KeywordMethod = "keyword"
	RegularMethod = "regular"
	FaviconMethod = "faviconhash"
)

const (
	BodyLocation   = "body"
	HeaderLocation = "header"
	TitleLocation  = "title"
)

func NewEHoleEngine() (*EHoleEngine, error) {
	var engine *EHoleEngine
	err := resources.UnmarshalData(resources.EholeData, &engine)
	if err != nil {
		return nil, err
	}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type EHoleEngine struct {
	Fingerprints []*Fingerprint `json:"fingerprint"`
	FaviconMap   map[string]string
}

func (engine *EHoleEngine) Name() string {
	return "ehole"
}

func (engine *EHoleEngine) Len() int {
	return len(engine.Fingerprints)
}

func (engine *EHoleEngine) Compile() error {
	engine.FaviconMap = make(map[string]string)
	for _, finger := range engine.Fingerprints {
		if finger.Method == RegularMethod {
			finger.compiledRegexp = make([]*regexp.Regexp, len(finger.Keyword))
			for i, reg := range finger.Keyword {
				/** Fix bug
				 * 使用 append 会导致数组前面有 len(finger.Keyword) 个 nil，在 `reg.Match` 时导致 panic（144行）
				 * 匹配引擎会将内容全部转小写，正则表达式也需要转小写
				 */
				//finger.compiledRegexp = append(finger.compiledRegexp, regexp.MustCompile(reg))
				finger.compiledRegexp[i] = regexp.MustCompile(strings.ToLower(reg))
			}
		} else if finger.Method == KeywordMethod {
			finger.LowerKeyword = make([]string, len(finger.Keyword))
			for i, word := range finger.Keyword {
				//finger.lowerKeyword = append(finger.lowerKeyword, strings.ToLower(word))
				finger.LowerKeyword[i] = strings.ToLower(word)
			}
		} else if finger.Method == FaviconMethod {
			for _, hash := range finger.Keyword {
				engine.FaviconMap[hash] = finger.Cms
			}
		}
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *EHoleEngine) WebMatch(content []byte) common.Frameworks {
	var header, body string
	content = bytes.ToLower(content)
	bodyBytes, headerBytes, ok := httputils.SplitHttpRaw(content)
	if ok {
		header = string(headerBytes)
		body = string(bodyBytes)
		return engine.MatchWithHeaderAndBody(header, body)
	}
	return make(common.Frameworks)
}

// ServiceMatch 实现Service指纹匹配 - ehole不支持Service指纹
func (engine *EHoleEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// ehole不支持Service指纹识别
	return nil
}

func (engine *EHoleEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // ehole支持Web指纹
		SupportService: false, // ehole不支持Service指纹
	}
}

func (engine *EHoleEngine) MatchWithHeaderAndBody(header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.Fingerprints {
		frame := finger.Match(header, body)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type Fingerprint struct {
	Cms            string   `json:"cms"`
	Method         string   `json:"method"`
	Location       string   `json:"location"`
	Keyword        []string `json:"keyword"`
	LowerKeyword   []string `json:"-"`
	compiledRegexp []*regexp.Regexp
}

func (finger *Fingerprint) Match(header, body string) *common.Framework {
	switch finger.Location {
	case BodyLocation, TitleLocation:
		if finger.MatchMethod(body) {
			return common.NewFramework(finger.Cms, common.FrameFromEhole)
		}
	case HeaderLocation:
		if finger.MatchMethod(header) {
			return common.NewFramework(finger.Cms, common.FrameFromEhole)
		}
	default:
		return nil
	}
	return nil
}

func (finger *Fingerprint) MatchMethod(content string) bool {
	switch finger.Method {
	case KeywordMethod:
		return finger.MatchKeyword(content)
	case RegularMethod:
		return finger.MatchRegexp(content)
	default:
		return false
	}
}

func (finger *Fingerprint) MatchKeyword(content string) bool {
	// Fix bug: 匹配引擎会将内容全部转小写，这里需要使用 LowerKeyword 检测
	//for _, k := range finger.Keyword {
	for _, k := range finger.LowerKeyword {
		if !strings.Contains(content, k) {
			return false
		}
	}
	return true
}

func (finger *Fingerprint) MatchRegexp(content string) bool {
	for _, reg := range finger.compiledRegexp {
		if !reg.Match([]byte(content)) {
			return false
		}
	}
	return true
}
