package fingerprinthub

import (
	"bytes"
	"github.com/chainreactors/utils/httputils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
	"net/http"
	"strings"
)

func NewFingerPrintHubEngine() (*FingerPrintHubsEngine, error) {
	var fingerprints []*FingerPrintHub
	err := resources.UnmarshalData(resources.Fingerprinthubdata, &fingerprints)
	if err != nil {
		return nil, err
	}
	engine := &FingerPrintHubsEngine{FingerPrints: fingerprints}
	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type FingerPrintHubsEngine struct {
	FingerPrints []*FingerPrintHub `json:"fingerprints"`
	FaviconMap   map[string]string `json:"favicon_map,omitempty"`
}

func (engine *FingerPrintHubsEngine) Name() string {
	return "fingerprinthub"
}

func (engine *FingerPrintHubsEngine) Len() int {
	return len(engine.FingerPrints)
}

func (engine *FingerPrintHubsEngine) Compile() error {
	engine.FaviconMap = make(map[string]string)
	for _, finger := range engine.FingerPrints {
		finger.Compile()
		if len(finger.FaviconHash) > 0 {
			for _, hash := range finger.FaviconHash {
				engine.FaviconMap[hash] = finger.Name
			}
		}
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *FingerPrintHubsEngine) WebMatch(content []byte) common.Frameworks {
	resp := httputils.NewResponseWithRaw(content)
	if resp != nil {
		body := bytes.ToLower(httputils.ReadBody(resp))
		return engine.MatchWithHttpAndBody(resp.Header, string(body))
	}
	return make(common.Frameworks)
}

// ServiceMatch 实现Service指纹匹配 - fingerprinthub不支持Service指纹
func (engine *FingerPrintHubsEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// fingerprinthub不支持Service指纹识别
	return nil
}

func (engine *FingerPrintHubsEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // fingerprinthub支持Web指纹
		SupportService: false, // fingerprinthub不支持Service指纹
	}
}

func (engine *FingerPrintHubsEngine) MatchWithHttpAndBody(header http.Header, body string) common.Frameworks {
	frames := make(common.Frameworks)
	for _, finger := range engine.FingerPrints {
		frame := finger.Match(header, body)
		if frame != nil {
			frames.Add(frame)
		}
	}
	return frames
}

type FingerPrintHub struct {
	Name        string            `json:"name"`
	FaviconHash []string          `json:"favicon_hash,omitempty"`
	Keyword     []string          `json:"keyword,omitempty"`
	Path        string            `json:"path"`
	Headers     map[string]string `json:"headers,omitempty"`
}

func (f *FingerPrintHub) Compile() {
	for i, word := range f.Keyword {
		f.Keyword[i] = strings.ToLower(word)
	}

	for k, v := range f.Headers {
		f.Headers[strings.ToLower(k)] = strings.ToLower(v)
	}
}

func (f *FingerPrintHub) Match(header http.Header, body string) *common.Framework {
	if len(f.Keyword) == 0 && len(f.Headers) == 0 {
		return nil
	}
	status := false
	if f.MatchHeader(header) && f.MatchBody(body) { // fingerprinthub 指纹库规则为且
		status = true
	}

	if status {
		return common.NewFramework(f.Name, common.FrameFromFingerprintHub)
	}
	return nil
}

func (f *FingerPrintHub) MatchHeader(header http.Header) bool {
	if len(f.Headers) == 0 {
		return true
	}
	status := true
	for k, v := range f.Headers {
		if v == "*" && header.Get(k) != "" {
			status = true
		} else if h := header.Get(k); h != "" && strings.Contains(h, v) {
			status = true
		} else {
			return false
		}
	}
	return status
}

func (f *FingerPrintHub) MatchBody(body string) bool {
	if len(f.Keyword) == 0 {
		return true
	}
	if body == "" {
		return false
	}
	status := true
	for _, key := range f.Keyword {
		if strings.Contains(body, key) {
			status = true
		} else {
			return false
		}
	}
	return status
}
