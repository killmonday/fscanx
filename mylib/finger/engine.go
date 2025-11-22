package fingers

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/chainreactors/utils/httputils"
	"github.com/killmonday/fscanx/mylib/finger/alias"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/ehole"
	"github.com/killmonday/fscanx/mylib/finger/favicon"
	"github.com/killmonday/fscanx/mylib/finger/fingerprinthub"
	"github.com/killmonday/fscanx/mylib/finger/fingers"
	"github.com/killmonday/fscanx/mylib/finger/goby"
	gonmap "github.com/killmonday/fscanx/mylib/finger/nmap"
	wappalyzer "github.com/killmonday/fscanx/mylib/finger/wappalyzer"
	"github.com/pkg/errors"
	"net/http"
	"strings"
)

const (
	FaviconEngine     = "favicon"
	FingersEngine     = "fingers"
	FingerPrintEngine = "fingerprinthub"
	WappalyzerEngine  = "wappalyzer"
	EHoleEngine       = "ehole"
	GobyEngine        = "goby"
	NmapEngine        = "nmap"
)

var (
	AllEngines           = []string{FingersEngine, FingerPrintEngine, WappalyzerEngine, EHoleEngine, GobyEngine, NmapEngine, FaviconEngine}
	DefaultEnableEngines = AllEngines

	NotFoundEngine = errors.New("engine not found")
)

func NewEngine(engines ...string) (*Engine, error) {
	if engines == nil {
		engines = DefaultEnableEngines
	}
	engine := &Engine{
		EnginesImpl:  make(map[string]EngineImpl),
		Enabled:      make(map[string]bool),
		Capabilities: make(map[string]common.EngineCapability),
	}
	var err error

	err = engine.InitEngine(FaviconEngine)
	if err != nil {
		return nil, err
	}
	for _, name := range engines {
		err = engine.InitEngine(name)
		if err != nil {
			return nil, err
		}
	}

	err = engine.Compile()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

type EngineImpl interface {
	Name() string
	Compile() error
	Len() int
	Capability() common.EngineCapability

	// Web指纹匹配 - 基于HTTP响应内容
	WebMatch(content []byte) common.Frameworks

	// Service指纹匹配 - 主动探测服务
	ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult
}

type Engine struct {
	EnginesImpl map[string]EngineImpl
	*alias.Aliases
	Enabled      map[string]bool
	Capabilities map[string]common.EngineCapability // 新增：记录各引擎能力
}

func (engine *Engine) String() string {
	var s strings.Builder
	for name, impl := range engine.EnginesImpl {
		s.WriteString(fmt.Sprintf(" %s:%d", name, impl.Len()))
	}
	return strings.TrimSpace(s.String())
}

func (engine *Engine) Compile() error {
	// 从所有引擎中填充Favicon引擎的数据
	if impl := engine.Fingers(); impl != nil {
		for hash, name := range impl.Favicons.Md5Fingers {
			engine.Favicon().Md5Fingers[hash] = name
		}
		for hash, name := range impl.Favicons.Mmh3Fingers {
			engine.Favicon().Mmh3Fingers[hash] = name
		}
	}

	if impl := engine.FingerPrintHub(); impl != nil {
		for hash, name := range impl.FaviconMap {
			engine.Favicon().Md5Fingers[hash] = name
		}
	}

	if impl := engine.EHole(); impl != nil {
		for hash, name := range impl.FaviconMap {
			engine.Favicon().Mmh3Fingers[hash] = name
		}
	}

	engine.Enabled[FaviconEngine] = false // 默认faviconEngine与其他引擎不同时使用

	// 将fingers指纹库的数据作为未配置alias的基准值
	var aliases []*alias.Alias
	if impl := engine.Fingers(); impl != nil {
		for _, finger := range impl.HTTPFingers {
			aliases = append(aliases, &alias.Alias{
				Name:    finger.Name,
				Vendor:  finger.Vendor,
				Product: finger.Product,
				AliasMap: map[string][]string{
					"fingers": []string{finger.Name},
				},
			})
		}
	}

	var err error
	engine.Aliases, err = alias.NewAliases(aliases...)
	if err != nil {
		return err
	}
	return nil
}

func (engine *Engine) Register(impl EngineImpl) bool {
	if impl == nil {
		return false
	}
	name := impl.Name()
	engine.EnginesImpl[name] = impl
	engine.Enabled[name] = true
	engine.Capabilities[name] = impl.Capability() // 自动记录引擎能力
	return true
}

func (engine *Engine) InitEngine(name string) error {
	var err error
	var impl EngineImpl
	if _, ok := engine.EnginesImpl[name]; !ok {
		switch name {
		case FingersEngine:
			impl, err = fingers.NewFingersEngine()
		case FingerPrintEngine:
			impl, err = fingerprinthub.NewFingerPrintHubEngine()
		case WappalyzerEngine:
			impl, err = wappalyzer.NewWappalyzeEngine()
		case EHoleEngine:
			impl, err = ehole.NewEHoleEngine()
		case GobyEngine:
			impl, err = goby.NewGobyEngine()
		case NmapEngine:
			impl, err = gonmap.NewNmapEngine()
		case FaviconEngine:
			impl = favicon.NewFavicons()
		default:
			return NotFoundEngine
		}
		if err != nil {
			return err
		}
		engine.Register(impl)
	}

	engine.Enabled[name] = true
	return nil
}

func (engine *Engine) Enable(name string) {
	if _, ok := engine.EnginesImpl[name]; ok {
		engine.Enabled[name] = true
	}
}

func (engine *Engine) Disable(name string) {
	engine.Enabled[name] = false
}

func (engine *Engine) Fingers() *fingers.FingersEngine {
	if impl, ok := engine.EnginesImpl[FingersEngine]; ok {
		return impl.(*fingers.FingersEngine)
	}
	return nil
}

func (engine *Engine) Favicon() *favicon.FaviconsEngine {
	if impl, ok := engine.EnginesImpl[FaviconEngine]; ok {
		return impl.(*favicon.FaviconsEngine)
	}
	return nil
}

func (engine *Engine) FingerPrintHub() *fingerprinthub.FingerPrintHubsEngine {
	if impl, ok := engine.EnginesImpl[FingerPrintEngine]; ok {
		return impl.(*fingerprinthub.FingerPrintHubsEngine)
	}
	return nil
}

func (engine *Engine) Wappalyzer() *wappalyzer.Wappalyze {
	if impl, ok := engine.EnginesImpl[WappalyzerEngine]; ok {
		return impl.(*wappalyzer.Wappalyze)
	}
	return nil
}

func (engine *Engine) EHole() *ehole.EHoleEngine {
	if impl, ok := engine.EnginesImpl[EHoleEngine]; ok {
		return impl.(*ehole.EHoleEngine)
	}
	return nil
}

func (engine *Engine) Goby() *goby.GobyEngine {
	if impl, ok := engine.EnginesImpl[GobyEngine]; ok {
		return impl.(*goby.GobyEngine)
	}
	return nil
}

func (engine *Engine) Nmap() *gonmap.NmapEngine {
	if impl, ok := engine.EnginesImpl[NmapEngine]; ok {
		return impl.(*gonmap.NmapEngine)
	}
	return nil
}

func (engine *Engine) GetEngine(name string) EngineImpl {
	if enabled, _ := engine.Enabled[name]; enabled {
		return engine.EnginesImpl[name]
	}
	return nil
}

// GetEnginesByType 根据指纹类型获取支持的引擎列表
func (engine *Engine) GetEnginesByType(fpType common.FingerprintType) []string {
	var engines []string
	for name, capability := range engine.Capabilities {
		if !engine.Enabled[name] {
			continue
		}
		switch fpType {
		case common.WebFingerprint:
			if capability.SupportWeb {
				engines = append(engines, name)
			}
		case common.ServiceFingerprint:
			if capability.SupportService {
				engines = append(engines, name)
			}
		}
	}
	return engines
}

// MatchByType 根据指纹类型进行匹配
func (engine *Engine) MatchByType(resp *http.Response, fpType common.FingerprintType) common.Frameworks {
	engines := engine.GetEnginesByType(fpType)
	return engine.MatchWithEngines(resp, engines...)
}

// Match use http.Response for web fingerprinting (deprecated, use WebMatch instead)
func (engine *Engine) Match(resp *http.Response) common.Frameworks {
	return engine.WebMatch(resp)
}

// WebMatch 专门用于Web指纹识别 - 保留原有性能优化
func (engine *Engine) WebMatch(resp *http.Response) common.Frameworks {
	content := httputils.ReadRaw(resp)
	// lower content for performance optimization
	lower := bytes.ToLower(content)
	body, header, _ := httputils.SplitHttpRaw(lower)
	combined := make(common.Frameworks)

	for name, ok := range engine.Enabled {
		if !ok {
			continue
		}

		// Check if engine supports web fingerprinting
		if !engine.Capabilities[name].SupportWeb {
			continue
		}

		var fs common.Frameworks
		switch name {
		case FingersEngine:
			var cert string
			if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
				cert = strings.Join(resp.TLS.PeerCertificates[0].DNSNames, ",")
			}
			fs, _ = engine.Fingers().HTTPMatch(lower, cert)
		case WappalyzerEngine:
			fs = engine.Wappalyzer().Fingerprint(resp.Header, body)
		case FingerPrintEngine:
			fs = engine.FingerPrintHub().MatchWithHttpAndBody(resp.Header, string(body))
		case EHoleEngine:
			fs = engine.EHole().MatchWithHeaderAndBody(string(header), string(body))
		case GobyEngine:
			fs = engine.Goby().MatchRaw(string(lower))
		case FaviconEngine:
			// Favicon engine is handled separately via MatchFavicon
			continue
		default:
			// For any other engines, use the generic WebMatch interface
			if impl, exists := engine.EnginesImpl[name]; exists {
				fs = impl.WebMatch(content)
			}
		}

		combined = engine.MergeFrameworks(combined, fs)
	}
	return combined
}

// ServiceMatch 专门用于Service指纹识别
func (engine *Engine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) []*common.ServiceResult {
	var results []*common.ServiceResult
	engines := engine.GetEnginesByType(common.ServiceFingerprint)

	for _, engineName := range engines {
		if eng := engine.GetEngine(engineName); eng != nil {
			result := eng.ServiceMatch(host, portStr, level, sender, callback)
			if result != nil && result.Framework != nil {
				results = append(results, result)
			}
		}
	}
	return results
}

// WebMatchWithEngines 用指定的引擎进行Web指纹匹配
func (engine *Engine) WebMatchWithEngines(content []byte, engines ...string) common.Frameworks {
	combined := make(common.Frameworks)
	for _, name := range engines {
		if impl, ok := engine.EnginesImpl[name]; ok && engine.Capabilities[name].SupportWeb {
			fs := impl.WebMatch(content)
			combined = engine.MergeFrameworks(combined, fs)
		}
	}
	return combined
}

// MatchWithEngines (deprecated, use WebMatchWithEngines instead)
func (engine *Engine) MatchWithEngines(resp *http.Response, engines ...string) common.Frameworks {
	content := httputils.ReadRaw(resp)
	return engine.WebMatchWithEngines(content, engines...)
}

func (engine *Engine) MatchFavicon(content []byte) common.Frameworks {
	favEngine := engine.Favicon()
	if favEngine != nil {
		return favEngine.WebMatch(content)
	}
	return make(common.Frameworks)
}

func (engine *Engine) MergeFrameworks(origin, other common.Frameworks) common.Frameworks {
	for _, frame := range other {
		aliasFrame, ok := engine.Aliases.FindFramework(frame)
		if aliasFrame != nil {
			if ok {
				frame.Name = aliasFrame.Name
				frame.UpdateAttributes(aliasFrame.ToWFN())
			}
			if aliasFrame.IsBlocked(frame.From.String()) {
				continue
			}
		}
		origin.Add(frame)
	}
	return origin
}

// DetectResponse Web指纹检测 - 基于HTTP响应
func (engine *Engine) DetectResponse(resp *http.Response) (common.Frameworks, error) {
	return engine.WebMatch(resp), nil
}

// DetectContent Web指纹检测 - 基于原始HTTP内容
func (engine *Engine) DetectContent(content []byte) (common.Frameworks, error) {
	resp, err := httputils.ReadResponse(bufio.NewReader(bytes.NewReader(content)))
	if err != nil {
		return nil, err
	}
	return engine.WebMatch(resp), nil
}

// DetectService Service指纹检测 - 基于主动探测
func (engine *Engine) DetectService(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) ([]*common.ServiceResult, error) {
	results := engine.ServiceMatch(host, portStr, level, sender, callback)
	return results, nil
}

// DetectFavicon Favicon指纹检测
func (engine *Engine) DetectFavicon(content []byte) *common.Framework {
	return engine.Favicon().WebMatch(content).One()
}
