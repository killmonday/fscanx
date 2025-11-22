package wappalyzer

import (
	"bytes"
	"github.com/chainreactors/utils/httputils"
	"github.com/killmonday/fscanx/mylib/finger/common"
	"github.com/killmonday/fscanx/mylib/finger/resources"
	"strings"
)

// Wappalyze is a client for working with tech detection
type Wappalyze struct {
	fingerprints *CompiledFingerprints
}

// New creates a new tech detection instance
func NewWappalyzeEngine() (*Wappalyze, error) {
	wappalyze := &Wappalyze{
		fingerprints: &CompiledFingerprints{
			Apps: make(map[string]*CompiledFingerprint),
		},
	}

	err := wappalyze.loadFingerprints()
	if err != nil {
		return nil, err
	}

	err = wappalyze.Compile()
	if err != nil {
		return nil, err
	}
	return wappalyze, nil
}

func (engine *Wappalyze) Name() string {
	return "wappalyzer"
}

func (engine *Wappalyze) Len() int {
	return len(engine.fingerprints.Apps)
}

func (engine *Wappalyze) Compile() error {
	return nil
}

// loadFingerprints loads the fingerprints and compiles them
func (engine *Wappalyze) loadFingerprints() error {
	var fingerprintsStruct Fingerprints
	err := resources.UnmarshalData(resources.WappalyzerData, &fingerprintsStruct)
	if err != nil {
		return err
	}

	for app, fingerprint := range fingerprintsStruct.Apps {
		engine.fingerprints.Apps[app] = compileFingerprint(app, fingerprint)
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *Wappalyze) WebMatch(content []byte) common.Frameworks {
	resp := httputils.NewResponseWithRaw(content)
	if resp != nil {
		return engine.Fingerprint(resp.Header, httputils.ReadBody(resp))
	}
	return make(common.Frameworks)
}

// ServiceMatch 实现Service指纹匹配 - wappalyzer不支持Service指纹
func (engine *Wappalyze) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// wappalyzer不支持Service指纹识别
	return nil
}

func (engine *Wappalyze) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // wappalyzer支持Web指纹
		SupportService: false, // wappalyzer不支持Service指纹
	}
}

// Fingerprint identifies technologies on a target,
// based on the received response headers and body.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (engine *Wappalyze) Fingerprint(headers map[string][]string, body []byte) common.Frameworks {
	uniqueFingerprints := make(common.Frameworks)

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := engine.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.
	uniqueFingerprints.Merge(engine.checkHeaders(normalizedHeaders))

	cookies := engine.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		uniqueFingerprints.Merge(engine.checkCookies(cookies))
	}

	// Check for stuff in the body finally
	uniqueFingerprints.Merge(engine.checkBody(normalizedBody))
	return uniqueFingerprints
}

// FingerprintWithTitle identifies technologies on a target,
// based on the received response headers and body.
// It also returns the title of the page.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (engine *Wappalyze) FingerprintWithTitle(headers map[string][]string, body []byte) (common.Frameworks, string) {
	uniqueFingerprints := make(common.Frameworks)

	// Lowercase everything that we have received to check
	normalizedBody := bytes.ToLower(body)
	normalizedHeaders := engine.normalizeHeaders(headers)

	// Run header based fingerprinting if the number
	// of header checks if more than 0.

	uniqueFingerprints.Merge(engine.checkHeaders(normalizedHeaders))

	cookies := engine.findSetCookie(normalizedHeaders)
	// Run cookie based fingerprinting if we have a set-cookie header
	if len(cookies) > 0 {
		uniqueFingerprints.Merge(engine.checkCookies(cookies))
	}

	// Check for stuff in the body finally
	if strings.Contains(normalizedHeaders["content-type"], "text/html") {
		bodyTech := engine.checkBody(normalizedBody)
		uniqueFingerprints.Merge(bodyTech)
		title := engine.getTitle(body)
		return uniqueFingerprints, title
	}
	return uniqueFingerprints, ""
}

// FingerprintWithInfo identifies technologies on a target,
// based on the received response headers and body.
// It also returns basic information about the technology, such as description
// and website URL.
//
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (engine *Wappalyze) FingerprintWithInfo(headers map[string][]string, body []byte) map[string]AppInfo {
	apps := engine.Fingerprint(headers, body)
	result := make(map[string]AppInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := engine.fingerprints.Apps[app]; ok {
			result[app] = AppInfo{
				Description: fingerprint.description,
				Website:     fingerprint.website,
				CPE:         fingerprint.cpe,
			}
		}
	}

	return result
}

// FingerprintWithCats identifies technologies on a target,
// based on the received response headers and body.
// It also returns categories information about the technology, is there's any
// Body should not be mutated while this function is being called, or it may
// lead to unexpected things.
func (engine *Wappalyze) FingerprintWithCats(headers map[string][]string, body []byte) map[string]CatsInfo {
	apps := engine.Fingerprint(headers, body)
	result := make(map[string]CatsInfo, len(apps))

	for app := range apps {
		if fingerprint, ok := engine.fingerprints.Apps[app]; ok {
			result[app] = CatsInfo{
				Cats: fingerprint.cats,
			}
		}
	}

	return result
}
