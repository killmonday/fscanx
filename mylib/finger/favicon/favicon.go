package favicon

import (
	"github.com/chainreactors/utils/encode"
	"github.com/killmonday/fscanx/mylib/finger/common"
)

func NewFavicons() *FaviconsEngine {
	return &FaviconsEngine{
		Md5Fingers:  make(map[string]string),
		Mmh3Fingers: make(map[string]string),
	}
}

type FaviconsEngine struct {
	Md5Fingers  map[string]string
	Mmh3Fingers map[string]string
}

func (engine *FaviconsEngine) Compile() error {
	return nil
}

func (engine *FaviconsEngine) Name() string {
	return "favicon"
}

func (engine *FaviconsEngine) Len() int {
	return len(engine.Md5Fingers) + len(engine.Mmh3Fingers)
}

func (engine *FaviconsEngine) HashMatch(md5, mmh3 string) *common.Framework {
	if engine.Md5Fingers[md5] != "" {
		return common.NewFramework(engine.Md5Fingers[md5], common.FrameFromICO)
	}

	if engine.Mmh3Fingers[mmh3] != "" {
		return common.NewFramework(engine.Mmh3Fingers[mmh3], common.FrameFromICO)
	}
	return nil
}

// WebMatch 实现Web指纹匹配
func (engine *FaviconsEngine) WebMatch(content []byte) common.Frameworks {
	md5h := encode.Md5Hash(content)
	mmh3h := encode.Mmh3Hash32(content)
	fs := make(common.Frameworks)
	fs.Add(engine.HashMatch(md5h, mmh3h))
	return fs
}

// ServiceMatch 实现Service指纹匹配 - favicon不支持Service指纹
func (engine *FaviconsEngine) ServiceMatch(host string, portStr string, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
	// favicon不支持Service指纹识别
	return nil
}

func (engine *FaviconsEngine) Capability() common.EngineCapability {
	return common.EngineCapability{
		SupportWeb:     true,  // favicon支持Web指纹（特定的favicon指纹）
		SupportService: false, // favicon不支持Service指纹
	}
}
