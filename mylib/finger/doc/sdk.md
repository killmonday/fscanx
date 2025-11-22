# Engine

## install

```
go get github.com/chainreactors/fingers@master
```

## 初始化

fingers 提供了一个预设配置的初始化API `NewEngine`, 提供初始化所有支持的引擎. 

```
func NewEngine(engines ...string) (*Engine, error)
```

如果engines为空则初始化所有引擎. 也可以选择自己需要的engine进行初始化.

```
FaviconEngine     = "favicon"
FingersEngine     = "fingers"
FingerPrintEngine = "fingerprinthub"
WappalyzerEngine  = "wappalyzer"
EHoleEngine       = "ehole"
GobyEngine        = "goby"
NmapEngine        = "nmap"
```

支持的引擎及能力：
- `fingers`: Web + Service指纹识别
- `fingerprinthub`: Web指纹识别
- `wappalyzer`: Web指纹识别
- `ehole`: Web指纹识别
- `goby`: Web指纹识别
- `nmap`: Service指纹识别
- `favicon`: Web指纹识别（图标）

```
need := []string{FingersEngine, FingerPrintEngine}
engine, err := NewEngine(need...)
if err != nil {
    panic(err)
}
```

## 指纹匹配

fingers引擎现在分为两大类：**Web指纹识别**和**Service指纹识别**。

### Web指纹识别

#### DetectResponse

通过http.Response匹配Web指纹

调用所有支持Web指纹的引擎对HTTP响应进行匹配

```golang
func TestEngine(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
       panic(err)
    }
    resp, err := http.Get("http://127.0.0.1:8080/")
    if err != nil {
       return
    }
    frames, err := engine.DetectResponse(resp)
    if err != nil {
       return
    }
    fmt.Println(frames.String())
}
```

#### DetectContent

通过[]bytes匹配Web指纹

如果已经进行过读取, 也可以使用`DetectContent(content []bytes)`代替`DetectResponse`

```
func TestEngine(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
       panic(err)
    }
    resp, err := http.Get("http://127.0.0.1:8080/")
    if err != nil {
       return
    }
	content := httputils.ReadRaw(resp)
	frames, err := engine.DetectContent(content)
	if err != nil {
		return
	}
    fmt.Println(frames.String())
}
```

#### DetectFavicon

因为favicon检测需要特殊的目录, 与其他指纹匹配传入的数据不同.

因此Engine提供了单独的`DetectFavicon` api

调用Favicon引擎对图标进行匹配:

```golang
func TestFavicon(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://baidu.com/favicon.ico")
	if err != nil {
		return
	}
	content := httputils.ReadRaw(resp)
	body, _, _ := httputils.SplitHttpRaw(content)
	frame := engine.DetectFavicon(body)
    fmt.Println(frame.String())
}
```

### Service指纹识别

Service指纹识别支持主动探测网络服务，目前支持的引擎包括：
- `fingers`: TCP socket指纹识别
- `nmap`: 基于nmap-service-probes的服务识别

#### DetectService

对指定主机和端口进行服务识别：

```golang
func TestServiceDetection(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
        panic(err)
    }
    
    // 创建ServiceSender
    sender := common.NewServiceSender(5 * time.Second)
    
    // 扫描指定主机端口
    results, err := engine.DetectService("127.0.0.1", 80, 3, sender, nil)
    if err != nil {
        return
    }
    
    for _, result := range results {
        if result.Framework != nil {
            fmt.Printf("Service: %s\n", result.Framework.String())
            if result.Framework.CPE() != "" {
                fmt.Printf("CPE: %s\n", result.Framework.CPE())
            }
        }
    }
}
```

#### ServiceMatch

底层Service指纹匹配接口，支持回调函数：

```golang
func TestServiceMatch(t *testing.T) {
    engine, err := NewEngine()
    if err != nil {
        panic(err)
    }
    
    sender := common.NewServiceSender(5 * time.Second)
    
    // 使用回调函数处理结果
    callback := func(result *common.ServiceResult) {
        if result.Framework != nil {
            fmt.Printf("Found: %s", result.Framework.String())
            if result.Framework.IsGuess() {
                fmt.Printf(" [GUESS]")
            }
            fmt.Printf("\n")
        }
    }
    
    results := engine.ServiceMatch("127.0.0.1", 22, 3, sender, callback)
    // results包含所有引擎的匹配结果
}
```

#### Guess功能

当服务端口开放但无法识别具体服务时，nmap引擎会根据端口号进行猜测：

```golang
// 对于开放但未识别的端口，nmap会根据常见端口服务进行猜测
// 例如：
// 22 -> ssh [GUESS]
// 80 -> http [GUESS] 
// 443 -> https [GUESS]
// 3306 -> mysql [GUESS]
```

## WebMatch / Match

`Match`是`DetectResponse`和`DetectContent`实际调用的接口, 区别在于`DetectContent`与`DetectResponse` 提供了一些性能优化与校验. 

Match只能接受`*http.Response`也意味着只接受合法的http返回值作为输入. 因为部分指纹引擎会有header, cookie相关的匹配part. 

```golang
func TestEngine_Match(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		panic(err)
	}
	resp, err := http.Get("http://127.0.0.1:8089")
	if err != nil {
		panic(err)
	}
	frames := engine.Match(resp)
	fmt.Println(frames.String())
}
```

## MatchWithEngines

指定引擎名字, 调用特定的Match

```golang
func TestEngine_MatchWithEngines(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	need := []string{FingersEngine, FingerPrintEngine}
	frames := engine.MatchWithEngines(resp, need...)
	for _, frame := range frames {
		t.Log(frame)
	}
}
```

## Disable

关闭特定引擎

`engine.Disable("ehole")`

## Enable

开启已经注册的引擎, 初始化的时候会自动Enable.

`engine.Enable("ehole")`

# 自定义引擎

## Impl

fingers中的引擎必须要实现以下接口才能注册到Engine中：
```
type EngineImpl interface {
	Name() string
	Compile() error
	Len() int
	Capability() common.EngineCapability

	// Web指纹匹配 - 基于HTTP响应内容
	WebMatch(content []byte) common.Frameworks

	// Service指纹匹配 - 主动探测服务
	ServiceMatch(host string, port int, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult
}
```

## 引擎能力声明

每个引擎需要通过`Capability()`方法声明自己支持的指纹类型：

```golang
type EngineCapability struct {
	SupportWeb     bool // 是否支持Web指纹识别
	SupportService bool // 是否支持Service指纹识别
}
```

例如：
- `nmap`引擎：只支持Service指纹识别
- `wappalyzer`引擎：只支持Web指纹识别  
- `fingers`引擎：同时支持Web和Service指纹识别

## 动态注册

实现了EngineImpl接口的struct将可以被注册到Engine中. 例如

```
func RegisterCustomEngine(engine *fingers.Engine) error {
    customEngine, err := NewCustomEngine()
    if err != nil {
       return err
    }
    engine.Register(customEngine)
    return nil
}
```

## 单指纹库调用

初始化单个指纹库并调用:

```golang
func TestFingersEngine(t *testing.T) {
	engine, err := fingers.NewFingersEngine()
	if err != nil {
		t.Error(err)
	}
	resp, err := http.Get("http://127.0.0.1")
	if err != nil {
		return
	}

	content := httputils.ReadRaw(resp)
	frames := engine.WebMatch(content)
	for _, frame := range frames {
		t.Log(frame)
	}
}
```

### 单独使用nmap引擎

```golang
func TestNmapEngine(t *testing.T) {
	engine, err := gonmap.NewNmapEngine()
	if err != nil {
		t.Error(err)
	}
	
	sender := common.NewServiceSender(5 * time.Second)
	result := engine.ServiceMatch("127.0.0.1", 22, 3, sender, nil)
	
	if result != nil && result.Framework != nil {
		fmt.Printf("Service: %s\n", result.Framework.String())
		if result.Framework.IsGuess() {
			fmt.Println("This is a guess based on port number")
		}
		if result.Framework.CPE() != "" {
			fmt.Printf("CPE: %s\n", result.Framework.CPE())
		}
	}
}
```

# Alias

多指纹库可能会出现同一个指纹在不同指纹库中存在不同命名的情况. 为了解决这个问题, 实现`alias`转换, 能让不同指纹库中的别名以统一的方式展示, 并且固定product与vendor, 能让没有实现CPE相关功能的指纹库也能支持CPE。

## Alias结构

`alias.yaml`在 https://github.com/chainreactors/fingers/blob/master/alias/aliases.yaml 中配置.

定义:

```go
type Alias struct {
	Name           string              `json:"name" yaml:"name"`
	normalizedName string
	Vendor         string              `json:"vendor" yaml:"vendor"`
	Product        string              `json:"product" yaml:"product"`
	Version        string              `json:"version,omitempty" yaml:"version"`
	Update         string              `json:"update,omitempty" yaml:"update"`
	Edition        string              `json:"edition,omitempty" yaml:"edition"`
	Label          string              `json:"label,omitempty" yaml:"label"`
	Priority       int                 `json:"priority,omitempty" yaml:"priority"`
	Target         []string            `json:"target,omitempty" yaml:"target"`
	AliasMap       map[string][]string `json:"alias" yaml:"alias"`
	Block          []string            `json:"block,omitempty" yaml:"block"`
	blocked        map[string]bool
}
```

### 新增字段说明

- **Label**: 逗号分隔的分类标签，用于对指纹进行分类，如 `web,server,proxy`
- **Priority**: 指纹优先级 (0-5)，用于指示指纹的重要程度或可信度
- **Target**: 测试目标URL或地址数组，支持URL格式如 `https://example.com` 或 `ip:port` 格式如 `192.168.1.1:80`

具体配置以nginx为例:

```yaml
- name: nginx               # 对外展示的名字
  vendor: nginx            # 厂商, 对应到CPE的vendor
  product: nginx           # 产品名, 对应到CPE的product
  label: web,server,proxy  # 分类标签
  priority: 2              # 优先级 (0-5)
  target:                  # 测试目标
    - https://nginx.org
    - nginx.org:80
  alias:                   # 别名映射
    fingers:              # 指纹库名
      - nginx             # 对应指纹库中的名字
    ehole:
      - nginx             # 可以是多个别名
    goby:
      - nginx
    wappalyzer:
      - Nginx
    fingerprinthub:
      - nginx
  block: []               # 需要屏蔽的引擎列表
```

## Alias验证

使用validate工具可以验证alias文件的格式：

```bash
# 验证alias文件
cd cmd/validate
go run main.go -engine alias aliases.yaml

# 输出alias JSON Schema
go run main.go -schema -engine alias
```

## Alias测试

使用test工具可以测试alias配置的正确性：

```bash
# 测试特定alias
cd cmd/test
go run main.go -alias aliases.yaml -name nginx_test

# 使用自定义目标覆盖alias配置
go run main.go -alias aliases.yaml -name nginx_test -target https://custom-nginx.com

# 对所有alias进行测试
go run main.go -alias aliases.yaml
``` 

### Block

配置了alias的映射后, 可以通过block来解决一些误报问题. 

以下配置表示: 如果goby识别到了`UFIDA NC`, 并且配置了block goby, 则这个结构不会合并到最终结果中. 

```
- name: 用友 NC     
  vendor: yonyou    
  product: NC		
  block:
  	- goby # 需要屏蔽的engine
  alias:            
    fingers:        
      - 用友NC       
    ehole:			
      - 用友NC
      - YONYOU NC
    goby:
      - UFIDA NC
    fingerprinthub:
      - yonyou-ufida-nc
```

## 初始化

Aliases初始化时将会进行一些性能优化的与功能特性. 

标准化所有指纹库的Name, 会进行以下操作

* 中文转拼音
* 大写转小写
* 忽略`_`, `-`, `[blank]`

添加指纹Name索引, 用来后续Find时加速等操作.

**默认情况下, 未特别配置到aliases.yaml的指纹, 将以`fingers`的原生指纹库作为基准值**

### NewAliases

alias提供了NewAliases, 将会使用`resources.AliasesData`的数据反序列化为`[]*Alias` 

```
func NewAliases(origin ...*Alias) (*Aliases, error) {
	var aliases []*Alias
	err := yaml.Unmarshal(resources.AliasesData, &aliases)
	if err != nil {
		return nil, err
	}
	aliasMap := &Aliases{
		Aliases: make(map[string]*Alias, len(aliases)+len(origin)),
		Map:     make(map[string]map[string]string),
	}

	err = aliasMap.Compile(append(origin, aliases...)) // yaml的优先级高于origin
	if err != nil {
		return nil, err
	}
	return aliasMap, nil
}
```

其中origin用来提供原先已经加载的alias配置. 例如在NewEngine中, 将会将`fingers`作为alias的基准值. 

```
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
```

### AppendAliases

alias提供了接口用来追加用户自定义的别名配置.  

```
func (as *Aliases) AppendAliases(other []*Alias) {
	err := as.Compile(other)
	if err != nil {
		return
	}
}
```

**需要注意的是, 追加的Alias中如果存在同名, 将会覆盖已有的配置.** 

内置的NewEngine的顺序为. 

1. fingers生成的别名
2. aliases.yaml 配置
3. 用户自定义加载的配置

越早加载的配置会被后续的加载的配置覆盖, 因此如果存在同名, 那么用户加载的配置是最高的优先级. 

## Find

### FindFramework

通过获取到的Framework获得统一的指纹命名.

```
func (as *Aliases) FindFramework(frame *common.Framework) (*Alias, bool) 
```

### FindAny

通过name查找是否存在统一命名

```
func (as *Aliases) FindAny(name string) (string, *Alias, bool)
```

### Find 

`FindAny`与`FindFramework`的底层接口

查找Aliases中是否已经配置了指定指纹库中的别名

```
func (as *Aliases) Find(engine, name string) (*Alias, bool)
```

# Framework

Engine的各种Detect或者Match的返回结果要么是`Frameworks`要么是`Framework`.

`Framework`就是fingers中的指纹标准输出格式. 它提供了到CPE标准的转换. 也提供了一些特殊的特性. 

* 支持重点关注指纹标记
* 支持自定义tag
* 支持保留指纹来源
* 支持导出到通用指纹格式

Framework定义:

```
type Framework struct {
    Name        string        `json:"name"`
    From        From          `json:"-"` // 指纹可能会有多个来源, 指纹合并时会将多个来源记录到froms中
    Froms       map[From]bool `json:"froms,omitempty"`
    Tags        []string      `json:"tags,omitempty"`
    IsFocus     bool          `json:"is_focus,omitempty"`
    *Attributes `json:"attributes,omitempty"`
}
```

Attributes即NVD定义的WFN所需要的属性. 
```
type Attributes struct {
	Part      string `json:"part" yaml:"part"`
	Vendor    string `json:"vendor" yaml:"vendor"`
	Product   string `json:"product" yaml:"product"`
	Version   string `json:"version,omitempty" yaml:"version,omitempty"`
	Update    string `json:"update,omitempty" yaml:"update,omitempty"`
	Edition   string `json:"edition,omitempty" yaml:"edition,omitempty"`
	SWEdition string `json:"sw_edition,omitempty" yaml:"sw_edition,omitempty"`
	TargetSW  string `json:"target_sw,omitempty" yaml:"target_sw,omitempty"`
	TargetHW  string `json:"target_hw,omitempty" yaml:"target_hw,omitempty"`
	Other     string `json:"other,omitempty" yaml:"other,omitempty"`
	Language  string `json:"language,omitempty" yaml:"language,omitempty"`
}
```

Framework的大部分api都是基础操作, 请直接参阅代码. 

## 输出

Framework的String()操作将会输出一个预置的格式.  尽可能简单的包含所有信息的输出, 但我也认为它并不是非常美观.

`tomcat:8.5.81:(goby fingers fingerprinthub)`

如果有需要, 可以自己实现一个格式化的函数

## From

指纹来源保留

需要注意的是指纹来源这一部分.  定义了目前内置的各种来源的可能性.  类型为int

```
type From int

const (
	FrameFromDefault From = iota
	FrameFromACTIVE
	FrameFromICO
	FrameFromNOTFOUND
	FrameFromGUESS
	FrameFromRedirect
	FrameFromFingers
	FrameFromFingerprintHub
	FrameFromWappalyzer
	FrameFromEhole
	FrameFromGoby
)
```

1-5是gogo内置的指纹来源, 包括了强制赋予, 主动识别, 图标, 404页面, 猜测, 重定向. 

6-10是第三方指纹引擎的数据.

建议使用时通过枚举值去定义. 

如果自定义指纹库想保留来源, 需要找一个自己喜欢的数字, 例如`666`, 然后将其注册到`FrameFromMap`中

```
var FrameFromMap = map[From]string{
	FrameFromDefault:        "default",
	FrameFromACTIVE:         "active",
	FrameFromICO:            "ico",
	FrameFromNOTFOUND:       "404",
	FrameFromGUESS:          "guess",
	FrameFromRedirect:       "redirect",
	FrameFromFingers:        "fingers",
	FrameFromFingerprintHub: "fingerprinthub",
	FrameFromWappalyzer:     "wappalyzer",
	FrameFromEhole:          "ehole",
	FrameFromGoby:           "goby",
}
```

自定义指纹引擎的代码中添加
```
var CustomSource = common.From(666)
func init() {
	common.FrameFromMap[CustomSource] = "custom"
}
```

## Frameworks

Frameworks是指纹检测结果的集合类型，提供丰富的操作方法。

```go
type Frameworks map[string]*Framework
```

### 常用操作

```go
package main

import (
    "fmt"
    "net/http"
    
    "github.com/chainreactors/fingers"
)

func main() {
    engine, err := fingers.NewEngine()
    if err != nil {
        panic(err)
    }
    
    resp, err := http.Get("https://example.com")
    if err != nil {
        return
    }
    
    frameworks, err := engine.DetectResponse(resp)
    if err != nil {
        return
    }
    
    // 获取数量和格式化输出
    fmt.Printf("检测到 %d 个框架: %s\n", frameworks.Len(), frameworks.String())
    
    // 获取特定框架
    if nginx, exists := frameworks.Get("nginx"); exists {
        fmt.Printf("找到 Nginx: %s\n", nginx.String())
    }
    
    // 转换为切片进行迭代
    for _, framework := range frameworks.ToSlice() {
        fmt.Printf("- %s (来源: %s)\n", framework.Name, framework.From)
        if framework.CPE() != "" {
            fmt.Printf("  CPE: %s\n", framework.CPE())
        }
    }
    
    // 过滤操作
    webServers := frameworks.Filter(func(f *common.Framework) bool {
        for _, tag := range f.Tags {
            if tag == "web-server" {
                return true
            }
        }
        return false
    })
    
    // 合并其他结果
    frameworks.Merge(otherFrameworks)
}

# MoreFingers

目前不提供公开访问

支持的指纹库

* tanggo
* cube

# 自定义SDK实现

## 创建自定义引擎

要实现自定义的指纹识别引擎，需要实现`EngineImpl`接口：

```golang
package customengine

import (
    "github.com/chainreactors/fingers/common"
)

type CustomEngine struct {
    name string
    // 指纹库数据
    fingerprints []CustomFingerprint
}

// 实现 EngineImpl 接口
func (e *CustomEngine) Name() string {
    return e.name
}

func (e *CustomEngine) Compile() error {
    // 编译指纹数据，如加载资源文件、预处理正则表达式等
    return nil
}

func (e *CustomEngine) Len() int {
    return len(e.fingerprints)
}

// 声明引擎能力
func (e *CustomEngine) Capability() common.EngineCapability {
    return common.EngineCapability{
        SupportWeb:     true,  // 支持Web指纹
        SupportService: false, // 不支持Service指纹
    }
}

// Web指纹匹配实现
func (e *CustomEngine) WebMatch(content []byte) common.Frameworks {
    frameworks := make(common.Frameworks)
    
    // 自定义匹配逻辑
    for _, fp := range e.fingerprints {
        if fp.Match(content) {
            framework := common.NewFramework(fp.Name, common.FrameFromDefault)
            // 设置CPE信息
            if fp.Vendor != "" || fp.Product != "" {
                framework.UpdateAttributes(&common.Attributes{
                    Part:    "a",
                    Vendor:  fp.Vendor,
                    Product: fp.Product,
                    Version: fp.Version,
                })
            }
            frameworks[fp.Name] = framework
        }
    }
    
    return frameworks
}

// Service指纹匹配实现（如果不支持Service指纹可以返回nil）
func (e *CustomEngine) ServiceMatch(host string, port int, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
    return nil // 此引擎不支持Service指纹
}
```

## 定义指纹结构

```golang
type CustomFingerprint struct {
    Name    string
    Vendor  string
    Product string
    Version string
    Rules   []MatchRule
}

type MatchRule struct {
    Type    string // header, body, title等
    Pattern string // 匹配模式
    Regex   *regexp.Regexp
}

func (fp *CustomFingerprint) Match(content []byte) bool {
    // 实现具体的匹配逻辑
    contentStr := string(content)
    
    for _, rule := range fp.Rules {
        switch rule.Type {
        case "body":
            if rule.Regex.MatchString(contentStr) {
                return true
            }
        case "header":
            // 解析HTTP头部进行匹配
            // ...
        }
    }
    return false
}
```

## 注册自定义引擎

### 方法一：直接注册到现有Engine

```golang
func main() {
    // 创建标准引擎
    engine, err := fingers.NewEngine()
    if err != nil {
        panic(err)
    }
    
    // 创建自定义引擎
    customEngine := &CustomEngine{
        name: "custom",
        fingerprints: loadCustomFingerprints(),
    }
    
    // 注册到引擎中
    success := engine.Register(customEngine)
    if !success {
        log.Println("Failed to register custom engine")
        return
    }
    
    // 使用引擎进行指纹识别
    resp, err := http.Get("http://example.com")
    if err != nil {
        return
    }
    
    frameworks, err := engine.DetectResponse(resp)
    if err != nil {
        return
    }
    
    fmt.Println("检测到的指纹：")
    for _, framework := range frameworks {
        fmt.Printf("- %s\n", framework.String())
        if framework.CPE() != "" {
            fmt.Printf("  CPE: %s\n", framework.CPE())
        }
    }
}
```

### 方法二：创建专用引擎初始化函数

```golang
func NewCustomEngine() (*CustomEngine, error) {
    engine := &CustomEngine{
        name: "custom",
    }
    
    // 加载指纹数据
    err := engine.loadFingerprints()
    if err != nil {
        return nil, err
    }
    
    return engine, nil
}

func (e *CustomEngine) loadFingerprints() error {
    // 从文件、数据库或其他数据源加载指纹
    // 例如：从JSON文件加载
    data, err := ioutil.ReadFile("custom_fingerprints.json")
    if err != nil {
        return err
    }
    
    var fingerprints []CustomFingerprint
    err = json.Unmarshal(data, &fingerprints)
    if err != nil {
        return err
    }
    
    // 预编译正则表达式
    for i := range fingerprints {
        for j := range fingerprints[i].Rules {
            regex, err := regexp.Compile(fingerprints[i].Rules[j].Pattern)
            if err != nil {
                return fmt.Errorf("failed to compile regex %s: %v", 
                    fingerprints[i].Rules[j].Pattern, err)
            }
            fingerprints[i].Rules[j].Regex = regex
        }
    }
    
    e.fingerprints = fingerprints
    return nil
}
```

## 完整使用示例

```golang
package main

import (
    "fmt"
    "net/http"
    
    "github.com/chainreactors/fingers"
    "path/to/your/customengine"
)

func main() {
    // 创建包含自定义引擎的引擎列表
    engine, err := fingers.NewEngine(fingers.FingersEngine, fingers.WappalyzerEngine)
    if err != nil {
        panic(err)
    }
    
    // 注册自定义引擎
    customEngine, err := customengine.NewCustomEngine()
    if err != nil {
        panic(err)
    }
    
    if !engine.Register(customEngine) {
        fmt.Println("Failed to register custom engine")
        return
    }
    
    // 验证引擎状态
    fmt.Printf("已注册引擎: %s\n", engine.String())
    
    // 使用特定引擎进行匹配
    resp, err := http.Get("http://example.com")
    if err != nil {
        return
    }
    
    // 只使用自定义引擎
    customFrameworks := engine.MatchWithEngines(resp, "custom")
    fmt.Printf("自定义引擎结果: %s\n", customFrameworks.String())
    
    // 使用所有引擎
    allFrameworks, _ := engine.DetectResponse(resp)
    fmt.Printf("所有引擎结果: %s\n", allFrameworks.String())
    
    // 禁用/启用引擎
    engine.Disable("custom")
    engine.Enable("custom")
}
```

## 高级功能

### Service指纹支持

如果自定义引擎需要支持Service指纹识别：

```golang
func (e *CustomEngine) ServiceMatch(host string, port int, level int, sender common.ServiceSender, callback common.ServiceCallback) *common.ServiceResult {
    // 根据level过滤探测内容
    probes := e.getProbesByLevel(level)
    
    for _, probe := range probes {
        // 发送探测数据
        response, err := sender.Send(host, port, probe.Data, "tcp")
        if err != nil {
            continue
        }
        
        // 匹配响应
        if framework := e.matchServiceResponse(response, probe); framework != nil {
            result := &common.ServiceResult{
                Framework: framework,
            }
            
            // 调用回调函数
            if callback != nil {
                callback(result)
            }
            
            return result
        }
    }
    
    return nil
}
```

### 与别名系统集成

自定义引擎的指纹会自动参与aliases.yaml的别名处理，确保输出统一化。

### CPE支持

确保Framework包含正确的CPE信息：

```golang
framework.UpdateAttributes(&common.Attributes{
    Part:    "a", // application
    Vendor:  "example",
    Product: "product",
    Version: "1.0.0",
})
```
