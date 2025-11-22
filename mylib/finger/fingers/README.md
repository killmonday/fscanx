# Fingers Engine SDK 文档

## 概述

`FingersEngine` 是 Fingers 库的核心引擎，提供丰富的 Web 应用和网络服务指纹识别能力。它支持 HTTP/HTTPS 协议的 Web 指纹匹配以及 TCP/UDP 协议的服务指纹匹配，包含被动检测和主动检测两种模式。

## 基本使用

### 1. 创建 FingersEngine 实例

```go
package main

import (
    "fmt"
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 使用默认配置创建引擎
    engine, err := fingers.NewFingersEngine()
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("FingersEngine 加载完成，包含 %d 个指纹\n", engine.Len())
}
```

### 2. Web 指纹检测

#### 从 HTTP 响应进行检测

```go
package main

import (
    "crypto/tls"
    "fmt"
    "net/http"
    
    "github.com/chainreactors/fingers/fingers"
    "github.com/chainreactors/utils/httputils"
)

func main() {
    // 创建引擎
    engine, err := fingers.NewFingersEngine()
    if err != nil {
        panic(err)
    }
    
    // 创建 HTTP 客户端
    client := &http.Client{
        Transport: &http.Transport{
            TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
        },
    }
    
    // 发送 HTTP 请求
    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    // 读取原始响应内容
    content := httputils.ReadRaw(resp)
    
    // 进行 Web 指纹匹配
    frameworks := engine.WebMatch(content)
    
    // 输出检测结果
    for _, framework := range frameworks {
        fmt.Printf("检测到: %s (来源: %s)\n", framework.Name, framework.From)
        if framework.Version != "" {
            fmt.Printf("版本: %s\n", framework.Version)
        }
        if len(framework.Tags) > 0 {
            fmt.Printf("标签: %v\n", framework.Tags)
        }
        fmt.Printf("CPE: %s\n", framework.CPE())
        fmt.Println("---")
    }
}
```

#### 从文件内容进行检测

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 创建引擎
    engine, err := fingers.NewFingersEngine()
    if err != nil {
        panic(err)
    }
    
    // 从文件读取 HTTP 响应内容
    content, err := os.ReadFile("response.raw")
    if err != nil {
        panic(err)
    }
    
    // 进行指纹匹配
    frameworks := engine.WebMatch(content)
    
    // 输出结果
    for _, framework := range frameworks {
        fmt.Printf("检测结果: %s\n", framework.String())
    }
}
```

### 3. 服务指纹检测

```go
package main

import (
    "fmt"
    "time"
    
    "github.com/chainreactors/fingers/fingers"
    "github.com/chainreactors/fingers/common"
)

func main() {
    // 创建引擎
    engine, err := fingers.NewFingersEngine()
    if err != nil {
        panic(err)
    }
    
    // 创建服务发送器
    sender := common.NewServiceSender(5 * time.Second)
    
    // 定义回调函数处理检测结果
    callback := func(result *common.ServiceResult) {
        if result.Framework != nil {
            fmt.Printf("检测到服务: %s\n", result.Framework.String())
        }
        if result.Vuln != nil {
            fmt.Printf("发现漏洞: %s\n", result.Vuln.Name)
        }
    }
    
    // 进行服务指纹检测
    result := engine.ServiceMatch("127.0.0.1", "80", 1, sender, callback)
    
    if result != nil && result.Framework != nil {
        fmt.Printf("最终结果: %s\n", result.Framework.String())
    }
}
```

## 高级功能

### 1. 使用自定义指纹库

`NewFingersEngineWithCustom` 函数允许您使用自定义的指纹库配置：

```go
package main

import (
    "fmt"
    "os"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 加载自定义 HTTP 指纹库
    httpConfig, err := os.ReadFile("custom_http_fingers.json")
    if err != nil {
        panic(err)
    }
    
    // 加载自定义 Socket 指纹库（可选）
    socketConfig, err := os.ReadFile("custom_socket_fingers.json")
    if err != nil {
        // Socket 配置是可选的
        socketConfig = nil
    }
    
    // 使用自定义配置创建引擎
    engine, err := fingers.NewFingersEngineWithCustom(httpConfig, socketConfig)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("使用自定义指纹库创建引擎成功，包含 %d 个指纹\n", engine.Len())
    
    // 正常使用引擎进行检测
    // ...
}
```

#### 自定义指纹库格式说明

- `httpConfig`: HTTP 指纹库配置，JSON 格式
- `socketConfig`: Socket 指纹库配置，JSON 格式（可以为 nil）

指纹库配置格式参考现有的指纹库文件结构。

### 2. 主动指纹检测

FingersEngine 支持主动指纹检测，会主动发送特定的探测包来获取更准确的指纹信息：

```go
package main

import (
    "fmt"
    "net/http"
    "time"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    engine, err := fingers.NewFingersEngine()
    if err != nil {
        panic(err)
    }
    
    // 定义发送器函数，用于主动探测
    sender := fingers.Sender(func(data []byte) ([]byte, bool) {
        // 根据探测数据构造 HTTP 请求
        client := &http.Client{Timeout: 5 * time.Second}
        
        // 这里是简化示例，实际实现需要根据 data 内容构造请求
        resp, err := client.Get("http://example.com/probe")
        if err != nil {
            return nil, false
        }
        defer resp.Body.Close()
        
        // 返回响应数据
        response := make([]byte, 1024)
        n, _ := resp.Body.Read(response)
        return response[:n], true
    })
    
    // 定义回调函数
    callback := fingers.Callback(func(framework *common.Framework, vuln *common.Vuln) {
        fmt.Printf("主动检测结果: %s\n", framework.String())
        if vuln != nil {
            fmt.Printf("发现漏洞: %s\n", vuln.Name)
        }
    })
    
    // 执行主动指纹检测
    frameworks, vulns := engine.HTTPActiveMatch(1, sender, callback)
    
    fmt.Printf("检测到 %d 个框架，%d 个漏洞\n", len(frameworks), len(vulns))
}
```

## 单个指纹测试

### Finger.Match 函数使用

`Finger.Match` 函数用于测试单个指纹规则的匹配情况。以下示例展示如何从 JSON/YAML 配置创建并测试单个指纹：

```go
package main

import (
    "encoding/json"
    "fmt"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 定义单个指纹的 JSON 配置
    fingerJSON := `{
        "name": "nginx",
        "rule": [
            {
                "method": "keyword",
                "keyword": ["nginx"]
            }
        ]
    }`
    
    // 反序列化创建指纹
    var finger fingers.Finger
    err := json.Unmarshal([]byte(fingerJSON), &finger)
    if err != nil {
        panic(err)
    }
    
    // 编译指纹规则
    err = finger.Compile(false)
    if err != nil {
        panic(err)
    }
    
    // 准备测试内容
    testContent := []byte(`HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Type: text/html

<html><body>Hello World</body></html>`)
    
    // 创建内容对象
    content := fingers.NewContent(testContent, "", true)
    
    // 测试指纹匹配（被动检测）
    framework, vuln, matched := finger.Match(content, 0, nil)
    
    if matched {
        fmt.Printf("✓ 指纹匹配成功: %s\n", framework.String())
        if framework.Version != "" {
            fmt.Printf("  版本: %s\n", framework.Version)
        }
    } else {
        fmt.Printf("✗ 指纹不匹配\n")
    }
}
```

### 使用 YAML 格式指纹

```go
package main

import (
    "fmt"
    
    "gopkg.in/yaml.v3"
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // YAML 格式的指纹配置
    fingerYAML := `
name: apache
rule:
  - method: keyword
    keyword: ["Apache"]
  - method: regex
    regex: "Apache/([\\d\\.]+)"
    version: "\\1"
`
    
    // 反序列化创建指纹
    var finger fingers.Finger
    err := yaml.Unmarshal([]byte(fingerYAML), &finger)
    if err != nil {
        panic(err)
    }
    
    // 编译指纹规则
    err = finger.Compile(false)
    if err != nil {
        panic(err)
    }
    
    // 测试内容
    testContent := []byte(`HTTP/1.1 200 OK
Server: Apache/2.4.41
Content-Type: text/html

<html><body>Apache Server</body></html>`)
    
    content := fingers.NewContent(testContent, "", true)
    
    // 执行匹配
    framework, vuln, matched := finger.Match(content, 0, nil)
    
    if matched {
        fmt.Printf("✓ 匹配成功: %s\n", framework.String())
        if framework.Version != "" {
            fmt.Printf("  版本: %s\n", framework.Version)
        }
    }
}
```

### 主动探测指纹测试

```go
package main

import (
    "encoding/json"
    "fmt"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 包含主动探测规则的指纹
    fingerJSON := `{
        "name": "custom-service",
        "rule": [
            {
                "method": "keyword",
                "keyword": ["custom"],
                "level": 1,
                "senddata": "GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n"
            }
        ]
    }`
    
    var finger fingers.Finger
    json.Unmarshal([]byte(fingerJSON), &finger)
    finger.Compile(false)
    
    // 定义简单的发送器
    sender := fingers.Sender(func(data []byte) ([]byte, bool) {
        // 模拟主动探测返回的响应
        response := []byte(`HTTP/1.1 200 OK
Server: custom-server

<html><body>Custom Admin Panel</body></html>`)
        return response, true
    })
    
    // 执行主动匹配（level=1 触发主动探测）
    framework, vuln, matched := finger.Match(nil, 1, sender)
    
    if matched {
        fmt.Printf("✓ 主动探测成功: %s\n", framework.String())
    }
}
```

## 引擎能力说明

FingersEngine 实现了 `EngineImpl` 接口，提供以下能力：

- **Web 指纹识别**: 支持 HTTP/HTTPS 协议的 Web 应用指纹识别
- **服务指纹识别**: 支持 TCP/UDP 协议的网络服务指纹识别
- **被动检测**: 基于现有响应内容进行指纹匹配
- **主动检测**: 发送特定探测包获取指纹信息
- **漏洞检测**: 在指纹匹配过程中发现潜在的安全问题
- **多协议支持**: HTTP, TCP, UDP 协议支持
- **版本识别**: 识别应用程序和服务的具体版本

## 指纹验证

### 命令行验证

使用 `validate` 命令可以快速验证指纹文件格式：

```bash
# 验证指纹文件
cd cmd/validate
go run main.go -engine fingers fingerprints.yaml

# 验证单个指纹
go run main.go -engine fingers single_finger.json
```

### 代码验证示例

在代码中验证 fingers 格式指纹：

```go
package main

import (
    "encoding/json"
    "fmt"
    "os"
    
    "github.com/chainreactors/fingers/fingers"
    "gopkg.in/yaml.v3"
)

func validateFingerprintFile(filename string) error {
    // 读取文件
    content, err := os.ReadFile(filename)
    if err != nil {
        return fmt.Errorf("读取文件失败: %w", err)
    }
    
    // 尝试解析为单个指纹
    var singleFinger fingers.Finger
    if err := json.Unmarshal(content, &singleFinger); err == nil {
        return validateSingleFingerprint(singleFinger)
    }
    
    // 尝试解析为指纹数组 (YAML)
    var fingerArray []fingers.Finger
    if err := yaml.Unmarshal(content, &fingerArray); err == nil {
        return validateFingerprintArray(fingerArray)
    }
    
    return fmt.Errorf("无法解析为有效的指纹格式")
}

func validateSingleFingerprint(finger fingers.Finger) error {
    // 验证必填字段
    if finger.Name == "" {
        return fmt.Errorf("指纹名称不能为空")
    }
    
    if len(finger.Rules) == 0 {
        return fmt.Errorf("指纹必须包含至少一个规则")
    }
    
    // 编译指纹以验证语法
    if err := finger.Compile(false); err != nil {
        return fmt.Errorf("指纹编译失败: %w", err)
    }
    
    fmt.Printf("✓ 指纹 '%s' 验证通过\n", finger.Name)
    return nil
}

func validateFingerprintArray(fingerprints []fingers.Finger) error {
    if len(fingerprints) == 0 {
        return fmt.Errorf("指纹数组不能为空")
    }
    
    validCount := 0
    for i, finger := range fingerprints {
        if err := validateSingleFingerprint(finger); err != nil {
            fmt.Printf("✗ 指纹[%d] '%s' 验证失败: %v\n", i, finger.Name, err)
        } else {
            validCount++
        }
    }
    
    fmt.Printf("验证完成: %d/%d 个指纹有效\n", validCount, len(fingerprints))
    return nil
}

func main() {
    if len(os.Args) < 2 {
        fmt.Println("用法: go run main.go <指纹文件>")
        return
    }
    
    filename := os.Args[1]
    if err := validateFingerprintFile(filename); err != nil {
        fmt.Printf("验证失败: %v\n", err)
        os.Exit(1)
    }
}
```

### 批量加载和验证

```go
package main

import (
    "fmt"
    
    "github.com/chainreactors/fingers/fingers"
)

func main() {
    // 直接使用 LoadFingers 加载和验证
    content := []byte(`[
        {
            "name": "nginx",
            "rule": [
                {
                    "regexps": {
                        "header": ["Server: nginx"]
                    },
                    "level": 0
                }
            ]
        }
    ]`)
    
    // LoadFingers 会自动验证格式
    fingerprintList, err := fingers.LoadFingers(content)
    if err != nil {
        fmt.Printf("加载失败: %v\n", err)
        return
    }
    
    // 编译验证每个指纹
    for _, finger := range fingerprintList {
        if err := finger.Compile(false); err != nil {
            fmt.Printf("指纹 '%s' 编译失败: %v\n", finger.Name, err)
        } else {
            fmt.Printf("指纹 '%s' 验证通过\n", finger.Name)
        }
    }
}
```

## 最佳实践

1. **引擎复用**: 创建引擎实例开销较大，建议在应用中复用引擎实例
2. **超时控制**: 在进行主动检测时，务必设置合适的超时时间
3. **错误处理**: 妥善处理网络请求和指纹匹配过程中的错误
4. **结果过滤**: 根据实际需求过滤和处理检测结果
5. **性能优化**: 对于大量目标的批量检测，考虑使用并发控制

## 注意事项

- 主动指纹检测可能会对目标系统产生影响，使用时需要谨慎
- 自定义指纹库需要遵循正确的格式规范
- 在生产环境中使用时，建议进行充分的测试
- 某些指纹可能存在误报，需要结合实际情况进行判断