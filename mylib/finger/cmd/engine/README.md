# Fingers Example

这是一个使用 Fingers 引擎进行指纹识别的命令行工具示例。

## 功能特性

- 支持多引擎指纹识别
- 支持 SSL 证书验证跳过
- 支持详细输出模式
- 支持 Favicon 专项检测
- 支持自定义资源文件覆盖

## 使用方法

### 基本用法

```bash
# 基本使用
go run example.go -u https://example.com

# 使用特定引擎
go run example.go -u https://example.com -e fingers,wappalyzer

# 显示详细信息
go run example.go -u https://example.com -v

# 忽略SSL证书验证
go run example.go -u https://example.com -k

# 仅检测favicon
go run example.go -u https://example.com -f
```

### 资源文件覆盖

工具支持覆盖所有内置的指纹库文件：

```bash
# Goby 指纹库
go run example.go -u https://example.com --goby custom_goby.json

# FingerPrintHub 指纹库
go run example.go -u https://example.com --fingerprinthub custom_fingerprinthub.json

# EHole 指纹库
go run example.go -u https://example.com --ehole custom_ehole.json

# Fingers 指纹库
go run example.go -u https://example.com --fingers custom_fingers.json

# Wappalyzer 指纹库
go run example.go -u https://example.com --wappalyzer custom_wappalyzer.json

# Aliases 配置
go run example.go -u https://example.com --aliases custom_aliases.yaml
```

资源文件说明：

- 支持 JSON 和 YAML 格式的资源文件
- JSON 文件会自动转换为 YAML 格式
- 非压缩文件会自动进行 gzip 压缩
- 可以同时覆盖多个资源文件

## 命令行参数

```
应用选项:
  -e, --engines=         指定要使用的引擎，多个引擎用逗号分隔 (默认: fingers,fingerprinthub,wappalyzer,ehole,goby)
  -k, --insecure        跳过 SSL 证书验证
  -u, --url=            要检测的目标 URL (必需)
  -v, --verbose         显示详细调试信息
  -f, --favicon         仅检测 favicon
      --goby=           覆盖 goby.json.gz
      --fingerprinthub= 覆盖 fingerprinthub_v3.json.gz
      --ehole=          覆盖 ehole.json.gz
      --fingers=        覆盖 fingers_http.json.gz
      --wappalyzer=     覆盖 wappalyzer.json.gz
      --aliases=        覆盖 aliases.yaml
```

## 输出示例

普通模式:

```
nginx/1.18.0 ubuntu/20.04
```

详细模式 (-v):

```
Loaded engines: fingers:1000 fingerprinthub:500 wappalyzer:300

Detected frameworks for https://example.com:
Name: nginx
Vendor: nginx
Product: nginx
Version: 1.18.0
CPE: cpe:/a:nginx:nginx:1.18.0
---
Name: ubuntu
Vendor: canonical
Product: ubuntu
Version: 20.04
CPE: cpe:/o:canonical:ubuntu:20.04
---
```

## 注意事项

1. 自定义资源文件必须符合对应引擎的数据格式要求
2. 建议先使用小规模数据测试自定义资源文件是否正确
3. 覆盖资源文件会影响所有使用该资源的引擎
4. 建议在测试环境中充分验证自定义资源文件后再在生产环境使用
