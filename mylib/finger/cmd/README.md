# CMD 工具集

Fingers 库提供了一系列命令行工具，用于指纹验证、测试和转换等操作。

## 可用工具

### validate - 指纹验证工具

**位置**: `cmd/validate/`  
**功能**: 验证 fingers 和 alias 格式文件的语法正确性

**主要特性**:
- 支持 fingers 指纹文件验证
- 支持 alias 别名文件验证  
- 生成 JSON Schema
- 详细的错误报告和统计

**快速使用**:
```bash
cd cmd/validate
# 验证指纹文件
go run main.go -engine fingers fingerprints.yaml
# 验证别名文件  
go run main.go -engine alias aliases.yaml
# 查看帮助
go run main.go -help
```

### test - 指纹测试工具

**位置**: `cmd/test/`  
**功能**: 对实际目标进行指纹检测和验证

**主要特性**:
- 通用指纹检测
- Alias 配置测试
- 目标覆盖功能
- 指纹匹配验证
- 详细的测试报告

**快速使用**:
```bash
cd cmd/test
# 通用指纹检测
go run main.go -target https://nginx.org -detect-all
# Alias测试
go run main.go -alias aliases.yaml -name nginx_test
# 查看帮助  
go run main.go -help
```

### transform - 数据转换工具

**位置**: `cmd/transform/`  
**功能**: 转换不同格式的指纹数据

**主要特性**:
- 支持多种指纹格式转换
- 批量处理能力
- 数据清洗和标准化

**快速使用**:
```bash
cd cmd/transform
go run transform.go [options]
```

### nmap - Nmap 服务探测

**位置**: `cmd/nmap/`  
**功能**: 基于 Nmap service-probes 的服务指纹识别

**主要特性**:
- TCP/UDP 服务探测
- 基于 nmap-service-probes 数据库
- 端口服务识别

**快速使用**:
```bash
cd cmd/nmap
go run nmap.go [target] [port]
```

### engine - 引擎示例

**位置**: `cmd/engine/`  
**功能**: 展示如何使用 Fingers 引擎的示例代码

**主要特性**:
- 引擎初始化示例
- Web 指纹检测示例
- Service 指纹检测示例

**快速使用**:
```bash
cd cmd/engine
go run example.go
```

## 工具链使用流程

### 1. 开发阶段
使用 `validate` 工具验证指纹文件格式：
```bash
cd cmd/validate
go run main.go -engine fingers new_fingerprints.yaml
```

### 2. 测试阶段  
使用 `test` 工具测试指纹准确性：
```bash
cd cmd/test
go run main.go -alias test_aliases.yaml -name new_fingerprint_test
```

### 3. 部署阶段
集成到应用程序中使用 Fingers 引擎进行实际检测。

## 注意事项

- 所有工具都支持 `-help` 参数查看详细使用说明
- 工具需要在对应目录下运行，或使用完整路径
- 部分工具需要网络连接进行实际测试
- 建议在测试环境中先验证功能后再用于生产环境

## 贡献

如需添加新的命令行工具，请：
1. 在 `cmd/` 下创建新目录
2. 实现相应功能
3. 添加使用文档
4. 更新本 README 文件