# CHANGELOG

## 2026-09-23

- 修复 ReadRawWithSize 池污染数据竞争（BL-MEM-001，P0）：所有返回路径拷贝后返回、defer 调整为先 Reset 后 Put、删除 DoWebScan 对共享 client.Timeout 的冗余赋值（兼数据竞争）
- POC 响应体读取限长（BL-MEM-002，P1）：getRespBody 对原始 body 与 gzip 解压后分别限制 4MB（超限静默截断，防全量读入与解压炸弹）；redis readreply 限长 16KB；go.mod 移除 pond 误标的 // indirect
- 新增回归测试：ReadRawWithSize 并发池隔离与错误路径拷贝语义（-race）、getRespBody 限长与 gzip 解压防护、readreply 16KB 上限
- 修复两个阻塞整包测试的既有测试 bug：ms17010_test.go 在 err 检查前解引用 nil conn 导致 panic；qqwry_test.go 在 qqwry.dat 缺失时改为跳过而非 panic

## 2026-06-11

- 新增 `-dp` 命令行选项：启用后对纯域名目标（如 `baidu.com`）自动组合 `-p` 指定的端口生成 `http://域名:端口` 和 `https://域名:端口` 格式的 URL
