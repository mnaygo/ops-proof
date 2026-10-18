# 离线 Nginx 日志诊断样例

输入行数：7；命中行数：6。

本报告只证明日志中出现的症状，后续检查尚未执行。

## upstream-refused · 2 次

连接上游时被拒绝。

证据：

    L1: 2026/10/18 09:00:01 [error] 101#101: *1 connect() failed (111: Connection refused) while connecting to upstream, client: [IP], request: "GET /api/status?[QUERY REDACTED] HTTP/1.1", upstream: "http://[IP]:3000/api/status?[QUERY REDACTED]"
    L2: 2026/10/18 09:00:03 [error] 101#101: *2 connect() failed (111: Connection refused) while connecting to upstream, client: [IP], request: "GET /health HTTP/1.1", upstream: "http://[IP]:3000/health"

下一步：核对该时刻的服务状态、监听地址与端口，并从 Nginx 所在网络验证连接。

判断边界：仅凭这一行不能确定是进程退出、端口错误、网络隔离还是主动拒绝规则。

## upstream-read-timeout · 1 次

等待上游响应头超时。

证据：

    L3: 2026/10/18 09:01:00 [error] 101#101: *3 upstream timed out (110: Connection timed out) while reading response header from upstream, request: "POST /api/report HTTP/1.1"

下一步：关联相同时间与请求的应用日志，检查慢请求、数据库等待和资源占用。

判断边界：不能仅凭日志证明增加超时时间就能解决问题。

## disk-full · 1 次

操作报告存储空间不足。

证据：

    L4: 2026/10/18 09:02:00 [crit] 101#101: *4 pwrite() failed (28: No space left on device) while writing to client

下一步：检查对应挂载点的空间、inode、配额和日志占用。

判断边界：不能只凭这行判断整个系统盘已满；不应直接删除文件。

## permission-denied · 1 次

文件或资源访问被拒绝。

证据：

    L5: 2026/10/18 09:03:00 [error] 101#101: *5 open() "/srv/demo/static/logo.svg" failed (13: Permission denied)

下一步：核对实际运行身份、路径逐级权限、访问控制与挂载选项。

判断边界：不能确定只是文件权限位问题；不建议用 chmod 777 处理。

## upstream-tls-expired · 1 次

上游 TLS 校验报告证书过期。

证据：

    L6: 2026/10/18 09:04:00 [error] 101#101: *6 upstream SSL certificate verify error: (10:certificate has expired) while SSL handshaking to upstream

下一步：检查被访问上游的证书有效期、证书链及本机时间。

判断边界：这不等于网站对外提供的证书也已过期。

## 适用边界

- 只分析提供的日志，未登录服务器，未执行修复。
- 未命中规则不表示服务健康。
- 遮盖常见结构化秘密；主机名、路径、自由文本及 IPv6 等仍可能包含敏感信息，分享前必须复核。
