# Ops Proof — offline Nginx log triage

Turn Nginx error logs into a short evidence report: what was observed, where it appeared, what to check next, and what the logs cannot establish.

**AI-assisted implementation. Synthetic examples, reproducible tests. No customer logs or customer case studies are included.**

## Run

Python 3.10+; standard library only.

```sh
python triage_nginx.py sample-error.log --output SAMPLE-REPORT-new.md
python triage_nginx.py sample-error.log --format json
python -m unittest -v
```

The CLI creates a new report and refuses to overwrite an existing file or the input log. It makes no network requests and does not execute repair commands. See [the example report](SAMPLE-REPORT.md) and [test results](TEST-RESULTS.txt).

## Covered symptoms

- Connection refused while connecting to an upstream.
- Timeout while connecting, distinguished from timeout while reading response headers.
- No space left on device.
- Permission denied.
- An upstream TLS certificate reported as expired.

Evidence includes source line numbers and occurrence counts. A report with no matches says **unknown**, not healthy. This is a deliberately small rule set, not an automatic root-cause determination or an incident-resolution system.

Common query parameters, authentication fields, quoted secret values, email addresses, IPv4 addresses and PEM private keys are masked. This is **not a complete sensitive-data detector**: hostnames, paths, IPv6 and free text may still require removal before sharing.

## Focused service enquiries

Available scope: a single Nginx/application startup or deployment incident, beginning with a review of sanitized logs. A delivery can include an evidence report, likely causes and remaining unknowns, a proposed fix, and a verification plan. Scope, fixed fee, timing and any server changes are agreed before customer work begins. AI participation is disclosed.

Open an issue with a non-sensitive problem summary, technology stack, expected outcome and budget. Do not post credentials, payment details, customer information or private server logs in a public issue. A sample generated from synthetic data is not evidence of a production repair.

## 中文

离线读取指定的 Nginx 错误日志，生成包含证据行号、次数、下一步检查及判断边界的报告。无第三方依赖，不连接服务器，不自动修复。示例使用合成日志，已有 12 项回归测试。

可询问单一应用启动、反向代理或部署问题的诊断服务。先看脱敏问题说明，确认固定范围、费用和验收标准，再执行客户任务。请通过 issue 提供不含秘密的信息；不要公开账号密码、付款信息或客户日志。

## References

- [Nginx connection timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_connect_timeout)
- [Nginx read timeout](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_read_timeout)
- [Nginx upstream TLS verification](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify)
