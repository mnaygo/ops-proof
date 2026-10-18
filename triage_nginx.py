"""Offline, read-only Nginx error-log triage. Python standard library only."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import ipaddress
import json
from pathlib import Path
import re
import sys


@dataclass(frozen=True)
class Rule:
    key: str
    pattern: str
    observation: str
    next_check: str
    limit: str


RULES = (
    Rule("upstream-refused", r"connect\(\) failed \((?:111|61|10061):[^\n]*[Cc]onnection refused\).*connecting to upstream",
         "连接上游时被拒绝。", "核对该时刻的服务状态、监听地址与端口，并从 Nginx 所在网络验证连接。",
         "仅凭这一行不能确定是进程退出、端口错误、网络隔离还是主动拒绝规则。"),
    Rule("upstream-read-timeout", r"upstream timed out[^\n]*reading response header from upstream",
         "等待上游响应头超时。", "关联相同时间与请求的应用日志，检查慢请求、数据库等待和资源占用。",
         "不能仅凭日志证明增加超时时间就能解决问题。"),
    Rule("upstream-connect-timeout", r"upstream timed out[^\n]*connecting to upstream",
         "建立上游连接超时。", "核对目标可达性、路由、防火墙和连接积压。",
         "连接超时与读取响应超时是不同阶段；本条不证明应用执行缓慢。"),
    Rule("disk-full", r"(?:\(28:\s*[Nn]o space left on device\)|[Nn]o space left on device)",
         "操作报告存储空间不足。", "检查对应挂载点的空间、inode、配额和日志占用。",
         "不能只凭这行判断整个系统盘已满；不应直接删除文件。"),
    Rule("permission-denied", r"\((?:13|5):\s*[Pp]ermission denied\)",
         "文件或资源访问被拒绝。", "核对实际运行身份、路径逐级权限、访问控制与挂载选项。",
         "不能确定只是文件权限位问题；不建议用 chmod 777 处理。"),
    Rule("upstream-tls-expired", r"(?:certificate verify failed[^\n]*certificate has expired|certificate has expired[^\n]*SSL handshak)",
         "上游 TLS 校验报告证书过期。", "检查被访问上游的证书有效期、证书链及本机时间。",
         "这不等于网站对外提供的证书也已过期。"),
)


def redact(text: str) -> str:
    # Redact common structured secrets; this is not a general PII detector.
    text = re.sub(r"-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----",
                  lambda m: "[PRIVATE KEY REDACTED]" + "\n" * m.group().count("\n"), text, flags=re.S)
    text = re.sub(r"(?i)(https?://)[^\s/@]+:[^\s/@]+@", r"\1[USERINFO]@", text)
    text = re.sub(r"\?[^\s\"'<>]*", "?[QUERY REDACTED]", text)
    text = re.sub(r"(?i)\b(?:authorization|cookie|set-cookie)\s*[:=][^\r\n]*", "[AUTH FIELD REDACTED]", text)
    text = re.sub(r'''(?i)\b(?:password|passwd|api[_-]?key|access[_-]?token|secret)\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s,;"']+)''',
                  "[SECRET REDACTED]", text)
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "[EMAIL]", text)
    def hide_ip(match: re.Match) -> str:
        try:
            ipaddress.ip_address(match.group())
            return "[IP]"
        except ValueError:
            return match.group()
    return re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", hide_ip, text)


def analyze(text: str) -> dict:
    # Match original content, render only redacted content, preserve original line numbers.
    original = text.splitlines()
    safe_lines = redact(text).splitlines()
    findings = []
    matched_lines: set[int] = set()
    for rule in RULES:
        evidence = []
        count = 0
        for index, line in enumerate(original):
            diagnostic = re.split(r",\s*(?:client|request):", line, maxsplit=1)[0]
            if re.search(rule.pattern, diagnostic):
                count += 1
                matched_lines.add(index + 1)
                if len(evidence) < 3:
                    evidence.append({"line": index + 1, "text": safe_lines[index]})
        if count:
            findings.append({"id": rule.key, "count": count, "observation": rule.observation,
                             "next_check": rule.next_check, "limit": rule.limit, "evidence": evidence})
    return {"format_version": 1, "mode": "offline-log-only", "line_count": len(original),
            "matched_line_count": len(matched_lines), "status": "findings" if findings else "unknown",
            "findings": findings,
            "limits": ["只分析提供的日志，未登录服务器，未执行修复。", "未命中规则不表示服务健康。",
                       "遮盖常见结构化秘密；主机名、路径、自由文本及 IPv6 等仍可能包含敏感信息，分享前必须复核。"]}


def markdown(report: dict) -> str:
    result = ["# 离线 Nginx 日志诊断样例", "", f"输入行数：{report['line_count']}；命中行数：{report['matched_line_count']}。",
              "", "本报告只证明日志中出现的症状，后续检查尚未执行。", ""]
    for finding in report["findings"]:
        result += [f"## {finding['id']} · {finding['count']} 次", "", finding["observation"], "",
                   "证据：", ""]
        for evidence in finding["evidence"]:
            result.append(f"    L{evidence['line']}: {evidence['text']}")
        result += ["", "下一步：" + finding["next_check"], "", "判断边界：" + finding["limit"], ""]
    if not report["findings"]:
        result += ["没有命中内置规则，当前结论为未知，需要其他证据。", ""]
    result += ["## 适用边界", ""] + ["- " + line for line in report["limits"]] + [""]
    return "\n".join(result)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown")
    parser.add_argument("--output", type=Path, help="Create a new report; existing files are never overwritten")
    args = parser.parse_args()
    try:
        if args.output and args.output.resolve() == args.log.resolve():
            raise ValueError("output must not be the input log")
        report = analyze(args.log.read_text(encoding="utf-8-sig", errors="strict"))
        result = (json.dumps(report, ensure_ascii=False, indent=2) + "\n"
                  if args.format == "json" else markdown(report))
        if args.output:
            with args.output.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write(result)
        else:
            sys.stdout.reconfigure(encoding="utf-8")
            print(result, end="")
        return 0
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Could not create report: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
