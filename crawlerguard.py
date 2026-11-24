#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CrawlerGuard — find which AI crawlers are eating your bandwidth, and get
ready-to-paste rules that stop them (robots.txt, Cloudflare, nginx).

Parses a standard Apache/Nginx combined access log, attributes traffic to
AI-training vs SEO crawlers, quantifies requests + bandwidth per bot, and
generates the exact blocking rules.

Author:   Baran Avisat <baranavisat@gmail.com>
Storefront: https://baranavi.gumroad.com/
License:  MIT
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# name -> what it does with your content
AI_BOTS = {
    "GPTBot": "OpenAI model training",
    "OAI-SearchBot": "OpenAI search",
    "ChatGPT-User": "ChatGPT browsing",
    "ClaudeBot": "Anthropic model training",
    "Claude-User": "Anthropic browsing",
    "Claude-SearchBot": "Anthropic search",
    "Google-Extended": "Gemini training (not search)",
    "CCBot": "Common Crawl training data",
    "Bytespider": "ByteDance training",
    "PerplexityBot": "Perplexity training/crawl",
    "Amazonbot": "Amazon/Alexa training",
    "Meta-ExternalAgent": "Meta AI training",
    "Applebot-Extended": "Apple Intelligence training",
    "YouBot": "You.com AI",
    "cohere-ai": "Cohere training",
    "Databricks": "Databricks training",
    "ImagesiftBot": "visual data harvesting",
    "Timpibot": "Tampio training",
}
SEO_BOTS = {
    "SemrushBot": "Semrush crawl",
    "AhrefsBot": "Ahrefs crawl",
    "MJ12bot": "Majestic crawl",
    "DotBot": "Moz/DotBot crawl",
    "bingbot": "Bing indexing",
    "YandexBot": "Yandex indexing",
}

LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) \S+" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)


def parse_line(line: str) -> Optional[dict]:
    """Parse one combined-log line; None when it doesn't match."""
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "ip": d["ip"],
        "method": d["method"],
        "path": d["path"],
        "status": int(d["status"]),
        "bytes": 0 if d["bytes"] == "-" else int(d["bytes"]),
        "ua": d["ua"],
    }


def classify(ua: str) -> Optional[Tuple[str, str]]:
    """Return (bot_name, kind) for a known crawler UA, else None."""
    ua_l = (ua or "").lower()
    for name in AI_BOTS:
        if name.lower() in ua_l:
            return name, "ai"
    for name in SEO_BOTS:
        if name.lower() in ua_l:
            return name, "seo"
    return None


@dataclass
class BotStat:
    name: str
    kind: str
    purpose: str
    requests: int = 0
    bytes: int = 0
    statuses: Dict[str, int] = field(default_factory=dict)
    top_paths: List[Tuple[str, int]] = field(default_factory=list)

    @property
    def mb(self) -> float:
        return round(self.bytes / 1_048_576, 2)


def analyze(entries: List[dict], min_requests: int = 1) -> List[BotStat]:
    """Aggregate known-crawler traffic, biggest bandwidth consumer first."""
    stats: Dict[str, BotStat] = {}
    paths: Dict[str, Counter] = {}
    for e in entries:
        hit = classify(e["ua"])
        if not hit:
            continue
        name, kind = hit
        st = stats.get(name)
        if st is None:
            purpose = AI_BOTS.get(name) or SEO_BOTS.get(name) or ""
            st = stats[name] = BotStat(name=name, kind=kind, purpose=purpose)
            paths[name] = Counter()
        st.requests += 1
        st.bytes += e["bytes"]
        key = str(e["status"])
        st.statuses[key] = st.statuses.get(key, 0) + 1
        paths[name][e["path"]] += 1
    out = [s for s in stats.values() if s.requests >= min_requests]
    for s in out:
        s.top_paths = paths[s.name].most_common(5)
    return sorted(out, key=lambda s: s.bytes, reverse=True)


# --------------------------------------------------------------------------
# Ready-to-paste rules
# --------------------------------------------------------------------------
def robots_rules(stats: List[BotStat]) -> str:
    lines = ["# CrawlerGuard — paste at the TOP of robots.txt"]
    for s in stats:
        lines += [f"User-agent: {s.name}", "Disallow: /", ""]
    lines += ["User-agent: *", "Allow: /", ""]
    return "\n".join(lines)


def cloudflare_expression(stats: List[BotStat]) -> str:
    names = " or ".join(f'http.user_agent contains "{s.name}"' for s in stats)
    return (
        "# CrawlerGuard — Cloudflare WAF custom rule\n"
        "# (Security > WAF > Custom rules > Create rule)\n"
        f"( {names} )"
    )


def nginx_map(stats: List[BotStat]) -> str:
    names = " ".join(f'"{s.name}"' for s in stats)
    return (
        "# CrawlerGuard — nginx: block in your server{} block\n"
        f"map $http_user_agent $bad_bot {{\n    default 0;\n"
        + "".join(f'    ~*{n} 1;\n' for s in stats for n in [re.escape(s.name)])
        + "}\n"
        "# then: if ($bad_bot) { return 403; }"
    )


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------
def render_markdown(stats: List[BotStat], source: str) -> str:
    ai = [s for s in stats if s.kind == "ai"]
    seo = [s for s in stats if s.kind == "seo"]
    total_mb = round(sum(s.bytes for s in stats) / 1_048_576, 2)
    lines = [
        "# CrawlerGuard Report",
        "",
        f"- **Log source:** `{source}`",
        f"- **Known crawlers found:** {len(stats)} "
        f"({len(ai)} AI-training, {len(seo)} SEO)",
        f"- **Bandwidth consumed by crawlers:** {total_mb} MB",
        f"- **Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Per-bot impact",
        "",
        "| Bot | Type | Purpose | Requests | Bandwidth |",
        "|---|---|---|---|---|",
    ]
    for s in stats:
        kind = "🤖 AI" if s.kind == "ai" else "🔍 SEO"
        lines.append(f"| `{s.name}` | {kind} | {s.purpose} | "
                     f"{s.requests} | {s.mb} MB |")
    if ai:
        lines += ["", "## Recommended action", "",
                  "Block the AI-training bots below — they add **zero** visitors "
                  "to your site while consuming bandwidth and training on your content.",
                  "", "### 1) robots.txt", "", "```", robots_rules(ai), "```",
                  "", "### 2) Cloudflare (one custom rule)", "", "```",
                  cloudflare_expression(ai), "```"]
    else:
        lines += ["", "No AI-training crawlers detected in this log. 🎉"]
    lines += ["", "---",
              "*Generated by CrawlerGuard — © 2026 Baran Avisat — "
              "support: baranavisat@gmail.com*", ""]
    return "\n".join(lines)


def render_json(stats: List[BotStat], source: str) -> str:
    return json.dumps({
        "tool": "CrawlerGuard",
        "owner": "Baran Avisat",
        "source": source,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "bots": [asdict(s) | {"mb": s.mb} for s in stats],
        "robots_txt": robots_rules(stats),
        "cloudflare_rule": cloudflare_expression(stats),
    }, ensure_ascii=False, indent=2)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        prog="crawlerguard",
        description="Find AI crawlers in your access log and get blocking rules.")
    ap.add_argument("logfile", help="Apache/Nginx combined access log")
    ap.add_argument("--out", default=".", help="output directory")
    ap.add_argument("--min-requests", type=int, default=1)
    args = ap.parse_args(argv)

    path = Path(args.logfile)
    if not path.exists():
        print(f"[!] Log not found: {path}", file=sys.stderr)
        return 2

    entries: List[dict] = []
    bad = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        e = parse_line(line)
        if e:
            entries.append(e)
        elif line.strip():
            bad += 1
    print(f"[*] Parsed {len(entries)} entries ({bad} unparsed).")

    stats = analyze(entries, min_requests=args.min_requests)
    if not stats:
        print("[+] No known crawlers found — nothing to block.")
        return 0

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "crawlerguard-report.md").write_text(
        render_markdown(stats, str(path)), encoding="utf-8")
    (out / "crawlerguard-report.json").write_text(
        render_json(stats, str(path)), encoding="utf-8")

    for s in stats:
        tag = "AI " if s.kind == "ai" else "SEO"
        print(f"  [{tag}] {s.name}: {s.requests} req, {s.mb} MB")
    print(f"[+] Wrote {out / 'crawlerguard-report.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
