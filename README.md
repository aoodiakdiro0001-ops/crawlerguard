# CrawlerGuard — Find which AI crawlers are eating your bandwidth

> **Your bandwidth bill is growing — and it's not human visitors.**
> GPTBot, ClaudeBot, Google-Extended and friends crawl your site, train on your content, and send you **zero** traffic.
> CrawlerGuard reads your access log, quantifies exactly what each bot consumed, and hands you **ready-to-paste blocking rules** in 30 seconds.
> **One command. One-time $19. No subscription.**

---

## The problem (with receipts)

- AI crawlers now account for a rapidly growing share of web traffic — site owners report bandwidth and server costs spiking with **no matching increase in visitors**.
- Blocking them "the right way" means editing `robots.txt`, writing Cloudflare WAF expressions, or fiddling with nginx `map` directives — most people never get around to it.
- Existing "bot management" solutions are enterprise-priced ($$$/month) or require DNS-level changes.

**CrawlerGuard = diagnosis + the exact fix, in one command.**

## What it does

1. **Parses** a standard Apache/Nginx combined access log (stdlib only)
2. **Attributes** traffic to 18 AI-training bots + 7 SEO crawlers (case-insensitive UA matching)
3. **Quantifies** requests + bandwidth per bot, with top-hit paths
4. **Generates** three ready-to-paste rule sets:
   - `robots.txt` block rules
   - Cloudflare WAF custom-rule expression
   - nginx `map` snippet
5. **Reports** in client-ready Markdown + machine-readable JSON

## Install

```bash
git clone https://github.com/aoodiakdiro0001-ops/crawlerguard.git
cd crawlerguard
# Python 3.9+ standard library only — nothing to install
```

## Usage

```bash
python crawlerguard.py /var/log/nginx/access.log
python crawlerguard.py access.log --out ./report --min-requests 5
```

### Sample output

```
[*] Parsed 148203 entries (0 unparsed).
  [AI ] GPTBot: 4210 req, 312.44 MB
  [AI ] ClaudeBot: 1876 req, 98.10 MB
  [AI ] Google-Extended: 990 req, 51.02 MB
  [SEO] SemrushBot: 402 req, 12.31 MB
[+] Wrote ./report/crawlerguard-report.md
```

The report includes the **exact** `robots.txt` block, the Cloudflare rule expression, and the nginx snippet — copy, paste, done.

## Scope & fairness

CrawlerGuard only reads log files **you provide** and generates configuration snippets. It does not attack, flood, or fingerprint any server. Blocking is opt-in and reversible.

## Support

- **Author:** Baran Avisat — `baranavisat@gmail.com`
- **Store:** [baranavi.gumroad.com](https://baranavi.gumroad.com/)
- **License:** MIT — © 2026 Baran Avisat

---

© 2026 Baran Avisat. All rights reserved. Free updates for life.
