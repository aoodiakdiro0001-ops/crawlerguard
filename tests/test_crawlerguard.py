#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for CrawlerGuard (no network, no real logs)."""
import unittest

from crawlerguard import (
    analyze,
    classify,
    cloudflare_expression,
    parse_line,
    render_json,
    render_markdown,
    robots_rules,
)


GOOD_LINE = ('203.0.113.7 - - [24/Nov/2026:10:00:00 +0000] '
             '"GET /pricing HTTP/1.1" 200 5120 "-" '
             '"Mozilla/5.0 (compatible; GPTBot/1.0; +https://openai.com/gptbot)"')
BYTES_DASH_LINE = ('203.0.113.8 - - [24/Nov/2026:10:00:01 +0000] '
                   '"HEAD / HTTP/1.1" 304 - "-" "curl/8.4"')
HUMAN_LINE = ('203.0.113.9 - - [24/Nov/2026:10:00:02 +0000] '
              '"GET / HTTP/1.1" 200 2048 "-" '
              '"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"')


class TestParseLine(unittest.TestCase):
    def test_gptbot_line(self):
        e = parse_line(GOOD_LINE)
        self.assertIsNotNone(e)
        self.assertEqual(e["status"], 200)
        self.assertEqual(e["bytes"], 5120)
        self.assertIn("GPTBot", e["ua"])

    def test_dash_bytes_is_zero(self):
        e = parse_line(BYTES_DASH_LINE)
        self.assertEqual(e["bytes"], 0)

    def test_garbage_returns_none(self):
        self.assertIsNone(parse_line("not a log line"))
        self.assertIsNone(parse_line(""))


class TestClassify(unittest.TestCase):
    def test_ai_bot(self):
        self.assertEqual(classify("Mozilla/5.0 (compatible; GPTBot/1.0)"),
                         ("GPTBot", "ai"))

    def test_seo_bot(self):
        self.assertEqual(classify("Mozilla/5.0 (compatible; SemrushBot/7~bl)"),
                         ("SemrushBot", "seo"))

    def test_case_insensitive(self):
        self.assertEqual(classify("... google-extended ..."),
                         ("Google-Extended", "ai"))

    def test_human_browser_is_none(self):
        self.assertIsNone(classify("Mozilla/5.0 Chrome/131.0"))


class TestAnalyze(unittest.TestCase):
    def test_aggregation_and_sorting(self):
        entries = [parse_line(GOOD_LINE), parse_line(GOOD_LINE),
                   parse_line(HUMAN_LINE)]
        entries = [e for e in entries if e]
        stats = analyze(entries)
        self.assertEqual(len(stats), 1)          # human traffic ignored
        self.assertEqual(stats[0].name, "GPTBot")
        self.assertEqual(stats[0].requests, 2)
        self.assertEqual(stats[0].bytes, 10240)
        self.assertEqual(stats[0].kind, "ai")

    def test_min_requests_filter(self):
        e = parse_line(GOOD_LINE)
        self.assertEqual(analyze([e], min_requests=5), [])

    def test_ai_sorted_before_small_seo(self):
        ai = parse_line(GOOD_LINE)  # 5120 bytes
        seo_line = ('1.1.1.1 - - [x] "GET / HTTP/1.1" 200 10 "-" '
                    '"Mozilla/5.0 (compatible; AhrefsBot/7.0)"')
        seo = parse_line(seo_line)
        stats = analyze([ai, seo])
        self.assertEqual(stats[0].name, "GPTBot")


class TestRules(unittest.TestCase):
    def _stats(self):
        return analyze([parse_line(GOOD_LINE)])

    def test_robots_rules(self):
        r = robots_rules(self._stats())
        self.assertIn("User-agent: GPTBot", r)
        self.assertIn("Disallow: /", r)
        self.assertIn("CrawlerGuard", r)

    def test_cloudflare_expression(self):
        c = cloudflare_expression(self._stats())
        self.assertIn('http.user_agent contains "GPTBot"', c)
        self.assertIn("Cloudflare", c)


class TestReporting(unittest.TestCase):
    def _stats(self):
        return analyze([parse_line(GOOD_LINE)])

    def test_markdown(self):
        md = render_markdown(self._stats(), "access.log")
        self.assertIn("GPTBot", md)
        self.assertIn("Bandwidth", md)
        self.assertIn("© 2026 Baran Avisat", md)

    def test_json(self):
        import json
        data = json.loads(render_json(self._stats(), "access.log"))
        self.assertEqual(data["tool"], "CrawlerGuard")
        self.assertEqual(data["bots"][0]["name"], "GPTBot")
        self.assertIn("User-agent: GPTBot", data["robots_txt"])


if __name__ == "__main__":
    unittest.main()
