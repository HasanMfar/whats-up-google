# What's up google - Google Access Scanner for V2Ray Subscriptions

![Written with ZCode](https://img.shields.io/badge/written%20with-ZCode-8A2BE2)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://github.com/HasanMfar/whats-up-google/actions/workflows/tests.yml/badge.svg)](https://github.com/HasanMfar/whats-up-google/actions/workflows/tests.yml)

> 🇮🇷 Full Persian docs: [README.fa.md](README.fa.md)

Checks your V2Ray subscription **config by config** and picks out the clean ones: for
each node it sends real requests through that node and sees whether Google lets it
through to Google Search, Gemini (web), the Gemini API and Antigravity - or flags/blocks it.

## About this project

V2Ray subscriptions bundle dozens of configs, and Google treats each **exit IP**
differently: some IPs get captchas on Search, some are region-blocked on Gemini,
some hit the Gemini API "location not supported" error, some are fine. The
subscription as a whole is therefore never uniformly usable - but individual
configs among them are.

This tool answers exactly two questions:

1. **Which of my configs does Google let through, and to which services?** - every
   config is tested through its own tunnel, with its ID recorded, so results are
   attributable per config.
2. **Which file should I import so it just works?** - the scanner hand-picks the
   passing configs into importable subscription tiers (`best`, `clean`, `gemini`,
   `antigravity`) instead of leaving you to eyeball a table.

It is a **diagnostic and picking tool**, not a proxy: all requests go through the
configs you already have. Testing runs locally - a temporary Xray process per node,
parallel probes for speed (20 nodes at a time by default), and full JSON/CSV
evidence behind every verdict.

## Quick start (Windows)

1. Double-click **`run.bat`**.
   - First time only: it installs the Python packages and downloads the Xray core.
   - `subscriptions.txt` opens in Notepad - paste your subscription URLs (one per
     line), save, close. The scan starts by itself.
2. Watch the live table: every config with its **ID**, server, exit country, latency
   and per-check result.
3. When it finishes, import into v2rayN:

| File | What's inside |
|------|---------------|
| `best_subscription.txt` | **Start here** - fastest config per working exit IP, for Gemini/Antigravity |
| `clean_subscription.txt` | Passed every check |
| `gemini_subscription.txt` | Usable for Gemini (web + API) - even if Search shows a captcha |
| `antigravity_subscription.txt` | Usable for Antigravity |

Each file is a base64 subscription - import it directly. `*_links.txt` holds the same
nodes as raw links. Full details (exit IP, ISP/ASN, per-check status) are in
`reports/scan-<timestamp>.json` / `.csv`.

## Verdicts

| Verdict | Meaning |
|---------|---------|
| `CLEAN` ✅ | Passed every check - Google doesn't flag this node |
| `FLAGGED` ⛔ | At least one check hit a block (captcha / region / location error) |
| `DEAD` 💀 | No HTTP response got through the node at all |
| `ERROR` ⚠️ | Node responded but a probe errored - rerun to confirm |

## From the terminal instead

```bash
python -m scanner                  # full scan
python -m scanner --dry-run        # just list parsed configs + IDs
python -m scanner --concurrency 40 # test 40 nodes in parallel (default 20)
python -m scanner --skip search    # drop a check: search/gemini/gemini_api/antigravity
python -m scanner --watch 30       # re-scan every 30 minutes
python -m scanner --file links.txt # local file of links instead of subscriptions.txt
```

## After each run

- The tool **prints every file it wrote** - JSON/CSV reports plus each hand-picked
  subscription tier - with its path and size.
- A subscription URL that returns no V2Ray links (an HTML page, a code list, ...)
  **fails loudly** with a 150-char preview of what it actually returned, instead of
  being silently skipped.
- Settings live in `config.json` (concurrency, timeout, per-check toggles). It is
  created once with defaults and **never overwritten** afterwards - precedence:
  defaults <- `config.json` <- CLI flags.

## Troubleshooting

- **Xray download fails** (GitHub blocked): set `HTTPS_PROXY`, or put the path to your
  own `xray.exe` in `xray_path` inside `config.json` (e.g. the one in your v2rayN folder).
- **"SOCKS port is already in use"**: leftover xray.exe processes from an interrupted
  scan are still running - close them in Task Manager, or change `socks_port_start`
  in `config.json`.
- **"subscription did not return V2Ray links"**: that URL is not a V2Ray subscription
  (a page, a code list, another client's export) - fix the URL; the error shows a
  150-char preview of what it returned.

## How blocking is detected

| Check | Flagged when |
|-------|--------------|
| Google Search | Redirected to the `/sorry` captcha page or unusual-traffic markers |
| Gemini web | 403, the country-block page, or `/unsupported` |
| Gemini API | `"User location is not supported for the API use"` - any other API error means the location is accepted |
| Antigravity | 403/429 or a block page |

## Project structure

```
scanner/
├── nodes.py           # parse vmess / vless / trojan / ss links, extract node IDs
├── subscriptions.py   # fetch + decode subscriptions (base64 and raw link lists)
├── xray.py            # auto-download the Xray core, one process per node
├── probes.py          # the four Google checks, run in parallel over SOCKS
├── clean_sub.py       # hand-pick clean configs into importable subscriptions
├── report.py          # live table + JSON/CSV reports
└── main.py            # CLI entry point and scan orchestration
```

---

## راهنمای فارسی (خلاصه)

ابزار اشتراک وی‌۲ری شما را **کانفیگ به کانفیگ** بررسی می‌کند و کانفیگ‌های تمیز را برای
جمینای و آنتی‌گرَویتی جدا می‌کند: روی **`run.bat`** دوبار کلیک کنید، آدرس اشتراک‌ها را در
`subscriptions.txt` بگذارید، و بعد از اسکن، `best_subscription.txt` را در v2rayN ایمپورت کنید.

➡️ **مستندات کامل فارسی: [README.fa.md](README.fa.md)**

## Disclaimer

This project was written with **ZCode**, an AI coding agent. It is provided as-is,
without any warranty of any kind - review the code before using it with anything
sensitive.

The tool is intended solely for personal use by users affected by the restrictions
Google applies to them (region blocks, captchas, location errors): it checks how those
restrictions affect the user's own subscription configs. **This code itself is not a
VPN or circumvention ("filter-breaker") tool** - it provides no proxy of its own and
only tests configs the user already has.
