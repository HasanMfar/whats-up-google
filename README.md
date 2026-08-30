# What's up google - Google Access Scanner for V2Ray Subscriptions

> 🇮🇷 Full Persian docs: [README.fa.md](README.fa.md)

Checks your V2Ray subscription **config by config** and picks out the clean ones: for
each node it sends real requests through that node and sees whether Google lets it
through to Google Search, Gemini (web), the Gemini API and Antigravity - or flags/blocks it.

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

Verdicts: `CLEAN` = passed everything - `FLAGGED` = Google blocks it (captcha / region
/ location error) - `DEAD` = nothing gets through - `ERROR` = rerun to confirm.

## From the terminal instead

```bash
python -m scanner                  # full scan
python -m scanner --dry-run        # just list parsed configs + IDs
python -m scanner --concurrency 16 # test 16 nodes in parallel (default 8)
python -m scanner --skip search    # drop a check: search/gemini/gemini_api/antigravity
python -m scanner --watch 30       # re-scan every 30 minutes
python -m scanner --file links.txt # local file of links instead of subscriptions.txt
```

## Troubleshooting

- **Xray download fails** (GitHub blocked): set `HTTPS_PROXY`, or put the path to your
  own `xray.exe` in `xray_path` inside `config.json` (e.g. the one in your v2rayN folder).
- **How blocking is detected**: Search → `/sorry` captcha page - Gemini web → 403 /
  country page - Gemini API → "User location is not supported" - Antigravity → 403/429
  or block page.

---

## راهنمای فارسی (خلاصه)

ابزار اشتراک وی‌۲ری شما را **کانفیگ به کانفیگ** بررسی می‌کند و کانفیگ‌های تمیز را برای
جمینای و آنتی‌گرَویتی جدا می‌کند: روی **`run.bat`** دوبار کلیک کنید، آدرس اشتراک‌ها را در
`subscriptions.txt` بگذارید، و بعد از اسکن، `best_subscription.txt` را در v2rayN ایمپورت کنید.

➡️ **مستندات کامل فارسی: [README.fa.md](README.fa.md)**
