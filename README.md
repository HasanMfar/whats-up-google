# What's up google - Google Access Scanner for V2Ray Subscriptions

> راهنمای فارسی پایین همین فایل است.

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

## راهنمای فارسی

ابزار اشتراک وی‌۲ری شما را **کانفیگ به کانفیگ** بررسی می‌کند و کانفیگ‌های تمیز را جدا
می‌کند: برای هر نود، درخواست‌های واقعی از طریق خودِ همان نود فرستاده می‌شود تا معلوم شود
گوگل اجازهٔ دسترسی به جستجو، جمینای (وب)، جمینای API و آنتی‌گرَویتی را می‌دهد یا پرچم/مسدودش می‌کند.

### شروع سریع (ویندوز)

۱. روی **`run.bat`** دوبار کلیک کنید.
   - فقط بار اول: پکیج‌های پایتون نصب و هستهٔ Xray دانلود می‌شود.
   - `subscriptions.txt` در نوت‌پد باز می‌شود - آدرس اشتراک‌ها را بگذارید (هر خط یک
     آدرس)، ذخیره و ببندید. اسکن خودش شروع می‌شود.
۲. جدول زنده را ببینید: هر کانفیگ با **آیدی**، سرور، کشور خروجی، تأخیر و نتیجهٔ هر بررسی.
۳. بعد از پایان، در v2rayN ایمپورت کنید:

| فایل | محتوا |
|------|-------|
| `best_subscription.txt` | **از اینجا شروع کنید** - سریع‌ترین کانفیگ به‌ازای هر IP سالم، برای جمینای/آنتی‌گرَویتی |
| `clean_subscription.txt` | همهٔ بررسی‌ها را پاس کرده |
| `gemini_subscription.txt` | برای جمینای (وب + API) قابل‌استفاده - حتی اگر جستجو کپچا بدهد |
| `antigravity_subscription.txt` | برای آنتی‌گرَویتی قابل‌استفاده |

هر فایل base64 است و مستقیم قابل ایمپورت است. `*_links.txt` همان نودها به‌صورت لینک خام
است. جزئیات کامل (IP خروجی، ISP/ASN، وضعیت هر بررسی) در `reports/scan-<زمان>.json` و `.csv`.

نتیجه‌ها: `CLEAN` = همه‌چیز پاس - `FLAGGED` = گوگل مسدودش کرده (کپچا / منطقه / خطای
موقعیت) - `DEAD` = هیچ‌چیز رد نمی‌شود - `ERROR` = دوباره اجرا کنید.

### از ترمینال

```bash
python -m scanner                  # اسکن کامل
python -m scanner --dry-run        # فقط لیست کانفیگ‌ها و آیدی‌ها
python -m scanner --concurrency 16 # تست همزمان ۱۶ نود (پیش‌فرض ۸)
python -m scanner --skip search    # حذف یک بررسی: search/gemini/gemini_api/antigravity
python -m scanner --watch 30       # تکرار اسکن هر ۳۰ دقیقه
python -m scanner --file links.txt # فایل محلی لینک‌ها به‌جای subscriptions.txt
```

### مشکلات رایج

- **دانلود Xray ناموفق** (گیت‌هاب فیلتر است): `HTTPS_PROXY` را ست کنید، یا در
  `config.json` مسیر `xray.exe` خودتان (مثلاً از پوشه v2rayN) را در `xray_path` بگذارید.
- **نحوهٔ تشخیص مسدودی**: جستجو → صفحهٔ کپچای `/sorry` - جمینای وب → ۴۰۳ / صفحهٔ کشور -
  جمینای API → خطای «User location is not supported» - آنتی‌گرَویتی → ۴۰۳/۴۲۹ یا صفحهٔ مسدودی.
