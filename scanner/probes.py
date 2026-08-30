"""Probe Google endpoints through a node's local SOCKS port."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import httpx

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")

# Google search: flagged IPs get redirected to /sorry/ with a captcha.
SORRY_MARKERS = ("/sorry", "unusual traffic", "g-recaptcha", "recaptcha/api",
                 "our systems have detected")
GEMINI_BLOCK_MARKERS = ("not available in your country", "unusual traffic", "/sorry", "g-recaptcha")
ANTIGRAVITY_BLOCK_MARKERS = ("unusual traffic", "/sorry", "g-recaptcha",
                             "not available in your country", "has been blocked")
LOCATION_MARKER = "location is not supported"


def _result(name: str, ok: bool | None, status="", detail="", url="", ms=None) -> dict:
    return {"check": name, "ok": ok, "status": status, "detail": detail[:200], "url": url, "ms": ms}


def _flagged_by(status: int, url: str, body: str, markers: tuple[str, ...]) -> bool:
    return (status in (403, 429, 451)
            or "/sorry" in url.lower()
            or any(m in body for m in markers))


def check_search(client: httpx.Client) -> dict:
    t0 = time.perf_counter()
    r = client.get("https://www.google.com/search", params={"q": "hello world", "hl": "en", "num": "20"})
    ms = int((time.perf_counter() - t0) * 1000)
    body = r.text.lower()
    flagged = "/sorry" in str(r.url).lower() or any(m in body for m in SORRY_MARKERS)
    return _result("search", not flagged, r.status_code,
                   "captcha/sorry page" if flagged else "clean", str(r.url), ms)


def check_gemini(client: httpx.Client) -> dict:
    t0 = time.perf_counter()
    r = client.get("https://gemini.google.com/")
    ms = int((time.perf_counter() - t0) * 1000)
    url = str(r.url).lower()
    body = r.text.lower()
    flagged = r.status_code in (403, 429, 451) or "/unsupported" in url or \
        any(m in body for m in GEMINI_BLOCK_MARKERS)
    return _result("gemini", not flagged, r.status_code,
                   "region blocked / captcha" if flagged else "clean", str(r.url), ms)


def check_gemini_api(client: httpx.Client) -> dict:
    t0 = time.perf_counter()
    r = client.get("https://generativelanguage.googleapis.com/v1beta/models")
    ms = int((time.perf_counter() - t0) * 1000)
    body = r.text.lower()
    # Any API-style error (401 "API key not valid" etc.) means the endpoint is reachable
    # and the IP location is accepted; only the location error means flagged.
    flagged = LOCATION_MARKER in body
    try:
        detail = r.json().get("error", {}).get("message", "")[:120]
    except Exception:
        detail = r.text[:120]
    return _result("gemini_api", not flagged, r.status_code,
                   detail or ("location blocked" if flagged else "clean"), str(r.url), ms)


def check_antigravity(client: httpx.Client) -> dict:
    t0 = time.perf_counter()
    r = client.get("https://antigravity.google/")
    ms = int((time.perf_counter() - t0) * 1000)
    body = r.text.lower()
    flagged = _flagged_by(r.status_code, str(r.url), body, ANTIGRAVITY_BLOCK_MARKERS)
    return _result("antigravity", not flagged, r.status_code,
                   "blocked" if flagged else "clean", str(r.url), ms)


CHECK_ORDER = [
    ("search", check_search),
    ("gemini", check_gemini),
    ("gemini_api", check_gemini_api),
    ("antigravity", check_antigravity),
]


def _run(fn, client: httpx.Client, retries: int) -> dict:
    last: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return fn(client)
        except Exception as e:  # noqa: BLE001 - network errors are expected per-node
            last = e
            if attempt < retries:
                time.sleep(0.5)
    return _result(fn.__name__.removeprefix("check_"), None, "ERR",
                   f"{type(last).__name__}: {last}")


def lookup_exit_ip(client: httpx.Client) -> dict:
    try:
        r = client.get("http://ip-api.com/json/",
                       params={"fields": "query,country,countryCode,isp,as"})
        j = r.json()
        return {"ip": j.get("query", ""), "country": j.get("country", ""),
                "country_code": j.get("countryCode", ""), "isp": j.get("isp", ""),
                "asn": j.get("as", "")}
    except Exception:
        try:
            r = client.get("https://api.ip.sb/geoip")
            j = r.json()
            return {"ip": j.get("ip", ""), "country": j.get("country", ""),
                    "country_code": j.get("country_code", ""),
                    "isp": j.get("organization", ""),
                    "asn": f"AS{j.get('asn', '')} {j.get('asn_organization', '')}"}
        except Exception as e:  # noqa: BLE001
            return {"ip": "", "country": "", "country_code": "", "isp": "",
                    "asn": f"lookup failed: {type(e).__name__}"}


def run_all_probes(socks_port: int, checks_enabled: dict, timeout: float, retries: int):
    """Run all enabled Google checks through one node, in parallel.

    Returns (results, exit_ip, alive). results maps check name -> result dict
    (ok: True passed / False flagged / None error) or None when disabled.
    """
    proxy_url = f"socks5://127.0.0.1:{socks_port}"
    results: dict[str, dict | None] = {}
    enabled = [(name, fn) for name, fn in CHECK_ORDER if checks_enabled.get(name, True)]
    with httpx.Client(proxy=proxy_url, timeout=timeout, follow_redirects=True,
                      trust_env=False,  # must go through the node, never a system proxy
                      headers={"User-Agent": UA, "Accept-Language": "en-US,en;q=0.9"}) as client:
        with ThreadPoolExecutor(max_workers=len(enabled) + 1) as ex:
            futs = {ex.submit(_run, fn, client, retries): name for name, fn in enabled}
            ip_fut = ex.submit(lookup_exit_ip, client)
            for fut in as_completed(futs):
                results[futs[fut]] = fut.result()
            exit_ip = ip_fut.result()
    for name, _ in CHECK_ORDER:  # record disabled checks explicitly
        results.setdefault(name, None)
    alive = any(r["ok"] is not None for r in results.values() if r)
    if not alive:
        exit_ip = {"ip": "", "country": "", "country_code": "", "isp": "", "asn": ""}
    return results, exit_ip, alive


def verdict_from(results: dict, alive: bool) -> str:
    vals = [r["ok"] for r in results.values() if r]
    if not alive or not vals or all(v is None for v in vals):
        return "DEAD"
    if any(v is False for v in vals):
        return "FLAGGED"
    if any(v is None for v in vals):
        return "ERROR"
    return "CLEAN"


def service_ok(results: dict, services: tuple[str, ...]) -> bool | None:
    """Hand-picking predicate: True when every requested check passed.

    Checks outside `services` (or disabled ones) are ignored, so a node that is
    captcha'd on Google Search can still be usable for Gemini/Antigravity.
    Returns None when nothing usable was tested (all disabled or errored).
    """
    saw_any = False
    ok = True
    for name in services:
        res = results.get(name)
        if res is None:  # check disabled in this run
            continue
        saw_any = True
        if res["ok"] is False:
            return False
        if res["ok"] is None:
            ok = None
    return ok if saw_any else None


# The services this scanner exists for: accessing Gemini and Antigravity.
TARGET_SERVICES = ("gemini", "gemini_api", "antigravity")


def node_latency_ms(results: dict) -> int | None:
    mss = [r["ms"] for r in results.values() if r and r.get("ms") is not None]
    return min(mss) if mss else None
