"""Run with: python tests/test_clean.py"""
import base64
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.clean_sub import best_per_ip, pick_for_services, write_clean_outputs  # noqa: E402
from scanner.nodes import Node  # noqa: E402


def ok(v: bool | None) -> dict:
    return {"check": "x", "ok": v, "status": 200 if v is not None else "ERR",
            "detail": "", "url": "", "ms": 100}


def row(raw, search, gemini, api, anti, ip, lat):
    return {
        "node": Node(protocol="vmess", id="uuid", server="s", port=1, raw=raw),
        "results": {"search": ok(search), "gemini": ok(gemini),
                    "gemini_api": ok(api), "antigravity": ok(anti)},
        "exit_ip": {"ip": ip, "country_code": "XX"},
        "latency_ms": lat,
        "verdict": "CLEAN" if all(v is True for v in (search, gemini, api, anti)) else
                   ("FLAGGED" if any(v is False for v in (search, gemini, api, anti)) else "ERROR"),
        "error": "",
    }


rows = [
    row("vmess://a", True, True, True, True, "1.1.1.1", 100),   # fully clean
    row("vmess://b", False, True, True, True, "2.2.2.2", 50),   # search-captcha'd, Gemini OK
    row("vmess://c", True, False, False, True, "3.3.3.3", 70),  # Gemini blocked
    row("vmess://d", True, True, True, True, "1.1.1.1", 80),    # same IP as a, slower
    row("vmess://e", True, True, None, True, "4.4.4.4", 90),    # API errored
]

strict = [r["node"].raw for r in rows if r["verdict"] == "CLEAN"]
assert strict == ["vmess://a", "vmess://d"], strict

gem = [r["node"].raw for r in pick_for_services(rows, ("gemini", "gemini_api"))]
assert gem == ["vmess://a", "vmess://b", "vmess://d"], gem

anti = [r["node"].raw for r in pick_for_services(rows, ("antigravity",))]
assert anti == ["vmess://a", "vmess://b", "vmess://c", "vmess://d", "vmess://e"], anti

best = [r["node"].raw for r in best_per_ip(pick_for_services(rows, ("gemini", "gemini_api", "antigravity")))]
# e drops out (API error); a drops out (same IP as d, slower); sorted by latency
assert best == ["vmess://b", "vmess://d"], best

tmp = Path(tempfile.mkdtemp())
outputs = write_clean_outputs(tmp, rows)
assert set(outputs) == {"clean (passed every check)", "gemini (usable for Gemini web + API)",
                        "antigravity (usable for Antigravity)",
                        "best (fastest config per exit IP, for Gemini/Antigravity)"}, outputs
decoded = base64.b64decode((tmp / "best_subscription.txt").read_text(encoding="ascii")).decode()
assert decoded == "vmess://b\nvmess://d", decoded
assert (tmp / "clean_links.txt").read_text(encoding="utf-8").splitlines() == ["vmess://a", "vmess://d"]

print("all hand-picking tests passed")
