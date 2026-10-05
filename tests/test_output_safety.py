"""Run with: python tests/test_output_safety.py

Everything the scanner prints comes from subscription data: URLs, payload
previews, node remarks (IPv6 names like "[2a01:4f8::1]"), adblock rules like
"[/api.waqi.info/]". Interpolated raw into rich markup strings those raise
MarkupError - which killed a real sweep mid-run. All of it must be escaped.
"""
import io
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from rich.console import Console  # noqa: E402

from scanner.clean_sub import print_summary  # noqa: E402
from scanner.nodes import Node  # noqa: E402
from scanner.report import build_table, print_output_files, safe  # noqa: E402

NASTY = [
    ("[2a01:4f8:1c18:4078::1]", "[2001:db8::1]"),   # IPv6 addresses in brackets
    ("[/api.waqi.info/]", "adguard.example"),          # adblock rule
    ("[bold]not bold[/bold]", "[Free] VIP"),          # markup look-alike
    ("plain remark", "5.6.7.8"),
]


def row(remark: str, server: str, verdict: str = "DEAD") -> dict:
    return {
        "node": Node(protocol="vmess", id="uuid", server=server, port=443, remark=remark),
        "results": {"search": None},
        "exit_ip": {"country_code": "US"},
        "latency_ms": 12,
        "verdict": verdict,
        "error": "",
    }


def capture(fn, *args) -> str:
    buf = io.StringIO()
    console = Console(file=buf, width=200, force_terminal=False)
    fn(console, *args)
    return buf.getvalue()


# 1. the live table renders every nasty remark/server (this crashed a real sweep)
out = capture(lambda c: c.print(build_table([row(r, s) for r, s in NASTY], "Google access scan")))
for remark, server in NASTY:
    assert remark in out, f"remark lost or not escaped: {remark!r}"
    assert server in out, f"server lost or not escaped: {server!r}"
print("1  live table renders bracketed remarks/servers ok")

# 2. a fetch-failure message with a payload preview (the exact repro crash)
detail = ("ValueError: subscription did not return V2Ray links (no vmess/vless/trojan/ss "
          "found) [https://example.com/sub] - first 150 chars: "
          "'||api.waqi.info^\\n!/\\n[/api.waqi.info/] ...'")
buf = io.StringIO()
console = Console(file=buf, width=200, force_terminal=False)
console.print(f"[red]subscription failed:[/red] {safe(detail)}")
assert "[/api.waqi.info/]" in buf.getvalue(), buf.getvalue()
assert "[red]" not in buf.getvalue() and "subscription failed:" in buf.getvalue()
print("2  fetch error messages are escaped ok")

# 3. output-file listing from a directory whose name contains brackets
tmp = Path(tempfile.mkdtemp()) / "[brackets] here"
tmp.mkdir()
out_file = tmp / "best_subscription.txt"
out_file.write_text("x", encoding="utf-8")
listed = capture(print_output_files, [out_file])
assert "[brackets] here" in listed, listed
print("3  bracketed output paths are escaped ok")

# 4. end-of-run summary with bracketed path and nasty remark data
summary = capture(print_summary, [row("[/api.waqi.info/]", "1.2.3.4")],
                  {"clean (passed every check)": out_file})
assert "[brackets] here" in summary, summary
print("4  summary printing is escaped ok")

# 5. safe() leaves ordinary text untouched
assert safe("vmess://abc@host:443?type=ws") == "vmess://abc@host:443?type=ws"
assert safe(1234) == "1234"

print("all output-safety tests passed")