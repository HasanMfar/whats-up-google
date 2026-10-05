"""Run with: python tests/test_subscriptions.py"""
import base64
import sys
from pathlib import Path
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from scanner.subscriptions import (  # noqa: E402
    decode_subscription,
    extract_links,
    fetch_subscription,
)

LINKS = [
    "vmess://eyJ2IjoiMiJ9",
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@us.example.com:443?security=reality#US",
    "trojan://p%40ss@jp.example.com:8443#JP",
    "ss://YWVzLTI1Ni1nY206cHcxMjM0NQ==@1.2.3.4:8388#SS",
]
PLAIN = "\n".join(LINKS)


def expect_links(payload: str, want: list[str], label: str, source: str = "test") -> None:
    out = decode_subscription(payload, source=source)
    got = [ln for ln in out.splitlines() if ln]
    assert got == want, f"{label}: expected {want}, got {got}"


# 1. plain links
expect_links(PLAIN, LINKS, "plain")

# 2. header line before the links (previously rejected the whole subscription)
expect_links("subscription-info: expire=3600\n" + PLAIN, LINKS, "header-first")

# 3. BOM prefix
expect_links("\ufeff" + PLAIN, LINKS, "bom")

# 4. comments and blank lines mixed in
expect_links("# my sub\n\n" + PLAIN + "\n# tail", LINKS, "comments")

# 5. unsupported scheme first / mixed in (previously rejected entirely)
expect_links("hysteria2://pw@h:443\n" + PLAIN, LINKS, "hy2-first")
expect_links("vmess://x\nunknown://junk\ntuic://y\n" + "\n".join(LINKS[1:]),
             ["vmess://x"] + LINKS[1:], "mixed-schemes")

# 6. whole-body base64: standard, url-safe, unpadded, wrapped in whitespace
expect_links(base64.b64encode(PLAIN.encode()).decode(), LINKS, "b64-std")
expect_links(base64.urlsafe_b64encode(PLAIN.encode()).decode().rstrip("="),
             LINKS, "b64-urlsafe-nopad")
expect_links("\n".join(base64.b64encode(PLAIN.encode()).decode()[i:i + 60]
                       for i in range(0, len(base64.b64encode(PLAIN.encode())), 60)),
             LINKS, "b64-wrapped")

# 7. base64 with a comment line in front of the blob
expect_links("# remark\n" + base64.b64encode(PLAIN.encode()).decode(), LINKS, "b64-comment")

# 8. per-line base64 (previously only the first line survived, rest was mojibake)
per_line = "\n".join(base64.b64encode(l.encode()).decode() for l in LINKS)
expect_links(per_line, LINKS, "b64-per-line")

# 9. double-encoded base64
expect_links(base64.b64encode(base64.b64encode(PLAIN.encode())).decode(), LINKS, "b64-double")

# 10. percent-encoded payload
expect_links(quote(PLAIN, safe=""), LINKS, "urlencoded")

# 11. percent-encoded base64
expect_links(quote(base64.b64encode(PLAIN.encode()).decode(), safe=""), LINKS, "urlencoded-b64")

# 12. CRLF + stray spaces
expect_links("  vmess://a  \r\n\r\n vless://b \r\n", ["vmess://a", "vless://b"], "crlf")

# extract_links drops junk, keeps every supported link
assert extract_links("junk\nvmess://a\n# c\nvless://b") == ["vmess://a", "vless://b"]

# unsupported payload shapes still fail loudly with the message main.py matches on
for bad, label in (
    ("<html><body>hello</body></html>", "html-page"),
    ("totally not a subscription", "garbage"),
    ("hysteria2://pw@h:443\ntuic://x@h:443", "unsupported-only"),
):
    try:
        decode_subscription(bad, source="bad")
    except ValueError as e:
        assert "did not return V2Ray links" in str(e), f"{label}: {e}"
    else:
        raise AssertionError(f"{label}: expected ValueError")


# fetch_subscription: mock transport, no network
def fetch_body(body: str, content_type: str = "text/plain") -> str:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=body, headers={"content-type": content_type})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        return fetch_subscription(client, "https://sub.example.com/token")


assert fetch_body("subscription-info: x\n" + PLAIN) == PLAIN

# Clash YAML is rejected
try:
    fetch_body("proxies:\n  - name: a\n    cipher: aes-128-gcm\n")
except ValueError as e:
    assert "Clash" in str(e), e
else:
    raise AssertionError("Clash payload should be rejected")

# HTML page gets a dedicated hint
try:
    fetch_body("<!DOCTYPE html><html><body>sign in</body></html>")
except ValueError as e:
    assert "HTML page" in str(e), e
else:
    raise AssertionError("HTML payload should be rejected")

# HTTP errors still propagate
def handler_404(request: httpx.Request) -> httpx.Response:
    return httpx.Response(404, text="nope")

with httpx.Client(transport=httpx.MockTransport(handler_404)) as client:
    try:
        fetch_subscription(client, "https://sub.example.com/gone")
    except httpx.HTTPStatusError:
        pass
    else:
        raise AssertionError("404 should raise")

# --- parallel fetching: aggregates results, isolates failures, escapes errors --
import argparse  # noqa: E402
import io  # noqa: E402
import tempfile  # noqa: E402

from rich.console import Console  # noqa: E402

from scanner import main as main_mod  # noqa: E402

tmp = Path(tempfile.mkdtemp())
(tmp / "subscriptions.txt").write_text(
    "https://a.example/sub\nhttps://b.example/sub\nhttps://c.example/sub\n", encoding="utf-8")

NASTY = "subscription did not return V2Ray links - first 150 chars: '[/api.waqi.info/]'"


def fake_fetch(client, url):
    if "b.example" in url:
        raise ValueError(NASTY)
    return PLAIN if "a.example" in url else "\n".join(LINKS[:2])


buf = io.StringIO()
orig_root, orig_fetch, orig_console = main_mod.ROOT, main_mod.fetch_subscription, main_mod.console
main_mod.ROOT = tmp
main_mod.fetch_subscription = fake_fetch
main_mod.console = Console(file=buf, width=200, force_terminal=False)
try:
    nodes, stats = main_mod.gather_nodes(argparse.Namespace(file=None))
finally:
    main_mod.ROOT = orig_root
    main_mod.fetch_subscription = orig_fetch
    main_mod.console = orig_console

assert stats["sources"] == 3, stats
assert stats["fetch_errors"] == 1, stats
assert len(nodes) == 4, [n.server for n in nodes]   # c.example repeats two links
assert stats["duplicates"] == 2, stats
assert "[/api.waqi.info/]" in buf.getvalue(), "error payload must be escaped, not parsed"
print("all subscription decoding tests passed")
