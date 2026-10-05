"""Fetch V2Ray subscription URLs and decode them into raw node-link text."""
from __future__ import annotations

import base64
import urllib.parse

import httpx

SUB_UA = "v2rayNG/1.9.16"  # many subscription backends only return base64 to known clients
_LINK_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")
# BOM / zero-width characters some backends prepend to the payload
_ZW_PREFIX = "\ufeff\u200b\u200c\u200d\u2060"
# how many times a base64 blob may be re-decoded (double/triple encoded subs exist)
_MAX_B64_ROUNDS = 3


def load_subscription_urls(path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def extract_links(text: str) -> list[str]:
    """Return every line that starts with a supported V2Ray scheme.

    Tolerates header lines, comments, BOM/zero-width prefixes and unsupported
    schemes (`hysteria2://...` etc.) mixed in - only the usable links survive.
    """
    links = []
    for line in text.splitlines():
        line = line.strip().lstrip(_ZW_PREFIX)
        if any(line.startswith(s) for s in _LINK_SCHEMES):
            links.append(line)
    return links


def _looks_like_links(text: str) -> bool:
    return bool(extract_links(text))


def b64_decode_tolerant(text: str) -> str:
    data = "".join(text.split()).replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data).decode("utf-8", "replace")


def _decode_b64_blob(text: str) -> str:
    """Decode a base64 payload, re-decoding while it still looks encoded."""
    s = text
    for _ in range(_MAX_B64_ROUNDS):
        if extract_links(s):
            return s
        s = b64_decode_tolerant(s)
    return s


def _decode_b64_per_line(text: str) -> str:
    """Many backends base64-encode each link line separately."""
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip().lstrip(_ZW_PREFIX)
        if not line or line.startswith("#"):
            continue
        try:
            decoded = b64_decode_tolerant(line)
        except Exception:
            continue
        out.extend(extract_links(decoded))
    return "\n".join(out)


def decode_subscription(text: str, source: str = "") -> str:
    """Decode any known subscription payload shape into plain link lines.

    Strategies tried in order:
      1. plain links (headers/comments/unsupported schemes ignored)
      2. whole-body base64 (url-safe, unpadded, whitespace, re-encoded)
      3. each line its own base64 chunk
      4. percent-encoded payload (with one extra base64 pass)
    All are evaluated and the one recovering the MOST supported links wins -
    a whole-body base64 pass can "half-succeed" on a per-line payload and
    otherwise shadow the strategy that would recover every link.
    """
    best: list[str] = []
    strategies = (
        lambda s: s,
        _decode_b64_blob,
        _decode_b64_per_line,
        lambda s: _decode_b64_blob(urllib.parse.unquote(s)),
    )
    for strategy in strategies:
        try:
            candidate = strategy(text)
        except Exception:
            continue
        links = extract_links(candidate)
        if len(links) > len(best):
            best = links
    if best:
        return "\n".join(best)

    preview = text.strip()[:150].replace("\n", " ")
    raise ValueError(
        f"subscription did not return V2Ray links (no vmess/vless/trojan/ss found)"
        + (f" [{source}]" if source else "")
        + f" - first 150 chars: {preview!r}"
    )


def fetch_subscription(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    r.raise_for_status()
    text = r.text
    low = text.lstrip(_ZW_PREFIX).lstrip().lower()
    if "proxies:" in text and "cipher:" in text:
        raise ValueError("looks like a Clash YAML subscription - this scanner supports V2Ray/Xray subs only")
    if low.startswith("<!doctype html") or low.startswith("<html"):
        raise ValueError(
            "got an HTML page instead of a subscription - this URL is probably a website, "
            "not a V2Ray subscription endpoint"
        )
    return decode_subscription(text, source=url)


def make_client() -> httpx.Client:
    """Client for subscription fetching. Honors system proxy env vars (trust_env)."""
    return httpx.Client(
        trust_env=True,
        timeout=20,
        follow_redirects=True,
        headers={"User-Agent": SUB_UA},
    )
