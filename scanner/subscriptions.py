"""Fetch V2Ray subscription URLs and decode them into raw node-link text."""
from __future__ import annotations

import base64

import httpx

SUB_UA = "v2rayNG/1.9.16"  # many subscription backends only return base64 to known clients
_LINK_SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")


def load_subscription_urls(path) -> list[str]:
    urls = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            urls.append(line)
    return urls


def _looks_like_links(text: str) -> bool:
    return any(text.lstrip().startswith(s) for s in _LINK_SCHEMES)


def b64_decode_tolerant(text: str) -> str:
    data = "".join(text.split()).replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data).decode("utf-8", "replace")


def decode_subscription(text: str) -> str:
    t = text.strip()
    if _looks_like_links(t):
        return t
    try:
        decoded = b64_decode_tolerant(t)
        if _looks_like_links(decoded):
            return decoded
    except Exception:
        pass
    return t  # let the link parser report the errors


def fetch_subscription(client: httpx.Client, url: str) -> str:
    r = client.get(url)
    r.raise_for_status()
    text = r.text
    if "proxies:" in text and "cipher:" in text:
        raise ValueError("looks like a Clash YAML subscription - this scanner supports V2Ray/Xray subs only")
    return decode_subscription(text)


def make_client() -> httpx.Client:
    """Client for subscription fetching. Honors system proxy env vars (trust_env)."""
    return httpx.Client(
        trust_env=True,
        timeout=20,
        follow_redirects=True,
        headers={"User-Agent": SUB_UA},
    )
