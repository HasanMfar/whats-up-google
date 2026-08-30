"""Parse V2Ray/Xray node links (vmess://, vless://, trojan://, ss://) into records."""
from __future__ import annotations

import base64
import json
import urllib.parse
from dataclasses import asdict, dataclass, field

SCHEMES = ("vmess://", "vless://", "trojan://", "ss://")


class LinkParseError(ValueError):
    pass


def b64decode_padded(data: str) -> bytes:
    """Base64 decode tolerating URL-safe alphabets, missing padding and whitespace."""
    data = "".join(data.split())
    data = data.replace("-", "+").replace("_", "/")
    data += "=" * (-len(data) % 4)
    return base64.b64decode(data)


@dataclass
class Node:
    protocol: str                 # vmess / vless / trojan / shadowsocks
    id: str                       # uuid or password - the node's identity
    server: str
    port: int
    remark: str = ""
    scheme: str = ""              # original link scheme
    raw: str = ""                 # original link, reused for clean-subscription output
    source: str = ""              # which subscription it came from
    network: str = "tcp"          # tcp / ws / grpc / h2 / httpupgrade / xhttp
    security: str = "none"        # none / tls / reality
    sni: str = ""
    host: str = ""                # ws/h2 Host header
    path: str = ""
    fingerprint: str = ""         # uTLS fingerprint
    flow: str = ""                # vless flow
    public_key: str = ""          # reality
    short_id: str = ""            # reality
    method: str = ""              # shadowsocks cipher
    alter_id: int = 0             # vmess
    cipher: str = "auto"          # vmess encryption
    service_name: str = ""        # grpc
    extra: dict = field(default_factory=dict)

    @property
    def dedupe_key(self) -> tuple:
        return (self.protocol, self.server, self.port, self.id)

    def id_prefix(self, n: int = 10) -> str:
        return self.id[:n] + "…" if len(self.id) > n else self.id

    def to_dict(self) -> dict:
        d = asdict(self)
        d["extra"] = json.dumps(self.extra, ensure_ascii=False) if self.extra else ""
        return d


def _split_hostport(hostport: str) -> tuple[str, int]:
    hostport = hostport.strip().rstrip("/")
    if hostport.startswith("["):  # [ipv6]:port
        host, _, rest = hostport.partition("]")
        return host.lstrip("["), int(rest.lstrip(":") or 443)
    host, _, port_s = hostport.rpartition(":")
    if not host:
        raise LinkParseError(f"bad host:port {hostport!r}")
    return host, int(port_s or 443)


def _normalize_network(net: str) -> str:
    net = (net or "tcp").strip().lower()
    return "xhttp" if net == "splithttp" else net


def parse_vmess(link: str, source: str) -> Node:
    payload = b64decode_padded(link[len("vmess://"):]).decode("utf-8", "replace")
    cfg = json.loads(payload)
    port = int(str(cfg.get("port", 443)).strip() or 443)
    net = _normalize_network(str(cfg.get("net", "tcp")))
    security = "tls" if str(cfg.get("tls", "")).lower() == "tls" else "none"
    return Node(
        protocol="vmess",
        id=str(cfg.get("id", "")).strip(),
        server=str(cfg.get("add", "")).strip(),
        port=port,
        remark=str(cfg.get("ps", "") or ""),
        scheme="vmess",
        raw=link,
        source=source,
        network=net,
        security=security,
        sni=str(cfg.get("sni", "") or ""),
        host=str(cfg.get("host", "") or ""),
        path=str(cfg.get("path", "") or ""),
        alter_id=int(cfg.get("aid", 0) or 0),
        cipher=str(cfg.get("scy", "") or "auto"),
        service_name=str(cfg.get("path", "") or ""),  # v2rayN exports grpc serviceName in path
        extra={"header_type": str(cfg.get("type", "") or "")},
    )


def _parse_userinfo_link(link: str, source: str, proto: str) -> Node:
    u = urllib.parse.urlsplit(link)
    if not u.hostname:
        raise LinkParseError("missing host")
    q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
    net = _normalize_network(q.get("type", "tcp"))
    security = q.get("security", "none").strip().lower() or "none"
    if proto == "trojan" and security == "none":
        security = "tls"  # trojan is TLS by definition
    return Node(
        protocol=proto,
        id=urllib.parse.unquote(u.username or ""),
        server=u.hostname,
        port=u.port or 443,
        remark=urllib.parse.unquote(u.fragment or ""),
        scheme=proto,
        raw=link,
        source=source,
        network=net,
        security=security,
        sni=q.get("sni", ""),
        host=q.get("host", ""),
        path=q.get("path", ""),
        fingerprint=q.get("fp", ""),
        flow=q.get("flow", "") if proto == "vless" else "",
        public_key=q.get("pbk", ""),
        short_id=q.get("sid", ""),
        service_name=q.get("serviceName", ""),
        extra={"encryption": q.get("encryption", "")},
    )


def parse_ss(link: str, source: str) -> Node:
    rest = link[len("ss://"):]
    frag = ""
    if "#" in rest:
        rest, frag = rest.split("#", 1)
    remark = urllib.parse.unquote(frag)
    plugin = ""
    if "?" in rest:
        rest, qs = rest.split("?", 1)
        pq = {k: v[0] for k, v in urllib.parse.parse_qs(qs).items()}
        plugin = pq.get("plugin", "")
    if "@" in rest:  # SIP002: base64(method:password)@host:port
        userinfo, hostport = rest.rsplit("@", 1)
        if ":" in userinfo:
            method_pass = urllib.parse.unquote(userinfo)
        else:
            method_pass = b64decode_padded(userinfo).decode("utf-8", "replace")
    else:  # legacy: base64(method:password@host:port)
        decoded = b64decode_padded(rest).decode("utf-8", "replace")
        if "@" not in decoded:
            raise LinkParseError("ss link missing @host:port")
        method_pass, hostport = decoded.rsplit("@", 1)
    if ":" not in method_pass:
        raise LinkParseError("ss link missing method:password")
    method, password = method_pass.split(":", 1)
    host, port = _split_hostport(hostport)
    return Node(
        protocol="shadowsocks",
        id=password,
        server=host,
        port=port,
        remark=remark,
        scheme="ss",
        raw=link,
        source=source,
        method=method,
        extra={"plugin": plugin},
    )


def parse_link(link: str, source: str) -> Node:
    low = link.strip()
    if low.startswith("vmess://"):
        return parse_vmess(low, source)
    if low.startswith("vless://"):
        return _parse_userinfo_link(low, source, "vless")
    if low.startswith("trojan://"):
        return _parse_userinfo_link(low, source, "trojan")
    if low.startswith("ss://"):
        return parse_ss(low, source)
    raise LinkParseError("unknown scheme")


def parse_links(text: str, source: str) -> tuple[list[Node], list[tuple[str, str]]]:
    """Parse a block of raw links. Returns (nodes, [(line, error)])."""
    nodes, errors = [], []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        try:
            nodes.append(parse_link(line, source))
        except Exception as e:  # noqa: BLE001 - report every bad line, keep scanning
            errors.append((line[:80], f"{type(e).__name__}: {e}"))
    return nodes, errors


def dedupe(nodes: list[Node]) -> tuple[list[Node], int]:
    unique, seen, dups = [], set(), 0
    for n in nodes:
        key = n.dedupe_key
        if key in seen:
            dups += 1
            continue
        seen.add(key)
        unique.append(n)
    return unique, dups
