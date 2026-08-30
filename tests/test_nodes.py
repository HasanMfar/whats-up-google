"""Run with: python tests/test_nodes.py"""
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner.nodes import b64decode_padded, dedupe, parse_links  # noqa: E402


def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


VMESS_JSON = {
    "v": "2", "ps": "HK VMess", "add": "hk.example.com", "port": "443",
    "id": "b831381d-6324-4d53-ad4f-8cda48b30811", "aid": "0", "scy": "auto",
    "net": "ws", "type": "none", "host": "cdn.example.com", "path": "/vmws",
    "tls": "tls", "sni": "hk.example.com",
}
VMESS = "vmess://" + b64(json.dumps(VMESS_JSON))
VLESS = ("vless://b831381d-6324-4d53-ad4f-8cda48b30811@us.example.com:443"
         "?encryption=none&security=reality&sni=www.google.com&fp=chrome"
         "&pbk=PUBKEY123&sid=ab12&type=grpc&serviceName=grpcsvc"
         "&flow=xtls-rprx-vision#US%20Reality")
TROJAN = ("trojan://p%40ssw0rd@jp.example.com:8443"
          "?security=tls&sni=jp.example.com&type=tcp#JP%20Trojan")
SS_SIP002 = "ss://" + b64("aes-256-gcm:pw12345") + "@1.2.3.4:8388#SS%20Node"
SS_LEGACY = "ss://" + b64("aes-256-gcm:pw12345@5.6.7.8:990") + "#legacy"

TEXT = "\n".join([
    VMESS, VLESS, TROJAN, SS_SIP002, SS_LEGACY,
    "garbage-line", "", "# comment", VMESS,
])

nodes, errors = parse_links(TEXT, source="test")
assert len(nodes) == 6, f"expected 6 nodes (incl. the duplicate), got {len(nodes)}"
assert len(errors) == 1, f"expected 1 parse error, got {errors}"

n = nodes[0]
assert n.protocol == "vmess"
assert n.id == "b831381d-6324-4d53-ad4f-8cda48b30811"
assert n.server == "hk.example.com" and n.port == 443
assert n.network == "ws" and n.security == "tls"
assert n.host == "cdn.example.com" and n.path == "/vmws"
assert n.remark == "HK VMess" and n.cipher == "auto" and n.alter_id == 0

v = nodes[1]
assert v.protocol == "vless"
assert v.security == "reality" and v.public_key == "PUBKEY123" and v.short_id == "ab12"
assert v.network == "grpc" and v.service_name == "grpcsvc"
assert v.flow == "xtls-rprx-vision" and v.fingerprint == "chrome"
assert v.remark == "US Reality"

t = nodes[2]
assert t.protocol == "trojan"
assert t.id == "p@ssw0rd", t.id
assert t.port == 8443 and t.security == "tls" and t.sni == "jp.example.com"

s = nodes[3]
assert s.protocol == "shadowsocks"
assert s.method == "aes-256-gcm" and s.id == "pw12345"
assert s.server == "1.2.3.4" and s.port == 8388 and s.remark == "SS Node"

s2 = nodes[4]
assert s2.server == "5.6.7.8" and s2.port == 990 and s2.remark == "legacy"

unique, dups = dedupe(nodes)
assert len(unique) == 5 and dups == 1

# padding-less / urlsafe vmess variant
nopad = "vmess://" + b64(json.dumps(VMESS_JSON)).rstrip("=").replace("+", "-").replace("/", "_")
cfg = json.loads(b64decode_padded(nopad[len("vmess://"):]).decode())
assert cfg["id"] == VMESS_JSON["id"]

print("all node parser tests passed")
