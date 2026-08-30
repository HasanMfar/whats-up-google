"""Locate or auto-download the Xray core and run one node per short-lived process."""
from __future__ import annotations

import json
import os
import platform
import socket
import subprocess
import time
import zipfile
from pathlib import Path

import httpx
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TransferSpeedColumn,
)

from .nodes import Node

GITHUB_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"

ASSET_NAMES = {
    ("Windows", "AMD64"): "Xray-windows-64.zip",
    ("Windows", "ARM64"): "Xray-windows-arm64-v8a.zip",
    ("Linux", "x86_64"): "Xray-linux-64.zip",
    ("Linux", "aarch64"): "Xray-linux-arm64-v8a.zip",
    ("Darwin", "arm64"): "Xray-macos-arm64-v8a.zip",
    ("Darwin", "x86_64"): "Xray-macos-64.zip",
}


def core_dir(root: Path) -> Path:
    return root / "bin" / "xray"


def ensure_xray(root: Path, configured_path: str = "") -> Path:
    """Return a path to xray(.exe), downloading the latest release if needed."""
    if configured_path:
        p = Path(configured_path)
        if p.exists():
            return p
        raise FileNotFoundError(f"config xray_path points to a missing file: {p}")

    d = core_dir(root)
    exe = d / ("xray.exe" if os.name == "nt" else "xray")
    if exe.exists():
        return exe

    asset = ASSET_NAMES.get((platform.system(), platform.machine()))
    if not asset:
        raise RuntimeError(
            f"No prebuilt Xray asset known for {platform.system()} {platform.machine()}; "
            "download xray manually and set xray_path in config.json"
        )
    d.mkdir(parents=True, exist_ok=True)

    with httpx.Client(trust_env=True, timeout=60, follow_redirects=True) as c:
        rel = c.get(GITHUB_API, headers={"User-Agent": "google-sub-scanner"}).json()
        version = rel.get("tag_name", "?")
        url = next(
            (a["browser_download_url"] for a in rel.get("assets", []) if a["name"] == asset),
            None,
        )
        if not url:
            raise RuntimeError(f"asset {asset} not found in latest Xray-core release")
        print(f"Downloading Xray core {version} ({asset}) ...")
        tmp = d / (asset + ".part")
        with c.stream("GET", url) as resp:
            resp.raise_for_status()
            total = int(resp.headers.get("content-length", 0) or 0)
            with Progress(
                SpinnerColumn(),
                "[progress.description]{task.description}",
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
            ) as prog:
                task = prog.add_task("xray-core", total=total or None)
                with open(tmp, "wb") as f:
                    for chunk in resp.iter_bytes(65536):
                        f.write(chunk)
                        prog.advance(task, len(chunk))

    with zipfile.ZipFile(tmp) as z:
        for name in z.namelist():
            if name.endswith((".exe", ".dat")):
                z.extract(name, d)
    tmp.unlink(missing_ok=True)
    if not exe.exists():
        raise RuntimeError("xray binary not found after extraction")
    (d / "version.txt").write_text(version, encoding="utf-8")
    print(f"Xray core {version} installed at {exe}")
    return exe


def _stream_settings(node: Node) -> dict:
    s: dict = {"network": node.network, "security": node.security}
    if node.security == "tls":
        s["tlsSettings"] = {
            "serverName": node.sni or node.host or node.server,
            "allowInsecure": False,
            "fingerprint": node.fingerprint or "",
        }
    elif node.security == "reality":
        s["realitySettings"] = {
            "serverName": node.sni or node.server,
            "publicKey": node.public_key,
            "shortId": node.short_id,
            "fingerprint": node.fingerprint or "chrome",
        }
    if node.network == "ws":
        s["wsSettings"] = {
            "path": node.path or "/",
            "headers": {"Host": node.host} if node.host else {},
        }
    elif node.network == "grpc":
        s["grpcSettings"] = {"serviceName": node.service_name or node.path or ""}
    elif node.network in ("h2", "http"):
        s["httpSettings"] = {"host": [node.host] if node.host else [], "path": node.path or "/"}
    elif node.network == "httpupgrade":
        s["httpupgradeSettings"] = {"host": node.host or node.server, "path": node.path or "/"}
    elif node.network == "xhttp":
        s["xhttpSettings"] = {"host": node.host or node.server, "path": node.path or "/"}
    return s


def build_outbound(node: Node) -> dict:
    stream = _stream_settings(node)
    if node.protocol == "vmess":
        return {
            "protocol": "vmess",
            "tag": "proxy",
            "settings": {"vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [{"id": node.id, "alterId": node.alter_id, "security": node.cipher or "auto", "level": 0}],
            }]},
            "streamSettings": stream,
        }
    if node.protocol == "vless":
        return {
            "protocol": "vless",
            "tag": "proxy",
            "settings": {"vnext": [{
                "address": node.server,
                "port": node.port,
                "users": [{"id": node.id, "encryption": "none", "flow": node.flow, "level": 0}],
            }]},
            "streamSettings": stream,
        }
    if node.protocol == "trojan":
        return {
            "protocol": "trojan",
            "tag": "proxy",
            "settings": {"servers": [{"address": node.server, "port": node.port, "password": node.id, "level": 0}]},
            "streamSettings": stream,
        }
    if node.protocol == "shadowsocks":
        return {
            "protocol": "shadowsocks",
            "tag": "proxy",
            "settings": {"servers": [{"address": node.server, "port": node.port, "method": node.method, "password": node.id, "uot": False}]},
        }
    raise ValueError(f"unsupported protocol: {node.protocol}")


def build_config(node: Node, socks_port: int) -> dict:
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [build_outbound(node), {"protocol": "freedom", "tag": "direct"}],
    }


class XrayStartupError(RuntimeError):
    pass


# Instances currently running, so Ctrl+C handlers can clean everything up.
active_instances: set["XrayInstance"] = set()

_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class XrayInstance:
    """One xray process exposing one node as a local SOCKS5 port."""

    def __init__(self, exe: Path, node: Node, socks_port: int, root: Path):
        self.exe = exe
        self.node = node
        self.socks_port = socks_port
        self.root = root
        self.proc: subprocess.Popen | None = None
        self.cfg_path = core_dir(root) / "tmp" / f"cfg-{socks_port}.json"
        self.log_path = core_dir(root) / "tmp" / f"xray-{socks_port}.log"

    def start(self, wait_seconds: float = 8.0):
        # If something already answers on this port (leftover xray from an
        # interrupted scan, another instance, ...), our node would silently
        # get tested through the WRONG proxy - fail loudly instead.
        try:
            with socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.3):
                raise XrayStartupError(
                    f"SOCKS port {self.socks_port} is already in use - "
                    "kill leftover xray.exe processes or change socks_port_start in config.json")
        except OSError:
            pass  # nothing listening - good

        self.cfg_path.parent.mkdir(parents=True, exist_ok=True)
        self.cfg_path.write_text(json.dumps(build_config(self.node, self.socks_port), indent=1), encoding="utf-8")
        logf = open(self.log_path, "w", encoding="utf-8", errors="replace")
        try:
            self.proc = subprocess.Popen(
                [str(self.exe), "run", "-c", str(self.cfg_path)],
                stdout=logf,
                stderr=subprocess.STDOUT,
                creationflags=_CREATE_NO_WINDOW,
            )
        finally:
            logf.close()
        active_instances.add(self)

        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-500:]
                self.stop()
                raise XrayStartupError(f"xray exited at startup: {tail.strip() or 'no output'}")
            try:
                with socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.3):
                    return
            except OSError:
                time.sleep(0.1)
        self.stop()
        raise XrayStartupError(f"xray never opened SOCKS port {self.socks_port} within {wait_seconds:.0f}s")

    def stop(self):
        active_instances.discard(self)
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None
        self.cfg_path.unlink(missing_ok=True)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
