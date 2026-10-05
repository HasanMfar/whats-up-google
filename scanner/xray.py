"""Locate or auto-download the Xray core and run one node per short-lived process."""
from __future__ import annotations

import atexit
import json
import os
import platform
import signal
import socket
import subprocess
import threading
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


# Instances currently running, so Ctrl+C handlers and exit hooks can clean everything up.
active_instances: set["XrayInstance"] = set()
_instances_lock = threading.Lock()


def _register(inst: "XrayInstance") -> None:
    with _instances_lock:
        active_instances.add(inst)


def _unregister(inst: "XrayInstance") -> None:
    with _instances_lock:
        active_instances.discard(inst)


def _terminate(proc: subprocess.Popen) -> bool:
    """terminate -> wait -> kill -> wait. Returns True once the child is confirmed dead.

    Shields every step from exceptions/interrupts: a second Ctrl+C must never
    leave a half-killed xray process behind.
    """
    try:
        if proc.poll() is not None:
            return False
    except BaseException:
        return False
    dead = False
    try:
        proc.terminate()
    except BaseException:
        pass
    try:
        proc.wait(timeout=2)
        dead = True
    except subprocess.TimeoutExpired:
        pass
    except BaseException:
        pass
    if not dead:
        try:
            proc.kill()
        except BaseException:
            pass
        try:
            proc.wait(timeout=2)
            dead = True
        except BaseException:
            pass
    return dead


def stop_all(timeout: float = 15.0) -> int:
    """Stop every tracked xray process; drains instances spawned concurrently.

    Returns the number of processes confirmed dead. Cleanup swallows
    exceptions (including KeyboardInterrupt) until the drain loop finishes or
    the timeout expires - a second Ctrl+C must not abort the sweep.
    """
    deadline = time.monotonic() + timeout
    stopped = 0
    while time.monotonic() < deadline:
        with _instances_lock:
            batch = list(active_instances)
        if not batch:
            break
        for inst in batch:
            try:
                if inst.stop():
                    stopped += 1
            except BaseException:  # noqa: BLE001 - stop() is already shielded
                pass
        time.sleep(0.02)
    return stopped


# --- last-resort cleanup: however the process dies, xray must die too ---------

_job_handle = None          # Windows job object holding every xray child
_job_disabled = False       # set when the job object is unsupported/unavailable
_job_lock = threading.Lock()
_JOB_OBJECT_EXTENDED_LIMIT_INFORMATION = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000


def _job_assign(proc: subprocess.Popen) -> bool:
    """Windows: assign the child to a job that kills it when THIS process exits.

    Covers the cases where Python never runs atexit or signal handlers:
    closing the console window, Task Manager "End task", a crash. Best effort
    - returns False on failure, then the signal/atexit hooks are the only net.
    """
    global _job_handle, _job_disabled
    if os.name != "nt" or _job_disabled:
        return False
    try:
        import ctypes
        from ctypes import wintypes

        with _job_lock:
            if _job_handle is None:
                k32 = ctypes.WinDLL("kernel32", use_last_error=True)

                class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD),
                    ]

                class IO_COUNTERS(ctypes.Structure):
                    _fields_ = [
                        ("ReadOperationCount", ctypes.c_uint64),
                        ("WriteOperationCount", ctypes.c_uint64),
                        ("OtherOperationCount", ctypes.c_uint64),
                        ("ReadTransferCount", ctypes.c_uint64),
                        ("WriteTransferCount", ctypes.c_uint64),
                        ("OtherTransferCount", ctypes.c_uint64),
                    ]

                class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
                    _fields_ = [
                        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                        ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t),
                    ]

                handle = k32.CreateJobObjectW(None, None)
                if not handle:
                    _job_disabled = True
                    return False
                info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
                info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                if not k32.SetInformationJobObject(
                    handle, _JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ctypes.byref(info), ctypes.sizeof(info),
                ):
                    k32.CloseHandle(handle)
                    _job_disabled = True
                    return False
                _job_handle = handle
            ok = bool(ctypes.WinDLL("kernel32", use_last_error=True).AssignProcessToJobObject(
                wintypes.HANDLE(_job_handle), wintypes.HANDLE(int(proc._handle))))
            _job_disabled = not ok
            return ok
    except Exception:
        _job_disabled = True
        return False


_hooks_installed = False
_hooks_lock = threading.Lock()


def _atexit_stop() -> None:
    stop_all(timeout=10)


def _signal_stop(signum, frame) -> None:
    stop_all(timeout=5)
    raise SystemExit(128 + signum)


def install_exit_hooks() -> None:
    """Kill tracked xray processes on interpreter exit or SIGTERM/SIGHUP/SIGBREAK.

    Ctrl+C keeps its normal KeyboardInterrupt flow (handlers in main.py);
    these cover the close/terminate paths that never raise KeyboardInterrupt.
    """
    global _hooks_installed
    with _hooks_lock:
        if _hooks_installed:
            return
        _hooks_installed = True
    atexit.register(_atexit_stop)
    for name in ("SIGTERM", "SIGHUP", "SIGBREAK"):
        sig = getattr(signal, name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _signal_stop)
        except (OSError, ValueError):
            pass


def kill_orphans(root: Path, keep_pids=()) -> int:
    """Kill xray processes left behind by earlier interrupted runs.

    Only processes whose command line references this repo's config directory
    (bin/xray/tmp/cfg-*.json) are ever touched; everything else is ignored.
    """
    cfg_dir = str(core_dir(root) / "tmp")
    with _instances_lock:
        keep = {os.getpid(),
                *(i.proc.pid for i in active_instances if i.proc is not None),
                *(int(p) for p in keep_pids)}
    killed = 0
    if os.name == "nt":
        keep_list = ",".join(str(p) for p in sorted(keep))
        ps = (
            f"$dir = '{cfg_dir.replace(chr(39), chr(39) * 2)}'; $n = 0; "
            "Get-CimInstance Win32_Process | ForEach-Object { "
            # $PID excludes PowerShell itself: the -Command argument contains $dir,
            # so its own command line matches the filter too.
            f"if ($_.CommandLine -and $_.CommandLine.Contains($dir) -and $_.ProcessId -ne $PID "
            f"-and $_.ProcessId -notin @({keep_list})) "
            "{ try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop; $n++ } catch {} } }; "
            "Write-Output $n"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, timeout=20,
            )
            killed = int((out.stdout or b"0").decode("utf-8", "replace").strip() or 0)
        except Exception:
            killed = 0  # never fail a scan over orphan cleanup
    else:
        try:
            out = subprocess.run(["ps", "-eo", "pid=,args="],
                                 capture_output=True, text=True, timeout=10)
            lines = out.stdout.splitlines()
        except Exception:
            return 0
        for line in lines:
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            pid_s, args = parts
            try:
                pid = int(pid_s)
            except ValueError:
                continue
            if pid in keep or cfg_dir not in args:
                continue
            try:
                os.kill(pid, signal.SIGTERM)
                killed += 1
            except OSError:
                pass
    if killed:
        print(f"Killed {killed} leftover xray process(es) from an earlier run.")
    return killed


_CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class XrayInstance:
    """One xray process exposing one node as a local SOCKS5 port."""

    def __init__(self, exe: Path, node: Node, socks_port: int, root: Path):
        self.exe = exe
        self.node = node
        self.socks_port = socks_port
        self.root = root
        self.proc: subprocess.Popen | None = None
        self._lock = threading.Lock()          # serializes proc hand-over between start/stop
        self._stop_requested = threading.Event()  # set by stop(); observed by start()
        self.cfg_path = core_dir(root) / "tmp" / f"cfg-{socks_port}.json"
        self.log_path = core_dir(root) / "tmp" / f"xray-{socks_port}.log"

    def start(self, wait_seconds: float = 8.0):
        if self._stop_requested.is_set():
            raise XrayStartupError("stopped before this node started")
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
        try:
            # A concurrent stop() may already have fired (Ctrl+C during a sweep):
            # never spawn a process nobody will reap.
            if self._stop_requested.is_set():
                raise XrayStartupError("stopped before this node started")
            logf = open(self.log_path, "w", encoding="utf-8", errors="replace")
            try:
                proc = subprocess.Popen(
                    [str(self.exe), "run", "-c", str(self.cfg_path)],
                    stdout=logf,
                    stderr=subprocess.STDOUT,
                    creationflags=_CREATE_NO_WINDOW,
                )
            finally:
                logf.close()
            with self._lock:
                self.proc = proc
            _job_assign(proc)
            _register(self)

            deadline = time.monotonic() + wait_seconds
            while time.monotonic() < deadline:
                if self._stop_requested.is_set():
                    raise XrayStartupError("stopped while waiting for the SOCKS port")
                if proc.poll() is not None:
                    tail = self.log_path.read_text(encoding="utf-8", errors="replace")[-500:]
                    raise XrayStartupError(f"xray exited at startup: {tail.strip() or 'no output'}")
                try:
                    with socket.create_connection(("127.0.0.1", self.socks_port), timeout=0.3):
                        return
                except OSError:
                    time.sleep(0.1)
            raise XrayStartupError(f"xray never opened SOCKS port {self.socks_port} within {wait_seconds:.0f}s")
        except BaseException:
            # Any failure between "about to spawn" and "running" must reap the
            # child - an exception here used to leak the process.
            self.stop()
            raise

    def stop(self) -> bool:
        """Terminate this instance's process.

        Idempotent, thread-safe and never raises: cleanup paths (worker
        finallys, Ctrl+C handlers, atexit) must not be interruptible.
        Returns True when this call confirmed the child dead.
        """
        self._stop_requested.set()
        killed = False
        try:
            try:
                with self._lock:
                    proc, self.proc = self.proc, None
            except BaseException:
                proc = None
            if proc is not None:
                killed = _terminate(proc)
        finally:
            _unregister(self)
            try:
                self.cfg_path.unlink(missing_ok=True)
            except OSError:
                pass  # Windows may still hold the file briefly; next sweep retries
        return killed

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.stop()
