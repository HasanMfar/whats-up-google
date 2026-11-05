"""Local bridge: run real Xray probes for the web workbench.

The GitHub Pages UI does everything it can in the browser - decoding, parsing,
inspecting, hand-picking, exporting. The one thing it cannot do is probe: a tab
has no raw TCP sockets, cannot listen on SOCKS and cannot start a native binary.
This server lends it exactly that half over loopback:

    python -m scanner --serve

Guards, in order of importance:

- it binds 127.0.0.1 (a non-loopback address is refused unless --allow-remote),
- every /api request needs the per-run pairing token it prints,
- requests carrying an Origin header must match the allowlist, so an unrelated
  website cannot drive scans on this machine (no allowlisted origin means no
  readable response either),
- node payloads are capped, and only one scan runs at a time.
"""
from __future__ import annotations

import hmac
import json
import mimetypes
import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import __version__, xray as xray_mod
from .main import PortPool, ROOT, load_config, test_node
from .nodes import parse_links
from .report import CHECKS
from .subscriptions import fetch_subscription, make_client

DOCS_DIR = ROOT / "docs"
# Where the one-file bridge sends people: it ships no static files itself.
HOSTED_WORKBENCH = "https://hasanmfar.github.io/whats-up-google/"
MAX_BODY = 8 * 1024 * 1024          # 8 MiB of links per request
MAX_LINKS = 5000                    # one browser scan at a time
MAX_LINK_CHARS = 8192
DEFAULT_ORIGINS = (
    "https://hasanmfar.github.io",
    "https://hasanmfar.github.io/whats-up-google",
)

# Where the browser is allowed to point: anything loopback. Same-origin requests
# from the page this server serves are covered automatically.
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _serialize_row(row: dict) -> dict:
    node = row["node"]
    return {
        "node": node.to_dict(),
        "results": row.get("results") or {},
        "exit_ip": row.get("exit_ip") or {},
        "latency_ms": row.get("latency_ms"),
        "verdict": row.get("verdict", "ERROR"),
        "error": row.get("error", ""),
        "tested_at": row.get("tested_at", ""),
    }


class ScanJob:
    """One browser-requested sweep. Append-only rows so the page can poll by cursor."""

    def __init__(self, links: list[str], checks: dict, concurrency: int, cfg: dict):
        self.id = uuid.uuid4().hex[:12]
        self.links = links
        self.checks = checks
        self.concurrency = max(1, min(int(concurrency or 20), 200))
        self.cfg = dict(cfg)
        self.rows: list[dict] = []
        self.lock = threading.Lock()
        self.total = 0
        self.status = "running"
        self.error = ""
        self.started = time.monotonic()
        self._cancel = threading.Event()
        self._pool: ThreadPoolExecutor | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> None:
        nodes, _errors = parse_links("\n".join(self.links), source="bridge")
        self.total = len(nodes)
        if not nodes:
            self.status = "error"
            self.error = "No usable vmess/vless/trojan/ss links were submitted."
            return
        threading.Thread(target=self._run, args=(nodes,), name=f"scan-{self.id}", daemon=True).start()

    def cancel(self) -> None:
        self._cancel.set()
        pool = self._pool
        if pool is not None:
            pool.shutdown(wait=False, cancel_futures=True)
        xray_mod.stop_all()

    def _push(self, row: dict) -> None:
        with self.lock:
            self.rows.append(_serialize_row(row))

    def _run(self, nodes) -> None:
        pool = None
        try:
            # Leftovers from an earlier/interrupted run would hold our ports.
            xray_mod.stop_all()
            xray_mod.kill_orphans(ROOT)
            xray_mod.clear_stale_tmp(ROOT)
            exe = xray_mod.ensure_xray(ROOT, self.cfg.get("xray_path", ""))
            cfg = {
                "checks": {name: bool(self.checks.get(name, True)) for name in CHECKS},
                "concurrency": self.concurrency,
                "timeout_seconds": self.cfg.get("timeout_seconds", 10),
                "retries": self.cfg.get("retries", 1),
            }
            ports = PortPool(int(self.cfg.get("socks_port_start", 10810)), self.concurrency + 4)
            pool = ThreadPoolExecutor(max_workers=self.concurrency)
            self._pool = pool
            futures = {}
            for node in nodes:
                futures[pool.submit(test_node, node, exe, ports, cfg)] = node
            for future in as_completed(futures):
                if self._cancel.is_set():
                    break
                node = futures[future]
                try:
                    self._push(future.result())
                except Exception as e:  # noqa: BLE001 - one node failing is a result
                    self._push({"node": node, "results": {}, "exit_ip": {}, "latency_ms": None,
                                "verdict": "ERROR", "error": f"{type(e).__name__}: {e}",
                                "tested_at": _now()})
        except Exception as e:  # noqa: BLE001 - surface setup failures to the page
            self.status = "error"
            self.error = f"{type(e).__name__}: {e}"
        finally:
            xray_mod.stop_all()
            if pool is not None:
                pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
            if self.status == "running":
                self.status = "cancelled" if self._cancel.is_set() else "done"

    # -- snapshots ---------------------------------------------------------
    def snapshot(self, since: int = 0) -> dict:
        with self.lock:
            rows = self.rows[since:]
            total_rows = len(self.rows)
        return {
            "id": self.id,
            "status": self.status,
            "error": self.error,
            "total": self.total,
            "done": total_rows,
            "since": total_rows,
            "elapsed": round(time.monotonic() - self.started, 1),
            "rows": rows,
        }


class Bridge:
    """Shared state for the handler: the token, the allowlist and the one job."""

    def __init__(self, token: str, allowed_origins: set[str], cfg: dict):
        self.token = token
        self.allowed_origins = allowed_origins
        self.cfg = cfg
        self.job: ScanJob | None = None
        self.lock = threading.Lock()

    def start_job(self, links, checks, concurrency) -> tuple[ScanJob | None, str]:
        with self.lock:
            if self.job is not None and self.job.status == "running":
                return None, "A scan is already running. Wait for it to finish or stop it."
            job = ScanJob(links, checks, concurrency, self.cfg)
            job.start()
            self.job = job
            return job, ""

    def find_job(self, job_id: str) -> ScanJob | None:
        with self.lock:
            job = self.job
        return job if job and job.id == job_id else None


JOB_PATH = re.compile(r"^/api/job/([0-9a-f]{6,32})$")


def make_handler(bridge: Bridge, docs_root: Path | None = None):
    """Handler for one bridge. Without docs_root only /api/* is served."""
    if docs_root is None:
        docs_root = DOCS_DIR if DOCS_DIR.is_dir() else None
    docs_root = docs_root.resolve() if docs_root is not None else None

    class Handler(BaseHTTPRequestHandler):
        server_version = f"whats-up-google/{__version__}"
        protocol_version = "HTTP/1.1"

        # -- plumbing ------------------------------------------------------
        def log_message(self, fmt, *args):  # noqa: D401 - silence per-request noise
            return

        def _origin(self) -> str | None:
            return self.headers.get("Origin")

        def _origin_allowed(self) -> bool:
            origin = self._origin()
            return origin is None or origin in bridge.allowed_origins

        def _send_cors(self) -> None:
            origin = self._origin()
            if origin is not None and origin in bridge.allowed_origins:
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Vary", "Origin")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Scanner-Token")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Max-Age", "600")
                # Chrome sends a Private Network Access preflight when a public
                # page (the hosted workbench) calls loopback. Answering it here
                # keeps the page able to reach the bridge from HTTPS.
                if self.headers.get("Access-Control-Request-Private-Network"):
                    self.send_header("Access-Control-Allow-Private-Network", "true")

        def _json(self, status: int, payload: dict, close: bool = False) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if close:
                # The request body was never read: leaving it in the socket
                # would corrupt the next keep-alive request on this connection.
                self.send_header("Connection", "close")
                self.close_connection = True
            self._send_cors()
            self.end_headers()
            self.wfile.write(body)

        def _refuse(self, status: int, message: str) -> None:
            self._json(status, {"error": message}, close=True)

        def _token_ok(self) -> bool:
            supplied = self.headers.get("X-Scanner-Token") or ""
            return hmac.compare_digest(supplied, bridge.token)

        def _read_json(self) -> dict:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if length > MAX_BODY:
                raise ValueError("That request is too large.")
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                data = json.loads(raw.decode("utf-8") or "{}")
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise ValueError("Body must be JSON.")
            if not isinstance(data, dict):
                raise ValueError("Body must be a JSON object.")
            return data

        # -- routes --------------------------------------------------------
        def do_OPTIONS(self):  # noqa: N802
            if not self._origin_allowed():
                self._json(403, {"error": "Origin not allowed."})
                return
            self.send_response(204)
            self.send_header("Content-Length", "0")
            self._send_cors()
            self.end_headers()

        def do_GET(self):  # noqa: N802
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/ping":
                self._json(200, {
                    "ok": True,
                    "name": "whats-up-google",
                    "version": __version__,
                    "xray": {"version": _xray_version(), "ready": bool(_xray_version())},
                })
                return
            if path.startswith("/api/"):
                if not self._origin_allowed():
                    self._json(403, {"error": "Origin not allowed."})
                    return
                if not self._token_ok():
                    self._json(403, {"error": "Missing or wrong pairing token."})
                    return
                match = JOB_PATH.match(path)
                if match:
                    job = bridge.find_job(match.group(1))
                    if job is None:
                        self._json(404, {"error": "No such scan."})
                        return
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
                    try:
                        since = max(0, int((query.get("since") or ["0"])[0]))
                    except ValueError:
                        since = 0
                    self._json(200, job.snapshot(since))
                    return
                self._json(404, {"error": "Unknown endpoint."})
                return
            self._serve_static(path)

        def do_POST(self):  # noqa: N802
            path = urllib.parse.urlsplit(self.path).path
            if not path.startswith("/api/"):
                self._refuse(404, "Unknown endpoint.")
                return
            if not self._origin_allowed():
                self._refuse(403, "Origin not allowed.")
                return
            if not self._token_ok():
                self._refuse(403, "Missing or wrong pairing token.")
                return
            try:
                payload = self._read_json()
            except ValueError as e:
                self._refuse(400, str(e))
                return

            if path == "/api/parse":
                self._json(200, self._parse(payload))
            elif path == "/api/fetch-subs":
                self._json(200, self._fetch_subs(payload))
            elif path == "/api/scan":
                self._scan(payload)
            elif path == "/api/cancel":
                job = bridge.find_job(str(payload.get("job_id") or ""))
                if job is None:
                    self._json(404, {"error": "No such scan."})
                    return
                job.cancel()
                self._json(200, {"ok": True, "id": job.id})
            else:
                self._json(404, {"error": "Unknown endpoint."})

        # -- handlers ------------------------------------------------------
        def _parse(self, payload: dict) -> dict:
            from .subscriptions import decode_subscription

            text = str(payload.get("text") or "")
            if not text.strip():
                return {"nodes": [], "errors": [], "duplicates": 0}
            if len(text) > MAX_BODY:
                return {"nodes": [], "errors": [{"line": "", "error": "Input too large"}], "duplicates": 0}
            links = decode_subscription(text)
            nodes, errors = parse_links(links, source="bridge")
            return {
                "nodes": [n.to_dict() for n in nodes],
                "errors": [{"line": line, "error": err} for line, err in errors],
                "duplicates": 0,
            }

        def _fetch_subs(self, payload: dict) -> dict:
            urls = [str(u).strip() for u in (payload.get("urls") or []) if str(u).strip()]
            urls = [u for u in urls if u.startswith(("http://", "https://"))][:64]
            if not urls:
                return {"results": []}
            results = []
            with make_client() as client:
                for url in urls:
                    try:
                        text = fetch_subscription(client, url)
                        parsed, errors = parse_links(text, source=url)
                        results.append({
                            "url": url, "status": "ok", "detail": "",
                            "nodes": [n.to_dict() for n in parsed],
                            "bad_lines": len(errors),
                        })
                    except Exception as e:  # noqa: BLE001 - a dead URL is a result
                        results.append({"url": url, "status": "error", "nodes": [],
                                        "detail": f"{type(e).__name__}: {e}"[:300]})
            return {"results": results}

        def _scan(self, payload: dict) -> None:
            links = [str(link) for link in (payload.get("links") or []) if str(link).strip()]
            if not links:
                self._json(400, {"error": "No links submitted."})
                return
            if len(links) > MAX_LINKS:
                self._json(400, {"error": f"At most {MAX_LINKS} configs per scan; this request had {len(links)}."})
                return
            if any(len(link) > MAX_LINK_CHARS for link in links):
                self._json(400, {"error": "One of the links is unreasonably long."})
                return
            checks = payload.get("checks") if isinstance(payload.get("checks"), dict) else {}
            job, problem = bridge.start_job(links, checks, payload.get("concurrency") or 20)
            if job is None:
                self._json(409, {"error": problem})
                return
            if job.status == "error":
                self._json(400, {"error": job.error or "Nothing to scan."})
                return
            self._json(200, {"job_id": job.id, "total": job.total, "status": job.status})

        def _serve_static(self, path: str) -> None:
            if docs_root is None:
                self._not_found()  # one-file bridge: the page lives on the site
                return
            if path in ("", "/"):
                path = "/index.html"
            relative = urllib.parse.unquote(path).lstrip("/")
            try:
                target = (DOCS_DIR / relative).resolve()
            except OSError:
                self._not_found()
                return
            # resolve() collapses .., so this also blocks path traversal
            if docs_root not in target.parents and target != docs_root:
                self._not_found()
                return
            if not target.is_file():
                self._not_found()
                return
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
                ctype += "; charset=utf-8"
            body = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _not_found(self) -> None:
            body = b"<!doctype html><title>404</title><p>Not found.</p>"
            self.send_response(404)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def _xray_version() -> str:
    """Report the locally installed core without downloading anything.

    ensure_xray() records the release tag next to the binary it extracted, so
    this never has to run xray.exe just to answer a status request.
    """
    try:
        exe = xray_mod.core_dir(ROOT) / ("xray.exe" if os.name == "nt" else "xray")
        if not exe.exists():
            return ""
        stamp = exe.parent / "version.txt"
        if stamp.exists():
            return stamp.read_text(encoding="utf-8").strip()[:40]
        return "installed"
    except Exception:  # noqa: BLE001 - a missing core is not an error worth reporting
        return ""


class BridgeServer(ThreadingHTTPServer):
    """One bridge per port.

    Windows lets two listeners bind the same port when SO_REUSEADDR is on,
    which used to mean a second --serve appeared to start but every request
    still went to the first one (and its older token). Refusing reuse turns
    that into a clear "port already in use" instead of a confusing 403.
    """

    daemon_threads = True
    allow_reuse_address = False
    allow_reuse_port = False


def parse_bind(spec: str) -> tuple[str, int]:
    spec = (spec or "127.0.0.1:8787").strip()
    if spec.isdigit():
        return "127.0.0.1", int(spec)
    host, _, port = spec.rpartition(":")
    host = host.strip("[]") or "127.0.0.1"
    try:
        return host, int(port or 8787)
    except ValueError:
        raise SystemExit(f"Bad --serve address {spec!r}; use HOST:PORT, e.g. 127.0.0.1:8787.")


def workbench_url(host: str, port: int, token: str, docs_root: Path | None) -> str:
    """URL to open for this bridge.

    A checkout serves the workbench itself. The one-file .pyz has no docs/, so
    it points at the hosted page and hands over its own address and token - the
    user never pastes anything.
    """
    token_q = urllib.parse.quote(token, safe="")
    if docs_root is not None:
        return f"http://{host}:{port}/?token={token_q}"
    bridge_q = urllib.parse.quote(f"http://{host}:{port}", safe="")
    return f"{HOSTED_WORKBENCH}?bridge={bridge_q}&token={token_q}"


def serve(spec: str, cfg: dict | None = None, open_browser: bool = False,
          allow_origins: list[str] | None = None, allow_remote: bool = False) -> None:
    """Run the loopback bridge until interrupted."""
    host, port = parse_bind(spec)
    if host not in LOOPBACK_HOSTS and not allow_remote:
        raise SystemExit(
            f"Refusing to bind {host}: the bridge can start scans, so it stays on loopback.\n"
            "Pass --allow-remote only if you understand who can reach that address."
        )
    docs_root = DOCS_DIR if DOCS_DIR.is_dir() else None

    cfg = dict(cfg or load_config())
    origins = set(DEFAULT_ORIGINS)
    for origin in allow_origins or []:
        origins.add(origin.rstrip("/"))
    origins.update({f"http://127.0.0.1:{port}", f"http://localhost:{port}"})
    if port == 80:
        origins.add("http://127.0.0.1")

    token = secrets.token_urlsafe(9)
    bridge = Bridge(token, origins, cfg)
    try:
        server = BridgeServer((host, port), make_handler(bridge, docs_root))
    except OSError as e:
        raise SystemExit(
            f"Could not listen on {host}:{port} ({e}).\n"
            "A bridge is probably already running there - stop it, or use another port:\n"
            f"  python -m scanner --serve 127.0.0.1:{port + 1}"
        )

    url = workbench_url(host, port, token, docs_root)
    xray_version = _xray_version()

    printf = lambda *args: print(*args, flush=True)  # noqa: E731 - banner must not sit in a buffer
    printf()
    printf("  What's up google - local bridge")
    printf(f"  Workbench   {url}")
    printf(f"  Token       {token}")
    printf(f"  Xray core   {xray_version or 'not downloaded yet (fetched on the first scan)'}")
    printf(f"  Origins     {', '.join(sorted(origins))}")
    if docs_root is None:
        printf("  Mode        one-file bridge - the workbench is the hosted page")
    printf()
    printf("  Xray cannot run inside a browser tab, so this process runs the probes.")
    printf("  Ctrl+C stops the bridge, and every Xray process with it.")
    printf()

    xray_mod.install_exit_hooks()
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001 - a headless session just skips this
            pass
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        job = bridge.job
        if job is not None and job.status == "running":
            job.cancel()
        xray_mod.stop_all()
        server.server_close()
        _ = sys.stdout.flush()
