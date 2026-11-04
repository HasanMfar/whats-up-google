"""Run with: python tests/test_server.py

The bridge can start scans on the machine it runs on, so its guards are the
point: token required, foreign origins refused, no path traversal, and the
workbench itself served from docs/. No Xray core is downloaded here.
"""
import base64
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import httpx  # noqa: E402

from scanner import server as server_mod  # noqa: E402

TOKEN = "test-token-123"
GITHUB_ORIGIN = "https://hasanmfar.github.io"
LINKS = [
    "vless://b831381d-6324-4d53-ad4f-8cda48b30811@us.example.com:443?security=reality&type=ws#US%20node",
    "trojan://p%40ss@jp.example.com:8443#JP",
    "ss://YWVzLTI1Ni1nY206cHcxMjM0NQ==@1.2.3.4:8388#SS",
]

bridge = server_mod.Bridge(TOKEN, {GITHUB_ORIGIN, "http://127.0.0.1:8787"}, {})
httpd = server_mod.ThreadingHTTPServer(("127.0.0.1", 0), server_mod.make_handler(bridge))
httpd.daemon_threads = True
threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True).start()
BASE = f"http://127.0.0.1:{httpd.server_address[1]}"
AUTH = {"X-Scanner-Token": TOKEN}


def expect(condition, label: str) -> None:
    if not condition:
        raise AssertionError(label)
    print(f"ok  {label}")


try:
    with httpx.Client(base_url=BASE, timeout=10) as client:
        # -- liveness ------------------------------------------------------
        r = client.get("/api/ping")
        expect(r.status_code == 200 and r.json().get("ok") is True, "ping answers without a token")

        # -- the workbench is served from docs/ ----------------------------
        r = client.get("/")
        expect(r.status_code == 200 and "text/html" in r.headers["content-type"], "index.html served")
        expect("What's up google" in r.text, "index.html has the product name")

        r = client.get("/assets/app.css")
        expect(r.status_code == 200 and "text/css" in r.headers["content-type"], "stylesheet served")
        r = client.get("/assets/app.js")
        expect(r.status_code == 200 and "javascript" in r.headers["content-type"], "app.js served")

        # -- traversal -----------------------------------------------------
        r = client.get("/%2e%2e%2fconfig.json")
        expect(r.status_code == 404 and '"concurrency"' not in r.text, "path traversal refused")
        r = client.get("/nope.css")
        expect(r.status_code == 404, "missing asset is a 404")

        # -- token ---------------------------------------------------------
        payload = {"text": "\n".join(LINKS)}
        r = client.post("/api/parse", json=payload)
        expect(r.status_code == 403, "parse without a token is refused")
        r = client.post("/api/parse", json=payload, headers={"X-Scanner-Token": "wrong"})
        expect(r.status_code == 403, "parse with a wrong token is refused")

        # -- origin --------------------------------------------------------
        r = client.post("/api/parse", json=payload, headers={**AUTH, "Origin": "https://evil.example"})
        expect(r.status_code == 403, "foreign origin is refused even with a token")
        expect("access-control-allow-origin" not in r.headers, "no CORS header for a foreign origin")

        # -- parse (no Origin: same-origin / CLI) --------------------------
        r = client.post("/api/parse", json=payload, headers=AUTH)
        expect(r.status_code == 200, "parse accepts an authorised request")
        nodes = r.json()["nodes"]
        expect(len(nodes) == 3, f"parse returns every link (got {len(nodes)})")
        expect(nodes[0]["protocol"] == "vless" and nodes[0]["security"] == "reality",
               "parsed node keeps protocol + security")
        expect(nodes[0]["remark"] == "US node", "url-encoded remark is decoded")

        # -- base64 subscription body --------------------------------------
        encoded = base64.b64encode("\n".join(LINKS).encode()).decode()
        r = client.post("/api/parse", json={"text": encoded}, headers=AUTH)
        expect(r.status_code == 200 and len(r.json()["nodes"]) == 3, "base64 body decoded")

        # -- preflight -----------------------------------------------------
        r = client.options("/api/parse", headers={"Origin": GITHUB_ORIGIN,
                                                  "Access-Control-Request-Method": "POST"})
        expect(r.status_code == 204, "preflight from the Pages origin is accepted")
        expect(r.headers.get("access-control-allow-origin") == GITHUB_ORIGIN, "CORS origin echoed")
        expect("x-scanner-token" in r.headers.get("access-control-allow-headers", "").lower(),
               "token header allowed in CORS")

        r = client.options("/api/parse", headers={"Origin": "https://evil.example",
                                                  "Access-Control-Request-Method": "POST"})
        expect(r.status_code == 403, "preflight from a foreign origin is refused")

        # -- misc endpoints ------------------------------------------------
        r = client.get("/api/job/deadbeefdead", headers=AUTH)
        expect(r.status_code == 404, "unknown job is a 404")
        r = client.post("/api/cancel", json={"job_id": "deadbeefdead"}, headers=AUTH)
        expect(r.status_code == 404, "cancelling an unknown job is a 404")
        r = client.post("/api/scan", json={"links": []}, headers=AUTH)
        expect(r.status_code == 400, "empty scan is rejected before Xray is touched")

        # -- bind parsing --------------------------------------------------
        expect(server_mod.parse_bind("127.0.0.1:9999") == ("127.0.0.1", 9999), "bind parse host:port")
        expect(server_mod.parse_bind("9999") == ("127.0.0.1", 9999), "bind parse bare port")
finally:
    httpd.shutdown()
    httpd.server_close()

print("\nall bridge tests passed")
