"""CLI entry point and scan orchestration."""
from __future__ import annotations

import argparse
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.live import Live

from . import __version__, xray as xray_mod
from .clean_sub import print_summary, write_clean_outputs
from .nodes import Node, dedupe, parse_links
from .probes import run_all_probes, verdict_from, node_latency_ms
from .report import CHECKS, build_table, print_output_files, summarize, write_reports
from .subscriptions import fetch_subscription, load_subscription_urls, make_client

ROOT = Path(__file__).resolve().parent.parent
console = Console()

DEFAULT_CONFIG = {
    "concurrency": 50,
    "timeout_seconds": 10,
    "retries": 1,
    "socks_port_start": 10810,
    "xray_path": "",
    "checks": {"search": True, "gemini": True, "gemini_api": True, "antigravity": True},
}


def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    cfg["checks"] = dict(DEFAULT_CONFIG["checks"])
    cfg_path = ROOT / "config.json"
    if cfg_path.exists():
        try:
            user = json.loads(cfg_path.read_text(encoding="utf-8-sig"))
            cfg.update({k: v for k, v in user.items() if k != "checks"})
            if isinstance(user.get("checks"), dict):
                cfg["checks"].update(user["checks"])
        except json.JSONDecodeError as e:
            console.print(f"[yellow]config.json is invalid ({e}); using defaults[/yellow]")
    else:
        cfg_path.write_text(json.dumps(DEFAULT_CONFIG, indent=2), encoding="utf-8")
    return cfg


def gather_nodes(args) -> tuple[list[Node], dict]:
    """Parse nodes from --file or from subscription URLs in subscriptions.txt."""
    stats = {"sources": 0, "fetch_errors": 0, "parse_errors": 0, "duplicates": 0}
    nodes: list[Node] = []

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8-sig")
        parsed, errors = parse_links(text, source=args.file)
        nodes.extend(parsed)
        stats["parse_errors"] += len(errors)
        for line, err in errors:
            console.print(f"[yellow]parse error:[/yellow] {line} -> {err}")
        unique, dups = dedupe(nodes)
        stats["duplicates"] += dups
        return unique, stats

    sub_path = ROOT / "subscriptions.txt"
    if not sub_path.exists():
        sub_path.write_text(
            "# Paste your V2Ray subscription URLs below, one per line.\n"
            "# Lines starting with # are ignored.\n"
            "# Example: https://example.com/api/v1/client/subscribe?token=xxxx\n",
            encoding="utf-8",
        )
        console.print(f"[red]{sub_path} was created - paste your subscription URLs into it and re-run.[/red]")
        sys.exit(1)

    urls = load_subscription_urls(sub_path)
    if not urls:
        console.print("[red]subscriptions.txt has no URLs. Paste at least one subscription URL.[/red]")
        sys.exit(1)

    with make_client() as client:
        for url in urls:
            stats["sources"] += 1
            console.print(f"[dim]Fetching subscription:[/dim] {url}")
            try:
                text = fetch_subscription(client, url)
            except Exception as e:  # noqa: BLE001
                stats["fetch_errors"] += 1
                console.print(f"[red]subscription failed:[/red] {type(e).__name__}: {e}")
                if "did not return V2Ray links" in str(e):
                    console.print("[yellow]  ^ check that this URL is a V2Ray subscription "
                                  "link, not a page or a code list.[/yellow]")
                continue
            parsed, errors = parse_links(text, source=url)
            nodes.extend(parsed)
            stats["parse_errors"] += len(errors)
            console.print(f"[dim]  -> {len(parsed)} nodes parsed, {len(errors)} bad lines[/dim]")

    unique, dups = dedupe(nodes)
    stats["duplicates"] += dups
    return unique, stats


def test_node(node: Node, exe: Path, socks_port: int, cfg: dict) -> dict:
    row = {
        "node": node,
        "results": {},
        "exit_ip": {},
        "latency_ms": None,
        "verdict": "PENDING",
        "error": "",
        "tested_at": "",
    }
    inst = xray_mod.XrayInstance(exe, node, socks_port, ROOT)
    try:
        inst.start()
    except Exception as e:  # noqa: BLE001
        row["verdict"] = "DEAD"
        row["error"] = f"xray: {e}"
        row["tested_at"] = datetime.now().isoformat(timespec="seconds")
        return row
    try:
        results, exit_ip, alive = run_all_probes(
            socks_port, cfg["checks"], cfg["timeout_seconds"], cfg["retries"])
        row["results"] = results
        row["exit_ip"] = exit_ip
        row["alive"] = alive
        row["latency_ms"] = node_latency_ms(results)
        row["verdict"] = verdict_from(results, alive)
        if not alive:
            row["error"] = "no probe got an HTTP response through this node"
    except Exception as e:  # noqa: BLE001
        row["verdict"] = "ERROR"
        row["error"] = f"{type(e).__name__}: {e}"
    finally:
        inst.stop()
    row["tested_at"] = datetime.now().isoformat(timespec="seconds")
    return row


def run_scan(nodes: list[Node], cfg: dict, live_title: str) -> list[dict]:
    exe = xray_mod.ensure_xray(ROOT, cfg.get("xray_path", ""))
    rows: list[dict] = []
    ports = [cfg["socks_port_start"] + i for i in range(len(nodes))]
    futures = {}
    with Live(build_table(rows, live_title), console=console, refresh_per_second=2) as live:
        with ThreadPoolExecutor(max_workers=cfg["concurrency"]) as pool:
            try:
                for node, port in zip(nodes, ports):
                    futures[pool.submit(test_node, node, exe, port, cfg)] = node
                for fut in as_completed(futures):
                    try:
                        rows.append(fut.result())
                    except Exception as e:  # noqa: BLE001
                        n = futures[fut]
                        rows.append({"node": n, "results": {}, "exit_ip": {}, "latency_ms": None,
                                     "verdict": "ERROR", "error": f"{type(e).__name__}: {e}",
                                     "tested_at": datetime.now().isoformat(timespec="seconds")})
                    rows.sort(key=lambda r: (r["node"].server, r["node"].port))
                    s = summarize(rows)
                    live.update(build_table(
                        rows,
                        f"{live_title}   [dim]done {s['CLEAN']+s['FLAGGED']+s['DEAD']+s['ERROR']}/{s['TOTAL']}"
                        f" - clean {s['CLEAN']} - flagged {s['FLAGGED']} - dead {s['DEAD']}[/dim]"))
            except KeyboardInterrupt:
                console.print("\n[yellow]Interrupted - stopping xray processes...[/yellow]")
                pool.shutdown(wait=False, cancel_futures=True)
                for inst in list(xray_mod.active_instances):
                    inst.stop()
                raise
    return rows


def main(argv=None):
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    ap = argparse.ArgumentParser(
        prog="python -m scanner",
        description="Scan V2Ray subscriptions and check Google (Search/Gemini/Gemini API/Antigravity) access per node.",
    )
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    ap.add_argument("--file", help="parse node links from a local file instead of subscriptions.txt")
    ap.add_argument("--concurrency", type=int, help="parallel node tests (default from config.json)")
    ap.add_argument("--json", dest="json_path", help="also write the JSON report to this path")
    ap.add_argument("--skip", action="append", choices=CHECKS,
                    help="disable a check (repeatable: search gemini gemini_api antigravity)")
    ap.add_argument("--dry-run", action="store_true", help="parse subscriptions and exit (no tests)")
    ap.add_argument("--check-xray", action="store_true", help="ensure the Xray core is present, then exit")
    ap.add_argument("--watch", type=int, metavar="MINUTES",
                    help="re-scan every N minutes until Ctrl+C")
    args = ap.parse_args(argv)

    cfg = load_config()
    if args.concurrency:
        cfg["concurrency"] = max(1, args.concurrency)
    for skip in args.skip or []:
        cfg["checks"][skip] = False

    if args.check_xray:
        exe = xray_mod.ensure_xray(ROOT, cfg.get("xray_path", ""))
        console.print(f"[green]Xray core ready:[/green] {exe}")
        return

    nodes, stats = gather_nodes(args)
    console.print(f"Parsed [bold]{len(nodes)}[/bold] unique nodes "
                  f"(duplicates removed: {stats['duplicates']}, "
                  f"bad lines: {stats['parse_errors']}, "
                  f"fetch errors: {stats['fetch_errors']})")

    if args.dry_run:
        console.print(build_table(
            [{"node": n, "results": {}, "exit_ip": {}, "latency_ms": None,
              "verdict": "PENDING", "error": ""} for n in nodes],
            "Dry run - parsed nodes (not tested)"))
        return

    if not nodes:
        console.print("[red]No nodes found - nothing to scan.[/red]")
        sys.exit(1)

    enabled = [c for c in CHECKS if cfg["checks"][c]]
    console.print(f"Checks enabled: [bold]{', '.join(enabled)}[/bold] - "
                  f"concurrency {cfg['concurrency']}")

    def once() -> list[dict]:
        rows = run_scan(nodes, cfg, "Google access scan")
        json_path, csv_path = write_reports(ROOT, rows, extra_meta={
            "sources": stats["sources"], "checks_enabled": enabled,
        })
        outputs = write_clean_outputs(ROOT, rows)
        print_summary(console, rows, outputs)
        print_output_files(console, [json_path, csv_path, *outputs.values()])
        return rows

    if args.watch:
        minutes = max(1, args.watch)
        while True:
            console.rule(f"[bold]Scan at {datetime.now().strftime('%H:%M:%S')}")
            try:
                once()
            except KeyboardInterrupt:
                raise
            console.print(f"[dim]Sleeping {minutes} minutes... (Ctrl+C to stop)[/dim]")
            time.sleep(minutes * 60)
    else:
        once()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")
