"""Hand-pick the clean configs from a scan and write importable subscriptions.

A subscription as a whole is never uniformly clean, so picking happens per
config node:

- clean_*   : nodes that passed every enabled check (strictest)
- gemini_*  : nodes usable for Gemini (web + API), even if Search flags them
- antigravity_*: nodes usable for Antigravity
- best_*    : one lowest-latency config per working exit IP, for Gemini/Antigravity
"""
from __future__ import annotations

import base64
from pathlib import Path

from .probes import TARGET_SERVICES, service_ok


def _latency(row: dict):
    lat = row.get("latency_ms")
    return (lat is None, lat or 0)


def pick_for_services(rows: list[dict], services: tuple[str, ...]) -> list[dict]:
    """Rows where every requested check passed (other checks' verdicts ignored)."""
    return [r for r in rows if service_ok(r["results"], services) is True]


def best_per_ip(rows: list[dict]) -> list[dict]:
    """Keep the fastest config per exit IP - subs repeat the same IP many times."""
    by_ip: dict[str, dict] = {}
    for r in rows:
        ip = (r.get("exit_ip") or {}).get("ip") or f"__noip__{r['node'].dedupe_key}"
        cur = by_ip.get(ip)
        if cur is None or _latency(r) < _latency(cur):
            by_ip[ip] = r
    return sorted(by_ip.values(), key=_latency)


def _write_sub(root: Path, name: str, links: list[str]) -> Path | None:
    if not links:
        return None
    (root / f"{name}_links.txt").write_text("\n".join(links) + "\n", encoding="utf-8")
    payload = "\n".join(links)
    sub_path = root / f"{name}_subscription.txt"
    sub_path.write_text(base64.b64encode(payload.encode("utf-8")).decode("ascii"), encoding="utf-8")
    return sub_path


def write_clean_outputs(root: Path, rows: list[dict]) -> dict[str, Path]:
    """Write all hand-picked subscription files. Returns {label: subscription path}."""
    out: dict[str, Path] = {}
    writers = (
        ("clean", [r["node"].raw for r in rows if r["verdict"] == "CLEAN"],
         "clean (passed every check)"),
        ("gemini", [r["node"].raw for r in pick_for_services(rows, ("gemini", "gemini_api"))],
         "gemini (usable for Gemini web + API)"),
        ("antigravity", [r["node"].raw for r in pick_for_services(rows, ("antigravity",))],
         "antigravity (usable for Antigravity)"),
        ("best", [r["node"].raw for r in best_per_ip(pick_for_services(rows, TARGET_SERVICES))],
         "best (fastest config per exit IP, for Gemini/Antigravity)"),
    )
    for name, links, label in writers:
        path = _write_sub(root, name, links)
        if path:
            out[label] = path
    return out


def print_summary(console, rows: list[dict], outputs: dict[str, Path]) -> None:
    from .report import summarize

    s = summarize(rows)
    gemini_n = len(pick_for_services(rows, ("gemini", "gemini_api")))
    anti_n = len(pick_for_services(rows, ("antigravity",)))
    best_n = len(best_per_ip(pick_for_services(rows, TARGET_SERVICES)))

    console.print()
    console.print(f"[bold]Summary:[/bold] {s['TOTAL']} nodes - "
                  f"[green]{s['CLEAN']} clean[/green], "
                  f"[red]{s['FLAGGED']} flagged[/red], "
                  f"[red]{s['DEAD']} dead[/red], "
                  f"[yellow]{s['ERROR']} errors[/yellow]")
    console.print(f"Hand-picked: [green]{gemini_n}[/green] for Gemini, "
                  f"[green]{anti_n}[/green] for Antigravity, "
                  f"[green]{best_n}[/green] best (one per exit IP)")
    if outputs:
        for label, path in outputs.items():
            console.print(f"  {path}  [dim]({label})[/dim]")
    else:
        console.print("[red]No node passed - no subscription files written.[/red]")
