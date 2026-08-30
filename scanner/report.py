"""Console table + JSON/CSV report writing."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from rich.table import Table

CHECKS = ["search", "gemini", "gemini_api", "antigravity"]
CHECK_LABELS = {"search": "Search", "gemini": "Gemini", "gemini_api": "API", "antigravity": "Anti"}

VERDICT_STYLES = {
    "CLEAN": "[green]CLEAN[/green]",
    "FLAGGED": "[red]FLAGGED[/red]",
    "DEAD": "[red]DEAD[/red]",
    "ERROR": "[yellow]ERROR[/yellow]",
    "PENDING": "[dim]...[/dim]",
}


def _check_cell(res: dict | None, verdict: str) -> str:
    if verdict == "DEAD":
        return "[red]x[/red]"
    if res is None:
        return "[dim]-[/dim]"
    if res["ok"] is True:
        return "[green]v[/green]"
    if res["ok"] is False:
        return "[red]X[/red]"
    return "[yellow]![/yellow]"


def build_table(rows: list[dict], title: str = "Google access scan") -> Table:
    table = Table(title=title, expand=True)
    table.add_column("#", justify="right", style="dim")
    table.add_column("Remark", max_width=28, no_wrap=True, overflow="ellipsis")
    table.add_column("Proto")
    table.add_column("Server", max_width=30, no_wrap=True, overflow="ellipsis")
    table.add_column("ID", max_width=14, no_wrap=True)
    table.add_column("Country", justify="center")
    table.add_column("ms", justify="right")
    for c in CHECKS:
        table.add_column(CHECK_LABELS[c], justify="center")
    table.add_column("Verdict")

    for i, row in enumerate(rows, 1):
        node = row["node"]
        verdict = row["verdict"]
        cells = [
            str(i),
            node.remark or "-",
            node.protocol,
            f"{node.server}:{node.port}",
            node.id_prefix(),
            (row.get("exit_ip") or {}).get("country_code", "") or "?",
            str(row["latency_ms"]) if row.get("latency_ms") is not None else "-",
        ]
        cells += [_check_cell(row["results"].get(c), verdict) for c in CHECKS]
        cells.append(VERDICT_STYLES.get(verdict, verdict))
        table.add_row(*cells)
    return table


def summarize(rows: list[dict]) -> dict:
    counts = {"CLEAN": 0, "FLAGGED": 0, "DEAD": 0, "ERROR": 0, "PENDING": 0}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    counts["TOTAL"] = len(rows)
    return counts


def write_reports(root: Path, rows: list[dict], extra_meta: dict | None = None) -> tuple[Path, Path]:
    reports_dir = root / "reports"
    reports_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = reports_dir / f"scan-{stamp}.json"
    csv_path = reports_dir / f"scan-{stamp}.csv"

    payload = {
        "generated": datetime.now().isoformat(timespec="seconds"),
        "summary": summarize(rows),
        "meta": extra_meta or {},
        "results": [
            {
                "node": r["node"].to_dict(),
                "results": r["results"],
                "exit_ip": r.get("exit_ip"),
                "latency_ms": r.get("latency_ms"),
                "verdict": r["verdict"],
                "error": r.get("error", ""),
                "tested_at": r.get("tested_at", ""),
            }
            for r in rows
        ],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    with open(csv_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["protocol", "remark", "id", "server", "port", "country", "exit_ip",
                    "isp", "latency_ms", *CHECKS, "verdict", "detail"])
        for r in rows:
            n = r["node"]
            ip = (r.get("exit_ip") or {})
            details = [f"{k}: {v['detail']}" for k, v in r["results"].items()
                       if v and v["ok"] is not True]
            w.writerow([n.protocol, n.remark, n.id, n.server, n.port,
                        ip.get("country_code", ""), ip.get("ip", ""), ip.get("isp", ""),
                        r.get("latency_ms", ""),
                        *[("" if r["results"].get(c) is None else
                           ({True: "pass", False: "fail", None: "error"}[r["results"][c]["ok"]]))
                          for c in CHECKS],
                        r["verdict"], " | ".join(details)])
    return json_path, csv_path
