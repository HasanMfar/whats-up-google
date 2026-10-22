"""Console table + JSON/CSV/HTML report writing."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path

from rich.markup import escape
from rich.table import Table

CHECKS = ["search", "gemini", "gemini_api", "antigravity"]
CHECK_LABELS = {"search": "Search", "gemini": "Gemini", "gemini_api": "API", "antigravity": "Anti"}


def safe(text) -> str:
    """Escape untrusted text before it reaches rich.

    Node remarks, subscription URLs and error previews routinely contain square
    brackets - IPv6 names like "[2a01:4f8::1]", adblock rules like
    "[/api.waqi.info/]", markup-like payloads. Interpolated raw into a rich
    string they are parsed as markup and raise MarkupError, which used to kill
    a running sweep. Everything that comes from a subscription must go through
    here.
    """
    return escape(str(text))


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
            safe(node.remark or "-"),
            safe(node.protocol),
            safe(f"{node.server}:{node.port}"),
            safe(node.id_prefix()),
            safe((row.get("exit_ip") or {}).get("country_code", "") or "?"),
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


def print_output_files(console, paths) -> None:
    """List every file the run produced, with its size."""
    console.print()
    console.print("[bold]Output files:[/bold]")
    for p in paths:
        console.print(f"  {safe(p)}  [dim]({p.stat().st_size / 1024:.1f} KB)[/dim]")


def write_html_report(root: Path, rows: list[dict], extra_meta: dict | None = None) -> Path:
    """Generates a self-contained, interactive HTML report."""
    reports_dir = root / "reports"
    reports_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = reports_dir / f"scan-{stamp}.html"

    summary = summarize(rows)
    
    # Prepare table rows for HTML
    html_rows = []
    for i, r in enumerate(rows, 1):
        node = r["node"]
        verdict = r["verdict"]
        ip = r.get("exit_ip") or {}
        latency = r.get("latency_ms", "")
        
        # Status class for CSS
        status_class = verdict.lower()
        
        # Detail string for the 'detail' column or tooltip
        details = [f"{k}: {v['detail']}" for k, v in r["results"].items()
                   if v and v["ok"] is not True]
        detail_str = " | ".join(details)

        # Check cells
        check_cells = []
        for c in CHECKS:
            res = r["results"].get(c)
            if verdict == "DEAD":
                val = '<span class="status-cell dead">x</span>'
            elif res is None:
                val = '<span class="status-cell pending">-</span>'
            elif res["ok"] is True:
                val = '<span class="status-cell clean">v</span>'
            elif res["ok"] is False:
                val = '<span class="status-cell dead">X</span>'
            else:
                val = '<span class="status-cell error">!</span>'
            check_cells.append(val)

        row_html = f"""
        <tr class="node-row">
            <td>{i}</td>
            <td class="remark">{safe(node.remark or "-")}</td>
            <td>{safe(node.protocol)}</td>
            <td class="server">{safe(f'{node.server}:{node.port}')}</td>
            <td>{safe(node.id_prefix())}</td>
            <td>{safe(ip.get("country_code", "?"))}</td>
            <td>{latency}</td>
            {''.join(check_cells)}
            <td><span class="badge badge-{status_class}">{verdict}</span></td>
            <td class="detail" title="{safe(detail_str)}">{safe(detail_str[:50])}{'...' if len(detail_str) > 50 else ''}</td>
        </tr>
        """
        html_rows.append(row_html)

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</title>
    <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.6; color: #333; background-color: #f8f9fa; margin: 0; padding: 20px; }}
        .container {{ max-width: 1400px; margin: 0 auto; }}
        h1 {{ color: #2c3e50; }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); text-align: center; }}
        .card .value {{ font-size: 2em; font-weight: bold; display: block; }}
        .card .label {{ color: #7f8c8d; font-size: 0.9em; text-transform: uppercase; }}
        
        /* Status Colors */
        .card.total {{ border-top: 5px solid #34495e; }}
        .card.clean {{ border-top: 5px solid #28a745; color: #28a745; }}
        .card.flagged {{ border-top: 5px solid #ffc107; color: #856404; }}
        .card.dead {{ border-top: 5px solid #dc3545; color: #721c24; }}
        .card.error {{ border-top: 5px solid #6c757d; color: #383d41; }}

        .badge {{ padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; }}
        .badge-clean {{ background: #d4edda; color: #155724; }}
        .badge-flagged {{ background: #fff3cd; color: #856404; }}
        .badge-dead {{ background: #f8d7da; color: #721c24; }}
        .badge-error {{ background: #e2e3e5; color: #383d41; }}
        .badge-pending {{ background: #eee; color: #999; }}

        .status-cell {{ text-align: center; font-weight: bold; font-size: 1.2em; }}
        .status-cell.clean {{ color: #28a745; }}
        .status-cell.dead {{ color: #dc3545; }}
        .status-cell.error {{ color: #ffc107; }}
        .status-cell.pending {{ color: #ccc; }}

        table.dataTable {{ background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .detail {{ color: #999; font-size: 0.8em; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        .remark, .server {{ max-width: 250px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Scan Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        
        <div class="summary-grid">
            <div class="card total"><span class="value">{summary['TOTAL']}</span><span class="label">Total</span></div>
            <div class="card clean"><span class="value">{summary['CLEAN']}</span><span class="label">Clean</span></div>
            <div class="card flagged"><span class="value">{summary['FLAGGED']}</span><span class="label">Flagged</span></div>
            <div class="card dead"><span class="value">{summary['DEAD']}</span><span class="label">Dead</span></div>
            <div class="card error"><span class="value">{summary['ERROR']}</span><span class="label">Error</span></div>
        </div>

        <table id="resultsTable" class="display" style="width:100%">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Remark</th>
                    <th>Proto</th>
                    <th>Server</th>
                    <th>ID</th>
                    <th>Country</th>
                    <th>ms</th>
                    {"".join(f"<th>{CHECK_LABELS[c]}</th>" for c in CHECKS)}
                    <th>Verdict</th>
                    <th>Details</th>
                </tr>
            </thead>
            <tbody>
                {"".join(html_rows)}
            </tbody>
        </table>
    </div>

    <script src="https://code.jquery.com/jquery-3.7.0.min.js"></script>
    <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
    <script>
        $(document).ready(function() {{
            $('#resultsTable').DataTable({{
                "pageLength": 50,
                "order": [[0, "asc"]],
                "language": {{
                    "search": "Filter nodes:",
                    "lengthMenu": "Show _MENU_ entries"
                }}
            }});
        }});
    </script>
</body>
</html>
"""
    html_path.write_text(html_template, encoding="utf-8")
    return html_path


def write_reports(root: Path, rows: list[dict], extra_meta: dict | None = None) -> tuple[Path, Path, Path]:
    reports_dir = root / "reports"
    reports_dir.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = reports_dir / f"scan-{stamp}.json"
    csv_path = reports_dir / f"scan-{stamp}.csv"
    html_path = write_html_report(root, rows, extra_meta)

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
    return json_path, csv_path, html_path
