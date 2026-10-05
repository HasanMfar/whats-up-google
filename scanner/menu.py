"""Interactive start menu shown when the scanner is launched without flags.

`run.bat` still runs `python -m scanner`; when stdin/stdout are a real
terminal and no mode flag was given, this menu picks what to do before the
scan starts. No extra dependencies - it is all `rich`.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt

from . import __version__
from .report import CHECK_LABELS, CHECKS

_MODES = {
    "1": "scan",
    "2": "checks",
    "3": "dry-run",
    "4": "watch",
    "5": "check-xray",
    "6": "exit",
}


@dataclass
class MenuChoice:
    """What the user picked - merged into config/CLI args by main()."""

    mode: str = "scan"                       # scan | dry-run | watch | check-xray
    checks: dict = field(default_factory=dict)
    concurrency: int = 20
    watch_minutes: int = 0


def _banner() -> Panel:
    lines = [
        "[bold]What should we do?[/bold]",
        "",
        "  [cyan]1[/cyan] Full scan - test every node through all checks",
        "  [cyan]2[/cyan] Pick which checks to run",
        "  [cyan]3[/cyan] Dry run - parse subscriptions only, no testing",
        "  [cyan]4[/cyan] Watch - rescan automatically every N minutes",
        "  [cyan]5[/cyan] Check / install the Xray core",
        "  [cyan]6[/cyan] Exit",
    ]
    return Panel("\n".join(lines), title=f"Google Access Scanner v{__version__}",
                 title_align="left")


def show_menu(console: Console, cfg: dict) -> MenuChoice | None:
    """Render the start menu and return the user's choices.

    Returns None when the user picks Exit. Defaults come from config.json;
    main() applies CLI flags afterwards so scripted overrides still win.
    """
    console.print(_banner())
    mode = Prompt.ask("\nChoose", choices=list(_MODES), default="1", console=console)
    mode = _MODES[mode]
    if mode == "exit":
        return None

    choice = MenuChoice(concurrency=max(1, int(cfg.get("concurrency", 20))))
    choice.checks = dict(cfg.get("checks", {}))

    if mode == "checks":
        console.print("\n[bold]Which checks should run?[/bold]")
        for name in CHECKS:
            choice.checks[name] = Confirm.ask(
                f"  [cyan]{CHECK_LABELS[name]}[/cyan] ({name})",
                default=bool(choice.checks.get(name, True)),
                console=console,
            )
        if not any(choice.checks.values()):
            console.print("[yellow]Nothing selected - enabling every check.[/yellow]")
            choice.checks = {name: True for name in CHECKS}
        mode = "scan"

    if mode == "watch":
        choice.watch_minutes = max(
            1, IntPrompt.ask("\nMinutes between scans", default=5, console=console))

    if mode in ("scan", "watch"):
        choice.concurrency = max(
            1, IntPrompt.ask("Parallel node tests", default=choice.concurrency,
                             console=console))

    choice.mode = mode
    return choice
