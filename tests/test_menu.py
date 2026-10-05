"""Run with: python tests/test_menu.py"""
import builtins
import io
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from rich.console import Console  # noqa: E402

from scanner.menu import show_menu  # noqa: E402

CFG = {
    "concurrency": 20,
    "checks": {"search": True, "gemini": False, "gemini_api": True, "antigravity": True},
}


def run_menu(answers, cfg=None):
    """Drive show_menu with scripted answers; returns (choice, printed_text)."""
    it = iter(answers)
    real_input = builtins.input
    builtins.input = lambda *a, **k: next(it)
    buf = io.StringIO()
    console = Console(file=buf, force_terminal=False, width=80)
    try:
        choice = show_menu(console, cfg if cfg is not None else CFG)
    finally:
        builtins.input = real_input
    return choice, buf.getvalue()


# 1. plain Enter accepts defaults: full scan, config checks, config concurrency
choice, text = run_menu(["", ""])
assert choice is not None
assert choice.mode == "scan"
assert choice.checks == CFG["checks"], choice.checks
assert choice.concurrency == 20
assert "Full scan" in text and "Google Access Scanner" in text

# 2. picking checks one by one + custom concurrency
choice, _ = run_menu(["2", "y", "n", "y", "y", "10"])
assert choice.mode == "scan"
assert choice.checks == {"search": True, "gemini": False,
                         "gemini_api": True, "antigravity": True}
assert choice.concurrency == 10

# 3. deselecting everything falls back to all checks
choice, _ = run_menu(["2", "n", "n", "n", "n", ""])
assert all(choice.checks.values()), choice.checks
assert choice.concurrency == 20

# 4. watch mode asks for the interval and concurrency
choice, _ = run_menu(["4", "15", "30"])
assert choice.mode == "watch"
assert choice.watch_minutes == 15
assert choice.concurrency == 30

# 5. watch interval is clamped to >= 1
choice, _ = run_menu(["4", "0", ""])
assert choice.watch_minutes == 1

# 6. dry run returns immediately (no concurrency prompt)
choice, _ = run_menu(["3"])
assert choice.mode == "dry-run"
assert choice.concurrency == 20

# 7. xray check mode
choice, _ = run_menu(["5"])
assert choice.mode == "check-xray"

# 8. subscription check mode, prune declined by default
choice, _ = run_menu(["6", "n"])
assert choice.mode == "check-subs" and choice.prune is False

# 9. subscription check mode with pruning accepted
choice, _ = run_menu(["6", "y"])
assert choice.mode == "check-subs" and choice.prune is True

# 10. Exit returns None
choice, _ = run_menu(["7"])
assert choice is None

# 9. invalid menu choice re-prompts, then accepts a valid one
choice, _ = run_menu(["9", "3"])
assert choice.mode == "dry-run"

# 10. concurrency below 1 is clamped
choice, _ = run_menu(["1", "-5"])
assert choice.concurrency == 1

print("all menu tests passed")
