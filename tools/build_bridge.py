"""Build the one-file bridge the workbench offers for download.

The site is static, and probing needs a local process, so the page hands out a
single .pyz instead of asking anyone to clone the repo or install a package:

    python whats-up-google-bridge.pyz --serve

Everything the scanner needs - its own modules plus the pure-Python dependencies
(httpx, socksio, rich) - is packed into that one file, so `pip`, `git` and a
virtualenv are all irrelevant to the visitor. The Xray core still downloads
itself on the first scan, exactly as it does from a checkout.

CI runs this into docs/ before every Pages deploy; the artifact is not committed
(docs/*.pyz is ignored), so there is one source of truth for the code.

    python tools/build_bridge.py            # docs/whats-up-google-bridge.pyz
    python tools/build_bridge.py --no-deps  # code only (offline / quick check)
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = "whats-up-google-bridge.pyz"
DEFAULT_OUT = ROOT / "docs" / ARTIFACT
IGNORE = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")

# The archive's entry point: a plain `python x.pyz` behaves like `python -m scanner`.
MAIN = '''"""Entry point of the one-file bridge."""
import sys

from scanner.main import main

if __name__ == "__main__":
    sys.exit(main())
'''


def build(out: Path, deps: bool = True) -> Path:
    with tempfile.TemporaryDirectory(prefix="wug-bridge-") as tmp:
        work = Path(tmp)
        shutil.copytree(ROOT / "scanner", work / "scanner", ignore=IGNORE)
        (work / "__main__.py").write_text(MAIN, encoding="utf-8")

        if deps:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "--quiet", "--no-compile",
                 "--target", str(work), "-r", str(ROOT / "requirements.txt")],
                check=True,
            )

        out.parent.mkdir(parents=True, exist_ok=True)
        out.unlink(missing_ok=True)
        zipapp.create_archive(work, target=out, interpreter="/usr/bin/env python3",
                              compressed=True)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build the standalone bridge .pyz.")
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT, help=f"default: docs/{ARTIFACT}")
    ap.add_argument("--no-deps", action="store_true",
                    help="skip vendoring httpx/rich (the artifact then needs them installed)")
    args = ap.parse_args(argv)
    path = build(args.out, deps=not args.no_deps)
    size = path.stat().st_size / (1024 * 1024)
    print(f"{path}  ({size:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
