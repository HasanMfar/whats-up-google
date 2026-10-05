"""`python -m scanner` entry point.

The KeyboardInterrupt guard must live HERE: importing `.main` and calling
main() directly means scanner/main.py's `if __name__ == "__main__"` block
never runs, so Ctrl+C anywhere outside run_scan (fetching subscriptions,
downloading the Xray core, the --watch sleep) used to die with a raw
traceback and no cleanup message.
"""
from . import xray as xray_mod
from .main import console, main

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")
    finally:
        # belt & braces next to the atexit/signal hooks and the Windows job
        # object: no way out of this process leaves xray running
        xray_mod.stop_all()
