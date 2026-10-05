"""Run with: python tests/test_kill_on_exit.py

Proves that when the user closes/kills the scanner process, the xray children
it spawned die with it - without any Python code getting a chance to run:
 - Windows: taskkill /F on the driver (same effect as Task Manager / window
   close) -> the KILL_ON_JOB_CLOSE job object must take the child down.
 - POSIX: SIGTERM to the driver -> exit hooks stop the child.
Skips (with a message) when job assignment is unavailable in this environment.
"""
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

TMP = Path(tempfile.mkdtemp(prefix="kill-on-exit-"))
STATUS = TMP / "status.txt"
DRIVER = TMP / "driver.py"

DRIVER_SRC = f'''
import subprocess, sys, time
from pathlib import Path
sys.path.insert(0, {str(REPO)!r})
from scanner import xray as x
from scanner.nodes import Node

status = Path({str(STATUS)!r})
child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(180)"])
inst = x.XrayInstance(Path(sys.executable),
                      Node(protocol="vmess", id="u", server="127.0.0.1", port=1),
                      1, Path({str(TMP)!r}))
inst.proc = child
x._register(inst)
job = x._job_assign(child)
x.install_exit_hooks()
status.write_text(f"{{child.pid}}\\n{{int(job)}}\\nREADY\\n")
time.sleep(180)
'''
DRIVER.write_text(DRIVER_SRC, encoding="utf-8")


def alive(pid: int) -> bool:
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FI", f"PID eq {pid}", "/NH"],
                                 capture_output=True, text=True, timeout=15)
            return str(pid) in out.stdout
        os.kill(pid, 0)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def force_kill(pid: int) -> None:
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=15)
        else:
            os.kill(pid, 9)
    except (OSError, subprocess.SubprocessError):
        pass


driver = subprocess.Popen([sys.executable, str(DRIVER)])
child_pid = None
try:
    deadline = time.monotonic() + 30
    lines: list = []
    while time.monotonic() < deadline:
        if driver.poll() is not None:
            raise AssertionError(f"driver exited early with {driver.returncode}")
        try:
            lines = STATUS.read_text(encoding="utf-8").splitlines()
        except OSError:
            lines = []
        if len(lines) >= 3 and lines[2] == "READY":
            break
        time.sleep(0.1)
    else:
        raise AssertionError("driver never became ready")

    child_pid, job_flag = int(lines[0]), int(lines[1])
    print(f"driver pid={driver.pid} child pid={child_pid} job-assigned={bool(job_flag)}")

    if os.name == "nt" and not job_flag:
        print("SKIP: job object unavailable here; only signal/atexit hooks apply, "
              "so the hard-kill case cannot be asserted in this environment")
    else:
        if os.name == "nt":
            # hard kill - no atexit, no signal handlers, nothing Python runs
            subprocess.run(["taskkill", "/F", "/PID", str(driver.pid)],
                           capture_output=True, timeout=15)
        else:
            os.kill(driver.pid, 15)  # SIGTERM, like a terminal closing
        deadline = time.monotonic() + 15
        while alive(child_pid) and time.monotonic() < deadline:
            time.sleep(0.2)
        assert not alive(child_pid), \
            "the xray stand-in survived its parent - kill-on-exit FAILED"
        assert driver.poll() is not None, "driver should be gone too"
        print("child died with the parent ok")
finally:
    if driver.poll() is None:
        force_kill(driver.pid)
    if child_pid and alive(child_pid):
        force_kill(child_pid)

print("kill-on-exit test passed")
