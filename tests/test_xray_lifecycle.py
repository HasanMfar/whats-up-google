"""Run with: python tests/test_xray_lifecycle.py

Exercises the xray process lifecycle against a fake process backend:
registration, idempotent stop, reaping on every start() failure path,
concurrency stress against stop_all(), interrupt-resistant cleanup and
orphan killing.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scanner import xray as x  # noqa: E402
from scanner.nodes import Node  # noqa: E402

REAL_POPEN = subprocess.Popen          # saved before tests patch subprocess.Popen
_real_connect = socket.create_connection  # saved before tests patch socket.create_connection

NODE = Node(protocol="vmess", id="uuid", server="127.0.0.1", port=1)
ROOT = Path(tempfile.mkdtemp(prefix="xray-test-"))

LIVE: dict = {}        # port -> FakeProc (currently listening)
SPAWNED: list = []     # every fake process ever spawned
CONNECT_MODE = "auto"  # auto | broken | raise-after-first
CALLS = [0]
STUBBORN = [False]


class _Ctx:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeProc:
    """Well-behaved fake: dies as soon as terminate() is called."""

    def __init__(self, args, port):
        self.args = args
        self.port = port
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15
        LIVE.pop(self.port, None)

    def kill(self):
        self.killed = True
        self.returncode = -9
        LIVE.pop(self.port, None)

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired(self.args, timeout or 0)
        return self.returncode


class StubbornProc(FakeProc):
    """Ignores terminate(); only kill() ends it - exercises the kill escalation."""

    def terminate(self):
        self.terminated = True  # process pretends to keep running


def fake_connect(addr, timeout=None):
    port = addr[1]
    CALLS[0] += 1
    if CONNECT_MODE == "raise-after-first" and CALLS[0] >= 2:
        raise RuntimeError("simulated failure while waiting for the SOCKS port")
    if CONNECT_MODE == "broken":
        raise OSError("connection refused")
    proc = LIVE.get(port)
    if proc is None or proc.returncode is not None:
        raise OSError("connection refused")
    return _Ctx()


def fake_popen(args, **kwargs):
    cfg_path = Path(args[args.index("-c") + 1])
    port = json.loads(cfg_path.read_text(encoding="utf-8"))["inbounds"][0]["port"]
    proc = (StubbornProc if STUBBORN[0] else FakeProc)(args, port)
    LIVE[port] = proc
    SPAWNED.append(proc)
    return proc


def patched():
    subprocess.Popen = fake_popen
    socket.create_connection = fake_connect


def unpatched():
    subprocess.Popen = REAL_POPEN
    socket.create_connection = _real_connect


def mk(port: int) -> x.XrayInstance:
    return x.XrayInstance(Path("fake-xray"), NODE, port, ROOT)


def reset(mode="auto", stubborn=False):
    global CONNECT_MODE
    CONNECT_MODE = mode
    STUBBORN[0] = stubborn
    CALLS[0] = 0
    LIVE.clear()
    with x._instances_lock:
        x.active_instances.clear()


# --- 1. happy path: start registers, stop terminates, unlinks cfg -------------
patched()
reset()
inst = mk(21001)
inst.start(wait_seconds=2)
assert inst in x.active_instances, "started instance must be registered"
cfg = inst.cfg_path
assert cfg.exists(), "config file should exist while running"
assert inst.stop() is True, "stop should confirm the process dead"
assert inst.proc is None and inst not in x.active_instances
assert not cfg.exists(), "config file should be removed on stop"
assert inst.stop() is False, "second stop is a no-op returning False"
print("1  start/stop lifecycle ok")

# --- 2. xray exits at startup: nothing registered, nothing leaked -------------
reset()
inst = mk(21002)
# no listener ever appears; make the process look like it died instantly
def dead_popen(args, **kwargs):
    proc = fake_popen(args, **kwargs)
    proc.returncode = 1
    LIVE.pop(proc.port, None)
    return proc

subprocess.Popen = dead_popen
try:
    inst.start(wait_seconds=2)
    raise AssertionError("start should raise when xray exits at startup")
except x.XrayStartupError as e:
    assert "exited at startup" in str(e), e
finally:
    subprocess.Popen = fake_popen
assert inst.proc is None and inst not in x.active_instances
print("2  startup-exit path reaps the child ok")

# --- 3. SOCKS port never opens: timeout reaps the child -----------------------
reset(mode="broken")
inst = mk(21003)
t0 = time.monotonic()
try:
    inst.start(wait_seconds=0.3)
    raise AssertionError("start should raise on timeout")
except x.XrayStartupError as e:
    assert "never opened SOCKS port" in str(e), e
assert time.monotonic() - t0 < 3
assert SPAWNED[-1].terminated and inst.proc is None and inst not in x.active_instances
print("3  startup timeout reaps the child ok")

# --- 4. exception while waiting (log read / unexpected error) reaps the child -
reset(mode="raise-after-first")
inst = mk(21004)
try:
    inst.start(wait_seconds=5)
    raise AssertionError("start should propagate the simulated failure")
except RuntimeError as e:
    assert "simulated failure" in str(e), e
assert inst.proc is None and inst not in x.active_instances
assert SPAWNED[-1].terminated, "child must be terminated when start() fails mid-way"
print("4  mid-start exception reaps the child ok")

# --- 5. port already in use: fail loudly, leave the foreign process alone -----
reset()
foreign = FakeProc(["foreign"], 21005)
LIVE[21005] = foreign
inst = mk(21005)
try:
    inst.start(wait_seconds=1)
    raise AssertionError("start should fail on a busy port")
except x.XrayStartupError as e:
    assert "already in use" in str(e), e
assert foreign.returncode is None, "the foreign listener must not be touched"
assert inst not in x.active_instances
print("5  busy-port precheck ok")

# --- 6. stop() during start(): no orphan, start aborts promptly ----------------
reset(mode="broken")
inst = mk(21006)
raised = {}


def starter():
    try:
        inst.start(wait_seconds=5)
    except BaseException as e:  # noqa: BLE001
        raised["e"] = e


t = threading.Thread(target=starter)
t.start()
deadline = time.monotonic() + 3
while inst not in x.active_instances and time.monotonic() < deadline:
    time.sleep(0.01)
assert inst in x.active_instances, "instance never registered"
inst.stop()  # simulate Ctrl+C cleanup hitting a mid-flight start
t.join(timeout=3)
assert not t.is_alive(), "start() should abort promptly after stop()"
assert isinstance(raised.get("e"), x.XrayStartupError), raised
assert SPAWNED[-1].returncode is not None
assert x.active_instances == set()
print("6  stop-during-start leaves no orphan ok")

# --- 7. stubborn process: terminate escalates to kill -------------------------
reset()
STUBBORN[0] = True
inst = mk(21007)
inst.start(wait_seconds=2)
proc = SPAWNED[-1]
assert inst.stop() is True
assert proc.terminated and proc.killed and proc.returncode is not None
print("7  terminate -> kill escalation ok")

# --- 8. stop() is safe when called concurrently -------------------------------
reset()
inst = mk(21008)
inst.start(wait_seconds=2)
errors = []


def do_stop():
    try:
        inst.stop()
    except Exception as e:  # noqa: BLE001
        errors.append(e)


threads = [threading.Thread(target=do_stop) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
assert not errors, errors
assert SPAWNED[-1].returncode is not None and x.active_instances == set()
print("8  concurrent stop() ok")

# --- 9. stress: 40 instances, 16 workers, stop_all() racing the sweep ---------
reset()
PORTS = list(range(21100, 21140))


def work(port):
    inst = mk(port)
    try:
        inst.start(wait_seconds=2)
        time.sleep(0.01)
    except Exception:  # noqa: BLE001 - stop_all() may abort in-flight starts
        pass
    finally:
        inst.stop()
    return port


stop_all_calls = [0]
baseline = len(SPAWNED)
stop_flag = threading.Event()


def stopper():
    while not stop_flag.is_set():
        x.stop_all(timeout=5)
        stop_all_calls[0] += 1
        time.sleep(0.02)


stop_thread = threading.Thread(target=stopper)
stop_thread.start()
with ThreadPoolExecutor(max_workers=16) as pool:
    list(pool.map(work, PORTS))
stop_flag.set()
stop_thread.join()
x.stop_all(timeout=5)
assert x.active_instances == set(), "registry must be empty after the sweep"
dead = [p for p in SPAWNED if p.returncode is None]
assert not dead, f"{len(dead)} fake processes survived the sweep"
assert 0 < len(SPAWNED) - baseline <= len(PORTS), f"spawned {len(SPAWNED) - baseline}"
print(f"9  concurrency stress ok ({len(SPAWNED) - baseline} spawned, {stop_all_calls[0]} stop_all passes)")

# --- 10. stop_all() survives a KeyboardInterrupt raised by an instance --------
reset()


class Grumpy(x.XrayInstance):
    calls = 0

    def stop(self):
        Grumpy.calls += 1
        if Grumpy.calls == 1:
            raise KeyboardInterrupt  # a second Ctrl+C mid-cleanup
        return super().stop()


g = Grumpy(Path("fake-xray"), NODE, 21200, ROOT)
g.start(wait_seconds=2)
x.stop_all(timeout=5)  # must not propagate the KeyboardInterrupt
assert x.active_instances == set(), "stop_all must finish despite the interrupt"
assert SPAWNED[-1].returncode is not None
print("10 stop_all resists a second Ctrl+C ok")

# --- 11. stop_all() drains instances registered while it runs -----------------
reset()
registered = []


def late_starter():
    for i in range(5):
        inst = mk(21300 + i)
        try:
            inst.start(wait_seconds=2)
        except Exception:  # noqa: BLE001
            pass
        registered.append(inst)
        time.sleep(0.05)


t = threading.Thread(target=late_starter)
t.start()
deadline = time.monotonic() + 3
while not registered and time.monotonic() < deadline:
    time.sleep(0.01)
assert registered, "first late instance never started"
x.stop_all(timeout=6)  # runs while the thread keeps adding instances
t.join()
x.stop_all(timeout=5)
assert x.active_instances == set()
for inst in registered:
    assert inst.proc is None, "late-registered instance leaked"
print("11 stop_all drains late registrations ok")

# --- 12. kill_orphans() only touches processes referencing our config dir -----
unpatched()  # subprocess.run() needs the real Popen
tmp_cfg = x.core_dir(ROOT) / "tmp"
ours = REAL_POPEN([sys.executable, "-c", "import time; time.sleep(60)", str(tmp_cfg)])
theirs = REAL_POPEN([sys.executable, "-c", "import time; time.sleep(60)"])
try:
    time.sleep(0.5)  # let PowerShell/ps enumerate the fresh processes
    killed = x.kill_orphans(ROOT)
    assert killed >= 1, "the decoy referencing our config dir must be killed"

    def alive(p):
        # poll() reaps our own POSIX children (a zombie must not read as alive)
        # and checks the process handle on Windows
        return p.poll() is None

    deadline = time.monotonic() + 10
    while alive(ours) and time.monotonic() < deadline:
        time.sleep(0.2)
    assert not alive(ours), "orphan matching our config dir must die"
    assert alive(theirs), "unrelated process must survive"
finally:
    for p in (ours, theirs):
        if p.poll() is None:
            p.kill()

# --- 13. exit hooks install cleanly and are idempotent ------------------------
x.install_exit_hooks()
x.install_exit_hooks()
print("12/13 kill_orphans + exit hooks ok")

print("all xray lifecycle tests passed")
