"""Run with: python tests/test_history.py"""
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from scanner.history import (MAX_AGE_DAYS, apply_limit, load_history, node_key,  # noqa: E402
                             partition, record_tested, save_history)
from scanner.nodes import Node  # noqa: E402


def n(proto="vmess", server="a.example", port=443, id="uuid-1") -> Node:
    return Node(protocol=proto, id=id, server=server, port=port)


nodes = [n(server=f"h{i}.example") for i in range(10)]

# 1. the key is stable, identity-aware and leaks no credentials
k = node_key(n())
assert k == node_key(n(server="a.example"))
assert k != node_key(n(server="b.example"))
assert k != node_key(n(proto="vless", server="a.example"))
assert k != node_key(n(id="other-id"))
assert "uuid" not in k and len(k) == 16

# 2. roundtrip through disk
tmp = Path(tempfile.mkdtemp()) / "reports" / "tested-nodes.json"
hist: dict = {}
record_tested(hist, [{"node": nodes[i]} for i in range(4)], stamp="2026-10-05T12:00:00")
assert len(hist) == 4
assert save_history(tmp, hist) == 4
assert load_history(tmp) == hist

# 3. a missing or broken file simply means "no history"
assert load_history(tmp.parent / "nope.json") == {}
broken = tmp.parent / "broken.json"
broken.write_text("{not json", encoding="utf-8")
assert load_history(broken) == {}

# 4. old entries drop out, so rotating configs come back into scope
old = (datetime.now(timezone.utc) - timedelta(days=MAX_AGE_DAYS + 1)).isoformat(timespec="seconds")
fresh = datetime.now(timezone.utc).isoformat(timespec="seconds")
assert save_history(tmp, {"a": old, "b": fresh, "c": "not-a-date"}) == 1
assert set(load_history(tmp)) == {"b"}

# 5. partition skips what was tested; skip_tested=False is the --retest path
fresh_nodes, seen = partition(nodes, hist)
assert len(fresh_nodes) == 6 and len(seen) == 4
assert all(node_key(x) in hist for x in seen)
assert all(node_key(x) not in hist for x in fresh_nodes)
all_nodes, seen2 = partition(nodes, hist, skip_tested=False)
assert len(all_nodes) == 10 and seen2 == []
assert partition(nodes, {}) == (nodes, [])

# 6. record_tested counts changes, and tolerates rows without a node
h3: dict = {}
assert record_tested(h3, [{"node": nodes[0]}, {"node": None}], stamp="s1") == 1
assert record_tested(h3, [{"node": nodes[0]}], stamp="s1") == 0
assert record_tested(h3, [{"node": nodes[0]}], stamp="s2") == 1

# 7. apply_limit: exact size, deterministic, and not just the head of the list
picked = apply_limit(nodes, 3)
assert len(picked) == 3 and all(p in nodes for p in picked)
assert apply_limit(nodes, 3) == picked                      # same seed, same chunk
assert apply_limit(nodes, 999) == nodes                    # no-op above the size
assert apply_limit(nodes, 0) == nodes and apply_limit(nodes, None) == nodes
assert apply_limit(nodes, 3) != nodes[:3]                 # sampled, not sequential

print("all history tests passed")