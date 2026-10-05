"""Remember which nodes were already tested, so huge lists can be scanned in chunks.

A big subscription set parses into tens of thousands of nodes - too many to test
in one run. This module keeps a local, credential-free record of what has already
been tested (keyed by a hash of protocol|server|port|id, never the raw link) so
the next run can pick up where the last one stopped.
"""
from __future__ import annotations

import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Entries older than this come back into scope, so rotating configs are retested.
MAX_AGE_DAYS = 30


def node_key(node) -> str:
    """Stable id for a node: a short hash, so no UUID/password is stored on disk."""
    raw = "|".join([str(node.protocol), str(node.server), str(node.port), str(node.id)])
    return hashlib.sha1(raw.encode("utf-8", "replace")).hexdigest()[:16]


def load_history(path: Path) -> dict:
    """Return {node_key: tested_at_iso}; a missing or broken file means no history."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError):
        return {}
    nodes = data.get("nodes") if isinstance(data, dict) else None
    if not isinstance(nodes, dict):
        return {}
    return {str(k): str(v) for k, v in nodes.items()}


def save_history(path: Path, history: dict, max_age_days: int = MAX_AGE_DAYS) -> int:
    """Write the history, dropping entries older than max_age_days.

    Returns how many entries were kept. Raises OSError on an unwritable file -
    callers warn instead of failing a finished scan.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
    kept: dict[str, str] = {}
    for key, stamp in history.items():
        try:
            when = datetime.fromisoformat(stamp)
        except (TypeError, ValueError):
            continue  # unreadable stamp: drop it rather than keep it forever
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        if when >= cutoff:
            kept[key] = stamp
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"version": 1, "nodes": kept}), encoding="utf-8")
    return len(kept)


def record_tested(history: dict, rows: list[dict], stamp: str | None = None) -> int:
    """Add every row's node to the history. Returns how many entries changed."""
    when = stamp or datetime.now().isoformat(timespec="seconds")
    added = 0
    for row in rows:
        node = row.get("node")
        if node is None:
            continue
        key = node_key(node)
        if history.get(key) != when:
            added += 1
        history[key] = when
    return added


def partition(nodes: list, history: dict, skip_tested: bool = True) -> tuple[list, list]:
    """Split nodes into (to_test, already_tested), preserving input order."""
    if not skip_tested or not history:
        return list(nodes), []
    fresh, seen = [], []
    for node in nodes:
        (seen if node_key(node) in history else fresh).append(node)
    return fresh, seen


def apply_limit(nodes: list, limit: int | None, seed: int = 0) -> list:
    """Take at most `limit` nodes, sampled deterministically.

    A deterministic sample (not simply the first N) matters for chunked
    scanning: subscription lists are ordered by provider, so the head of the
    list is usually all the same kind of config.
    """
    if not limit or limit <= 0 or len(nodes) <= limit:
        return list(nodes)
    return random.Random(seed).sample(list(nodes), limit)