"""Summarize bounded metadata-only timings without mislabeling model wait."""

import json
from collections import Counter
from pathlib import Path


def union_seconds(intervals):
    total = 0.0
    end = float("-inf")
    for left, right in sorted(intervals):
        total += max(0, right - max(end, left))
        end = max(end, right)
    return round(total, 3)


def summarize(path: Path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 6_000_000:
        return None
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    tools = {}
    intervals = []
    spans = []
    started = None
    starts = ends = 0
    events = Counter()
    for row in rows:
        if row["kind"] == "agent_start":
            starts += 1
            started = float(row["time"])
        elif row["kind"] == "agent_end":
            ends += 1
            if started is not None:
                spans.append((started, float(row["time"])))
                started = None
        elif row["kind"] == "mcp":
            seconds = max(0, float(row["seconds"]))
            entry = tools.setdefault(
                row["tool"], {"calls": 0, "seconds": 0.0, "max_seconds": 0.0, "errors": 0, "operations": 0}
            )
            entry["calls"] += 1
            entry["seconds"] += seconds
            entry["max_seconds"] = max(entry["max_seconds"], seconds)
            entry["errors"] += int(bool(row.get("failed")))
            entry["operations"] += int(row.get("batch_size", 1))
            intervals.append((float(row["started"]), float(row["started"]) + seconds))
        elif row["kind"] == "provider_event":
            events[row["event_type"] + (":" + row["tool"] if row.get("tool") else "")] += 1
    for entry in tools.values():
        entry["seconds"] = round(entry["seconds"], 3)
        entry["max_seconds"] = round(entry["max_seconds"], 3)
    agent = union_seconds(spans)
    busy = union_seconds(
        [(max(a, c), min(b, d)) for a, b in intervals for c, d in spans if max(a, c) < min(b, d)]
    )
    return {
        "complete": starts > 0 and starts == ends and started is None,
        "agent_seconds": agent,
        "mcp_busy_seconds": busy,
        "outside_mcp_seconds": round(max(0, agent - busy), 3),
        "outside_mcp_explanation": "Model generation, provider/transport waits, native harness tools and orchestration; not pure inference time.",
        "mcp": tools,
        "provider_events": dict(events),
    }
