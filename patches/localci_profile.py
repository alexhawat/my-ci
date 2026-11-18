"""Metadata-only timing; never stores prompts, arguments, output or credentials."""

import json
import os
import threading
import time
from pathlib import Path

_lock = threading.Lock()


def event(kind, **fields):
    path = os.environ.get("LOCALCI_PROFILE_PATH")
    if not path:
        return
    row = {"kind": kind, "time": time.monotonic(), **fields}
    try:
        with _lock:
            target = Path(path)
            if target.exists() and target.stat().st_size > 5_000_000:
                return
            with target.open("a") as stream:
                stream.write(json.dumps(row) + "\n")
    except OSError:
        pass


async def invoke(tool, arguments):
    start = time.monotonic()
    failed = True
    try:
        result = await tool.execute(arguments)
        failed = bool(getattr(result, "is_error", False))
        return result
    finally:
        event(
            "mcp",
            tool=tool.name,
            started=start,
            seconds=time.monotonic() - start,
            failed=failed,
            batch_size=len(arguments.get("requests", [])) if tool.name in {"git_batch", "read_batch"} else 1,
        )


def prepare_read_transport(diff, tmpdir):
    from mergecraft.evidence.run_packet import resolve_packet_path

    read_dir = resolve_packet_path(tmpdir=str(tmpdir), change_slug="local-review").parent / "git-read"
    read_dir.mkdir(parents=True, exist_ok=True)
    safe_diff = read_dir / "full-review.patch"
    safe_diff.write_bytes(diff.read_bytes())
    return (
        f"\nLocal CI read transport: authoritative complete diff is {safe_diff}. "
        "Use read_batch with path @diff for the full diff and repository-relative paths for grouped line-range reads of the diff or tracked HEAD files. "
        "It returns real text and records only lines actually shown, retaining coverage gates. "
        "Read the full diff in ranges of up to 2000 lines, grouping independent ranges in one call. "
        "Group 4-8 related source/test/document reads per call where possible. "
        "Native file reads are disabled for this local review. Use the directly listed read_batch MCP tool before reading files; batch related independent requests together. For base revisions use git show, then read_batch on its outputPath. Continue every truncated range; all source context remains available. Do not repeatedly reread known text. "
        "Review every changed file and preserve all verification and completion requirements. "
        "The response includes actual token usage: reserve enough budget for verification and "
        "the required terminal verdict; never approve uncovered or unresolved work. "
    )
