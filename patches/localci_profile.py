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
            batch_size=len(arguments.get("requests", [])) if tool.name == "git_batch" else 1,
        )
