"""Sample outer container cgroups (including their nested CI containers)."""

import asyncio
import contextlib
import json
import re
import sqlite3
import time

SAMPLE_INTERVAL = 5.0


def memory_bytes(value: str) -> int:
    match = re.fullmatch(r"\s*([0-9.]+)\s*([KMGT]?i?B)\s*", value)
    if not match:
        return 0
    units = {
        "B": 1,
        "kB": 1000,
        "KB": 1000,
        "MB": 1000**2,
        "GB": 1000**3,
        "TB": 1000**4,
        "KiB": 1024,
        "MiB": 1024**2,
        "GiB": 1024**3,
        "TiB": 1024**4,
    }
    return int(float(match[1]) * units.get(match[2], 1))


async def sample_resources(store, rid: str, names: set[str]):
    previous = None
    while True:
        proc = None
        try:
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{json .}}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            output, _ = await asyncio.wait_for(proc.communicate(), 10)
            rows = [json.loads(line) for line in output.decode().splitlines() if line.strip()]
            rows = [r for r in rows if r.get("Name") in names]
            now = time.time()
            if rows:
                cpu = sum(float(r["CPUPerc"].rstrip("%")) for r in rows)
                memory = sum(memory_bytes(r["MemUsage"].split("/")[0]) for r in rows)
                # Never extrapolate over a period when no container was observed.
                interval = min(now - previous, 15) if previous else 0
                await asyncio.to_thread(store.usage_sample, rid, now, cpu, memory, interval)
                previous = now
            else:
                previous = None
        except (OSError, ValueError, KeyError, TimeoutError, sqlite3.Error):
            previous = None
        finally:
            if proc and proc.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                await proc.wait()
        await asyncio.sleep(SAMPLE_INTERVAL)
