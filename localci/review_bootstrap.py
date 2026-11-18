"""Prepare copied review inputs, then run mergeCraft entirely as its image user.

The pinned image starts as root and drops only the agent subprocess. Local diff
reviews create private XDG directories before that drop, leaving OpenCode unable
to write its log/auth tree. Starting the CLI unprivileged keeps ownership aligned.
"""

import json
import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path


def handoff_tree(root: Path, uid: int, gid: int) -> None:
    """Change ownership of copied input entries without following repository links."""
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError(f"Expected a real input directory: {root}")
    os.chown(root, uid, gid, follow_symlinks=False)
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in [*dirs, *files]:
            os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)


def prepare() -> None:
    account = pwd.getpwnam("mergecraft")
    if account.pw_uid == 0 or account.pw_gid == 0:
        raise RuntimeError("The review runtime requires a non-root mergecraft user")
    if os.getuid() == 0:
        for root in (Path("/review"), Path("/control")):
            handoff_tree(root, account.pw_uid, account.pw_gid)
        os.setgroups([])
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    if os.getuid() != account.pw_uid or os.getgid() != account.pw_gid:
        raise RuntimeError("Could not enter the mergecraft runtime account")
    os.umask(0o077)
    os.environ.update(HOME=account.pw_dir, USER=account.pw_name, LOGNAME=account.pw_name, TMPDIR="/tmp")


def preserve_evidence(root: Path) -> None:
    """Keep the evidence packet even when the CLI cannot produce its final report."""
    packets = sorted(
        (
            path
            for path in root.glob("mergecraft-diff-review-*/evidence/*merge-evidence-packet.json")
            if not path.is_symlink() and path.is_file()
        ),
        key=lambda path: path.stat().st_mtime,
    )
    for packet in reversed(packets):
        if packet.is_symlink() or not packet.is_file() or packet.stat().st_size > 10_000_000:
            continue
        try:
            packet.resolve().relative_to(root.resolve())
            json.loads(packet.read_text())
            shutil.copyfile(packet, root / "mergecraft-evidence.json")
        except (ValueError, OSError):
            continue
        narrative = packet.parent.parent / "localci-review.md"
        if narrative.is_file() and not narrative.is_symlink() and narrative.stat().st_size <= 1_000_000:
            shutil.copyfile(narrative, root / "mergecraft-review.md")
        metrics = packet.parent.parent / "localci-metrics.json"
        if metrics.is_file() and not metrics.is_symlink() and metrics.stat().st_size < 100_000:
            try:
                data = json.loads(metrics.read_text())
                allowed = {key: data[key] for key in ("tokens", "cost", "timing", "attempts") if key in data}
                (root / "mergecraft-metrics.json").write_text(json.dumps(allowed))
            except (ValueError, TypeError, OSError):
                pass
        break


if __name__ == "__main__":
    prepare()
    code = subprocess.call(["mergecraft", *sys.argv[1:]])
    try:
        preserve_evidence(Path("/tmp"))
    except OSError:
        print("Could not preserve the review evidence packet", file=sys.stderr)
    sys.exit(code)
