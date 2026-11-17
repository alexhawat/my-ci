"""Create a consistent private backup of settings, queue, and encrypted credentials."""

import contextlib
import os
import sqlite3
import sys
import tarfile
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from localci.store import Store


def create_backup(root: Path) -> Path:
    database = root / "localci.db"
    key = root / "encryption.key"
    # Check first: opening a missing database would create and migrate an empty one.
    if not database.is_file():
        raise RuntimeError(f"Database {database} is missing; no backup was created")
    if not key.is_file():
        raise RuntimeError(f"Encryption key {key} is missing; no backup was created")
    destination = root / "backups"
    destination.mkdir(mode=0o700, exist_ok=True)
    # An interrupted earlier backup leaves a partial file holding the key; an hour is far
    # longer than any backup takes, so older ones are not a concurrent run's work.
    for stale in destination.glob(".*.partial"):
        with contextlib.suppress(OSError):
            if time.time() - stale.lstat().st_mtime > 3600:
                stale.unlink()
    path = destination / f"localci-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.tar.gz"
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "localci.db"
        Store(database).backup(snapshot)
        # A unique 0600 temporary name: concurrent backups never share a partial file.
        fd, name = tempfile.mkstemp(dir=destination, prefix=f".{path.name}.", suffix=".partial")
        partial = Path(name)
        try:
            with os.fdopen(fd, "wb") as file:
                with tarfile.open(fileobj=file, mode="w:gz", dereference=True) as archive:
                    archive.add(snapshot, arcname="localci.db")
                    archive.add(key, arcname="encryption.key")
                file.flush()
                os.fsync(file.fileno())
            # Only a complete archive ever appears under its final name, and linking,
            # unlike renaming, never replaces an archive that is already there.
            try:
                os.link(partial, path)
            except FileExistsError:
                raise RuntimeError(f"{path} already exists; no backup was created") from None
            except OSError as exc:
                raise RuntimeError(
                    f"Cannot publish {path}: the backup directory must support hard links "
                    f"({exc.strerror or exc}); no backup was created"
                ) from None
        finally:
            partial.unlink(missing_ok=True)
    directory = os.open(destination, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def main() -> int:
    try:
        path = create_backup(Path(os.environ.get("LOCALCI_DATA", "/data")))
    except (RuntimeError, OSError, sqlite3.Error) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
