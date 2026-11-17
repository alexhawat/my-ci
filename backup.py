"""Create a consistent private backup of settings, queue, and encrypted credentials."""

import os
import sys
import tarfile
import tempfile
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
    path = destination / f"localci-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.tar.gz"
    if path.exists():
        raise RuntimeError(f"{path} already exists; no backup was created")
    partial = destination / f".{path.name}.partial"
    with tempfile.TemporaryDirectory() as tmp:
        snapshot = Path(tmp) / "localci.db"
        Store(database).backup(snapshot)
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(fd, "wb") as file:
                with tarfile.open(fileobj=file, mode="w:gz") as archive:
                    archive.add(snapshot, arcname="localci.db")
                    archive.add(key, arcname="encryption.key")
                file.flush()
                os.fsync(file.fileno())
            # Only a complete archive ever appears under its final name.
            os.replace(partial, path)
        except BaseException:
            partial.unlink(missing_ok=True)
            raise
    directory = os.open(destination, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return path


def main() -> int:
    try:
        path = create_backup(Path(os.environ.get("LOCALCI_DATA", "/data")))
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    print(path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
