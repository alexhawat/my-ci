"""Create a consistent private backup of settings, queue, and encrypted credentials."""

import os
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from localci.store import Store

root = Path(os.environ.get("LOCALCI_DATA", "/data"))
destination = root / "backups"
destination.mkdir(mode=0o700, exist_ok=True)
key = root / "encryption.key"
if not key.is_file():
    raise RuntimeError("Encryption key is missing; no backup was created")
path = destination / f"localci-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.tar.gz"
with tempfile.TemporaryDirectory() as tmp:
    database = Path(tmp) / "localci.db"
    Store(root / "localci.db").backup(database)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as file, tarfile.open(fileobj=file, mode="w:gz") as archive:
        archive.add(database, arcname="localci.db")
        archive.add(root / "encryption.key", arcname="encryption.key")
print(path)
