import hashlib
import os
import sqlite3
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

import backup
from localci.store import Store

SCRIPT = Path(__file__).resolve().parents[1] / "backup.py"


def data_root(tmp_path: Path) -> Path:
    root = tmp_path / "data"
    Store(root / "localci.db").save_settings({"max_parallel_runs": 1})
    (root / "encryption.key").write_bytes(Fernet.generate_key())
    return root


def run(root: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        env={**os.environ, "LOCALCI_DATA": str(root)},
        capture_output=True,
        text=True,
    )


def test_backup_writes_complete_private_archive(tmp_path):
    root = data_root(tmp_path)
    result = run(root)
    assert result.returncode == 0, result.stderr
    path = Path(result.stdout.strip())
    assert path.parent == root / "backups"
    assert path.stat().st_mode & 0o777 == 0o600
    assert os.listdir(root / "backups") == [path.name]
    with tarfile.open(path) as archive:
        assert set(archive.getnames()) == {"localci.db", "encryption.key"}
        archive.extractall(tmp_path / "restored", filter="data")
    assert Store(tmp_path / "restored" / "localci.db").settings()["max_parallel_runs"] == 1
    assert (tmp_path / "restored" / "encryption.key").read_bytes() == (root / "encryption.key").read_bytes()


@pytest.mark.parametrize("missing", ["encryption.key", "localci.db"])
def test_backup_requires_database_and_key(tmp_path, missing):
    root = data_root(tmp_path)
    (root / missing).unlink()
    result = run(root)
    assert result.returncode == 1
    assert "no backup was created" in result.stderr and missing in result.stderr
    assert not (root / "backups").exists()
    # A wrong data path must never create or migrate an empty database.
    assert (root / "localci.db").exists() == (missing != "localci.db")


def test_failed_write_leaves_no_archive(tmp_path, monkeypatch):
    root = data_root(tmp_path)
    original = tarfile.TarFile.add

    def add(self, name, arcname=None, *args, **kwargs):
        if arcname == "encryption.key":
            raise OSError("fixture write failure")
        return original(self, name, arcname, *args, **kwargs)

    monkeypatch.setattr(tarfile.TarFile, "add", add)
    with pytest.raises(OSError, match="fixture write failure"):
        backup.create_backup(root)
    assert os.listdir(root / "backups") == []


def test_same_second_backup_is_refused_without_replacing_the_first(tmp_path, monkeypatch):
    root = data_root(tmp_path)

    class Frozen(backup.datetime):
        @classmethod
        def now(cls, tz=None):
            return cls(2030, 1, 2, 3, 4, 5, tzinfo=tz)

    monkeypatch.setattr(backup, "datetime", Frozen)
    first = backup.create_backup(root)
    original = first.read_bytes()
    with pytest.raises(RuntimeError, match="already exists"):
        backup.create_backup(root)
    assert first.read_bytes() == original
    assert not list((root / "backups").glob(".*.partial"))


def test_stale_partial_holding_the_key_is_removed_but_a_recent_one_is_left(tmp_path):
    root = data_root(tmp_path)
    backups = root / "backups"
    backups.mkdir(mode=0o700)
    stale, recent = backups / ".old.tar.gz.partial", backups / ".new.tar.gz.partial"
    for path in (stale, recent):
        path.write_bytes(b"partial")
    os.utime(stale, (1, 1))
    backup.create_backup(root)
    assert not stale.exists() and recent.exists()  # A recent one may be a concurrent backup.


def test_volume_without_hard_links_fails_clearly_and_leaves_nothing(tmp_path, monkeypatch):
    root = data_root(tmp_path)

    def unsupported(*_):
        raise PermissionError(1, "Operation not permitted")

    monkeypatch.setattr(backup.os, "link", unsupported)
    with pytest.raises(RuntimeError, match="hard links"):
        backup.create_backup(root)
    assert not list((root / "backups").iterdir())


def restored_database(path: Path, tmp_path: Path) -> Path:
    with tarfile.open(path) as archive:
        archive.extractall(tmp_path / "restored", filter="data")
    return tmp_path / "restored" / "localci.db"


def test_wal_rows_not_yet_in_the_main_file_are_backed_up_read_only(tmp_path):
    root = tmp_path / "data"
    root.mkdir()
    (root / "encryption.key").write_bytes(Fernet.generate_key())
    database = root / "localci.db"
    # The service keeps its connection open; committed rows live only in the WAL.
    live = sqlite3.connect(database)
    try:
        assert live.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        live.execute("PRAGMA wal_autocheckpoint=0")
        live.execute("CREATE TABLE items (value TEXT)")
        live.executemany("INSERT INTO items VALUES (?)", [("a",), ("b",)])
        live.commit()
        assert (root / "localci.db-wal").stat().st_size > 0
        main_file = database.read_bytes()
        assert b"CREATE TABLE items" not in main_file  # Only in the WAL so far.
        path = backup.create_backup(root)
        assert database.read_bytes() == main_file  # No checkpoint or write by the backup.
        live.execute("INSERT INTO items VALUES ('after')")
        live.commit()
    finally:
        live.close()
    snapshot = restored_database(path, tmp_path)
    assert not snapshot.with_name("localci.db-wal").exists()
    restored = sqlite3.connect(snapshot)
    try:
        assert restored.execute("SELECT value FROM items ORDER BY value").fetchall() == [("a",), ("b",)]
    finally:
        restored.close()


def test_backup_never_migrates_an_older_database(tmp_path):
    root = data_root(tmp_path)
    database = root / "localci.db"
    # As if the database was written by an older release and this is a newer tool.
    older = sqlite3.connect(database)
    try:
        older.execute("PRAGMA user_version=1")
        older.commit()
    finally:
        older.close()
    files = sorted(os.listdir(root))
    before = hashlib.sha256(database.read_bytes()).hexdigest(), database.stat().st_mtime_ns
    result = run(root)
    assert result.returncode == 0, result.stderr
    assert (hashlib.sha256(database.read_bytes()).hexdigest(), database.stat().st_mtime_ns) == before
    # Nothing else was written beside it: no WAL, and no migration's pre-upgrade copy.
    assert sorted(os.listdir(root)) == sorted([*files, "backups"])
    for path in (database, restored_database(Path(result.stdout.strip()), tmp_path)):
        connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        try:
            assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        finally:
            connection.close()


def test_backup_tool_does_not_import_the_store(tmp_path):
    probe = "import sys, backup; print('localci' in sys.modules)"
    result = subprocess.run(
        [sys.executable, "-c", probe], cwd=SCRIPT.parent, capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


def test_database_path_is_quoted_in_the_read_only_uri(tmp_path):
    root = data_root(tmp_path / "odd?name#dir %41")
    path = backup.create_backup(root)
    assert Store(restored_database(path, tmp_path)).settings()["max_parallel_runs"] == 1
