import os
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
