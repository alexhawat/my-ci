"""Transient WAL read races must not cancel unrelated active CI and reviews."""

import asyncio
import sqlite3
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from localci.controller import Controller
from localci.store import Store
from localci.worker import healthy, serve


def protocol_error(code=sqlite3.SQLITE_PROTOCOL):
    error = sqlite3.OperationalError("locking protocol")
    error.sqlite_errorcode = code
    return error


def test_select_reopens_connection_after_protocol_race(tmp_path, monkeypatch):
    store = Store(tmp_path / "ci.db")
    original = store.connect
    attempts = []

    @contextmanager
    def flaky(*, write=True):
        attempts.append(write)
        if len(attempts) <= 2:
            raise protocol_error()
        with original(write=write) as db:
            yield db

    monkeypatch.setattr(store, "connect", flaky)
    assert store.rows("SELECT 42 AS answer") == [{"answer": 42}]
    assert attempts == [False, False, False]
    store.close()


@pytest.mark.parametrize(
    "sql,code,expected_attempts",
    [
        ("SELECT 1", sqlite3.SQLITE_PROTOCOL, 5),
        ("SELECT 1", sqlite3.SQLITE_IOERR, 1),
        ("DELETE FROM runs RETURNING id", sqlite3.SQLITE_PROTOCOL, 1),
    ],
)
def test_read_retries_are_bounded_and_do_not_replay_writes(
    tmp_path, monkeypatch, sql, code, expected_attempts
):
    store = Store(tmp_path / "ci.db")
    attempts = []

    @contextmanager
    def fail(*, write=True):
        attempts.append(write)
        raise protocol_error(code)
        yield  # pragma: no cover - defines a failing context manager

    monkeypatch.setattr(store, "connect", fail)
    with pytest.raises(sqlite3.OperationalError):
        store.rows(sql)
    assert len(attempts) == expected_attempts
    store.close()


async def test_heartbeat_protocol_race_does_not_cancel_running_work(tmp_path, monkeypatch):
    original = Store.connect
    faulted = []
    active, cancelled, stop = asyncio.Event(), asyncio.Event(), asyncio.Event()

    @contextmanager
    def flaky(self, *, write=True):
        with original(self, write=write) as db:
            if write:
                yield db
                return

            def execute(sql, args=()):
                if "worker_wake" in sql and not faulted:
                    faulted.append(True)
                    raise protocol_error()
                return db.execute(sql, args)

            yield SimpleNamespace(execute=execute)

    async def work(self):
        active.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(Store, "connect", flaky)
    monkeypatch.setattr(Controller, "worker", work)
    monkeypatch.setattr(Controller, "monitor", work)
    task = asyncio.create_task(serve(tmp_path, stop))
    try:
        await asyncio.wait_for(active.wait(), 2)
        for _ in range(100):
            if healthy(tmp_path):
                break
            await asyncio.sleep(0.01)
        assert faulted and healthy(tmp_path)
        assert not task.done() and not cancelled.is_set()
    finally:
        stop.set()
        await asyncio.wait_for(task, 2)
    assert cancelled.is_set()
