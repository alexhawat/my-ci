import json

import pytest

from patches.localci_compaction import UsageJournal


def write(journal, **row):
    with journal.path.open("a") as stream:
        stream.write(json.dumps({"nonce": journal.nonce, **row}) + "\n")


def usage(journal, request, count, *, kind="primary"):
    write(journal, kind="request", session="fixture", request=request, request_kind=kind)
    write(
        journal,
        kind="usage",
        session="fixture",
        request=request,
        request_kind=kind,
        tokens={
            "input": count,
            "output": count,
            "reasoning": count,
            "cache": {"read": count, "write": count},
        },
        cost=count / 1000,
    )


def test_cumulative_journal_preserves_each_disjoint_counter_and_compaction(tmp_path):
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    usage(journal, 1, 100)
    usage(journal, 2, 130, kind="compaction")
    rows = []
    journal.drain(rows.append)
    assert [row["part"]["tokens"]["input"] for row in rows] == [100, 30]
    assert rows[1]["part"]["tokens"]["cache"] == {"read": 30, "write": 30}
    assert journal.compactions == 1
    journal.drain(rows.append)
    assert len(rows) == 2
    journal.finish()


@pytest.mark.parametrize(
    "failure", ["decrease", "negative", "boolean", "nonce", "pending", "duplicate", "kind", "error"]
)
def test_incomplete_or_invalid_usage_fails_closed(tmp_path, failure):
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    usage(journal, 1, 100)
    journal.drain(lambda row: None)
    if failure == "decrease":
        usage(journal, 2, 90)
    elif failure in {"negative", "boolean"}:
        usage(journal, 2, -1 if failure == "negative" else True)
    elif failure == "nonce":
        write(journal, kind="ready", nonce="incorrect")
    elif failure == "pending":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
    elif failure == "duplicate":
        usage(journal, 1, 120)
    elif failure == "kind":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
        write(journal, kind="usage", session="fixture", request=2, request_kind="compaction")
    else:
        write(journal, kind="error")
    with pytest.raises((ValueError, KeyError)):
        journal.drain(lambda row: None)
        journal.finish()


def test_partial_write_waits_for_newline_but_cannot_finalize(tmp_path):
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    fragment = json.dumps(
        {
            "nonce": journal.nonce,
            "kind": "request",
            "session": "fixture",
            "request": 1,
            "request_kind": "primary",
        }
    )
    with journal.path.open("a") as stream:
        stream.write(fragment)
    journal.drain(lambda row: None)
    assert not journal.pending
    with pytest.raises(ValueError, match="incomplete"):
        journal.finish()
    with journal.path.open("a") as stream:
        stream.write("\n")
    journal.drain(lambda row: None)
    assert journal.pending == {("fixture", 1): "primary"}


def test_native_primary_usage_must_reconcile(tmp_path):
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    usage(journal, 1, 100)
    journal.drain(lambda row: None)
    event = {
        "type": "step_finish",
        "sessionID": "fixture",
        "part": {
            "messageID": "primary",
            "tokens": {"input": 100, "output": 100, "reasoning": 100, "cache": {"read": 100, "write": 100}},
        },
    }
    journal.note_native(event)
    journal.note_native(event)
    journal.finish()
    event["part"]["messageID"] = "unaccounted"
    journal.note_native(event)
    with pytest.raises(ValueError, match="reconcile"):
        journal.finish()


def test_native_primary_keeps_compaction_with_missing_subscription_price(tmp_path):
    journal = UsageJournal(tmp_path)
    usage(journal, 1, 100)
    usage(journal, 2, 130, kind="compaction")
    usage(journal, 3, 200)
    rows = [json.loads(line) for line in journal.path.read_text().splitlines()]
    for row in rows:
        if row["kind"] == "usage":
            row["cost"] = None
    journal.path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    measured = []
    journal.drain(measured.append, native_primary=True)
    assert [event["part"]["tokens"]["input"] for event in measured] == [30]
    assert journal.compactions == 1
