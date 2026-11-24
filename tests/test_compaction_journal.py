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


@pytest.mark.parametrize(
    ("row", "message"),
    [
        (
            {"reason": "Provider request failed; complete usage unavailable", "status": 429},
            "Provider request failed; complete usage unavailable (HTTP 429)",
        ),
        (
            {"reason": "Provider request failed; complete usage unavailable"},
            "Provider request failed; complete usage unavailable",
        ),
        (
            {"reason": "Usage arrived without a metered request"},
            "Usage arrived without a metered request",
        ),
        # A status that is not an HTTP status code is left out.
        (
            {"reason": "Usage event subscription failed", "status": "429 fixture-text"},
            "Usage event subscription failed",
        ),
        # A reason the plugin does not write is never copied into the evidence.
        (
            {"reason": "fixture-provider-text", "status": 500},
            "Usage journal reported an incomplete provider request",
        ),
        ({}, "Usage journal reported an incomplete provider request"),
    ],
)
def test_plugin_failure_names_the_cause_without_copying_provider_text(tmp_path, row, message):
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    write(journal, kind="error", **row)
    with pytest.raises(ValueError) as raised:
        journal.drain(lambda row: None)
    assert str(raised.value) == message


def test_unknown_row_kind_is_not_described_by_its_own_reason(tmp_path):
    journal = UsageJournal(tmp_path)
    write(journal, kind="fixture", reason="Usage event subscription failed", status=429)
    with pytest.raises(ValueError) as raised:
        journal.drain(lambda row: None)
    assert str(raised.value) == "Usage journal reported an incomplete provider request"


def test_consume_records_the_cause_in_the_halt_reason_and_the_saved_usage(tmp_path, monkeypatch):
    import sys
    import types

    from patches import localci_compaction

    saved = []
    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    write(journal, kind="request", session="fixture", request=1, request_kind="primary")
    write(
        journal,
        kind="error",
        reason="Provider request failed; complete usage unavailable",
        status=429,
    )
    live = types.SimpleNamespace(journal=journal, save=lambda: saved.append(True))
    package = types.ModuleType("mergecraft")
    module = types.ModuleType("mergecraft.localci_live_budget")
    module.current = lambda: live  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mergecraft", package)
    monkeypatch.setitem(sys.modules, "mergecraft.localci_live_budget", module)
    accumulator = types.SimpleNamespace(halt_reason=None)

    assert localci_compaction.consume(accumulator, {}, lambda row: None)

    detail = "Provider request failed; complete usage unavailable (HTTP 429)"
    assert accumulator.halt_reason == f"Complete model usage unavailable ({detail}); review stopped"
    assert live.journal_error_detail == detail
    assert live.journal_error_type == "ValueError"
    assert saved == [True]

    # A failure this module did not raise is named by its type only.
    journal.path.write_text("not json\n")
    journal.offset = 0
    accumulator.halt_reason = None
    assert localci_compaction.consume(accumulator, {}, lambda row: None)
    assert live.journal_error_detail == "JSONDecodeError"
    assert accumulator.halt_reason == "Complete model usage unavailable (JSONDecodeError); review stopped"
