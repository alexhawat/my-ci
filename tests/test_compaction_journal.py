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


def bind_live(monkeypatch, journal, *, mistral):
    """Give ``consume`` a live budget without importing the patched mergeCraft tree."""
    import sys
    import types

    live = types.SimpleNamespace(
        journal=journal,
        mistral=mistral,
        journal_error_type="",
        journal_partial=False,
        saves=0,
    )
    live.save = lambda: setattr(live, "saves", live.saves + 1)
    module = types.ModuleType("mergecraft.localci_live_budget")
    module.current = lambda: live  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "mergecraft", types.ModuleType("mergecraft"))
    monkeypatch.setitem(sys.modules, "mergecraft.localci_live_budget", module)
    return live, types.SimpleNamespace(halt_reason=None)


STOP_DETAIL = {
    "not-json": "JSONDecodeError",
    "missing-session": "KeyError",
    "usage-without-request": "KeyError",
    "tokens-not-a-mapping": "Usage counters invalid",
    "cache-not-a-mapping": "Usage counters invalid",
    "unknown-kind": "Usage journal row of an unknown kind",
    "nonce": "Usage journal provenance mismatch",
    "plugin-error": "Usage journal reported an incomplete provider request",
    "usage-without-tokens": "Usage counters missing",
    "usage-with-null-counter": "Usage counters missing",
}


def stopped(detail):
    return f"Complete model usage unavailable ({detail}); review stopped"


def corrupt(journal, failure):
    if failure == "not-json":
        with journal.path.open("a") as stream:
            stream.write("not json\n")
    elif failure == "missing-session":
        write(journal, kind="request", request=2, request_kind="primary")
    elif failure == "usage-without-request":
        write(journal, kind="usage", session="fixture", request=9, request_kind="primary")
    elif failure == "tokens-not-a-mapping":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
        write(journal, kind="usage", session="fixture", request=2, request_kind="primary", tokens=[1])
    elif failure == "cache-not-a-mapping":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
        write(
            journal,
            kind="usage",
            session="fixture",
            request=2,
            request_kind="primary",
            tokens={"input": 1, "output": 1, "reasoning": 1, "cache": 5},
        )
    elif failure == "unknown-kind":
        write(journal, kind="fixture")
    elif failure == "nonce":
        write(journal, kind="error", nonce="incorrect")
    else:
        raise AssertionError(failure)


@pytest.mark.parametrize(
    "failure",
    [
        "not-json",
        "missing-session",
        "usage-without-request",
        "tokens-not-a-mapping",
        "cache-not-a-mapping",
        "unknown-kind",
        "nonce",
    ],
)
@pytest.mark.parametrize("mistral", [True, False])
def test_consume_stops_the_review_on_a_malformed_journal(tmp_path, monkeypatch, failure, mistral):
    from patches import localci_compaction

    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    corrupt(journal, failure)
    live, accumulator = bind_live(monkeypatch, journal, mistral=mistral)

    assert localci_compaction.consume(accumulator, {}, lambda row: None)

    assert accumulator.halt_reason == stopped(STOP_DETAIL[failure])
    assert live.journal_error_detail == STOP_DETAIL[failure]
    assert live.journal_partial is False
    assert live.journal_error_type and live.saves == 1


def report_gap(journal, gap):
    if gap == "plugin-error":
        write(journal, kind="error")
    elif gap == "usage-without-tokens":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
        write(journal, kind="usage", session="fixture", request=2, request_kind="primary")
    elif gap == "usage-with-null-counter":
        write(journal, kind="request", session="fixture", request=2, request_kind="primary")
        write(
            journal,
            kind="usage",
            session="fixture",
            request=2,
            request_kind="primary",
            tokens={"input": None, "output": 1, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        )
    else:
        raise AssertionError(gap)


@pytest.mark.parametrize("gap", ["plugin-error", "usage-without-tokens", "usage-with-null-counter"])
def test_consume_keeps_a_mistral_review_running_across_a_reported_gap(tmp_path, monkeypatch, gap):
    from patches import localci_compaction

    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    report_gap(journal, gap)
    live, accumulator = bind_live(monkeypatch, journal, mistral=True)

    # False hands the event back to the CLI's own step metering.
    assert localci_compaction.consume(accumulator, {}, lambda row: None) is False

    assert accumulator.halt_reason is None
    assert live.journal_partial is True
    assert live.journal_error_type == "JournalGap"
    assert live.journal_error_detail == STOP_DETAIL[gap]
    # The gap is remembered: later events also fall back to the CLI's metering.
    assert localci_compaction.consume(accumulator, {}, lambda row: None) is False
    assert accumulator.halt_reason is None


@pytest.mark.parametrize("gap", ["plugin-error", "usage-without-tokens", "usage-with-null-counter"])
def test_consume_stops_other_providers_on_the_same_gap(tmp_path, monkeypatch, gap):
    from patches import localci_compaction

    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    report_gap(journal, gap)
    live, accumulator = bind_live(monkeypatch, journal, mistral=False)

    assert localci_compaction.consume(accumulator, {}, lambda row: None)

    assert accumulator.halt_reason == stopped(STOP_DETAIL[gap])
    assert live.journal_partial is False


def test_mistral_completion_gaps_are_advisory_but_a_torn_journal_is_not(tmp_path, monkeypatch):
    from patches import localci_compaction

    # A request that never reported usage is a gap.
    journal = UsageJournal(tmp_path / "pending")
    write(journal, kind="ready")
    write(journal, kind="request", session="fixture", request=1, request_kind="primary")
    live, accumulator = bind_live(monkeypatch, journal, mistral=True)
    assert localci_compaction.consume(accumulator, {}, lambda row: None, final=True) is False
    assert (accumulator.halt_reason, live.journal_partial) == (None, True)

    # An unterminated last line is not: the journal cannot be trusted to be whole.
    journal = UsageJournal(tmp_path / "torn")
    write(journal, kind="ready")
    with journal.path.open("a") as stream:
        stream.write('{"nonce": "')
    live, accumulator = bind_live(monkeypatch, journal, mistral=True)
    assert localci_compaction.consume(accumulator, {}, lambda row: None, final=True)
    assert accumulator.halt_reason == stopped("Usage journal incomplete at review completion")
    assert live.journal_partial is False


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
        ({"reason": "Usage arrived without a metered request"}, "Usage arrived without a metered request"),
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
def test_plugin_error_row_names_its_cause_without_copying_provider_text(tmp_path, monkeypatch, row, message):
    from patches import localci_compaction
    from patches.localci_compaction import JournalGap

    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    write(journal, kind="error", **row)
    with pytest.raises(JournalGap) as raised:
        journal.drain(lambda row: None)
    assert str(raised.value) == message

    # The same text reaches the halt reason of a provider that stops on a gap.
    journal = UsageJournal(tmp_path / "halt")
    write(journal, kind="ready")
    write(journal, kind="error", **row)
    live, accumulator = bind_live(monkeypatch, journal, mistral=False)
    assert localci_compaction.consume(accumulator, {}, lambda row: None)
    assert accumulator.halt_reason == stopped(message)


@pytest.mark.parametrize("mistral", [True, False])
def test_a_value_error_from_the_usage_callback_is_named_by_type_only(tmp_path, monkeypatch, mistral):
    from patches import localci_compaction

    journal = UsageJournal(tmp_path)
    write(journal, kind="ready")
    usage(journal, 1, 100, kind="compaction")
    live, accumulator = bind_live(monkeypatch, journal, mistral=mistral)

    def absorb(row):
        raise ValueError("fixture-upstream-text")

    assert localci_compaction.consume(accumulator, {}, absorb)
    assert live.journal_error_detail == "ValueError"
    assert accumulator.halt_reason == stopped("ValueError")
    assert "fixture-upstream-text" not in accumulator.halt_reason


def test_a_missing_plugin_is_named(tmp_path, monkeypatch):
    from patches import localci_compaction

    journal = UsageJournal(tmp_path)
    live, accumulator = bind_live(monkeypatch, journal, mistral=False)
    assert localci_compaction.consume(accumulator, {"type": "step_finish"}, lambda row: None)
    assert accumulator.halt_reason == stopped("Usage plugin did not initialize")
    assert live.journal_error_type == "ValueError"


@pytest.mark.parametrize(
    ("partial", "stopped_flag", "reason"),
    [
        (False, True, "Complete model usage unavailable: Usage counters invalid"),
        (True, False, ""),
    ],
)
def test_saved_usage_names_the_accounting_failure(tmp_path, monkeypatch, partial, stopped_flag, reason):
    import importlib
    import sys
    import types

    profile = types.ModuleType("mergecraft.localci_profile")
    profile.event = lambda *args, **kwargs: None  # type: ignore[attr-defined]
    bounds = types.ModuleType("mergecraft.utils.run_bounds")
    bounds.BudgetExhausted = type("BudgetExhausted", (Exception,), {})  # type: ignore[attr-defined]
    for name, module in {
        "mergecraft": types.ModuleType("mergecraft"),
        "mergecraft.utils": types.ModuleType("mergecraft.utils"),
        "mergecraft.localci_profile": profile,
        "mergecraft.utils.run_bounds": bounds,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.delitem(sys.modules, "patches.localci_live_budget", raising=False)
    live_budget = importlib.import_module("patches.localci_live_budget")
    monkeypatch.setenv("LOCALCI_PROFILE_PATH", str(tmp_path / "profile.jsonl"))

    tracker = types.SimpleNamespace(
        tokens_used=0, bounds=types.SimpleNamespace(token_budget=100, token_ceiling=110)
    )
    live = live_budget.LiveBudget(tracker)
    live.mistral = partial
    live.journal_error_type = "JournalIntegrityError" if not partial else "JournalGap"
    live.journal_error_detail = "Usage counters invalid" if not partial else "Usage counters missing"
    live.journal_partial = partial
    live.save()

    saved = json.loads((tmp_path / "mergecraft-usage.json").read_text())
    assert saved["stopped"] is stopped_flag
    assert saved["reason"] == reason
    assert saved["accounting_error"] == live.journal_error_detail
    assert saved["accounting_error_type"] == live.journal_error_type
