"""Bounded review artifacts and the pinned CLI's completion/exit contract."""

import hashlib
import json
from pathlib import Path

from localci.policy import review_state


def read_json(path: Path, limit: int):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        return None
    return json.loads(path.read_text())


def terminal_event(line: str):
    if not line.startswith("{") or len(line) > 100_000:
        return None
    try:
        data = json.loads(line)
    except ValueError:
        return None
    if not isinstance(data, dict) or data.get("event") not in ("verdict", "run_finished"):
        return None
    # Never export arbitrary tool arguments or model text into the runtime record.
    outcome = data.get("outcome")
    known_outcomes = ("passed", "failed", "inconclusive", "configuration_error", "infra_error", "timed_out")
    code = data.get("exit_code")
    return {
        "event": data["event"],
        "protocol_version": "1" if data.get("protocol_version") == "1" else "unsupported",
        "outcome": outcome if isinstance(outcome, str) and outcome in known_outcomes else None,
        "exit_code": code if type(code) is int and 0 <= code <= 255 else None,
    }


REVIEW_THRESHOLDS = {"major": "Major or Critical", "minor": "Minor and above", "trivial": "Any finding"}
SEVERITY_RANK = {"trivial": 0, "minor": 1, "major": 2, "critical": 3}


def classify_review(
    code: int,
    events: dict,
    *,
    primary_available: bool = True,
    findings: list[dict] | None = None,
    failure_threshold: str = "major",
    configuration_error: str = "",
) -> tuple[str, str]:
    """The CLI lets blocking findings override even an inconclusive exit code.

    Verified in the pinned image's run_outcome.cli_exit_code_for_review: any
    blocking finding forces 11, independently of the RunOutcome. Consequently
    code 11 alone does NOT establish that a review completed.
    """
    # Config loading precedes JSONL initialization in the CLI. An explicit
    # validation failure plus exit 30 is a blocked review, never a pass.
    if code == 30 and not events and configuration_error:
        return "blocked", f"Review configuration invalid (CLI exit 30):\n{configuration_error}"
    verdict, finished = events.get("verdict", {}), events.get("run_finished", {})
    if not all(
        isinstance(e, dict)
        and e.get("event") == name
        and e.get("protocol_version") == "1"
        and type(e.get("exit_code")) is int
        and e["exit_code"] == code
        for name, e in (("verdict", verdict), ("run_finished", finished))
    ):
        return "error", f"Review completion protocol missing, invalid or inconsistent (CLI exit {code})"
    outcome = verdict.get("outcome")
    expected = {
        "passed": {0, 10, 11},
        "failed": {10, 11, 12},
        "inconclusive": {11, 20},
        "configuration_error": {11, 30},
        "infra_error": {11, 40},
        "timed_out": {11, 50},
    }
    if not isinstance(outcome, str) or code not in expected.get(outcome, set()):
        return "error", f"Review outcome/exit-code contract mismatch (CLI exit {code})"
    if outcome == "passed" and code in (0, 10):
        if not primary_available or (code == 10 and not findings):
            return (
                "error",
                f"Review findings unavailable or inconsistent with CLI exit {code}; cannot apply failure threshold",
            )
        if failure_threshold not in REVIEW_THRESHOLDS:
            return "error", "Invalid review failure threshold"
        values = findings or []
        ranks = [SEVERITY_RANK.get(str(f.get("severity", "")).casefold()) for f in values]
        if any(rank is None for rank in ranks):
            return "error", "Unknown finding severity; cannot apply review failure threshold"
        blocking = sum(rank >= SEVERITY_RANK[failure_threshold] for rank in ranks if rank is not None)
        threshold = REVIEW_THRESHOLDS[failure_threshold]
        if blocking:
            return (
                "failure",
                f"Review completed; {blocking} of {len(values)} findings meet failure threshold: {threshold} (CLI exit {code})",
            )
        if values:
            return (
                "success",
                f"Review completed with {len(values)} non-blocking findings; failure threshold: {threshold} (CLI exit {code})",
            )
        return "success", "Review passed (CLI outcome passed; exit 0)"
    if outcome in ("passed", "failed"):
        state, detail = review_state(code)
        if outcome == "failed":
            state, detail = "failure", "Review execution failed"
    else:
        state, detail = {
            "inconclusive": (
                "blocked",
                "Review inconclusive; terminal review completion was not established",
            ),
            "configuration_error": ("blocked", "Review configuration required"),
            "infra_error": ("error", "Review provider/infrastructure failure"),
            "timed_out": ("error", "Review timed out"),
        }[outcome]
    if outcome == "passed":
        # "passed" is the CLI saying the review ran to completion, not that the
        # change passed review; printing it beside a failure reads as a contradiction.
        return state, f"{detail} (review ran to completion; CLI exit {code})"
    return state, f"{detail} (CLI outcome {outcome}; exit {code})"


def finding_rows(data):
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise ValueError("Expected a findings object")
    values = data["findings"]
    if len(values) > 10000:
        raise ValueError("Too many findings")
    for item in values:
        if not isinstance(item, dict) or not isinstance(item.get("evidence", []), list):
            raise ValueError("Invalid finding")
        if any(not isinstance(e, str) for e in item.get("evidence", [])):
            raise ValueError("Invalid finding evidence")
        if any(
            item.get(k) is not None and not isinstance(item[k], (str, int))
            for k in ("severity", "message", "path", "start_line", "end_line", "remediation")
        ):
            raise ValueError("Invalid finding fields")
    return values


def primary_findings(directory: Path):
    return finding_rows(read_json(directory / "mergecraft.json", 2_000_000))


def bound_packet(run: dict, directory: Path):
    path = directory / "mergecraft-evidence.json"
    packet = read_json(path, 10_000_000)
    runtime = read_json(directory / "mergecraft-runtime.json", 100_000)
    if not isinstance(packet, dict) or packet.get("schema_version") not in {"1.13.0", "1.19.0", "1.21.0"}:
        raise ValueError("Unsupported or missing evidence schema")
    if (
        not isinstance(runtime, dict)
        or any(runtime.get(k) != run[k] for k in ("repo", "head", "base"))
        or runtime.get("run_id") != run["id"]
    ):
        raise ValueError("Evidence is not bound to this run/revision")
    if runtime.get("evidence_sha256") != hashlib.sha256(path.read_bytes()).hexdigest():
        raise ValueError("Evidence digest mismatch")
    if packet.get("reviewed_head_sha") not in (None, run["head"]):
        raise ValueError("Evidence head mismatch")
    if packet.get("change_id") not in ("local/review@patch", f"{run['repo']}#{run['pr']}"):
        raise ValueError("Evidence change mismatch")
    values = finding_rows(packet)
    if any(item.get("scope") not in ("change", "run") for item in values):
        raise ValueError("Unknown finding scope")
    return packet


def recover_findings(run: dict, directory: Path):
    """Exact duplicates only; preserve distinct draft/final entries with provenance."""
    packet = bound_packet(run, directory)
    rows, seen = [], set()
    for item in packet["findings"]:
        if item["scope"] != "change":
            continue
        identity = json.dumps(item, sort_keys=True)
        if identity not in seen:
            seen.add(identity)
            rows.append(item)
    return rows


def configuration_diagnostic(store, run_id: str) -> str:
    """Preserve multiline validation context, including info-level field names."""
    starts = store.rows(
        "SELECT id FROM run_events WHERE run_id=? AND phase='mergeCraft' "
        "AND message LIKE '%config validation failed:%' ORDER BY id DESC LIMIT 1",
        (run_id,),
    )
    if not starts:
        return ""
    rows = store.rows(
        "SELECT message FROM run_events WHERE run_id=? AND phase='mergeCraft' AND id>=? ORDER BY id LIMIT 80",
        (run_id, starts[0]["id"]),
    )
    lines = []
    for row in rows:
        line = row["message"]
        if line.startswith(("mergeCraft exited", "Error response from daemon:", "{", "ERROR:", "BLOCKED:")):
            break
        lines.append(line)
    return "\n".join(lines)[:12000]


def budget_diagnostic(store, run_id: str) -> str:
    rows = store.rows(
        "SELECT message FROM run_events WHERE run_id=? AND phase='mergeCraft' "
        "AND message LIKE '%run budget exhausted (%' ORDER BY id DESC LIMIT 1",
        (run_id,),
    )
    return rows[0]["message"][:12000] if rows else ""
