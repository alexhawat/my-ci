"""Bounded, redacted check evidence shared by the dashboard and PR comments."""

import json
import re
from pathlib import Path

from localci.ci_report import evidence as ci_evidence
from localci.results import BAD
from localci.review_evidence import (
    REVIEW_THRESHOLDS,
    budget_diagnostic,
    configuration_diagnostic,
    primary_findings,
    recover_findings,
)
from localci.review_profile import summarize as summarize_profile
from localci.runner import sanitize

TERMINAL = {"success", "failure", "error", "blocked", "cancelled", "skipped"}


def clean(value, secrets: list[str], limit=3000) -> str:
    # Redact, strip control characters, redact again; truncate only afterwards.
    return sanitize(str("" if value is None else value), secrets)[:limit]


def reports(run: dict, root: Path, store, secrets: list[str]) -> dict:
    steps = json.loads(run["steps"]) if isinstance(run["steps"], str) else run["steps"]
    config = json.loads(run["config"])
    final = run["state"] in TERMINAL
    review = next((s for s in steps if s["name"] == "mergeCraft"), None)
    ci = [s for s in steps if s["name"] != "mergeCraft"]
    result = {}
    # Parallel review can finish before CI. Publish each phase only after its
    # own configured checks are terminal, including blocked/skipped workflows.
    expected = {Path(path).name for path in config.get("workflows", [])}
    completed = {s["name"] for s in ci if s["state"] in TERMINAL}
    ci_complete = expected <= completed and all(s["state"] in TERMINAL for s in ci) and bool(ci)
    run_level = False
    # Review-only repositories have no CI workflows and therefore no CI report.
    if config.get("workflows") and (final or ci_complete):
        states = {s["state"] for s in ci}
        state = next((s for s in ("failure", "error", "blocked", "cancelled") if s in states), "success")
        if not any(s["state"] == "success" and s["name"] != "Checkout" for s in ci) and state == "success":
            state = "skipped"
        # A run-level failure outside every check (e.g. the overall time limit) must
        # not be reported as CI success. A failed review explains its own run state.
        review_bad = bool(review and review["state"] in BAD | {"cancelled"})
        if final and run["state"] in BAD | {"cancelled"}:
            if not review:
                state = run["state"]
            elif not review_bad and state not in BAD | {"cancelled"}:
                state, run_level = run["state"], True
        result["ci"] = {"state": state, "checks": ci, "findings": [], "diagnostics": []}
    if (review and review["state"] in TERMINAL) or final:
        if review and review["state"] == "skipped":
            result["review"] = {"state": "skipped", "checks": [review], "findings": [], "diagnostics": []}
        elif config.get("review") and not review:
            # The run ended (blocked checkout, merge conflict, setup error...) before
            # the review step was ever registered: not run, which is not a skip.
            result["review"] = {
                "state": "not run",
                "checks": [],
                "findings": [],
                "diagnostics": [clean(run.get("message") or run["state"], secrets)],
                "run_state": run["state"],
            }
        elif config.get("review"):
            result["review"] = {
                "state": review["state"] if review else "skipped",
                "checks": [review] if review else [],
                "findings": [],
                "diagnostics": [],
            }
            report = result["review"]
            report["failure_threshold"] = REVIEW_THRESHOLDS.get(
                config.get("review_failure_threshold"), "Legacy exit-code policy"
            )
            report["policy_adjustment"] = config.get("review_policy_adjustment")
            count = (review or {}).get("non_blocking_findings", 0) if report["state"] == "success" else 0
            report["non_blocking_findings"] = count
            report["result_label"] = (
                f"success with {count} non-blocking findings" if count else report["state"]
            )
            directory = root / "artifacts" / run["id"]
            values = None
            report["findings_source"] = "unavailable"
            try:
                values = primary_findings(directory)
                report["findings_source"] = "primary"
            except (ValueError, TypeError, OSError):
                report["diagnostics"].append(
                    "No readable primary mergeCraft JSON report; it is missing, invalid or could not be parsed."
                )
                try:
                    values = recover_findings(run, directory)
                    report["findings_source"] = "evidence"
                    report["diagnostics"].append(
                        "Findings recovered from run-bound evidence. Review completion remains governed by the CLI outcome; draft/final entries may overlap and are not unique confirmed defects."
                    )
                except (ValueError, TypeError, OSError):
                    report["diagnostics"].append(
                        "Findings unavailable: no supported evidence packet with matching run/revision provenance and digest."
                    )
            if values is not None:
                report["finding_count"] = len(values)
                for item in values[:100]:
                    report["findings"].append(
                        {
                            key: clean(item.get(key), secrets)
                            for key in (
                                "severity",
                                "message",
                                "path",
                                "start_line",
                                "end_line",
                                "remediation",
                                "rule_id",
                                "source",
                                "fingerprint",
                            )
                        }
                        | {"evidence": [clean(e, secrets, 1000) for e in item.get("evidence", [])[:8]]}
                    )
        elif config.get("workflows"):
            result["review"] = {
                "state": "skipped",
                "checks": [],
                "findings": [],
                "diagnostics": ["mergeCraft was not enabled for this run."],
            }
    if "ci" in result:
        result["ci"]["jobs"] = ci_evidence(run, store, lambda value: clean(value, secrets, 1200))
    if "review" in result and result["review"]["state"] not in {"skipped", "not run"}:
        add_review_record(result["review"], root / "artifacts" / run["id"], secrets)
    for kind, report in result.items():
        report["checks"] = [
            {
                "name": clean(s["name"], secrets, 200),
                "state": s["state"],
                "message": clean(s.get("message"), secrets),
            }
            for s in report["checks"]
        ]
        if report["state"] in BAD | {"cancelled"}:
            if kind == "ci":
                for job in report.get("jobs", []):
                    for check in job["checks"]:
                        if check["state"] == "failure":
                            excerpt = "\n".join(check.get("diagnostics", []))
                            if excerpt:
                                report["diagnostics"].append(
                                    clean(f"{job['name']} / {check['name']}:\n{excerpt}", secrets, 12000)
                                )
            if kind == "review":
                diagnostic = configuration_diagnostic(store, run["id"]) or budget_diagnostic(store, run["id"])
                if diagnostic:
                    report["diagnostics"].insert(0, clean(diagnostic, secrets, 12000))
                # The CLI labels semantic completion failures as ordinary output.
                # Keep these explanations even when generic error rows are noisy.
                completion_rows = store.rows(
                    """SELECT message FROM run_events WHERE run_id=? AND phase='mergeCraft'
                    AND (message LIKE '%submit_review_verdict terminal submission%'
                         OR message LIKE '%no terminal review verdict was submitted%'
                         OR message LIKE '%semantic_rejection%')
                    ORDER BY id DESC LIMIT 8""",
                    (run["id"],),
                )
                report["diagnostics"].extend(
                    dict.fromkeys(clean(e["message"], secrets, 1000) for e in reversed(completion_rows))
                )
            has_step_output = kind == "ci" and bool(report["diagnostics"])
            phases = [s["name"] for s in report["checks"] if s["state"] in BAD | {"cancelled"}]
            if phases and not has_step_output:
                placeholders = ",".join("?" for _ in phases)
                rows = store.rows(
                    f"SELECT phase,job,message FROM run_events WHERE run_id=? AND level='error' AND phase IN ({placeholders}) ORDER BY id DESC LIMIT 20",
                    (run["id"], *phases),
                )
                report["diagnostics"].extend(
                    clean(f"{e['job'] or e['phase']}: {e['message']}", secrets, 1000) for e in reversed(rows)
                )
            if not report["checks"] or (kind == "ci" and (not review or run_level)):
                report["diagnostics"].append(clean(run.get("message"), secrets))
    return result


def literal(value, *, block: bool = False) -> str:
    """Render untrusted repository/review text as text, not Markdown or mentions.

    Every ASCII punctuation character that can start Markdown structure is
    backslash-escaped (headings, quotes, lists, setext ``=``/``-`` underlines,
    tables, links, emphasis, math). Inline text (list items, headings, table
    cells) is collapsed to one line so it cannot end its container; ``block``
    text keeps its lines, each neutralised the same way.
    """
    text = str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("@", "@\u200b")
    text = re.sub(r"([\\`*_{}\[\]()#+.!|~>=$-])", r"\\\1", text)
    lines = re.split(r"\r\n|\r|\n", text)
    if len(lines) == 1:
        return text
    if not block:
        return " ".join(line.strip() for line in lines if line.strip())
    # Leading indentation would turn lines into code blocks or list continuations.
    return "\n".join(line.lstrip(" \t") for line in lines)


def comment_body(run: dict, kind: str, report: dict, url: str) -> str:
    footer = f"Commit `{run['head']}` · run `{run['id']}`\n\n[Full run — Tailscale access required]({url})"
    if kind == "review" and report["state"] == "not run":
        reason = "; ".join(report["diagnostics"]) or report.get("run_state", "")
        return f"### mergeCraft: not run\n\nThe run ended before the review started — {literal(reason)}\n\n{footer}"
    if kind == "review" and report["state"] == "skipped":
        reason = "; ".join(c["message"] for c in report["checks"]) or "; ".join(report["diagnostics"])
        return f"### mergeCraft: skipped\n\n{literal(reason, block=True)}\n\n{footer}"
    if kind == "review":
        return review_body(run, report, url)
    title = "Local CI"
    lines = [
        f"<!-- localci:ci:v2:{run['id']} -->",
        f"## {title}: {report['state']}",
        "",
        f"Commit `{run['head']}` · attempt {run.get('attempt', 1)} · run `{run['id']}`",
        "",
        f"[Full run, logs and artifacts — Tailscale access required]({url})",
        "",
    ]
    for check in report["checks"]:
        lines.append(f"- **{literal(check['name'])}: {check['state']}** — {literal(check['message'])}")
    if report["diagnostics"]:
        lines += ["", "### Diagnostic details", "", "Bounded output from failed checks:", ""]
        for diagnostic in report["diagnostics"][:6]:
            lines += ["> " + literal(line) for line in diagnostic.splitlines()]
            lines.append("")
        lines += ["Full output is retained in the private run log."]
    lines += [
        "",
        "CI and mergeCraft are separate results. This comment reports workflow execution only.",
        "",
        "### Jobs and checks performed",
        "",
    ]
    lines += [
        "Workflow-step exit statuses are shown below; conditional subchecks can skip work even when their step succeeds.",
        "",
    ]
    for job in report.get("jobs", []):
        seconds = job["finished"] - job["started"] if job["finished"] else None
        duration = f"{seconds / 60:.1f} min" if seconds is not None else "duration unavailable"
        lines += [
            f"#### {literal(job['name'])} — {literal(job['state'])} · {duration}",
            f"Workflow: {literal(job['workflow'])}",
            "",
        ]
        for check in job["checks"][:80]:
            lines += [
                f"- {literal(check['name'])}: **{check['state']}** ({literal(check['duration']) or 'duration unavailable'})"
            ]
        if job["summaries"]:
            lines += [
                "",
                "Observed test/coverage/skip summaries:",
                *[f"- {literal(v)}" for v in job["summaries"]],
            ]
    skipped = [c for c in report["checks"] if c["state"] in {"skipped", "blocked"}]
    if skipped:
        lines += ["", "### Checks not executed", ""]
        lines += [
            f"- **{literal(c['name'])}: {c['state']}** — {literal(c['message'])}. This is not a passing check."
            for c in skipped
        ]
    if not report.get("jobs"):
        lines += [
            "Per-job execution evidence is unavailable for this run; see the workflow result and retained logs."
        ]
    body = "\n".join(lines)
    if len(body) > 60000:
        body = body[:59000] + "\n\nReport truncated. Full evidence is available in the private run artifacts."
    return body


def read_artifact(path: Path, limit: int = 10_000_000):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > limit:
        return None
    return json.loads(path.read_text())


def add_review_record(report: dict, directory: Path, secrets: list[str]) -> None:
    """Project only public evidence fields; never export provider configuration."""
    record = {}
    report["record"] = record
    report["run_health"] = []
    report["analyzers"] = []
    try:
        packet = (
            read_artifact(directory / "mergecraft-evidence.json")
            if report.get("findings_source") != "unavailable"
            else None
        )
        if isinstance(packet, dict):
            agent = packet.get("agent") or {}
            trajectory = packet.get("trajectory") or {}
            retries = trajectory.get("retries", 0)
            record.update(
                provider=clean(agent.get("provider") or "Unavailable", secrets),
                model=clean(agent.get("executed_model") or agent.get("model") or "Unavailable", secrets),
                verdict=clean(packet.get("agent_terminal_verdict") or "Unavailable", secrets),
                files_changed=[clean(f, secrets, 500) for f in (packet.get("files_changed") or [])[:500]],
                files_read=[clean(f, secrets, 500) for f in (trajectory.get("files_read") or [])[:500]],
                tool_calls=len(trajectory.get("tool_calls") or []),
                tool_retries=retries if isinstance(retries, int) else len(retries or []),
                blast_radius=clean((packet.get("blast_radius") or {}).get("lane") or "Unavailable", secrets),
                scope_reason=clean((packet.get("blast_radius") or {}).get("reason"), secrets),
            )
            report["analyzers"] = [
                {k: clean(item.get(k), secrets, 500) for k in ("name", "status", "command")}
                for item in (packet.get("deterministic_checks") or [])[:100]
                if isinstance(item, dict)
            ]
            report["run_health"] = [
                {k: clean(item.get(k), secrets, 1500) for k in ("severity", "message", "path", "remediation")}
                for item in (packet.get("run_health") or {}).get("findings", [])[:100]
                if isinstance(item, dict)
            ]
        else:
            report["diagnostics"].append("Detailed review evidence is unavailable for this run.")
        metrics = read_artifact(directory / "mergecraft-metrics.json", 100_000)
        if isinstance(metrics, dict):
            for key in ("tokens", "cost", "timing", "attempts"):
                if key in metrics:
                    record[key] = clean(metrics[key], secrets, 2000)
        runtime = read_artifact(directory / "mergecraft-runtime.json", 100_000)
        usage = read_artifact(directory / "mergecraft-usage.json", 100_000)
        if isinstance(usage, dict) and usage.get("schema_version") == 1:
            counts = usage.get("tokens", {})
            record["tokens"] = clean(
                f"{usage.get('total_tokens')} reported across {usage.get('steps')} model steps "
                f"(input {counts.get('input')}, cached read {counts.get('cache_read')}, "
                f"cached write {counts.get('cache_write')}, output {counts.get('output')}, "
                f"reasoning {counts.get('reasoning')}; ceiling {usage.get('ceiling')}; "
                f"duplicate events ignored {usage.get('duplicates_ignored')})",
                secrets,
                2000,
            )
            if usage.get("stopped"):
                report["diagnostics"].insert(0, clean(usage.get("reason"), secrets, 2000))
        if isinstance(runtime, dict):
            for key in ("image", "container_seconds", "timeout_seconds", "model_attempt_limit", "exit_code"):
                if key in runtime:
                    record[key] = clean(runtime[key], secrets, 500)
        profile = summarize_profile(directory / "mergecraft-profile.jsonl")
        if profile:
            record["profile"] = profile
        narrative = directory / "mergecraft-review.md"
        if not narrative.is_symlink() and narrative.is_file() and narrative.stat().st_size <= 1_000_000:
            report["narrative"] = clean(narrative.read_text(), secrets, 18000)
    except (ValueError, TypeError, AttributeError, KeyError, OSError):
        report["diagnostics"].append("Detailed review evidence could not be parsed; inspect the artifacts.")


def review_body(run: dict, report: dict, url: str) -> str:
    record = report.get("record", {})
    lines = [
        "<!-- mergecraft-deterministic-record:v1 -->",
        "### mergeCraft run record",
        "",
        f"- Outcome: **{literal(report.get('result_label', report['state']))}**",
        f"- Failure threshold: {literal(report.get('failure_threshold', 'Legacy exit-code policy'))}",
        f"- CLI exit code: {literal(record.get('exit_code', 'Not recorded'))}",
        f"- Verdict diagnostic: {literal(record.get('verdict', 'Unavailable'))} (agent signal; the outcome above applies the local-ci failure threshold)",
        f"- Change: {literal(run['repo'])}#{run['pr']}",
        f"- Reviewed commit: `{run['head']}` · base `{run.get('base', 'unavailable')}`",
        f"- Blast radius: {literal(record.get('blast_radius', 'Unavailable'))} — {literal(record.get('scope_reason', ''))}",
        f"- Provider: {literal(record.get('provider', 'Unavailable'))}",
        f"- Model: {literal(record.get('model', 'Unavailable'))}",
        f"- CI attempt: {run.get('attempt', 1)} · model attempts: {literal(record.get('attempts', 'Not recorded'))}",
        f"- Tokens: {literal(record.get('tokens', 'Not recorded by this run'))}",
        f"- Cost: {literal(record.get('cost', 'Not recorded by this run'))}",
        f"- Timing: {literal(record.get('timing', 'Not recorded by this run'))}",
        f"- Review work: {record.get('tool_calls', 'unknown')} tool calls · {len(record.get('files_read', []))} files read · {record.get('tool_retries', 'unknown')} tool retries",
        "- Coverage: file reads listed below; hunk coverage was not recorded. A file read is not proof of complete review.",
        f"- Run: `{run['id']}` · [Full run, logs and artifacts — Tailscale access required]({url})",
        f"- Review image: {literal(record.get('image') or 'Not recorded by this run')}",
        f"- Container wall time: {literal(record.get('container_seconds', 'Not recorded'))} seconds · deadline {literal(record.get('timeout_seconds', 'Not recorded'))} seconds · model attempt cap {literal(record.get('model_attempt_limit', 'Not recorded'))}",
        "- Publication path: local-ci native GitHub COMMENT review",
        "",
        "### Pre-merge checks",
        "",
        "- Review sandbox: separate Docker container; shell, push, approval and auto-merge disabled.",
        "- CI runs independently. Its outcome is reported separately by Local CI.",
    ]
    lines += [
        f"- {literal(c['name'])}: **{literal(c['state'])}** — {literal(c['message'])}"
        for c in report["checks"]
    ]
    lines += [
        f"- Analyzer {literal(c['name'])}: **{literal(c['status'])}**" for c in report.get("analyzers", [])
    ]
    lines += ["", "<details><summary>Review scope and files read</summary>", "", "Changed files:"]
    lines += [f"- {literal(f)}" for f in record.get("files_changed", [])]
    lines += ["", "Files recorded as read:"]
    lines += [f"- {literal(f)}" for f in record.get("files_read", [])]
    if report.get("policy_adjustment"):
        lines += [
            "",
            "This legacy exit-10 result was re-evaluated from retained evidence using the displayed threshold. CI was not rerun.",
        ]
    lines += ["", "</details>", "", "<details open><summary>Change-scoped findings</summary>", ""]
    if report.get("findings_source") == "evidence":
        lines += [
            f"Recovered {report.get('finding_count', len(report['findings']))} finding entries from retained evidence; the primary JSON report was unavailable.",
            "These are retained review claims, not independently verified defects. Draft/final entries may overlap; counts are entries, not unique defects. An incomplete review remains incomplete after recovery.",
            "",
        ]
    for f in report["findings"]:
        lines += [
            f"#### {literal(f['severity'])} — {literal(f['path'])}:{literal(f['start_line'])}",
            "",
            literal(f["message"], block=True),
            "",
        ]
        if report.get("findings_source") == "evidence":
            lines += [
                f"- Provenance: {literal(f.get('rule_id'))} · {literal(f.get('source'))} · fingerprint {literal(f.get('fingerprint'))}"
            ]
        lines += [f"- Evidence: {literal(e)}" for e in f["evidence"]]
        if f["remediation"]:
            lines += [f"- Suggested fix: {literal(f['remediation'])}"]
    if not report["findings"]:
        lines += [
            "Change-scoped findings are unavailable; do not interpret missing evidence as a clean review."
            if report.get("findings_source") == "unavailable"
            else "No change-scoped findings in the available report. This alone is not an approval."
        ]
    if report.get("finding_count", 0) > len(report["findings"]):
        lines += ["Additional finding entries are retained in the private artifact."]
    lines += [
        "",
        "</details>",
        "",
        "<details><summary>Run health (review coverage and execution)</summary>",
        "",
    ]
    for f in report.get("run_health", []):
        lines += [
            f"- **{literal(f['severity'])}** — {literal(f['path'])}: {literal(f['message'])} {literal(f['remediation'])}"
        ]
    if not report.get("run_health"):
        lines += ["No run-health evidence was recorded."]
    lines += ["", "</details>", "", "<!-- mergecraft-review-body:v1 -->", "### Review summary", ""]
    lines += [
        literal(
            report.get("narrative")
            or "Agent narrative was not preserved by this run. The findings and deterministic evidence above are the available review record.",
            block=True,
        )
    ]
    if report["diagnostics"]:
        lines += ["", "### Diagnostic details", *[f"- {literal(d)}" for d in report["diagnostics"] if d]]
    body = "\n".join(lines)
    if len(body) > 60000:
        body = (
            body[:58000]
            + "\n\n</details>\nReport truncated. Full evidence is available in the private run artifacts."
        )
    return body
