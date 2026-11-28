"""A mergeCraft review that a CI workflow ran, published as this run's review message.

Some repositories review pull requests inside a CI workflow, through mergeCraft's
OpenAI Agents SDK integration, instead of with my-ci's own mergeCraft review. The
workflow has no GitHub token, so it uploads its report as the artifact
``mergecraft-agents-sdk-review`` (schema ``mergecraft.agents-sdk-review.v1``,
defined in mergeCraft's ``mergecraft.agents_sdk.report``). When a repository
opts in with ``publish_workflow_review``, my-ci reads that artifact after CI and
publishes it as the run's native COMMENT review, with the same login and marker
as its own review.

The artifact is produced by a job that runs pull-request code, so everything in
it is untrusted: it is size-capped before it is opened, must be bound to the
reviewed head commit, and every string is redacted, stripped of control
characters, cleared of secret-looking tokens and later rendered as literal text.
It is the workflow's claim, and the message says so; it never replaces CI's own
result or my-ci's review sandbox.
"""

import json
import re
import zipfile
from pathlib import Path

ARTIFACT = "mergecraft-agents-sdk-review"
FILENAME = f"{ARTIFACT}.json"
SCHEMA = "mergecraft.agents-sdk-review.v1"
SEVERITIES = ("Critical", "Major", "Minor", "Trivial")
BLOCKING = frozenset({"Critical", "Major"})
MAX_ARCHIVE_BYTES = 4_000_000
MAX_REPORT_BYTES = 2_000_000
MAX_FINDINGS = 100
MAX_LISTED_FILES = 500
# Token shapes worth hiding even when they are not one of this repository's own
# configured values (those are redacted by value): model-provider and cloud keys,
# chat tokens and private-key blocks.
SECRET_SHAPES = re.compile(
    r"sk-(?:proj-|ant-)?[A-Za-z0-9_-]{16,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|AIza[0-9A-Za-z_-]{30,}"
    r"|xox[abprs]-[A-Za-z0-9-]{10,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"
)


class Unavailable(ValueError):
    """No usable report: the reason is safe to show."""


def _archives(directory: Path) -> list[Path]:
    root = directory / "ci"
    if not root.is_dir() or root.is_symlink():
        return []
    # act's artifact server stores <run id>/<name>/<name>.zip for each upload.
    return sorted(
        path
        for path in root.glob(f"*/{ARTIFACT}/{ARTIFACT}.zip")
        if not any(p.is_symlink() for p in (path, path.parent, path.parent.parent))
    )


def read(directory: Path) -> dict:
    """The report document from this run's CI artifacts, or ``Unavailable``."""
    archives = _archives(directory)
    if not archives:
        raise Unavailable(f"The CI workflows uploaded no {ARTIFACT} artifact for this run.")
    if len(archives) > 1:
        raise Unavailable(f"{len(archives)} {ARTIFACT} artifacts were uploaded; expected one.")
    archive = archives[0]
    if not archive.is_file() or archive.stat().st_size > MAX_ARCHIVE_BYTES:
        raise Unavailable(f"The {ARTIFACT} artifact is not a file of at most {MAX_ARCHIVE_BYTES} bytes.")
    try:
        with zipfile.ZipFile(archive) as bundle:
            member = next((m for m in bundle.infolist() if m.filename == FILENAME), None)
            if member is None:
                raise Unavailable(f"The {ARTIFACT} artifact has no {FILENAME} at its root.")
            if member.file_size > MAX_REPORT_BYTES:
                raise Unavailable(f"{FILENAME} is larger than {MAX_REPORT_BYTES} bytes.")
            with bundle.open(member) as handle:
                raw = handle.read(MAX_REPORT_BYTES + 1)
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, EOFError) as exc:
        raise Unavailable(f"The {ARTIFACT} artifact could not be opened ({type(exc).__name__}).") from None
    if len(raw) > MAX_REPORT_BYTES:
        raise Unavailable(f"{FILENAME} is larger than {MAX_REPORT_BYTES} bytes.")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise Unavailable(f"{FILENAME} is not UTF-8 JSON.") from None
    if not isinstance(document, dict):
        raise Unavailable(f"{FILENAME} is not a JSON object.")
    return document


def _whole(value) -> int | None:
    return value if type(value) is int and 0 <= value < 10**12 else None


def normalize(document: dict, head: str, clean) -> dict:
    """Check the document against the schema and the reviewed commit; clean every string.

    ``clean(value, limit)`` redacts this repository's credentials and strips
    control characters. Fields of the wrong type are dropped, not trusted.
    """
    if document.get("schema") != SCHEMA:
        raise Unavailable(f"{FILENAME} does not declare schema {SCHEMA}.")
    status = document.get("status")
    if status not in {"reviewed", "skipped", "error"}:
        raise Unavailable(f"{FILENAME} has no valid status.")
    if document.get("head_sha") != head:
        raise Unavailable(f"{FILENAME} is not bound to the reviewed commit {head[:12]}.")

    def text(value, limit=3000) -> str:
        if not isinstance(value, str):
            return ""
        return SECRET_SHAPES.sub("[redacted]", clean(value, limit * 2))[:limit]

    def paths(items: list) -> list[str]:
        return [text(p, 500) for p in items[:MAX_LISTED_FILES] if isinstance(p, str)]

    def listed(key) -> list:
        value = document.get(key)
        return value if isinstance(value, list) else []

    def mapping(key) -> dict:
        value = document.get(key)
        return value if isinstance(value, dict) else {}

    raw_findings = listed("findings")
    findings = []
    for item in raw_findings:
        if len(findings) >= MAX_FINDINGS:
            break
        if not isinstance(item, dict) or item.get("severity") not in SEVERITIES:
            continue
        line = _whole(item.get("line"))
        findings.append(
            {
                "severity": item["severity"],
                "path": text(item.get("file"), 500),
                "start_line": str(line) if line else "",
                "message": text(item.get("message"), 6000),
                "remediation": text(item.get("suggested_fix"), 3000),
            }
        )
    findings.sort(key=lambda f: SEVERITIES.index(f["severity"]))
    usage = mapping("usage")
    pr = _whole(document.get("pull_request"))
    return {
        "status": status,
        "reason": text(document.get("reason"), 2000),
        "pull_request": pr,
        "base_sha": text(document.get("base_sha"), 64),
        "model": text(document.get("model"), 200),
        "summary": text(document.get("summary"), 8000),
        "findings": findings,
        "finding_count": sum(
            1 for f in raw_findings if isinstance(f, dict) and f.get("severity") in SEVERITIES
        ),
        "dropped": [text(d, 500) for d in listed("dropped")[:50] if isinstance(d, str)],
        "changed_files": paths(listed("changed_files")),
        "omitted_files": paths(listed("omitted_files")),
        "usage": {k: _whole(usage.get(k)) for k in ("requests", "input_tokens", "output_tokens")},
    }


def outcome(review: dict) -> tuple[str, str]:
    """(report state, label) using the workflow gate's own rule: Critical or Major fails."""
    if review["status"] == "error":
        return "failure", "review failed"
    if review["status"] == "skipped":
        return "skipped", "skipped by the workflow"
    blocking = sum(1 for f in review["findings"] if f["severity"] in BLOCKING)
    total = review["finding_count"]
    if blocking:
        return "failure", f"changes requested: {blocking} blocking of {total} findings"
    if total:
        return "success", f"success with {total} non-blocking findings"
    return "success", "success: no findings"


def tokens(review: dict) -> str:
    usage = review["usage"]
    if usage["input_tokens"] is None and usage["output_tokens"] is None:
        return "Not recorded by the workflow"
    return f"{usage['input_tokens']} input · {usage['output_tokens']} output" + (
        f" · {usage['requests']} model requests" if usage["requests"] is not None else ""
    )


def report(directory: Path, head: str, clean) -> dict:
    """The run's review report, built from the workflow's artifact."""
    base = {"source": "workflow", "checks": [], "findings": [], "diagnostics": [], "analyzers": []}
    try:
        review = normalize(read(directory), head, clean)
    except Unavailable as exc:
        return base | {
            "state": "unavailable",
            "result_label": "no review report",
            "diagnostics": [str(exc)],
        }
    state, label = outcome(review)
    return base | {
        "state": state,
        "result_label": label,
        "failure_threshold": "Major and above (the workflow's gate)",
        "findings_source": "workflow",
        "finding_count": review["finding_count"],
        "findings": [f | {"end_line": "", "evidence": []} for f in review["findings"]],
        "narrative": review["summary"],
        "run_health": [
            {
                "severity": "Dropped",
                "message": reason,
                "path": "guardrail",
                "remediation": "",
            }
            for reason in review["dropped"]
        ],
        "record": {
            "provider": "OpenAI Agents SDK, run by the CI workflow",
            "model": review["model"] or "Not recorded by the workflow",
            "verdict": review["status"],
            "tokens": tokens(review),
            "files_changed": review["changed_files"],
            "files_omitted": review["omitted_files"],
        },
        "workflow_review": review,
        "diagnostics": [f"Reason given by the workflow: {review['reason']}"] if review["reason"] else [],
    }
