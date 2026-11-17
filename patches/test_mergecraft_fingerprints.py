"""Run inside the patched review image, offline and without provider credentials."""

import json
import re
import tempfile
from pathlib import Path

from mergecraft.analyzers.finding import (
    Finding,
    make_finding,
    resolve_finding_short_ids,
    validate_findings_export,
    write_findings_json,
)
from mergecraft.review.output import finding_json_records


def check():
    def finding(fingerprint):
        return make_finding(
            tool="fixture",
            rule_id="fixture",
            category="Stability & Availability",
            severity="Major",
            confidence="certain",
            message="Retained finding",
            path="src/example.py",
            start_line=1,
            end_line=1,
            source="agent",
            fingerprint=fingerprint,
        )

    labels = [
        "network-metadata-access",
        "rollback-behavior-mismatch",
        "url-normalization-redaction",
        "review:inspection-timeout-label:src/example/worker.py:42",
        "review:duplicate-finding-id:src/example/engine.py:27",
    ]
    findings = [finding(v) for v in labels]
    for label, row in zip(labels, findings, strict=True):
        assert re.fullmatch(r"[0-9a-f]{64}", row.fingerprint)
        assert finding(label).fingerprint == row.fingerprint
        assert Finding.model_validate(row.model_dump()).fingerprint == row.fingerprint
    assert finding("a" * 64).fingerprint == "a" * 64
    assert len(set(r.fingerprint for r in findings)) == len(labels)
    records = finding_json_records(findings)
    assert len(records) == len(labels) and all(r["short_id"].startswith("MC-") for r in records)
    assert all(r["severity"] == "Major" and r["message"] == "Retained finding" for r in records)
    assert len(validate_findings_export({"findings": records})) == len(labels)
    with tempfile.TemporaryDirectory() as temp:
        target = Path(temp) / "findings.json"
        write_findings_json(target, [r.model_dump() for r in findings])
        assert len(json.loads(target.read_text())["findings"]) == len(labels)
    for unsafe in (
        "",
        "..",
        "../secret",
        "/tmp/finding",
        "x\\y",
        "bad\nvalue",
        "review:../secret",
        "review:src/../../secret",
        "x" * 2049,
    ):
        try:
            finding(unsafe) if unsafe else Finding.model_validate(
                {**findings[0].model_dump(), "fingerprint": ""}
            )
        except ValueError:
            pass
        else:
            raise AssertionError(f"Accepted unsafe identifier: {unsafe!r}")
    assert len(set(resolve_finding_short_ids(["abcdef11", "abcdef22"]).values())) == 2
    print(
        "PASS: synthetic fingerprints normalize deterministically; JSON/agent export retains findings; unsafe IDs rejected"
    )


if __name__ == "__main__":
    check()
