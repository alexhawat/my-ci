"""Explain CI from observed act events, without treating log prose as authority."""

import re
from collections import OrderedDict, deque


class StepOutput:
    """Keep failure tracebacks before warning/coverage noise, with a bounded tail."""

    def __init__(self):
        self.tail = deque(maxlen=20)
        self.failure = []
        self.failure_bytes = 0
        self.in_failure = False
        self.trace_remaining = 0
        self.truncated = False

    def append(self, text):
        self.tail.append(text)
        if re.match(r"=+\s*(FAILURES|ERRORS)\s*=+", text):
            self.in_failure = True
        elif re.match(r"=+\s*(warnings summary|tests coverage|short test summary|.*seconds)", text, re.I):
            self.in_failure = False
            self.trace_remaining = 0
        if text.startswith("Traceback (most recent call last):"):
            self.trace_remaining = 30
        if self.in_failure or self.trace_remaining:
            if len(self.failure) < 120 and self.failure_bytes + len(text) <= 9000:
                self.failure.append(text)
                self.failure_bytes += len(text)
            else:
                self.truncated = True
            self.trace_remaining = max(0, self.trace_remaining - 1)

    def diagnostics(self):
        if not self.failure:
            return list(self.tail)
        result = list(self.failure)
        if self.truncated:
            result.append("[Failure excerpt truncated; full traceback is in the retained log.]")
        # Preserve the final command/test summary separately from the traceback.
        tail = list(self.tail)
        if tail and result[-len(tail) :] != tail:
            result += ["[Final output]"] + tail
        return result


def evidence(run, store, clean):
    jobs = OrderedDict()
    output = {}
    pending_failure = {}
    rows = store.rows(
        "SELECT timestamp,phase,job,message FROM run_events WHERE run_id=? AND phase!='mergeCraft' ORDER BY id LIMIT 50000",
        (run["id"],),
    )
    for row in rows:
        name = row["job"].strip()
        if not name:
            continue
        key = (row["phase"], name)
        job = jobs.setdefault(
            key,
            {
                "workflow": clean(row["phase"]),
                "name": clean(name),
                "state": "unknown",
                "started": row["timestamp"],
                "finished": None,
                "checks": [],
                "summaries": [],
            },
        )
        text = row["message"]
        context = output.setdefault(key, StepOutput())
        if re.match(r"⭐\s+Run ", text):
            context = output[key] = StepOutput()
            pending_failure.pop(key, None)
        if text.startswith("|"):
            context.append(clean(text.removeprefix("|").strip()))
        elif (
            key in pending_failure and text and not text.startswith(("⭐", "✅", "❌", "🏁", "🐳", "⚙", "❓"))
        ):
            # act may print a raw engine error after the failure marker.
            context.append(clean(text))
        if key in pending_failure:
            pending_failure[key]["diagnostics"] = context.diagnostics()
        match = re.match(r"(?:✅\s+Success|❌\s+Failure) - (Main|Pre|Post) (.+?)(?: \[([^\]]+)\])?$", text)
        if match:
            job["checks"].append(
                {
                    "name": clean(match[2] if match[1] == "Main" else f"{match[1]} {match[2]}"),
                    "state": "success" if text.startswith("✅") else "failure",
                    "duration": clean(match[3] or ""),
                    # Capture the failed step's output, regardless of its event
                    # level. act often emits real errors as ordinary stdout.
                    "diagnostics": context.diagnostics() if text.startswith("❌") else [],
                }
            )
            if text.startswith("❌"):
                pending_failure[key] = job["checks"][-1]
            else:
                pending_failure.pop(key, None)
                context = output[key] = StepOutput()
        if "🏁  Job succeeded" in text or "🏁  Job failed" in text:
            job["state"] = "success" if "succeeded" in text else "failure"
            job["finished"] = row["timestamp"]
            pending_failure.pop(key, None)
        # These are evidence snippets, never inputs to the workflow success gate.
        if re.search(
            r"\d+ passed(?:,|\s)|\d+ failed(?:,|\s)|TOTAL\s+\d|^\| # (tests|pass|fail|skipped) \d|skipp.*(unavailable|not installed|not found)|skipping|not available.*skip|not installed.*skip",
            text,
            re.I,
        ):
            value = clean(text.removeprefix("| ").strip())
            if value not in job["summaries"] and len(job["summaries"]) < 12:
                job["summaries"].append(value)
    return list(jobs.values())[:50]
