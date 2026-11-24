"""Notice a reviewer that repeats itself, tell it, then stop the review.

A model can fall into repeating the same tool calls. Every step sends the whole
conversation again, so such a loop spends the token ceiling on nothing. Two patterns
count as a loop:

* the same call, with the same arguments, again and again;
* findings sent for verification again and again with no verdict recorded in between.

The limits come from 209 stored reviews. No completed review (180) made one call six
times or sent findings twice without recording a verdict; the two looping ones did.
"""

import hashlib
import json
import threading

NOTICE_AT = 3
STOP_AT = 6


class LoopGuard:
    def __init__(self):
        self._lock = threading.Lock()
        self._calls = {}
        self._unanswered = 0
        self._compactions = 0
        self.reason = ""

    def record(self, name, arguments, compactions=0):
        """Count one call. Return a note for the model, or ``""``."""
        payload = json.dumps(arguments, sort_keys=True, default=repr)
        key = (name, hashlib.sha256(payload.encode()).digest())
        with self._lock:
            if compactions != self._compactions:
                # A summary replaced earlier results, so reading them again is legitimate.
                self._compactions = compactions
                self._calls.clear()
                self._unanswered = 0
            count = self._calls[key] = self._calls.get(key, 0) + 1
            if name == "verify_agent_findings":
                self._unanswered += 1
            elif name == "record_finding_verdict":
                self._unanswered = 0
            pending = self._unanswered if name == "verify_agent_findings" else 0
            worst = max(count, pending)
            if worst < NOTICE_AT:
                return ""
            if worst >= STOP_AT and not self.reason:
                # The tool name is mergeCraft's own; no argument is copied.
                self.reason = f"Repeated tool calls without progress ({name}, {worst} times); review stopped"
        if pending >= count:
            return (
                f"Local CI: findings were sent for verification {pending} times with no verdict recorded. "
                "Do not send them again. Record one verdict per finding with record_finding_verdict, then "
                f"submit the review verdict. The review stops at {STOP_AT}."
            )
        return (
            f"Local CI: this exact call has now been made {count} times and returns the same result. "
            "Do not repeat it. Use what you have: record any outstanding finding verdicts, then submit the "
            f"review verdict. The review stops at {STOP_AT}."
        )
