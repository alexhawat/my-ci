"""Keep independent check outcomes visible and never hide a failed CI check."""

BAD = {"failure", "error", "blocked"}


def check_summary(steps: list[dict]) -> str:
    return "; ".join(
        f"{s['name']}: "
        + (
            f"{s['non_blocking_findings']} non-blocking findings"
            if s["state"] == "success" and s.get("non_blocking_findings")
            else s["state"]
        )
        for s in steps
        if s["name"] != "Checkout"
    )


def aggregate(steps: list[dict], fallback: str, message: str) -> tuple[str, str]:
    problems = [
        f"{s['name']}: {s['state']} ({s.get('message') or 'see log'})" for s in steps if s["state"] in BAD
    ]
    if fallback == "cancelled":
        # The run stays cancelled, but checks that had already failed remain visible.
        return fallback, f"{message}; before cancellation: {'; '.join(problems)}" if problems else message
    states = {s["state"] for s in steps} | {fallback}
    outcome = next((s for s in ("failure", "error", "blocked") if s in states), fallback)
    if problems:
        summary = "; ".join(problems)
        if fallback in BAD and fallback not in {s["state"] for s in steps}:
            summary += f"; {message}"
        return outcome, summary
    if outcome == "success":
        count = sum(s.get("non_blocking_findings", 0) for s in steps if s["state"] == "success")
        if count:
            message = f"All configured checks passed; review completed with {count} non-blocking findings"
        # A check where nothing ran is not a pass; name it instead of counting it silently.
        skipped = [s["name"] for s in steps if s["state"] == "skipped" and s["name"] != "Checkout"]
        if skipped:
            ran = "Checks that ran passed" + (f" with {count} non-blocking review findings" if count else "")
            message = f"{ran}; skipped without running: {', '.join(skipped)}"
    return outcome, message
