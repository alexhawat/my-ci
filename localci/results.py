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
    if fallback == "cancelled":
        return fallback, message
    states = {s["state"] for s in steps} | {fallback}
    outcome = next((s for s in ("failure", "error", "blocked") if s in states), fallback)
    problems = [
        f"{s['name']}: {s['state']} ({s.get('message') or 'see log'})" for s in steps if s["state"] in BAD
    ]
    if problems:
        summary = "; ".join(problems)
        if fallback in BAD and fallback not in {s["state"] for s in steps}:
            summary += f"; {message}"
        return outcome, summary
    if outcome == "success":
        count = sum(s.get("non_blocking_findings", 0) for s in steps if s["state"] == "success")
        if count:
            message = f"All configured checks passed; review completed with {count} non-blocking findings"
    return outcome, message
