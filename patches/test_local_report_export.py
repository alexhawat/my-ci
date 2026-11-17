"""Exercise the installed accounting patch with real mergeCraft budget types."""

import json
import tempfile
import textwrap
from pathlib import Path
from types import SimpleNamespace

from mergecraft.utils.run_bounds import BudgetTracker, RunBounds

source = Path("/opt/mergecraft/src/mergecraft/review/offline_agent.py").read_text()
assert "max_attempts=3," in source
start = source.index("        # Local CI preserves only accounting")
end = source.index("        # End local CI accounting export", start)
code = compile(textwrap.dedent(source[start:end]), "<localci-accounting>", "exec")
tracker = BudgetTracker(
    RunBounds(
        token_budget=1000,
        cost_budget_usd=5,
        tool_call_budget=100,
        run_timeout_s=3000,
        context_retrieval_timeout_s=60,
        max_diff_lines=10000,
        external_operation_timeout_s=60,
    )
)
tracker.record_tokens(123, phase="reviewer_dispatch")
tracker.record_cost(0.01)
with tempfile.TemporaryDirectory() as folder:
    context = {
        "budget_tracker": tracker,
        "_localci_usages": [SimpleNamespace(cost_usd=0.01)],
        "timing_payload": {"line": "agent 4s"},
        "tmpdir": Path(folder),
        "tool_state": SimpleNamespace(
            terminal_submission=SimpleNamespace(summary="Authoritative review summary")
        ),
        "markdown_output": "Transport final output",
    }
    exec(code, context)
    data = json.loads((Path(folder) / "localci-metrics.json").read_text())
    assert "123 used" in data["tokens"] and "$0.010000" in data["cost"]
    assert data["attempts"] == 1 and data["timing"] == "agent 4s"
    assert (Path(folder) / "localci-review.md").read_text() == "Authoritative review summary"
    context["tool_state"].terminal_submission = None

    context["_localci_usages"] = [None, SimpleNamespace(cost_usd=0.01)]
    exec(code, context)
    data = json.loads((Path(folder) / "localci-metrics.json").read_text())
    assert data["tokens"].startswith("Unavailable") and data["cost"].startswith("Unavailable")
    assert data["attempts"] == 2
    assert (Path(folder) / "localci-review.md").read_text() == "Transport final output"
print("Offline review accounting: complete and missing provider usage passed")
