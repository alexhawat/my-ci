"""Every element the dashboard script looks up at load must exist in the page."""

import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "localci" / "static"
# Rendered by the script itself before it is looked up.
CREATED_BY_SCRIPT = {"select-visible-runs"}


def test_every_element_app_js_looks_up_is_in_index_html():
    script = (STATIC / "app.js").read_text()
    page = (STATIC / "index.html").read_text()
    wanted = set(re.findall(r"\$\('([A-Za-z0-9_-]+)'\)", script))
    present = set(re.findall(r'\bid="([^"]+)"', page))
    # A missing element makes $(...).addEventListener throw at load, and the
    # dashboard then shows no repositories or pull requests at all.
    assert sorted(wanted - present - CREATED_BY_SCRIPT) == []


def test_agent_access_controls_are_present():
    page = (STATIC / "index.html").read_text()
    for element in ("integration-agent-access", "agent-access-panel", "agent-token-form"):
        assert f'id="{element}"' in page
    assert sorted(re.findall(r'name="agent-scope" value="([^"]+)"', page)) == [
        "read",
        "write-config",
        "write-runs",
    ]
