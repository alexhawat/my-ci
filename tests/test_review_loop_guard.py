import subprocess

import pytest

from patches.localci_citation import describe
from patches.localci_loop_guard import NOTICE_AT, STOP_AT, LoopGuard


def test_one_repeated_call_is_named_then_stops_the_review():
    guard = LoopGuard()
    notes = [guard.record("read_batch", {"requests": [{"path": "a.py"}]}) for _ in range(STOP_AT)]
    assert not any(notes[: NOTICE_AT - 1]) and all(notes[NOTICE_AT - 1 :])
    assert (
        guard.reason == f"Repeated tool calls without progress (read_batch, {STOP_AT} times); review stopped"
    )
    assert "a.py" not in guard.reason + "".join(notes)


def test_alternating_calls_are_still_a_loop():
    guard = LoopGuard()
    for index in range(2 * STOP_AT):
        guard.record("read_batch", {"path": str(index % 2)})
    assert guard.reason


def test_argument_order_does_not_hide_a_repeat():
    guard = LoopGuard()
    for index in range(STOP_AT):
        guard.record("git", {"a": 1, "b": 2} if index % 2 else {"b": 2, "a": 1})
    assert guard.reason


def test_new_calls_and_a_few_repeats_never_stop_a_review():
    guard = LoopGuard()
    for index in range(200):
        assert guard.record("read_batch", {"path": str(index)}) == ""
    # The most any completed stored review repeated one call.
    for _ in range(STOP_AT - 1):
        guard.record("git", {"command": "status"})
    assert guard.reason == ""


def test_verification_without_a_verdict_is_a_loop_even_with_new_arguments():
    guard = LoopGuard()
    notes = [guard.record("verify_agent_findings", {"body": str(i)}) for i in range(STOP_AT)]
    assert "no verdict recorded" in notes[NOTICE_AT - 1] and guard.reason


def test_a_recorded_verdict_is_progress():
    guard = LoopGuard()
    for index in range(4 * STOP_AT):
        assert guard.record("verify_agent_findings", {"body": str(index)}) == ""
        guard.record("record_finding_verdict", {"fingerprint": str(index)})
    assert guard.reason == ""


def test_compaction_makes_reading_again_legitimate():
    guard = LoopGuard()
    for compactions in range(5):
        for _ in range(STOP_AT - 1):
            guard.record("read_batch", {"path": "a.py"}, compactions)
    assert guard.reason == ""


@pytest.fixture
def repo(tmp_path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    git("init", "-b", "main")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture@example.com")
    git("config", "core.autocrlf", "false")
    (tmp_path / ".agents").mkdir()
    (tmp_path / ".agents/tool.py").write_text("fixture\n")
    (tmp_path / ".agents/link.py").symlink_to("tool.py")
    (tmp_path / "doc [1]*.md").write_text("fixture\n")
    git("add", ".")
    git("commit", "-qm", "fixture")
    (tmp_path / "untracked.py").write_text("fixture\n")
    return tmp_path


def test_a_file_of_the_reviewed_commit_is_described_not_dropped(repo):
    changed = describe(repo, ".agents/tool.py", frozenset({".agents/tool.py"}))
    assert "removed it from the working tree" in changed and "not a reason to drop" in changed
    unchanged = describe(repo, ".agents/tool.py", frozenset())
    assert "this diff does not change it" in unchanged
    assert describe(repo, "doc [1]*.md", None)


@pytest.mark.parametrize(
    "path",
    [
        "missing.py",
        "untracked.py",
        ".agents",
        ".agents/link.py",
        ".agents/",
        "./.agents/tool.py",
        "../x",
        "/etc/passwd",
        ".agents//tool.py",
        ".agents/*",
        ":(glob)**",
        "HEAD:.agents/tool.py",
        "a`b",
        "a\nb",
        "a\\b",
        "",
        "x" * 1001,
    ],
)
def test_anything_else_keeps_the_upstream_text(repo, path):
    assert describe(repo, path, None) is None


def test_git_environment_cannot_redirect_the_lookup(repo, tmp_path_factory, monkeypatch):
    other = tmp_path_factory.mktemp("other")
    subprocess.run(["git", "init", "-q"], cwd=other, check=True)
    monkeypatch.setenv("GIT_DIR", str(other / ".git"))
    assert describe(repo, ".agents/tool.py", None)


def test_a_directory_that_is_no_repository_keeps_the_upstream_text(tmp_path):
    assert describe(tmp_path, "a.py", None) is None
