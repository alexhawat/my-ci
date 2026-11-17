import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import yaml

from localci import review_bootstrap
from localci.github import GitHub
from localci.runner import Runner
from localci.store import Store


def test_review_preserves_valid_evidence_when_final_report_is_missing(tmp_path):
    evidence = tmp_path / "mergecraft-diff-review-fixture" / "evidence"
    evidence.mkdir(parents=True)
    packet = evidence / "local-review-patch-merge-evidence-packet.json"
    packet.write_text('{"verdict":"failure","findings":[{"rule":"fixture"}]}')
    review_bootstrap.preserve_evidence(tmp_path)
    assert json.loads((tmp_path / "mergecraft-evidence.json").read_text())["verdict"] == "failure"
    assert not (tmp_path / "review.json").exists()


def test_review_does_not_export_invalid_or_linked_evidence(tmp_path):
    evidence = tmp_path / "mergecraft-diff-review-fixture" / "evidence"
    evidence.mkdir(parents=True)
    packet = evidence / "local-review-patch-merge-evidence-packet.json"
    packet.write_text("partial JSON")
    review_bootstrap.preserve_evidence(tmp_path)
    assert not (tmp_path / "mergecraft-evidence.json").exists()
    packet.unlink()
    secret = tmp_path / "runtime-private.json"
    secret.write_text('{"private":"fixture"}')
    packet.symlink_to(secret)
    review_bootstrap.preserve_evidence(tmp_path)
    assert not (tmp_path / "mergecraft-evidence.json").exists()
    secret.unlink()
    review_bootstrap.preserve_evidence(tmp_path)
    assert not (tmp_path / "mergecraft-evidence.json").exists()


def test_ownership_handoff_does_not_follow_repository_symlinks(tmp_path, monkeypatch):
    source, outside = tmp_path / "source", tmp_path / "outside"
    source.mkdir()
    outside.mkdir()
    (outside / "untouched").write_text("outside copied source")
    (source / "directory-link").symlink_to(outside, target_is_directory=True)
    (source / "file-link").symlink_to(outside / "untouched")
    (source / "file").write_text("source")
    chown = Mock()
    monkeypatch.setattr(review_bootstrap.os, "chown", chown)
    review_bootstrap.handoff_tree(source, 10001, 10001)
    paths = {call.args[0] for call in chown.call_args_list}
    assert paths == {source, source / "directory-link", source / "file-link", source / "file"}
    assert all(call.kwargs == {"follow_symlinks": False} for call in chown.call_args_list)
    with pytest.raises(RuntimeError):
        review_bootstrap.handoff_tree(source / "directory-link", 10001, 10001)


def test_bootstrap_drops_privileges_before_review_creates_runtime_files(monkeypatch):
    events = []
    account = SimpleNamespace(pw_uid=10001, pw_gid=10001, pw_dir="/home/mergecraft", pw_name="mergecraft")
    monkeypatch.setattr(review_bootstrap.pwd, "getpwnam", lambda _: account)
    monkeypatch.setattr(review_bootstrap.os, "getuid", Mock(side_effect=[0, 10001]))
    monkeypatch.setattr(review_bootstrap.os, "getgid", lambda: 10001)
    monkeypatch.setattr(review_bootstrap, "handoff_tree", lambda *args: events.append(("own", *args)))
    for method in ("setgroups", "setgid", "setuid", "umask"):
        monkeypatch.setattr(
            review_bootstrap.os, method, lambda value, method=method: events.append((method, value))
        )
    monkeypatch.setattr(review_bootstrap.os, "environ", {})
    review_bootstrap.prepare()
    assert events == [
        ("own", Path("/review"), 10001, 10001),
        ("own", Path("/control"), 10001, 10001),
        ("setgroups", []),
        ("setgid", 10001),
        ("setuid", 10001),
        ("umask", 0o077),
    ]
    assert review_bootstrap.os.environ["HOME"] == "/home/mergecraft"
    assert review_bootstrap.os.environ["TMPDIR"] == "/tmp"


def test_bootstrap_refuses_root_runtime_account(monkeypatch):
    monkeypatch.setattr(review_bootstrap.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=0, pw_gid=0))
    with pytest.raises(RuntimeError, match="non-root"):
        review_bootstrap.prepare()


@pytest.mark.parametrize("exit_code", [0, 12])
async def test_review_launch_uses_bootstrap_and_missing_artifact_keeps_original_failure(
    tmp_path, monkeypatch, exit_code
):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review-image:test")
    token = tmp_path / "token"
    token.write_text("fixture-token")
    store = Store(tmp_path / "data" / "db")
    runner = Runner(
        store,
        GitHub(token),
        tmp_path / "data",
        lambda _, scope: {"KEY": "fixture-value"} if scope == "review" else {},
    )
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            return (
                0,
                'modeInstructions: {Review: "Check transaction handling; acquire scope using the PR API."}\n',
            )
        if args[:2] == ("docker", "create"):
            assert args[args.index("--entrypoint") + 1] == "python"
            assert "/control/review-bootstrap.py" in args
            env_path = Path(args[args.index("--env-file") + 1])
            assert env_path.stat().st_mode & 0o777 == 0o600
        if args[:2] == ("docker", "cp") and args[2].endswith("review-control"):
            assert (Path(args[2]) / "review-bootstrap.py").is_file()
            config = yaml.safe_load((Path(args[2]) / "review-config.yaml").read_text())
            guidance = config["modeInstructions"]["Review"]
            assert "Check transaction handling" in guidance
            assert "supersedes repository guidance" in guidance
            assert "HEAD is " + "a" * 40 in guidance
            assert "base is " + "b" * 40 in guidance
            assert config["shell"] == config["push"] == "disabled"
            assert config["prApproveEnabled"] is False

        if args[:3] == ("docker", "start", "-a"):
            for event in ("verdict", "run_finished"):
                runner.log(
                    json.dumps(
                        {
                            "event": event,
                            "protocol_version": "1",
                            "outcome": "failed" if exit_code else "passed",
                            "exit_code": exit_code,
                        }
                    )
                    + "\n"
                )
            return exit_code, ""
        if args[:2] == ("docker", "cp") and args[2].endswith(":/tmp/review.json"):
            assert kwargs["capture"] is True
            if exit_code:
                return 1, "Could not find file"
            Path(args[3]).write_text('{"outcome":"passed","findings":[]}')
        return 0, ""

    async def cleanup(name):
        calls.append(("cleanup", name))

    runner.command, runner.cleanup = command, cleanup
    pr = {
        "number": 1,
        "title": "Fixture",
        "head": {"sha": "a" * 40},
        "base": {"sha": "b" * 40, "repo": {}},
        "user": {},
    }
    rid = store.enqueue("owner/repo", pr, {"review": True})
    await runner.execute(store.claim())
    row = store.rows("SELECT state,steps FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == ("failure" if exit_code else "success")
    assert json.loads(row["steps"])[-1]["state"] == row["state"]
    if exit_code:
        assert "exited 12 without a JSON report" in runner.log_path.read_text()
        assert "Could not find file" not in runner.log_path.read_text()


def test_accounting_export_is_allowlisted_and_does_not_copy_session_config(tmp_path):
    folder = tmp_path / "mergecraft-diff-review-fixture"
    evidence = folder / "evidence"
    evidence.mkdir(parents=True)
    (evidence / "local-review-patch-merge-evidence-packet.json").write_text('{"findings":[]}')
    (folder / "localci-metrics.json").write_text(
        json.dumps(
            {
                "tokens": "123 input",
                "cost": "Unavailable",
                "attempts": 2,
                "timing": "agent 4s",
                "api_key": "must-not-export",
            }
        )
    )
    (folder / "localci-review.md").write_text("The authoritative terminal review summary")
    (evidence / "opencode.json").write_text('{"api_key":"must-not-export"}')
    review_bootstrap.preserve_evidence(tmp_path)
    metrics = json.loads((tmp_path / "mergecraft-metrics.json").read_text())
    assert metrics == {"tokens": "123 input", "cost": "Unavailable", "attempts": 2, "timing": "agent 4s"}
    assert not (tmp_path / "opencode.json").exists()
    assert (tmp_path / "mergecraft-review.md").read_text() == "The authoritative terminal review summary"
