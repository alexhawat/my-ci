import base64
import copy
import json
import os
import subprocess
import sys
import tarfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi.testclient import TestClient

from localci.app import Controller, RepoConfig, create_app
from localci.github import GitHub, app_jwt
from localci.policy import Blocked, eligible, is_pr_workflow, plan, review_state, workflow
from localci.runner import Runner, redact
from localci.store import Store


def pr(head="a" * 40, base="b" * 40):
    return {
        "number": 4,
        "title": "Test PR",
        "state": "open",
        "draft": False,
        "head": {"sha": head, "repo": {"full_name": "owner/repo"}},
        "base": {"sha": base, "repo": {"full_name": "owner/repo"}},
        "user": {"login": "owner"},
    }


def repo():
    return {
        "full_name": "owner/repo",
        "private": True,
        "html_url": "https://github.com/owner/repo",
        "default_branch": "main",
    }


def test_discovery_preserves_opt_in_and_configuration(tmp_path):
    store = Store(tmp_path / "db")
    store.discover([repo()])
    assert store.repo("owner/repo")["enabled"] == 0
    store.execute("UPDATE repos SET enabled=1,config=?", ('{"review":true}',))
    store.discover([repo()])
    assert store.repo("owner/repo")["enabled"] == 1
    assert json.loads(store.repo("owner/repo")["config"])["review"]


def test_enqueue_idempotency_atomic_claim_and_retry(tmp_path):
    store = Store(tmp_path / "db")
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: store.enqueue("owner/repo", pr(), {}), range(8)))
    assert sum(r is not None for r in results) == 1
    with ThreadPoolExecutor(max_workers=8) as pool:
        claimed = list(pool.map(lambda _: store.claim(), range(8)))
    assert sum(r is not None for r in claimed) == 1
    rid = next(r for r in results if r)
    assert store.enqueue("owner/repo", pr(), {}, retry=True) is None
    store.finish(rid, "failure", "Test failure")
    assert store.enqueue("owner/repo", pr(), {}, retry=True) != rid


@pytest.mark.parametrize("change", ["head", "base", "draft", "closed"])
def test_stale_runs_cancel_on_any_test_context_change(tmp_path, change):
    store = Store(tmp_path / "db")
    rid = store.enqueue("owner/repo", pr(), {})
    updated = pr()
    if change in {"head", "base"}:
        updated[change]["sha"] = "c" * 40
    if change == "draft":
        updated["draft"] = True
    store.cancel_stale("owner/repo", [] if change == "closed" else [updated])
    row = store.rows("SELECT * FROM runs WHERE id=?", (rid,))[0]
    assert row["cancel"] == 1 and row["state"] == "cancelled"
    assert store.claim() is None


def test_backup_restore(tmp_path):
    store = Store(tmp_path / "db")
    store.discover([repo()])
    store.enqueue("owner/repo", pr(), {})
    store.backup(tmp_path / "backup")
    restored = Store(tmp_path / "backup")
    assert restored.repo("owner/repo")["name"] == "owner/repo"
    assert restored.claim()["head"] == "a" * 40


def test_backup_archive_restores_encrypted_credentials(tmp_path):
    controller = Controller(tmp_path / "data")
    encrypted = controller.cipher.encrypt(b"test-only-provider").decode()
    controller.store.execute("INSERT INTO secrets VALUES(?,?,?)", ("owner/repo", "review:API_KEY", encrypted))
    script = Path(__file__).resolve().parents[1] / "backup.py"
    archive_path = Path(
        subprocess.check_output(
            [sys.executable, str(script)], env={**os.environ, "LOCALCI_DATA": str(controller.root)}, text=True
        ).strip()
    )
    assert archive_path.stat().st_mode & 0o777 == 0o600
    restored = tmp_path / "restored"
    restored.mkdir()
    with tarfile.open(archive_path) as archive:
        assert set(archive.getnames()) == {"localci.db", "encryption.key"}
        archive.extractall(restored, filter="data")
    rows = Store(restored / "localci.db").rows("SELECT ciphertext FROM secrets")
    assert (
        Fernet((restored / "encryption.key").read_bytes()).decrypt(rows[0]["ciphertext"].encode())
        == b"test-only-provider"
    )


def test_synthetic_ci_plan_keeps_full_checks():
    path = Path(__file__).with_name("fixtures") / "example-ci.yml"
    data, notes = plan(path.read_text(), set(), {})
    assert set(data["jobs"]) == {"tests", "containers", "secrets"}
    assert data["jobs"]["tests"]["services"]["postgres"]["image"] == "postgres:17-bookworm"
    assert data["jobs"]["containers"]["strategy"]["fail-fast"] is False
    assert any("--cov-fail-under=60" in s.get("run", "") for s in data["jobs"]["tests"]["steps"])
    assert "--redact" in data["jobs"]["secrets"]["steps"][-1]["run"]
    assert notes


@pytest.mark.parametrize(
    "job,reason",
    [
        ("runs-on: windows-latest\n    steps: []", "unsupported runner"),
        ("uses: org/repo/.github/workflows/reuse.yml@main", "reusable"),
        ("runs-on: ubuntu-latest\n    environment: production\n    steps: []", "deployment"),
        ("runs-on: ubuntu-latest\n    permissions: {id-token: write}\n    steps: []", "OIDC"),
        ("runs-on: ubuntu-latest\n    steps: [{run: 'echo ${{ secrets.MISSING }}'}]", "secrets required"),
        ("runs-on: ubuntu-latest\n    steps: [{uses: 'github/codeql-action/init@v3'}]", "CodeQL"),
    ],
)
def test_unsupported_work_does_not_pass(job, reason):
    with pytest.raises(Blocked, match=reason):
        plan("on: pull_request\njobs:\n  test:\n    " + job, set(), {})


def test_disabled_codeql_matches_original_condition():
    text = "on: pull_request\njobs:\n  analyze:\n    if: vars.RUN_OPTIONAL_SCAN == 'true'\n    runs-on: ubuntu-latest\n    steps: [{uses: 'github/codeql-action/init@v3'}]"
    _, notes = plan(text, set(), {})
    assert "disabled" in notes[0]
    with pytest.raises(Blocked, match="CodeQL"):
        plan(text, set(), {"RUN_OPTIONAL_SCAN": "true"})


def test_workflow_yaml_does_not_coerce_on_or_false():
    data = workflow("on: [pull_request, push]\njobs: {test: {strategy: {fail-fast: false}}}")
    assert is_pr_workflow(data)
    assert data["jobs"]["test"]["strategy"]["fail-fast"] is False
    assert not is_pr_workflow({"on": "pull_request_target"})


def test_fork_draft_and_closed_prs_never_execute():
    assert eligible(pr(), "owner/repo")
    for change in ("fork", "draft", "closed"):
        value = pr()
        if change == "fork":
            value["head"]["repo"]["full_name"] = "someone/fork"
        elif change == "draft":
            value["draft"] = True
        else:
            value["state"] = "closed"
        assert not eligible(value, "owner/repo")


def test_nonzero_review_is_never_clean():
    value = pr()
    value["head"]["repo"] = None
    assert not eligible(value, "owner/repo")
    assert review_state(0)[0] == "success"
    assert review_state(10)[0] == "success"
    for code in (11, 12, 20, 30, 40, 50, 99):
        assert review_state(code)[0] != "success"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_TAILSCALE_LOGIN", "owner@example.com")
    monkeypatch.setenv("LOCALCI_URL", "https://machine.example:9443")
    app = create_app(tmp_path, background=False)
    app.state.controller.store.discover([repo()])
    with TestClient(
        app, headers={"Tailscale-User-Login": "owner@example.com", "Origin": "https://machine.example:9443"}
    ) as client:
        yield client


def test_dashboard_auth_and_csrf(client):
    assert client.get("/").status_code == 200
    assert client.get("/api/state", headers={"Tailscale-User-Login": "attacker"}).status_code == 403
    assert client.post("/api/sync", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.get("/healthz", headers={"Tailscale-User-Login": ""}).status_code == 200
    assert "frame-ancestors 'none'" in client.get("/").headers["content-security-policy"]


def test_secrets_encrypted_write_only_and_scope_separated(client):
    value = "test-provider-secret-never-return"
    assert (
        client.put(
            "/api/repos/owner/repo/secrets", json={"scope": "review", "name": "API_KEY", "value": value}
        ).status_code
        == 200
    )
    state = client.get("/api/state")
    assert value not in state.text
    assert state.json()["repos"][0]["secrets"] == ["review:API_KEY"]
    controller = client.app.state.controller
    assert value not in controller.store.rows("SELECT * FROM secrets")[0]["ciphertext"]
    assert controller.secrets("owner/repo", "ci") == {}
    assert controller.secrets("owner/repo", "review")["API_KEY"] == value
    assert (
        client.put("/api/repos/owner/repo/secrets", json={"name": "GH_TOKEN", "value": value}).status_code
        == 400
    )


def test_enable_requires_checks_and_disable_cancels(client):
    assert client.put("/api/repos/owner/repo", json={"enabled": True}).status_code == 400
    assert client.put("/api/repos/owner/repo", json={"enabled": True, "review": True}).status_code == 200
    store = client.app.state.controller.store
    rid = store.enqueue("owner/repo", pr(), {})
    assert client.put("/api/repos/owner/repo", json={"enabled": False}).status_code == 200
    assert store.rows("SELECT state FROM runs WHERE id=?", (rid,))[0]["state"] == "cancelled"
    assert store.claim() is None


def test_input_paths_and_variables_are_bounded():
    with pytest.raises(ValueError):
        RepoConfig(workflows=["../../etc/passwd.yml"])
    with pytest.raises(ValueError):
        RepoConfig(variables={"VAR": "a\nINJECTED=value"})


def test_artifact_download_cannot_escape_run_directory(client, tmp_path):
    controller = client.app.state.controller
    rid = controller.store.enqueue("owner/repo", pr(), {})
    artifacts = controller.root / "artifacts" / rid
    artifacts.mkdir(parents=True)
    (artifacts / "proof.txt").write_text("test output")
    (artifacts / "escape").symlink_to(controller.root / "encryption.key")
    listing = client.get(f"/api/runs/{rid}/artifacts").json()
    assert listing == [{"path": "proof.txt", "bytes": 11}]
    assert client.get(f"/api/runs/{rid}/artifact", params={"path": "proof.txt"}).text == "test output"
    assert client.get(f"/api/runs/{rid}/artifact", params={"path": "../../encryption.key"}).status_code == 404
    assert client.get(f"/api/runs/{rid}/artifact", params={"path": "escape"}).status_code == 404


def test_log_redaction():
    secret = "provider-test-secret"
    text = secret + " " + base64.b64encode(secret.encode()).decode() + " ghp_examplevalue123"
    assert redact(text, [secret]) == "[redacted] [redacted] [redacted]"


async def test_review_credentials_are_only_given_to_fresh_outer_container(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_REVIEW_IMAGE", "review-image:test")
    token = tmp_path / "token"
    token.write_text("control-plane-token")
    store = Store(tmp_path / "data" / "db")
    runner = Runner(
        store,
        GitHub(token),
        tmp_path / "data",
        lambda _, scope: {"CI_SECRET": "ci-value"} if scope == "ci" else {"PROVIDER_KEY": "review-value"},
    )
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        if args[:2] == ("git", "clone"):
            Path(args[-1]).mkdir(parents=True)
        if args[:2] == ("git", "show"):
            return 0, "{}"
        if args[:2] == ("git", "diff"):
            return 0, "diff --git a/a b/a\n"
        if args[:2] == ("docker", "create"):
            content = Path(args[args.index("--env-file") + 1]).read_text()
            assert "review-value" in content
            assert "ci-value" not in content and "control-plane-token" not in content
            assert "--privileged" not in args and "-v" not in args
            assert Path(args[args.index("--env-file") + 1]).parent.name != "control"
        if args[:3] == ("docker", "start", "-a"):
            runner.log(
                '{"event":"verdict","protocol_version":"1","outcome":"passed","exit_code":0}\n{"event":"run_finished","protocol_version":"1","exit_code":0}\n'
            )
        if args[:2] == ("docker", "cp") and args[2].endswith(":/tmp/review.json"):
            Path(args[3]).write_text('{"findings":[]}')
        return 0, ""

    async def cleanup(name):
        calls.append(("CLEANUP", name))

    runner.command, runner.cleanup = command, cleanup
    rid = store.enqueue("owner/repo", pr(), {"review": True})
    await runner.execute(store.claim())
    row = store.rows("SELECT state,message FROM runs WHERE id=?", (rid,))[0]
    assert row["state"] == "success", row
    assert any(c[:2] == ("docker", "create") for c in calls)
    assert not any(c[:2] == ("docker", "exec") and "review" in c for c in calls)


async def test_status_retries_without_overwriting_newer_attempt(tmp_path):
    controller = Controller(tmp_path)
    store = controller.store
    first = store.enqueue("owner/repo", pr(), {})
    store.finish(first, "failure", "failed")
    second = store.enqueue("owner/repo", pr(), {}, retry=True)
    controller.github.status = AsyncMock(side_effect=RuntimeError("GitHub unavailable"))
    await controller.publish()
    assert controller.github.status.call_count == 1
    assert controller.github.status.call_args.args[0]["id"] == second
    assert store.rows("SELECT published FROM runs WHERE id=?", (second,))[0]["published"] == 0
    controller.github.status = AsyncMock(return_value="GitHub commit status via gh login")
    controller.publish_retries.clear()
    await controller.publish()
    assert store.rows("SELECT published FROM runs WHERE id=?", (second,))[0]["published"] == 1


@pytest.mark.parametrize("status,attempts", [(404, 3), (422, 3), (500, 12)])
async def test_publish_that_cannot_succeed_is_abandoned_so_retention_can_prune_it(tmp_path, status, attempts):
    from localci.github import GitHubError

    controller = Controller(tmp_path)
    store = controller.store
    rid = store.enqueue("owner/repo", pr(), {})
    store.finish(rid, "failure", "failed")
    controller.github.request = AsyncMock(return_value=pr())
    controller.github.status = AsyncMock(
        side_effect=GitHubError(status, "POST", "repos/owner/repo/statuses/x")
    )
    for attempt in range(1, attempts + 1):
        assert store.rows("SELECT published FROM runs WHERE id=?", (rid,))[0]["published"] == 0
        controller.publish_retries = {k: (n, 0.0) for k, (n, _) in controller.publish_retries.items()}
        await controller.publish()
        assert controller.github.status.call_count == attempt
    row = store.rows("SELECT published,publish_error FROM runs WHERE id=?", (rid,))[0]
    assert row["published"] == 1 and f"not published after {attempts} attempts" in row["publish_error"]
    await controller.publish()
    assert controller.github.status.call_count == attempts  # No further requests.


async def test_publish_backoff_honours_the_wait_github_asks_for(tmp_path):
    import time

    from localci.github import GitHubError, retry_after

    assert retry_after({"retry-after": "120"}) == 120
    assert retry_after({"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(time.time() + 600)}) > 590
    assert retry_after({"retry-after": "999999"}) == 3600 and retry_after({"retry-after": "soon"}) is None
    assert retry_after({"x-ratelimit-remaining": "12", "x-ratelimit-reset": "1"}) is None
    controller = Controller(tmp_path)
    rid = controller.store.enqueue("owner/repo", pr(), {})
    controller.store.finish(rid, "failure", "failed")
    controller.github.request = AsyncMock(return_value=pr())
    controller.github.status = AsyncMock(side_effect=GitHubError(403, "POST", "statuses", retry_after=900.0))
    await controller.publish()
    assert controller.publish_retries[rid][1] - time.time() > 890  # Not the 5 s first backoff.
    await controller.publish()
    assert controller.github.status.call_count == 1


async def test_changed_base_is_not_published_as_passing(tmp_path):
    controller = Controller(tmp_path)
    rid = controller.store.enqueue("owner/repo", pr(), {})
    controller.store.finish(rid, "success", "passed")
    controller.github.request = AsyncMock(return_value=pr(base="c" * 40))
    controller.github.status = AsyncMock(return_value="GitHub commit status via gh login")
    await controller.publish()
    controller.github.status.assert_not_called()


async def test_pending_publication_does_not_lose_a_concurrent_completion(tmp_path):
    controller = Controller(tmp_path)
    rid = controller.store.enqueue("owner/repo", pr(), {})

    async def complete_during_pending(*_):
        controller.store.finish(rid, "success", "Passed")

    controller.github.status = AsyncMock(side_effect=complete_during_pending)
    await controller.publish()
    assert controller.store.rows("SELECT published FROM runs WHERE id=?", (rid,))[0]["published"] == 0
    controller.github.request = AsyncMock(return_value=pr())
    controller.github.status = AsyncMock(return_value="GitHub commit status via gh login")
    await controller.publish()
    assert controller.github.status.call_args.args[1] == "success"
    assert controller.store.rows("SELECT published FROM runs WHERE id=?", (rid,))[0]["published"] == 1


def test_app_jwt_is_signed_and_short_lived():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()
    token = app_jwt("123", pem)
    header, payload, signature = token.split(".")
    key.public_key().verify(
        base64.urlsafe_b64decode(signature + "=="),
        f"{header}.{payload}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    assert claims["iss"] == "123" and claims["exp"] - claims["iat"] == 600


async def test_app_check_run_reconciles_by_external_id_and_revokes_token(tmp_path, monkeypatch):
    github = GitHub(tmp_path / "token")
    monkeypatch.setattr("localci.github.app_jwt", lambda *_: "jwt")
    calls = []

    async def request(method, path, **kwargs):
        calls.append((method, path, copy.deepcopy(kwargs)))
        if path.endswith("/installation"):
            return {"id": 9}
        if path.endswith("/access_tokens"):
            return {"token": "installation-token"}
        if "/commits/" in path:
            return {"check_runs": [{"id": 88, "external_id": "run1", "app": {"id": 123}}]}
        return {}

    github.request = request
    run = {"id": "run1", "repo": "owner/repo", "head": "a" * 40, "state": "success", "steps": "[]"}
    await github.check_run(
        run, "success", "Passed", "https://local.example", {"app_id": "123", "private_key": "key"}
    )
    assert any(m == "PATCH" and p.endswith("check-runs/88") for m, p, _ in calls)
    token_request = next(k for _, p, k in calls if p.endswith("access_tokens"))
    assert token_request["json"] == {"repositories": ["repo"], "permissions": {"checks": "write"}}
    assert calls[-1][:2] == ("DELETE", "installation/token")


def test_retry_limit_survives_restart_and_new_revisions_get_fresh_budget(tmp_path):
    from localci.store import RetryLimitReached

    path = tmp_path / "localci.db"
    store = Store(path)
    for _ in range(3):
        rid = store.enqueue("owner/repo", pr(), {}, retry=True)
        assert rid
        store.finish(rid, "failure", "fixture")
        assert store.enqueue("owner/repo", pr(), {}) is None  # Polling never retries failures.
    store.close()
    store = Store(path)
    with pytest.raises(RetryLimitReached, match="3 attempts"):
        store.enqueue("owner/repo", pr(), {}, retry=True)
    changed = pr()
    changed["head"]["sha"] = "c" * 40
    assert store.enqueue("owner/repo", changed, {})
    changed = pr()
    changed["base"]["sha"] = "d" * 40
    assert store.enqueue("owner/repo", changed, {})
    store.save_settings({"max_retries": 3})
    assert store.enqueue("owner/repo", pr(), {}, retry=True)
    store.close()


def test_retention_never_requeues_completed_revisions_or_resets_retry_budget(tmp_path):
    import time

    from localci.store import RetryLimitReached

    c = Controller(tmp_path)
    for _ in range(3):
        rid = c.store.enqueue("owner/repo", pr(), {}, retry=True)
        c.store.finish(rid, "failure", "fixture")
        c.store.execute("UPDATE runs SET published=1,finished=? WHERE id=?", (time.time() - 15 * 86400, rid))
    c.prune()
    assert not c.store.rows("SELECT id FROM runs")
    assert c.store.enqueue("owner/repo", pr(), {}) is None
    with pytest.raises(RetryLimitReached):
        c.store.enqueue("owner/repo", pr(), {}, retry=True)
    c.store.save_settings({"max_retries": 3})
    rid = c.store.enqueue("owner/repo", pr(), {}, retry=True)
    assert c.store.rows("SELECT attempt FROM runs WHERE id=?", (rid,))[0]["attempt"] == 4
    c.store.close()


def test_v2_upgrade_backfills_budget_and_keeps_v2_restore_backup(tmp_path):
    # The old layout is reproduced from the current schema; no database file written by a
    # released v1 or v2 build is available to this repository.
    import sqlite3

    from localci.store import RetryLimitReached

    path = tmp_path / "localci.db"
    store = Store(path)
    for _ in range(3):
        rid = store.enqueue("owner/repo", pr(), {}, retry=True)
        store.finish(rid, "failure", "fixture")
    store.close()
    with sqlite3.connect(path) as db:
        db.execute("DROP TABLE revision_attempts")
        db.execute("PRAGMA user_version=2")
    upgraded = Store(path)
    assert upgraded.rows("PRAGMA user_version")[0]["user_version"] == 4
    with pytest.raises(RetryLimitReached):
        upgraded.enqueue("owner/repo", pr(), {}, retry=True)
    upgraded.close()
    saved = path.with_suffix(".pre-v3.sqlite")
    assert saved.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(saved) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        assert db.execute("SELECT COUNT(*) FROM runs").fetchone()[0] == 3
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    restored = tmp_path / "restored.db"
    import shutil

    shutil.copyfile(saved, restored)
    restored_store = Store(restored)
    assert restored_store.rows("SELECT attempts FROM revision_attempts")[0]["attempts"] == 3
    restored_store.close()
