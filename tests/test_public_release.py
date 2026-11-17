import os
import re
import subprocess
from pathlib import Path

import yaml

from localci.controller import Controller

ROOT = Path(__file__).parents[1]


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.splitlines()


def tracked_text() -> dict[str, str]:
    result = {}
    for name in tracked_files():
        path = ROOT / name
        if path.is_file() and path.stat().st_size <= 2_000_000:
            try:
                result[name] = path.read_text()
            except UnicodeDecodeError:
                pass
    return result


def test_no_personal_paths_or_commit_identities():
    personal_path = re.compile(r"/(?:Users|home)/(?!mergecraft(?:/|\b)|runner(?:/|\b))[^/\s]+")
    failures = [
        f"{name}: developer path" for name, text in tracked_text().items() if personal_path.search(text)
    ]
    history = subprocess.run(
        ["git", "log", "HEAD", "--format=%an <%ae>%n%cn <%ce>"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    for line in history.splitlines():
        assert line.endswith("@users.noreply.github.com>"), f"Personal commit identity: {line}"
    assert not failures, "Personal paths in public release:\n" + "\n".join(failures)


def test_no_credential_shaped_values():
    expressions = [
        r"gh[pousr]_[A-Za-z0-9_]{20,}",
        r"github_pat_[A-Za-z0-9_]{20,}",
        r"sk-[A-Za-z0-9_-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"AIza[0-9A-Za-z_-]{30,}",
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
        r"xox[baprs]-[A-Za-z0-9-]{10,}",
        r"(?:sk|rk)_live_[A-Za-z0-9]{16,}",
        r"tskey-[A-Za-z0-9-]{16,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ]
    failures = [
        f"{name}: {pattern}"
        for name, text in tracked_text().items()
        for pattern in expressions
        if re.search(pattern, text)
    ]
    assert not failures, "Credential-shaped values in public release:\n" + "\n".join(failures)


def test_workflow_fixture_is_synthetic():
    text = (ROOT / "tests/fixtures/example-ci.yml").read_text()
    assert "Synthetic compatibility fixture" in text
    assert "example.com" not in text  # No pretend external endpoint is executed.
    assert "fixture-only" in text
    assert "source:" not in text.casefold()
    data = yaml.safe_load(text)
    assert set(data["jobs"]) == {"tests", "containers", "secrets"}


def test_public_deployment_defaults():
    compose = (ROOT / "compose.yaml").read_text()
    assert "${LOCALCI_URL:-http://localhost:8787}" in compose
    assert "${LOCALCI_HOST_LABEL:-local worker}" in compose
    assert "127.0.0.1:8787:8787" in compose
    build = (ROOT / "scripts/build_review.sh").read_text()
    assert "https://github.com/alexhawat/mergeCraft.git" in build
    assert "965c7346f89cc07828e4d359bc7806239c96fe33" in build


def test_host_label_is_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALCI_HOST_LABEL", "build-worker")
    monkeypatch.setenv("LOCALCI_URL", "https://ci.example.com/")
    controller = Controller(tmp_path)
    try:
        assert controller.host_label == "build-worker"
        assert controller.base_url == "https://ci.example.com"
    finally:
        controller.store.close()


def test_public_project_files_exist():
    files = set(tracked_files())
    for name in ["LICENSE", "SECURITY.md", "CONTRIBUTING.md", "TESTING.md", ".env.example"]:
        assert (ROOT / name).is_file()
        assert name in files
    assert "MIT License" in (ROOT / "LICENSE").read_text()
    assert os.access(ROOT / "scripts/build_review.sh", os.X_OK)


def test_no_private_network_names_or_addresses():
    # Generic shapes only: no list of real names, so the test itself cannot leak one.
    expressions = {
        "tailnet hostname": r"\b[a-z0-9-]+\.ts\.net\b",
        "CGNAT/tailnet address": r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
        "private IPv4 address": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
        "private registry namespace": "ghcr" + r"\.io/" + "alexhawat" + r"\b",
    }
    failures = [
        f"{name}: {label}: {match.group(0)}"
        for name, text in tracked_text().items()
        for label, pattern in expressions.items()
        for match in re.finditer(pattern, text, re.I)
    ]
    assert not failures, "Private network details in public release:\n" + "\n".join(failures)


def test_email_addresses_are_placeholders():
    # Only dotted domains look like deliverable addresses; action@sha pins and
    # single-label fixtures such as localci@localhost do not match.
    allowed = ("example.com", "example.org", "example.net", "users.noreply.github.com", "anthropic.com")
    failures = []
    for name, text in tracked_text().items():
        for match in re.finditer(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b", text):
            domain = match.group(1).casefold()
            if domain != "github.com" and not any(domain == d or domain.endswith("." + d) for d in allowed):
                failures.append(f"{name}: {match.group(0)}")
    assert not failures, "Non-placeholder email addresses in public release:\n" + "\n".join(failures)
