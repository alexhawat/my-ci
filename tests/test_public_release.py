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


# Generic shapes only: no list of real names, so the test itself cannot leak one.
PERSONAL_PATH = re.compile(r"/(?:Users|home)/(?!mergecraft(?:/|\b)|runner(?:/|\b))[^/\s]+")
PRIVATE_NETWORK = {
    "tailnet hostname": r"\b[a-z0-9-]+\.ts\.net\b",
    "CGNAT/tailnet address": r"\b100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}\b",
    "private IPv4 address": r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
    # Unique-local and link-local IPv6 (Tailscale's own range is unique-local). A
    # range whose host part is empty, such as the documented prefix of a block
    # followed by "::/8", names no host and is not flagged.
    "private IPv6 address": (
        r"(?<![0-9a-f:])(?:f[cd][0-9a-f]{2}|fe[89ab][0-9a-f]):[0-9a-f:]*:[0-9a-f]{0,4}"
        r"(?![0-9a-f])(?![0-9a-f:]*(?<=::)/\d)"
    ),
    "private registry namespace": "ghcr" + r"\.io/" + "alexhawat" + r"\b",
}
# Only dotted domains look like deliverable addresses; action@sha pins and
# single-label fixtures such as localci@localhost do not match.
EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})\b")
PLACEHOLDER_DOMAINS = ("example.com", "example.org", "example.net", "users.noreply.github.com")
# git@github.com is a clone address and the other is the commit co-author trailer's
# no-reply mailbox; other mailboxes at those domains belong to people.
PLACEHOLDER_ADDRESSES = ("git@github.com", "noreply@" + "anthropic.com")


def personal_emails(text: str) -> list[str]:
    found = []
    for match in EMAIL.finditer(text):
        domain = match.group(1).casefold()
        if match.group(0).casefold() in PLACEHOLDER_ADDRESSES:
            continue
        if not any(domain == d or domain.endswith("." + d) for d in PLACEHOLDER_DOMAINS):
            found.append(match.group(0))
    return found


def private_network_names(text: str) -> list[str]:
    return [
        f"{label}: {match.group(0)}"
        for label, pattern in PRIVATE_NETWORK.items()
        for match in re.finditer(pattern, text, re.I)
    ]


def git_log(fmt: str) -> str:
    return subprocess.run(
        ["git", "log", "HEAD", f"--format={fmt}"], cwd=ROOT, check=True, capture_output=True, text=True
    ).stdout


def test_no_personal_paths_or_commit_identities():
    failures = [
        f"{name}: developer path" for name, text in tracked_text().items() if PERSONAL_PATH.search(text)
    ]
    for line in git_log("%an <%ae>%n%cn <%ce>").splitlines():
        assert line.endswith("@users.noreply.github.com>"), f"Personal commit identity: {line}"
    assert not failures, "Personal paths in public release:\n" + "\n".join(failures)


def test_commit_messages_hold_no_personal_details():
    messages = git_log("%B")
    failures = [f"email: {address}" for address in personal_emails(messages)]
    failures += [f"developer path: {match.group(0)}" for match in PERSONAL_PATH.finditer(messages)]
    failures += private_network_names(messages)  # Tailnet names and addresses included.
    assert not failures, "Personal details in commit messages:\n" + "\n".join(failures)


def test_privacy_patterns_flag_concrete_values_only():
    tailnet = "fd7a:115c"  # Split so the source itself holds no complete address.
    for address in (tailnet + ":a1e0::1", tailnet + ":a1e0:ab12:4843:cd96:6258:b240", "fe80:" + ":1/64"):
        assert private_network_names(f"route {address} here"), address
    for documented in ("fd00::/8", "fc00::/7", "fe80::/10", tailnet + ":a1e0::/48"):
        assert not private_network_names(f"range {documented} here"), documented
    person = "someone@"
    assert personal_emails(f"{person}anthropic.com {person}sub.anthropic.com {person}github.com") == [
        f"{person}anthropic.com",
        f"{person}sub.anthropic.com",
        f"{person}github.com",
    ]
    trailer = "Co-Authored-By: Claude <" + "noreply@" + "anthropic.com>"
    assert not personal_emails(
        f"{trailer} git@github.com a@example.com b@x.example.org 1+c@users.noreply.github.com"
    )


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
    failures = [
        f"{name}: {found}" for name, text in tracked_text().items() for found in private_network_names(text)
    ]
    assert not failures, "Private network details in public release:\n" + "\n".join(failures)


def test_email_addresses_are_placeholders():
    failures = [
        f"{name}: {address}" for name, text in tracked_text().items() for address in personal_emails(text)
    ]
    assert not failures, "Non-placeholder email addresses in public release:\n" + "\n".join(failures)
