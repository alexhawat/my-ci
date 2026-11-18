"""Exercise the pinned mergeCraft analyzers without networking. Must run as the non-root review user."""

import json
import os
import subprocess
import sys
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import ANY, patch

from mergecraft.analyzers.execution import provision_platform_key
from mergecraft.analyzers.provision import ProvisionError, provision_managed_binary
from mergecraft.analyzers.registry import get_manifest, load_catalog
from warm_review_analyzers import warm_analyzers


def check_platform_selection():
    with patch("sys.platform", "linux"):
        for machine, arch in (
            ("x86_64", "amd64"),
            ("AMD64", "amd64"),
            ("aarch64", "arm64"),
            ("ARM64", "arm64"),
        ):
            with patch("platform.machine", return_value=machine):
                assert provision_platform_key() == f"linux-{arch}"
    for system, machine in (("linux", "riscv64"), ("win32", "amd64")):
        with patch("sys.platform", system), patch("platform.machine", return_value=machine):
            try:
                provision_platform_key()
            except ProvisionError as exc:
                assert f"{system}/{machine}" in str(exc)
            else:
                raise AssertionError("Unsupported platform accepted")


def check_provenance():
    for manifest in load_catalog():
        amd64 = manifest.provenance.get("linux-amd64")
        if amd64 is None:
            continue
        arm64 = manifest.provenance["linux-arm64"]
        assert arm64.url != amd64.url and arm64.sha256 != amd64.sha256, manifest.id
        assert any(arch in arm64.url.lower() for arch in ("arm64", "aarch64")), manifest.id

    manifest = get_manifest("trufflehog")
    for platform in ("linux-amd64", "linux-arm64"):
        with (
            TemporaryDirectory() as tmp,
            patch(
                "mergecraft.analyzers.provision._download_pinned_url",
                side_effect=lambda _url, dest: dest.write_bytes(b"fixture with a bad checksum"),
            ) as download,
        ):
            cache = Path(tmp)
            try:
                provision_managed_binary(manifest=manifest, platform=platform, cache_dir=cache)
            except ProvisionError as exc:
                assert "sha256 mismatch" in str(exc)
                assert manifest.provenance[platform].sha256 in str(exc)
            else:
                raise AssertionError("Bad checksum accepted")
            download.assert_called_once_with(manifest.provenance[platform].url, ANY)
            assert not any(path.is_file() for path in cache.rglob(manifest.command[0]))


def check_elf_machine(binary: Path, machine: int):
    with binary.open("rb") as file:
        header = file.read(20)
    assert header[:6] == b"\x7fELF\x02\x01", binary
    assert int.from_bytes(header[18:20], "little") == machine, binary


def check_warmed_analyzers(platform: str):
    # Root would hide a cache the review user cannot read.
    assert os.geteuid() != 0, "Run as the review user (for example --user mergecraft), not root"
    binaries = warm_analyzers(platform)
    machine = {"linux-amd64": 62, "linux-arm64": 183}[platform]
    for name in ("trufflehog", "osv-scanner"):
        binary = binaries[name]
        check_elf_machine(binary, machine)
        version = subprocess.check_output([binary, "--version"], text=True, timeout=60)
        assert get_manifest(name).version in version, version
        print(version.strip())

    semgrep = binaries["semgrep"]
    # The Python launcher runs anywhere; the native engine is what must match the target.
    cores = [path for path in semgrep.parent.parent.rglob("semgrep-core") if path.is_file()]
    assert cores, "semgrep-core not found in the warmed cache"
    for core in cores:
        check_elf_machine(core, machine)
    with TemporaryDirectory() as tmp:
        cwd = Path(tmp)
        (cwd / "fixture.py").write_text('print("fixture")\n')
        (cwd / "rule.yml").write_text(
            "rules:\n"
            "  - id: local-fixture\n"
            "    languages: [python]\n"
            "    pattern: print(...)\n"
            "    message: fixture matched\n"
            "    severity: WARNING\n"
        )
        output = subprocess.check_output(
            [
                semgrep,
                "scan",
                "--config",
                "rule.yml",
                "--metrics=off",
                "--disable-version-check",
                "--json",
                "fixture.py",
            ],
            cwd=cwd,
            env=os.environ
            | {
                "PATH": f"{semgrep.parent}{os.pathsep}{os.environ['PATH']}",
                "PYTHONPATH": str(semgrep.parent.parent),
            },
            text=True,
            timeout=60,
        )
    report = json.loads(output)
    assert report["version"] == get_manifest("semgrep").version
    assert report["errors"] == []
    assert [result["check_id"] for result in report["results"]] == ["local-fixture"]
    print(f"Semgrep {report['version']} matched the local fixture")


if __name__ == "__main__":
    check_platform_selection()
    check_provenance()
    check_warmed_analyzers(sys.argv[1])
