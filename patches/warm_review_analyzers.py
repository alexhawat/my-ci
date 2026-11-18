"""Bake pinned managed analyzers into each container's private image cache.

No shared writable host volume: a review can never poison another run's tools.

What is checked, and what is not:
- TruffleHog and OSV-Scanner are downloaded once and compared with the SHA-256
  pinned for the target platform. Their cache path includes the platform. A
  later cache hit is compared with a receipt that provisioning wrote itself,
  which detects accidental change but not tampering by the cache's owner.
- Semgrep is pinned by package version only (no hash and no receipt), and its
  cache path has no architecture in it. That is safe only because each image
  bakes its own cache; never share this cache between architectures.
"""

import os
import sys
from pathlib import Path

from mergecraft.analyzers.execution import provision_platform_key
from mergecraft.analyzers.pattern import provision_pip_script
from mergecraft.analyzers.provision import provision_managed_binary
from mergecraft.analyzers.registry import get_manifest


def warm_analyzers(expected_platform: str) -> dict[str, Path]:
    platform = provision_platform_key()
    if platform != expected_platform:
        raise RuntimeError(f"Review image target {expected_platform} does not match runtime {platform}")

    cache = Path(os.environ["XDG_CACHE_HOME"]) / "mergecraft/analyzer-cache"
    binaries = {}
    for name in ("trufflehog", "osv-scanner"):
        result = provision_managed_binary(manifest=get_manifest(name), platform=platform, cache_dir=cache)
        binaries[name] = result.resolved_path
    binaries["semgrep"] = provision_pip_script(
        package="semgrep", version=get_manifest("semgrep").version, script="semgrep", cache_dir=cache
    )
    print(f"Pinned review analyzers ready for {platform}")
    return binaries


if __name__ == "__main__":
    warm_analyzers(sys.argv[1])
