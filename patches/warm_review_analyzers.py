"""Bake pinned managed analyzers into each container's private image cache.

No shared writable host volume: a review can never poison another run's tools.
Normal upstream pin/receipt validation remains active on every cache hit.
"""

import os
from pathlib import Path

from mergecraft.analyzers.execution import provision_platform_key
from mergecraft.analyzers.pattern import provision_pip_script
from mergecraft.analyzers.provision import provision_managed_binary
from mergecraft.analyzers.registry import get_manifest

cache = Path(os.environ["XDG_CACHE_HOME"]) / "mergecraft/analyzer-cache"
for name in ("trufflehog", "osv-scanner"):
    provision_managed_binary(manifest=get_manifest(name), platform=provision_platform_key(), cache_dir=cache)
manifest = get_manifest("semgrep")
provision_pip_script(package="semgrep", version=manifest.version, script="semgrep", cache_dir=cache)
print("Pinned review analyzers ready")
