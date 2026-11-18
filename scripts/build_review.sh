#!/usr/bin/env bash
set -euo pipefail

# Build from the digest-pinned public reviewer image and local compatibility patches.
# No private registry authentication or provider credential is used.
root=$(cd -- "$(dirname -- "$0")/.." && pwd)

docker build \
  --platform linux/amd64 \
  --file "$root/Dockerfile.review" \
  --tag localci-review:1 \
  "$root"

printf 'Built localci-review:1 from the pinned public mergeCraft image\n'
