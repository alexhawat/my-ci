#!/usr/bin/env bash
set -euo pipefail

# Build the review image from public mergeCraft and local compatibility patches.
# linux/amd64 starts from the published reviewer image, pinned by digest in
# Dockerfile.review. No linux/arm64 image is published, so that target first builds
# the same mergeCraft revision from public source and uses it as the base.
# No private registry authentication or provider credential is used.
revision=6dc67ab3ce873a4b313553d5e1ac9e469295eb03
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$root/runtime/mergecraft-source"
# Normalize a Docker platform spelling to linux/amd64 or linux/arm64, or fail.
normalize_platform() {
  local value
  value=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  case "$value" in
    amd64 | x86_64 | linux/amd64 | linux/x86_64 | linux/amd64/v[1-4]) printf 'linux/amd64\n' ;;
    arm64 | aarch64 | linux/arm64 | linux/aarch64 | linux/arm64/v8) printf 'linux/arm64\n' ;;
    *)
      printf 'Unsupported review image platform: %s (use one of linux/amd64 or linux/arm64)\n' "$1" >&2
      return 1
      ;;
  esac
}

requested=${REVIEW_PLATFORM:-${DOCKER_DEFAULT_PLATFORM:-}}
native=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
platform=$(normalize_platform "${requested:-$native}")
# compose.yaml runs localci-review:1 without --platform, so only a build for the
# Docker server's own architecture may take that tag by default.
if [ -n "${REVIEW_IMAGE:-}" ]; then
  review_image=$REVIEW_IMAGE
elif [ "$platform" = "$(normalize_platform "$native" 2>/dev/null)" ]; then
  review_image=localci-review:1
else
  review_image="localci-review:1-${platform#linux/}"
fi

if [ "$platform" = linux/amd64 ]; then
  base_image=$(sed -n 's/^ARG BASE_IMAGE=//p' "$root/Dockerfile.review")
  [[ $base_image =~ ^ghcr\.io/alexhawat/mergecraft@sha256:[0-9a-f]{64}$ ]]
  docker run --rm ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 \
    verify --certificate-identity 'https://github.com/alexhawat/mergeCraft/.github/workflows/ci-cd.yml@refs/heads/main' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    --certificate-github-workflow-sha "$revision" "$base_image" >/dev/null
  docker build \
    --platform "$platform" \
    --build-arg "BASE_IMAGE=$base_image" \
    --file "$root/Dockerfile.review" \
    --tag "$review_image" \
    "$root"
  printf 'Built %s for %s from the pinned public mergeCraft image\n' "$review_image" "$platform"
  exit 0
fi

# Dockerfile.review asserts that its base reports this same revision.
grep -Fq "$revision" "$root/Dockerfile.review"
base_image="localci-mergecraft-base:${revision:0:12}-${platform#linux/}"
mkdir -p "$root/runtime"
if [ ! -d "$source_dir/.git" ]; then
  rm -rf "$source_dir"
  git init "$source_dir"
  git -C "$source_dir" remote add origin https://github.com/alexhawat/mergeCraft.git
fi
git -C "$source_dir" fetch --depth=1 origin "$revision"
git -C "$source_dir" checkout --detach FETCH_HEAD
test "$(git -C "$source_dir" rev-parse HEAD)" = "$revision"

docker build \
  --platform "$platform" \
  --build-arg "SOURCE_REVISION=$revision" \
  --file "$source_dir/docker/Dockerfile" \
  --tag "$base_image" \
  "$source_dir"
docker build \
  --platform "$platform" \
  --build-arg "BASE_IMAGE=$base_image" \
  --file "$root/Dockerfile.review" \
  --tag "$review_image" \
  "$root"

printf 'Built %s for %s from public mergeCraft source %s\n' "$review_image" "$platform" "$revision"
