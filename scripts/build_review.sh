#!/usr/bin/env bash
set -euo pipefail

# Build the exact public runtime source, then apply My CI's compatibility patches.
# No private registry authentication or provider credential is used.
revision=965c7346f89cc07828e4d359bc7806239c96fe33
root=$(cd -- "$(dirname -- "$0")/.." && pwd)
source_dir="$root/runtime/mergecraft-source"

mkdir -p "$root/runtime"
if [ ! -d "$source_dir/.git" ]; then
  rm -rf "$source_dir"
  git init "$source_dir"
  git -C "$source_dir" remote add origin https://github.com/alexhawat/mergeCraft.git
fi
git -C "$source_dir" fetch --depth=1 origin "$revision"
git -C "$source_dir" checkout --detach FETCH_HEAD
test "$(git -C "$source_dir" rev-parse HEAD)" = "$revision"

rm -rf "$source_dir/.localci"
mkdir -p "$source_dir/.localci"
cp "$root/Dockerfile.review" "$source_dir/.localci/Dockerfile.review"
cp -R "$root/patches" "$source_dir/.localci/patches"

docker build \
  --build-arg "SOURCE_REVISION=$revision" \
  --file "$source_dir/docker/Dockerfile" \
  --tag "localci-mergecraft-base:${revision:0:12}" \
  "$source_dir"
docker build \
  --build-arg "BASE_IMAGE=localci-mergecraft-base:${revision:0:12}" \
  --file "$source_dir/.localci/Dockerfile.review" \
  --tag localci-review:1 \
  "$source_dir/.localci"

printf 'Built localci-review:1 from public mergeCraft source %s\n' "$revision"
