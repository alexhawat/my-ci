#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
umask 077
mkdir -p runtime
if [ -d runtime/github-token ]; then
  printf 'runtime/github-token is a directory; remove the accidental Docker bind-mount directory first.\n' >&2
  exit 1
fi
trap 'rm -f runtime/github-token.new' EXIT
if ! gh auth status >/dev/null 2>&1; then
  gh auth login --hostname github.com --git-protocol https --web
fi
# Never echo the credential or put it in shell arguments. Keep the mounted inode stable on refresh.
gh auth token --hostname github.com > runtime/github-token.new
test -s runtime/github-token.new
cat runtime/github-token.new > runtime/github-token
rm runtime/github-token.new
chmod 600 runtime/github-token
printf 'GitHub login ready for Local CI.\n'
