"""Focused real Docker regression for artifact upload compatibility."""

import asyncio

import smoke

smoke.WORKFLOW = r"""name: Artifact regression
on: pull_request
jobs:
  artifact:
    runs-on: ubuntu-latest
    steps:
      - run: |
          test "$(cat /proc/1/comm)" = docker-init
          test "$(stat -f -c %T /tmp)" = tmpfs
          test "$(stat -c %a /tmp)" = 1777
          printf '#!/bin/sh\necho temporary-executable\n' > /tmp/check-exec
          chmod +x /tmp/check-exec
          test "$(/tmp/check-exec)" = temporary-executable
          mkdir -p output
          echo local-artifact > output/proof.txt
      - uses: actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9
        with:
          name: local-proof
          path: output/proof.txt
"""

if __name__ == "__main__":
    asyncio.run(smoke.main())
