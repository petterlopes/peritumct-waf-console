#!/usr/bin/env bash
set -euo pipefail
# Working-tree secret scan (no Gitleaks binary).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
fail=0
if grep -RInE 'BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY' --exclude-dir=.git . ; then
  echo "FAIL private key material" >&2
  fail=1
fi
if grep -RInE 'AKIA[0-9A-Z]{16}' --exclude-dir=.git . ; then
  echo "FAIL AWS access key id" >&2
  fail=1
fi
if grep -RInE 'ghp_[A-Za-z0-9]{20,}' --exclude-dir=.git . ; then
  echo "FAIL GitHub token" >&2
  fail=1
fi
exit "$fail"
