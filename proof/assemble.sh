#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + MANIFEST for this committed bundle.
# Frozen evidence (lineage log, capture, R1/R2/R5 artifacts) is already in
# proof/ and is not regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"

{
  echo "# Provenance — nimrod proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/nimrod"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  if [ -x bin/nimrod ]; then
    echo "binary: bin/nimrod"
    echo "binary_sha256: $(sha256sum bin/nimrod | awk '{print $1}')"
  else
    echo "binary: bin/nimrod (not present; gitignored)"
    echo "binary_sha256: (rebuild with nimble build -d:release -y)"
  fi
  echo "toolchain: $(nim --version 2>/dev/null | head -1 || echo 'nim not on PATH')"
  echo "nimble: $(nimble --version 2>/dev/null | head -1 || echo 'nimble not on PATH')"
  echo "target: Linux amd64"
  echo "build: nimble build -d:release -y"
  echo
  echo "# Honest caveats"
  echo "Nim compiles via C. The binary hash is for this toolchain and this tree."
  echo "A different Nim, C compiler, libc, or build path is expected to produce"
  echo "different bytes. Behavioural re-runs (R1 shim, in-repo R5 tests) are the"
  echo "stronger check. See REPRODUCIBLE-BUILD.md."
  echo "This script refreshes provenance + MANIFEST only. Frozen evidence in"
  echo "r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
} > "$PROOF/provenance.txt"

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
