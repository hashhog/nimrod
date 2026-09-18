#!/usr/bin/env bash
# proof/on-promote.sh — post-promote hook for this node.
#
# After a pin is written to deploy/nimrod/, the proof bundle must attest
# that pin (and the live exe) or check-pin.sh / verify.sh stay red until
# the next person remembers. A check that is always red is as useless as
# one that is always green.
#
# This is the in-repo release step:
#   bash proof/on-promote.sh
#   bash proof/on-promote.sh /path/to/deploy/nimrod/nimrod
#   nimble attest_pin
#
# tools/promote_mainnet.sh lives in the meta-repo and is out of this
# node's charter; call this script immediately after it. assemble.sh
# --pin is what actually rewrites provenance + MANIFEST.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ $# -gt 0 ]; then
  exec bash "$ROOT/proof/assemble.sh" --pin "$@"
fi
exec bash "$ROOT/proof/assemble.sh" --pin
