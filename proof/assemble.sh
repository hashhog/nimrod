#!/usr/bin/env bash
# proof/assemble.sh — refresh provenance + MANIFEST from the promoted pin.
#
# The attested binary MUST be the one actually running (the deploy pin),
# not a local rebuild of bin/nimrod. Run this after every promote:
#
#   bash proof/assemble.sh --pin
#   bash proof/assemble.sh --pin /path/to/deploy/nimrod/nimrod
#
# Frozen evidence (lineage log, capture, R1/R2/R5 artifacts) is already
# in proof/ and is not regenerated from outside this repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
# choosenim / nimble are often not on a non-interactive PATH
export PATH="${HOME}/.nimble/bin:${PATH}"

usage() {
  echo "usage: $0 [--pin [PATH]] [--local-bin]" >&2
  exit 2
}

PIN_ARG=""
PIN_FORCED=0
LOCAL_BIN=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pin)
      PIN_FORCED=1
      if [ -n "${2:-}" ] && [ "${2#-}" = "$2" ]; then
        PIN_ARG="$2"
        shift 2
      else
        shift
      fi
      ;;
    --pin=*)
      PIN_FORCED=1
      PIN_ARG="${1#--pin=}"
      shift
      ;;
    --local-bin)
      LOCAL_BIN=1
      shift
      ;;
    -h|--help)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

discover_pin() {
  if [ -n "$PIN_ARG" ]; then
    printf '%s\n' "$PIN_ARG"
    return 0
  fi
  if [ -n "${NIMROD_PIN:-}" ]; then
    printf '%s\n' "$NIMROD_PIN"
    return 0
  fi
  local cand
  for cand in "$ROOT/../deploy/nimrod/nimrod" /home/work/hashhog/deploy/nimrod/nimrod; do
    if [ -x "$cand" ]; then
      printf '%s\n' "$cand"
      return 0
    fi
  done
  return 1
}

BINARY=""
BINARY_SHA=""
DEPLOY_PIN=""
DEPLOY_SHORT=""
DEPLOY_SHA=""
SOURCE="none"

if [ "$LOCAL_BIN" -eq 0 ] && pin="$(discover_pin)"; then
  if [ ! -x "$pin" ]; then
    echo "assemble: pin is not an executable: $pin" >&2
    exit 1
  fi
  BINARY="$(readlink -f "$pin")"
  BINARY_SHA="$(sha256sum "$BINARY" | awk '{print $1}')"
  SOURCE="pin"
  man="$(dirname "$pin")/MANIFEST"
  if [ -f "$man" ]; then
    DEPLOY_PIN="$(awk -F= '/^sha=/{print $2; exit}' "$man")"
    DEPLOY_SHORT="$(awk -F= '/^short=/{print $2; exit}' "$man")"
    DEPLOY_SHA="$(awk -F= '/^sha256=/{print $2; exit}' "$man")"
    if [ -n "$DEPLOY_SHA" ] && [ "$DEPLOY_SHA" != "$BINARY_SHA" ]; then
      echo "assemble: pin file sha256=$BINARY_SHA != MANIFEST sha256=$DEPLOY_SHA" >&2
      exit 1
    fi
  fi
  if [ -z "$DEPLOY_SHA" ]; then
    DEPLOY_SHA="$BINARY_SHA"
  fi
elif [ -x bin/nimrod ]; then
  if [ "$PIN_FORCED" -eq 1 ]; then
    echo "assemble: --pin was given but no pin was found" >&2
    exit 1
  fi
  BINARY="bin/nimrod"
  BINARY_SHA="$(sha256sum bin/nimrod | awk '{print $1}')"
  SOURCE="local-bin"
else
  if [ "$PIN_FORCED" -eq 1 ]; then
    echo "assemble: --pin was given but no pin was found" >&2
    exit 1
  fi
  BINARY="bin/nimrod (not present; gitignored)"
  BINARY_SHA="(rebuild with nimble build -d:release -y)"
  SOURCE="missing"
fi

if [ -z "$DEPLOY_PIN" ]; then
  DEPLOY_PIN="$(git rev-parse HEAD)"
fi
if [ -z "$DEPLOY_SHORT" ]; then
  DEPLOY_SHORT="$(git rev-parse --short=12 "$DEPLOY_PIN" 2>/dev/null || git rev-parse --short=12 HEAD)"
fi

{
  echo "# Provenance — nimrod proof bundle"
  echo "assembled_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "repo: https://github.com/hashhog/nimrod"
  echo "branch: $(git rev-parse --abbrev-ref HEAD)"
  echo "commit: $(git rev-parse HEAD)"
  echo "commit_short: $(git rev-parse --short=12 HEAD)"
  echo "subject: $(git log -1 --format=%s | cut -c1-120)"
  echo "tree_clean: $([ -z "$(git status --porcelain)" ] && echo yes || echo NO)"
  echo "binary: $BINARY"
  echo "binary_sha256: $BINARY_SHA"
  echo "toolchain: $(nim --version 2>/dev/null | head -1 || echo 'nim not on PATH')"
  echo "nimble: $(nimble --version 2>/dev/null | head -1 || echo 'nimble not on PATH')"
  echo "target: Linux amd64"
  echo "build: nimble build -d:release -y"
  echo "deploy_pin: $DEPLOY_PIN"
  echo "deploy_short: $DEPLOY_SHORT"
  echo "deploy_sha256: ${DEPLOY_SHA:-$BINARY_SHA}"
  echo "source: $SOURCE"
  echo
  echo "# Honest caveats"
  echo "The attested binary is the promoted pin (deploy/nimrod/MANIFEST"
  echo "sha256=${DEPLOY_SHA:-$BINARY_SHA}, commit $DEPLOY_SHORT), which must be"
  echo "byte-identical to the live mainnet unit's /proc/<pid>/exe. Re-run"
  echo "this script with --pin after every promote; proof/check-pin.sh and"
  echo "proof/verify.sh fail if a pin is present and does not match."
  echo "Nim compiles via C. The binary hash is for this toolchain and this"
  echo "tree. A different Nim, C compiler, libc, or build path is expected"
  echo "to produce different bytes. Behavioural re-runs (R1 shim, in-repo"
  echo "R5 tests) are the stronger check. See REPRODUCIBLE-BUILD.md."
  echo "This script refreshes provenance + MANIFEST only. Frozen evidence in"
  echo "r1/ r2/ r4/ r5/ is not regenerated from outside this repository."
} > "$PROOF/provenance.txt"

if [ "$SOURCE" != "missing" ]; then
  python3 - "$PROOF/claims.json" "$BINARY_SHA" "$DEPLOY_PIN" <<'PY'
import pathlib, sys
path, sha, pin = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
text = path.read_text()
import re
text2, n = re.subn(r'("binary_sha256":\s*")[^"]*"', r'\1' + sha + '"', text, count=1)
if n != 1:
    sys.exit("assemble: failed to patch claims.json binary_sha256")
if pin:
    text2, n = re.subn(r'("parent_commit":\s*")[^"]*"', r'\1' + pin + '"', text2, count=1)
    if n != 1:
        sys.exit("assemble: failed to patch claims.json parent_commit")
path.write_text(text2)
PY
fi

# Hash every file except MANIFEST itself, stable order.
( cd "$PROOF" && find . -type f ! -name MANIFEST.sha256 | sed 's|^\./||' | LC_ALL=C sort \
    | xargs -d '\n' sha256sum > MANIFEST.sha256 )

echo "assemble: $PROOF"
echo "  source: $SOURCE"
echo "  binary: $BINARY"
echo "  binary_sha256: $BINARY_SHA"
echo "  deploy_pin: $DEPLOY_PIN"
echo "  files: $(find "$PROOF" -type f | wc -l)"
echo "  manifest: $(wc -l < "$PROOF/MANIFEST.sha256") hashes"
