#!/usr/bin/env bash
# proof/check-pin.sh — attested-binary closure.
#
# The bundle's binary_sha256 MUST be the promoted pin (and the live exe
# when the unit is running). A bundle that describes a binary nobody is
# running is not a proof. Re-run `bash proof/assemble.sh --pin` after
# every promote.
#
# Exit 0 if every observable hash matches. Exit 1 on mismatch.
# A stranger without a pin and without the live unit still exits 0
# (claims.json vs provenance.txt consistency only).
#
# Env:
#   NIMROD_PIN            explicit pin path (must exist if set)
#   CHECK_PIN_NO_DEFAULT  if 1, do not look at well-known pin paths
#   CHECK_PIN_NO_LIVE     if 1, skip the live-unit /proc/<pid>/exe check
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROOF="$ROOT/proof"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

want="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("'"$PROOF"'/claims.json").read_text())["provenance"]["binary_sha256"])')"
prov_sha="$(awk '/^binary_sha256:/{print $2; exit}' "$PROOF/provenance.txt")"
if [ -z "$want" ] || [ "$want" = "(rebuild" ]; then
  die "claims.json provenance.binary_sha256 is empty / placeholder"
elif [ "$want" != "$prov_sha" ]; then
  die "claims.json binary_sha256=$want != provenance.txt $prov_sha"
else
  say "claims.json == provenance.txt binary_sha256=$want"
fi

discover_pin() {
  if [ -n "${NIMROD_PIN:-}" ]; then
    printf '%s\n' "$NIMROD_PIN"
    return 0
  fi
  if [ "${CHECK_PIN_NO_DEFAULT:-}" = "1" ]; then
    return 1
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

if pin="$(discover_pin)"; then
  if [ ! -e "$pin" ]; then
    die "NIMROD_PIN=$pin does not exist"
  else
    pin="$(readlink -f "$pin")"
    got="$(sha256sum "$pin" | awk '{print $1}')"
    man="$(dirname "$pin")/MANIFEST"
    if [ -f "$man" ]; then
      man_sha="$(awk -F= '/^sha256=/{print $2; exit}' "$man")"
      if [ -n "$man_sha" ] && [ "$man_sha" != "$got" ]; then
        die "pin file sha256=$got != MANIFEST sha256=$man_sha ($man)"
      fi
    fi
    if [ "$got" != "$want" ]; then
      die "attested binary_sha256=$want is not the pin at $pin ($got). Re-run: bash proof/assemble.sh --pin $pin"
    else
      say "provenance: pin $pin sha256=$want"
    fi
  fi
else
  say "NOTE: no pin found; skipped pin sha256 check (set NIMROD_PIN or promote to deploy/nimrod)."
fi

if [ "${CHECK_PIN_NO_LIVE:-}" != "1" ] && command -v systemctl >/dev/null 2>&1; then
  pid="$(systemctl --user show -p MainPID --value hashhog-nimrod-mainnet 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && [ "$pid" != "0" ] && [ -r "/proc/$pid/exe" ]; then
    got_live="$(sha256sum "/proc/$pid/exe" | awk '{print $1}')"
    if [ "$got_live" != "$want" ]; then
      die "attested binary_sha256=$want is not the live exe (pid $pid sha256=$got_live). The proof must attest the binary actually running."
    else
      say "provenance: live exe sha256=$want (pid $pid)"
    fi
  else
    say "NOTE: live unit not running; skipped exe sha256 check."
  fi
fi

if [ "$fail" -ne 0 ]; then
  exit 1
fi
exit 0
