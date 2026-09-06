#!/usr/bin/env bash
# Run the COMPLETE nimrod test suite.
#
# WHY THIS EXISTS
# ---------------
# HISTORY: `nimble test` builds and runs tests/test_all.nim, which used to
# import 112 of the 224 test_*.nim files in tests/. The other 112 were never
# referenced, so they were never compiled and never run. Until 2026-08-30
# test_all.nim did not even compile (an ambiguous MinBlocksToKeep, fixed in
# 62a042a), so the aggregate ran ZERO tests -- every nimrod "tests pass" on
# record came from running individual files by hand.
#
# FIXED 2026-09-06: test_all.nim now imports every tests/test_*.nim except the
# files it names (with a reason) in ExcludedTests, a compile-time guard fails
# the BUILD if a test file is neither imported nor excluded, and every test
# module uses unittest2 so the [Summary] line counts the whole run. Pass 1 is
# therefore no longer a partial view of the suite.
#
# Pass 1 is the aggregate. Pass 2 compiles and runs EVERY test file on its own.
# It is still worth running: it is the only thing that exercises the files
# test_all.nim excludes, and it reports compile failures separately from test
# failures, because a file that no longer compiles is a different problem from
# one that fails.
#
# Pass 2 is SLOW -- it is one nim compile per file (~10-30s each, so roughly an
# hour for 224). It is a periodic check, not a pre-commit gate. Limit it while
# iterating:  ./run-all-tests.sh --only 'test_addr*'
set -uo pipefail
cd "$(dirname "$0")"
FILTER="${2:-}"; [ "${1:-}" = "--only" ] && FILTER="$2"

echo "== pass 1: aggregate (tests/test_all.nim -- every tests/test_*.nim except its ExcludedTests)"
# unittest2 exits non-zero on any failure and nim reports that as
# "execution of an external program failed", which buries the counts. Capture
# the run and print unittest2's own [Summary] line instead.
AGG=$(mktemp)
nim c --hints:off -r --nimcache:/tmp/nimrod_all_cache tests/test_all.nim > "$AGG" 2>&1
grep -E "^\[Summary\]|^\[Coverage\]" "$AGG" || tail -3 "$AGG"
rm -f "$AGG"

echo
echo "== pass 2: every tests/test_*.nim individually"
COMPILE_FAIL=(); TEST_FAIL=(); OK=0
for f in tests/${FILTER:-test_*}.nim; do
  m=$(basename "$f" .nim); [ "$m" = "test_all" ] && continue
  if ! nim c --hints:off --nimcache:"/tmp/nimrod_cache_$m" "$f" >/dev/null 2>&1; then
    COMPILE_FAIL+=("$m"); continue
  fi
  if "tests/$m" >/dev/null 2>&1; then OK=$((OK+1)); else TEST_FAIL+=("$m"); fi
done

echo
echo "individually: $OK ok, ${#TEST_FAIL[@]} failing, ${#COMPILE_FAIL[@]} not compiling"
[ ${#COMPILE_FAIL[@]} -gt 0 ] && printf '  DOES NOT COMPILE: %s\n' "${COMPILE_FAIL[@]}"
[ ${#TEST_FAIL[@]}    -gt 0 ] && printf '  FAILING:          %s\n' "${TEST_FAIL[@]}"
[ ${#TEST_FAIL[@]} -eq 0 ] && [ ${#COMPILE_FAIL[@]} -eq 0 ] && { echo "GREEN"; exit 0; }
exit 1
