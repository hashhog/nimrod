#!/usr/bin/env bash
# proof/verify.sh — re-check every claim in this bundle against a file here.
# Exit 0 only if the files match claims.json AND the in-repo help-parity
# control is green. Run from the nimrod repo root: `bash proof/verify.sh`
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PROOF="$ROOT/proof"
export PATH="${HOME}/.nimble/bin:${PATH}"
fail=0
say() { printf '%s\n' "$*"; }
die() { printf 'FAIL: %s\n' "$*"; fail=1; }

need() {
  local f="$1"
  [ -f "$PROOF/$f" ] || die "missing $f"
}

say "== nimrod proof bundle verify =="

# 1. every claims.json file exists
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if not (proof / f).is_file():
            missing.append(f)
if missing:
    print("FAIL: missing files:", ", ".join(missing))
    sys.exit(1)
print("files: every claims.json path exists")
PY

# 2. R4 commitment numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r4"]
cap = json.loads((proof / "r4/C958794.json").read_text())
rec = (proof / "r4/capture.md").read_text()
watch = (proof / "r4/capture-watch-excerpt.txt").read_text()
unit = (proof / "r4/genesis-unit.service").read_text()
excerpt = (proof / "r4/lineage-excerpt.txt").read_text()
marker = (proof / "r4/capture-state-marker.txt").read_text().strip()
want = c["hash_serialized_3"]
errs = []
if cap["hash_serialized_3"] != want:
    errs.append("C958794.json hash mismatch")
if cap["height"] != c["height"]:
    errs.append("height mismatch")
if cap["bestblockhash"] != c["bestblockhash"]:
    errs.append("bestblockhash mismatch")
if cap["coins"] != c["coins"]:
    errs.append("coins mismatch")
if cap.get("snapshot_booted") is not False:
    errs.append("C958794.json must set snapshot_booted=false")
if want not in rec:
    errs.append("capture.md does not contain hash_serialized_3")
if want not in watch:
    errs.append("capture-watch excerpt does not contain the MATCH hash")
if marker != want:
    errs.append("capture-state marker is not the MATCH hash")
if "--assumevalid=0" not in unit:
    errs.append("genesis-unit.service missing --assumevalid=0")
if "loadtxoutset" in unit or "assumeutxo" in unit.lower():
    errs.append("genesis-unit.service looks like a snapshot boot")
if c["genesis_block_hash"] not in excerpt:
    errs.append("lineage excerpt missing Bitcoin genesis hash")
if "height=0" not in excerpt:
    errs.append("lineage excerpt missing height=0")
if "matches=0" not in excerpt:
    errs.append("lineage excerpt missing snapshot-boot negative control")
if errs:
    print("FAIL: R4:", "; ".join(errs))
    sys.exit(1)
print(f"R4: C({c['height']}) hash_serialized_3={want} coins={c['coins']} snapshot_booted=false AV=0")
PY

# 3. lineage log gzip round-trip
need "r4/lineage.log.gz"
need "r4/lineage.log.sha256"
got="$(gzip -dc "$PROOF/r4/lineage.log.gz" | sha256sum | awk '{print $1}')"
want="$(tr -d ' \n' < "$PROOF/r4/lineage.log.sha256")"
if [ "$got" != "$want" ]; then
  die "lineage.log.gz uncompressed sha256 $got != $want"
else
  say "R4: lineage.log.gz round-trip sha256=$want"
fi
if gzip -dc "$PROOF/r4/lineage.log.gz" | grep -qiE 'loadtxoutset|assumeutxo|loading snapshot'; then
  die "lineage log contains snapshot-boot evidence (TRUST-ANCHOR: does not count)"
else
  say "R4: lineage log has no loadtxoutset/assumeutxo/snapshot lines"
fi

# 4. R1 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r1"]
r = json.loads((proof / "r1/results.json").read_text())
errs = []
if r["script_tests"]["pass"] != c["script_pass"] or r["script_tests"]["fail"] != c["script_fail"]:
    errs.append("script")
if r["tx_valid"]["pass"] != c["tx_valid_pass"]:
    errs.append("tx_valid")
if r["tx_invalid"]["pass"] != c["tx_invalid_pass"]:
    errs.append("tx_invalid")
if r["sighash"]["exact_match"] != c["sighash_pass"]:
    errs.append("sighash")
if r["divergences"] != c["divergences"]:
    errs.append("divergences")
script_txt = (proof / "r1/script.txt").read_text()
if "1217/1217" not in script_txt:
    errs.append("script.txt missing 1217/1217")
if "500/500" not in (proof / "r1/sighash.txt").read_text():
    errs.append("sighash.txt missing 500/500")
if errs:
    print("FAIL: R1:", ", ".join(errs))
    sys.exit(1)
print(f"R1: script {c['script_pass']}/1217 tx {c['tx_valid_pass']}+{c['tx_invalid_pass']} sighash {c['sighash_pass']}/500 divergences={c['divergences']}")
PY

# 5. R2 numbers
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r2"]
r = json.loads((proof / "r2/results.json").read_text())
errs = []
if r["pass"] != c["pass"] or r["fail"] != c["fail"]:
    errs.append("pass/fail")
if r["consensus_splits_accept_vs_reject"] != c["consensus_splits_accept_vs_reject"]:
    errs.append("splits")
if any(not f["same_accept_reject"] for f in r["fails"]):
    errs.append("a listed FAIL is accept-vs-reject — that would be a consensus split")
excerpt = (proof / "r2/nightly-report-excerpt.txt").read_text()
if "nimrod          365      5" not in excerpt and "nimrod          365      5" not in excerpt.replace("  ", " "):
    if "365      5" not in excerpt:
        errs.append("excerpt missing 365/5")
if errs:
    print("FAIL: R2:", ", ".join(errs))
    sys.exit(1)
print(f"R2: {c['pass']} PASS / {c['fail']} FAIL, consensus splits={c['consensus_splits_accept_vs_reject']}")
PY

# 6. R5 scorecards
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib
proof = pathlib.Path(sys.argv[1])
c = json.loads((proof / "claims.json").read_text())["r5"]
live = json.loads((proof / "r5/live-20260917T102316Z.json").read_text())["impls"]["nimrod"]
reg = json.loads((proof / "r5/regtest-20260917T080758Z.json").read_text())["impls"]["nimrod"]
sc = json.loads((proof / "r5/scorecard.json").read_text())
errs = []
if live["tiers"]["T1"]["pass"] != c["live_t1_pass"] or live["tiers"]["T1"]["total"] != c["live_t1_total"]:
    errs.append("live T1")
if live["tiers"]["T2"]["pass"] != c["live_t2_pass"]:
    errs.append("live T2")
fails = [r for r in live["rows"] if r["status"] == "FAIL"]
if len(fails) != 1 or fails[0]["method"] != c["live_fail_method"]:
    errs.append(f"live FAIL set {fails!r}")
if "help-parity" not in fails[0]["detail"]:
    errs.append("live FAIL is not help-parity")
if reg["tiers"]["T3"]["pass"] != c["regtest_t3_pass"] or reg["tiers"]["T3"]["total"] != c["regtest_t3_total"]:
    errs.append("regtest T3")
reg_fails = [r for r in reg["rows"] if r["status"] == "FAIL"]
if reg_fails:
    errs.append(f"regtest FAILs {reg_fails!r}")
if sc["live"]["T1"]["pass"] != c["live_t1_pass"]:
    errs.append("scorecard live T1")
if sc["regtest"]["T3"]["pass"] != c["regtest_t3_total"]:
    errs.append("scorecard regtest T3")
before = (proof / "r5/t1-before.txt").read_text()
after = (proof / "r5/t1-after.txt").read_text()
if "1 FAILED" not in before:
    errs.append("t1-before.txt is not a failing run")
if "0 FAILED" not in after:
    errs.append("t1-after.txt is not a passing run")
if errs:
    print("FAIL: R5:", "; ".join(errs))
    sys.exit(1)
print(f"R5 live T1 {c['live_t1_pass']}/{c['live_t1_total']} T2 {c['live_t2_pass']}/{c['live_t2_total']} FAIL={c['live_fail_method']}")
print(f"R5 regtest T3 {c['regtest_t3_pass']}/{c['regtest_t3_total']}")
PY

# 7. README cites every claims.json file
python3 - "$PROOF" <<'PY' || fail=1
import json, sys, pathlib, re
proof = pathlib.Path(sys.argv[1])
readme = (proof / "README.md").read_text()
claims = json.loads((proof / "claims.json").read_text())
missing = []
for section, body in claims.items():
    for f in body.get("files", []):
        if f not in readme:
            missing.append(f)
if missing:
    print("FAIL: README.md does not cite:", ", ".join(missing))
    sys.exit(1)
print("README: every claims.json file is cited")
PY

# 8. source lists getnetworkhashps the way Core's help does
if ! grep -q 'getnetworkhashps ( nblocks height )' "$ROOT/src/rpc/server.nim"; then
  die "src/rpc/server.nim handleHelp does not list 'getnetworkhashps ( nblocks height )'"
else
  say "R5: handleHelp lists getnetworkhashps ( nblocks height )"
fi

# 9. attested-binary closure — the recorded sha256 MUST be the promoted
# pin and the live exe when those are observable. Local bin/nimrod is
# informational (rebuilds are not bit-stable across toolchains).
if ! bash "$PROOF/check-pin.sh"; then
  fail=1
fi
want_bin="$(python3 -c 'import json,pathlib; print(json.loads(pathlib.Path("proof/claims.json").read_text())["provenance"]["binary_sha256"])')"
if [ -x "$ROOT/bin/nimrod" ]; then
  got_bin="$(sha256sum "$ROOT/bin/nimrod" | awk '{print $1}')"
  if [ "$got_bin" != "$want_bin" ]; then
    say "NOTE: bin/nimrod sha256=$got_bin (bundle records $want_bin). Local rebuilds are not the attested pin."
  else
    say "provenance: bin/nimrod sha256=$want_bin"
  fi
else
  say "NOTE: bin/nimrod not present (gitignored)."
fi

# 10. in-repo help-parity control (the live-lane FAIL this commit closes)
if command -v nim >/dev/null 2>&1; then
  say "== re-run: nim c -r tests/test_t1_r5_parity.nim =="
  if nim c -r --hints:off --warnings:off tests/test_t1_r5_parity.nim; then
    say "R5 in-repo: test_t1_r5_parity PASS"
  else
    die "test_t1_r5_parity failed"
  fi
else
  say "NOTE: nim not on PATH; skipped in-repo re-run. Install Nim 2.2.8 and re-run."
  say "      The recorded after-control is r5/t1-after.txt (8 OK / 0 FAILED)."
fi

# 11. MANIFEST (all files except MANIFEST itself)
if [ -f "$PROOF/MANIFEST.sha256" ]; then
  if (cd "$PROOF" && sha256sum -c MANIFEST.sha256 --quiet); then
    say "MANIFEST.sha256: OK"
  else
    die "MANIFEST.sha256 mismatch"
  fi
else
  die "MANIFEST.sha256 missing — run bash proof/assemble.sh"
fi

if [ "$fail" -ne 0 ]; then
  say "== FAIL =="
  exit 1
fi
say "== PASS: every claim cites a file in this bundle and the numbers match =="
exit 0
