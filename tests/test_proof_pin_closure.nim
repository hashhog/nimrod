## Attested-binary closure for the proof bundle.
##
## CONTROL: `bash proof/check-pin.sh`
##   before assemble --pin: attested sha256 != deploy pin / live exe
##   after:                 attested sha256 == pin == live exe
##
## This file is the in-repo half that does not need the live pin:
##   1. claims.json binary_sha256 == provenance.txt
##   2. check-pin.sh rejects a pin whose sha256 is not the attested one
##      (negative control — a check that cannot fail is not a check)
##
## The load-bearing pin == live match is proof/check-pin.sh itself,
## which verify.sh runs. Re-run `bash proof/assemble.sh --pin` after
## every promote.

import unittest2
import std/[os, osproc, strutils, json]

const RepoRoot = currentSourcePath().parentDir().parentDir()
const ProofDir = RepoRoot / "proof"

suite "proof pin closure":
  test "claims.json binary_sha256 matches provenance.txt":
    let claims = parseJson(readFile(ProofDir / "claims.json"))
    let want = claims["provenance"]["binary_sha256"].getStr()
    check want.len == 64
    var provSha = ""
    for line in readFile(ProofDir / "provenance.txt").splitLines():
      if line.startsWith("binary_sha256:"):
        provSha = line.split(maxsplit = 1)[1]
        break
    check provSha == want

  test "check-pin.sh rejects a pin whose sha256 is not the attested one":
    let fake = getTempDir() / "nimrod_fake_pin_" & $getCurrentProcessId()
    writeFile(fake, "not-the-attested-binary\n")
    defer:
      if fileExists(fake):
        removeFile(fake)
    let r = execCmdEx(
      "env NIMROD_PIN=" & fake.quoteShell() &
      " CHECK_PIN_NO_LIVE=1 bash " & (ProofDir / "check-pin.sh").quoteShell())
    check r.exitCode != 0
    check "FAIL:" in r.output
    check "is not the pin" in r.output
