## Regression tests for the BIP-444 Pay-to-Anchor + unknown-witness-version
## handling in verifyWitnessProgram / verifyWitnessProgramWithError.
##
## Reference: BIP-141 / Core script/interpreter.cpp:1947-1998 — only v0 +
## non-20/non-32 is a consensus failure; v1 + non-32 (and v2-v16) are
## anyone-can-spend (forward soft-fork compat). P2A is recognized
## explicitly via `IsPayToAnchor` (line 1990) and is unconditionally valid
## regardless of the relay DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM flag.
##
## Pre-fix nimrod bugs (closed in this commit):
##   1. verifyWitnessProgramWithError v1+non-32 returned
##      seWitnessProgramMismatch instead of falling through to
##      anyone-can-spend (matching Core's behavior).
##   2. Both bool and WithError variants rejected an empty witness for
##      unknown witness versions — Core ignores witness contents for v2+.
##
## Mainnet wedge that exposed the lunarblock+rustoshi version of this
## same bug class: block 945,394 tx 26b9fa21bb16d8fb... input 0,
## prevout `51024e73`. See project_p2a_945394_closure.md.

import unittest2
import ../src/script/interpreter
import ../src/primitives/types

suite "P2A and unknown witness version (945,394 wedge class)":
  # Common dummy fixtures — the bug is in dispatch, not signature checking.
  let dummyTx = Transaction()
  let dummyAmount = Satoshi(0)
  let inputIndex = 0
  let p2aProgram: seq[byte] = @[0x4e'u8, 0x73'u8]
  let emptyWitness: seq[seq[byte]] = @[]

  test "WithError: P2A spend (v1 + 0x4e73) succeeds":
    let res = verifyWitnessProgramWithError(
      emptyWitness, 1, p2aProgram, dummyTx, inputIndex, dummyAmount, {sfTaproot})
    check res == seOk

  test "WithError: P2A succeeds without sfTaproot":
    # P2A is not gated on Taproot activation (it's matched explicitly).
    let res = verifyWitnessProgramWithError(
      emptyWitness, 1, p2aProgram, dummyTx, inputIndex, dummyAmount, {})
    check res == seOk

  test "WithError: P2A succeeds even with DISCOURAGE flag":
    # Per Core line 1990, P2A returns true unconditionally — DISCOURAGE
    # only applies to the catch-all unknown-version branch, not P2A.
    let res = verifyWitnessProgramWithError(
      emptyWitness, 1, p2aProgram, dummyTx, inputIndex, dummyAmount,
      {sfTaproot, sfDiscourageUpgradableWitnessProgram})
    check res == seOk

  test "WithError: v1 + 4-byte non-P2A program succeeds":
    let res = verifyWitnessProgramWithError(
      emptyWitness, 1, @[0x00'u8, 0x01'u8, 0x02'u8, 0x03'u8], dummyTx,
      inputIndex, dummyAmount, {sfTaproot})
    check res == seOk

  test "WithError: v1 + 30-byte program with DISCOURAGE flag fails (relay-only)":
    var program: seq[byte] = @[]
    for _ in 0 ..< 30:
      program.add(0x00'u8)
    let res = verifyWitnessProgramWithError(
      emptyWitness, 1, program, dummyTx, inputIndex, dummyAmount,
      {sfTaproot, sfDiscourageUpgradableWitnessProgram})
    check res == seDiscourageUpgradableWitnessProgram

  test "WithError: v2 + empty witness succeeds (BIP-141 forward compat)":
    # Pre-fix this returned seWitnessProgramMismatch — wrong, Core
    # returns success regardless of witness contents for unknown versions.
    var program: seq[byte] = @[]
    for _ in 0 ..< 32:
      program.add(0x00'u8)
    let res = verifyWitnessProgramWithError(
      emptyWitness, 2, program, dummyTx, inputIndex, dummyAmount, {sfTaproot})
    check res == seOk

  test "WithError: v0 + non-20/non-32 still consensus-fails wrong-length":
    # Regression: the v0 length check is BIP-141 consensus and must NOT
    # have been weakened by the v1 forward-compat fix.
    var program: seq[byte] = @[]
    for _ in 0 ..< 16:
      program.add(0x00'u8)
    let res = verifyWitnessProgramWithError(
      emptyWitness, 0, program, dummyTx, inputIndex, dummyAmount, {})
    check res == seWitnessProgramMismatch

  test "bool: v2 + empty witness succeeds (consensus path)":
    # Mirror of the WithError v2 test for the consensus-bool variant.
    # Pre-fix this returned false — wrong per BIP-141.
    var program: seq[byte] = @[]
    for _ in 0 ..< 32:
      program.add(0x00'u8)
    let res = verifyWitnessProgram(
      emptyWitness, 2, program, dummyTx, inputIndex, dummyAmount, {sfTaproot})
    check res == true

  test "bool: v2 + DISCOURAGE flag still rejects":
    var program: seq[byte] = @[]
    for _ in 0 ..< 32:
      program.add(0x00'u8)
    let res = verifyWitnessProgram(
      emptyWitness, 2, program, dummyTx, inputIndex, dummyAmount,
      {sfTaproot, sfDiscourageUpgradableWitnessProgram})
    check res == false
