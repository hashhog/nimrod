## #53 (2026-08-27): storage-side calculateBlockWork must be EXACT
## 2^256/(target+1) — it used to quantise to a single bit ("for
## simplicity"), letting chains whose true works differ by up to 2x
## compare EQUAL at compareWork256 (the close-work 1-block-race case).
## FAILS AT PARENT: difficulty-1 work quantises to 0x0100000000 there;
## the exact value is 0x0100010001 (Core arith_uint256 GetBlockProof).
import unittest2
import ../src/storage/chainstate
import ../src/network/sync

proc toHexBE(w: array[32, byte]): string =
  ## big-endian hex, no leading zeros
  result = ""
  var started = false
  for i in countdown(31, 0):
    if not started and w[i] == 0: continue
    started = true
    result.add(chr(if (w[i] shr 4) < 10: ord('0') + int(w[i] shr 4) else: ord('a') + int(w[i] shr 4) - 10))
    result.add(chr(if (w[i] and 0xF) < 10: ord('0') + int(w[i] and 0xF) else: ord('a') + int(w[i] and 0xF) - 10))
  if result.len == 0: result = "0"

suite "exact block work (#53)":
  test "difficulty-1 bits gives the exact Core value 0x0100010001":
    let w = chainstate.calculateBlockWork(0x1d00ffff'u32)
    check toHexBE(w) == "0100010001"

  test "regtest bits gives exact value 2":
    # target = 0x7fffff... -> 2^256/(target+1) = 2
    let w = chainstate.calculateBlockWork(0x207fffff'u32)
    check toHexBE(w) == "02"

  test "storage and network work functions are byte-identical":
    for bits in [0x1d00ffff'u32, 0x207fffff'u32, 0x1b0404cb'u32,
                 0x170331db'u32, 0x1a05db8b'u32]:
      let a = chainstate.calculateBlockWork(bits)
      let b = sync.calculateWork(bits)
      check a == b

  test "close-work discrimination: harder bits strictly heavier":
    # Two targets within the same power-of-two band: the quantised
    # version mapped both to the SAME single bit; exact work must order
    # them strictly.
    # 0x07.. and 0x04.. share the same top-bit position (3 bits), so the
    # quantised parent maps BOTH to the same single-bit work — this check
    # fails there; exact division orders them strictly.
    let easier = chainstate.calculateBlockWork(0x1b0704cb'u32)
    let harder = chainstate.calculateBlockWork(0x1b0404cb'u32)
    var gt = false
    for i in countdown(31, 0):
      if harder[i] != easier[i]:
        gt = harder[i] > easier[i]
        break
    check gt
