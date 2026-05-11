## BIP-30 + BIP-34 coinbase comprehensive audit tests
## Covers all 10 gates in Bitcoin Core's ConnectBlock / ContextualCheckBlock
## for BIP-30 UTXO-duplicate rejection and BIP-34 coinbase height enforcement.
##
## Reference: Bitcoin Core validation.cpp:2397-2476, 4151-4158, 6189-6199
## + IsBIP30Repeat / IsBIP30Unspendable helpers (validation.cpp:6189-6199).

import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc makeMinimalCoinbaseTx(heightBytes: seq[byte] = @[0x01'u8, 0x00]): Transaction =
  ## Build a minimal coinbase transaction.
  ## heightBytes is placed in scriptSig (must be 2..100 bytes).
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffff_ffff'u32),
      scriptSig: heightBytes,
      sequence: 0xffff_ffff'u32
    )],
    outputs: @[TxOut(value: Satoshi(5_000_000_000'i64), scriptPubKey: @[0x51'u8])],
    lockTime: 0
  )

proc makeNonCoinbaseTx(): Transaction =
  ## Build a minimal non-coinbase transaction.
  var prevTxid: array[32, byte]
  prevTxid[0] = 0xab
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(prevTxid), vout: 0),
      scriptSig: @[0x51'u8],
      sequence: 0xffff_ffff'u32
    )],
    outputs: @[TxOut(value: Satoshi(1_000_000'i64), scriptPubKey: @[0x51'u8])],
    lockTime: 0
  )

proc makeBlockWithCoinbase(coinbase: Transaction): Block =
  ## Wrap a coinbase transaction in a block with a zeroed header.
  Block(txs: @[coinbase], header: BlockHeader())

proc makeBlockWithTxs(txs: seq[Transaction]): Block =
  Block(txs: txs, header: BlockHeader())

proc alwaysHasUtxo(op: OutPoint): bool {.gcsafe, raises: [].} = true
proc neverHasUtxo(op: OutPoint): bool {.gcsafe, raises: [].} = false

proc makeHasUtxoForTx(tx: Transaction): proc(op: OutPoint): bool {.gcsafe, raises: [].} =
  let txid = tx.txid()
  let outpoints = block:
    var ops: seq[OutPoint]
    for v in 0 ..< tx.outputs.len:
      ops.add(OutPoint(txid: TxId(txid), vout: uint32(v)))
    ops
  proc(op: OutPoint): bool {.gcsafe, raises: [].} =
    for o in outpoints:
      if o.txid == op.txid and o.vout == op.vout: return true
    false

proc zeroHash(): array[32, byte] = default(array[32, byte])

proc fakeHash(b: byte): array[32, byte] =
  ## Create a fake (non-canonical) block hash.
  result[0] = b

# ---------------------------------------------------------------------------
# Suite: isBip30Repeat (Gate 1 — height + hash check)
# ---------------------------------------------------------------------------

suite "isBip30Repeat — height + hash Gate 1":

  test "h=91842 canonical hash is a BIP-30 repeat":
    # Bitcoin Core validation.cpp:6191
    let h = bip30HashFromHex(
      "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    )
    check isBip30Repeat(91842'i32, h)

  test "h=91880 canonical hash is a BIP-30 repeat":
    # Bitcoin Core validation.cpp:6192
    let h = bip30HashFromHex(
      "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    )
    check isBip30Repeat(91880'i32, h)

  test "h=91842 wrong hash is NOT a repeat (fork protection)":
    ## Core Bug this fixes: old code exempted by height alone.
    ## A fork block at height 91842 with a different hash must NOT be exempted.
    check not isBip30Repeat(91842'i32, fakeHash(0xde))

  test "h=91880 wrong hash is NOT a repeat (fork protection)":
    check not isBip30Repeat(91880'i32, fakeHash(0xbe))

  test "height 91841 is not a repeat (adjacent height)":
    let h = bip30HashFromHex(
      "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    )
    check not isBip30Repeat(91841'i32, h)

  test "height 91843 is not a repeat (adjacent height)":
    check not isBip30Repeat(91843'i32, zeroHash())

  test "heights 91722 and 91812 are NOT BIP-30 repeats (those are Unspendable)":
    ## The unspendable blocks (91722/91812) are the FIRST of each duplicate pair.
    ## Only the REPEAT blocks (91842/91880) get the IsBIP30Repeat exemption.
    check not isBip30Repeat(91722'i32, zeroHash())
    check not isBip30Repeat(91812'i32, zeroHash())

# ---------------------------------------------------------------------------
# Suite: isBip30Unspendable (DisconnectBlock helper — Gates 9)
# ---------------------------------------------------------------------------

suite "isBip30Unspendable — DisconnectBlock helper":

  test "h=91722 canonical hash is unspendable":
    # Bitcoin Core validation.cpp:6197
    let h = bip30HashFromHex(
      "00000000000271a2dc26e7667f8419f2e15416dc6955e5a6c6cdf3f2574dd08e"
    )
    check isBip30Unspendable(91722'i32, h)

  test "h=91812 canonical hash is unspendable":
    # Bitcoin Core validation.cpp:6198
    let h = bip30HashFromHex(
      "00000000000af0aed4792b1acee3d966af36cf5def14935db8de83d6f9306f2f"
    )
    check isBip30Unspendable(91812'i32, h)

  test "h=91722 wrong hash is NOT unspendable":
    check not isBip30Unspendable(91722'i32, fakeHash(0xaa))

  test "h=91812 wrong hash is NOT unspendable":
    check not isBip30Unspendable(91812'i32, fakeHash(0xbb))

  test "heights 91842/91880 are NOT unspendable (those are Repeats)":
    check not isBip30Unspendable(91842'i32, zeroHash())
    check not isBip30Unspendable(91880'i32, zeroHash())

# ---------------------------------------------------------------------------
# Suite: checkBip30 — full logic (Gates 1-10)
# ---------------------------------------------------------------------------

suite "checkBip30 — BIP-30 UTXO duplicate enforcement":

  # Gate 1: IsBIP30Repeat exempts canonical repeat blocks by height+hash

  test "Gate 1: canonical h=91842 block is exempt even with duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hash = bip30HashFromHex(
      "00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec"
    )
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 91842'i32, hash, params, hasUtxo)
    check r.isOk  # Must be exempt (IsBIP30Repeat)

  test "Gate 1: canonical h=91880 block is exempt even with duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hash = bip30HashFromHex(
      "00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721"
    )
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 91880'i32, hash, params, hasUtxo)
    check r.isOk

  test "Gate 1 hash-check: fork block at h=91842 with wrong hash IS rejected":
    ## Old bug: code only checked height → fork blocks at 91842/91880 got a
    ## false exemption.  With the fix, the hash must also match.
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let wrongHash = fakeHash(0x01)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 91842'i32, wrongHash, params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  test "Gate 1 hash-check: fork block at h=91880 with wrong hash IS rejected":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 91880'i32, fakeHash(0x02), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  # Pre-BIP34 height — must enforce

  test "Pre-BIP34 h=91843 enforces BIP-30 with duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 91843'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  test "Pre-BIP34 h=100000 enforces BIP-30 with duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 100_000'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  test "Pre-BIP34 h=100000 passes when no duplicate UTXO":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let r = checkBip30(blk, 100_000'i32, zeroHash(), params, neverHasUtxo)
    check r.isOk

  # Gate 2: BIP34 canonical-chain exemption (mainnet bip34Hash is non-zero)

  test "Gate 2: post-BIP34 mainnet h=228000 skips BIP-30 (bip34Hash matches)":
    ## After bip34Height (227931) and before 1,983,702, BIP-30 is skipped when
    ## params.bip34Hash is non-zero (mainnet/testnet3).
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 228_000'i32, zeroHash(), params, hasUtxo)
    check r.isOk  # BIP-34 canonical chain: skip BIP-30

  test "Gate 2: exactly at bip34Height (h=227931) skips BIP-30 on mainnet":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 227_931'i32, zeroHash(), params, hasUtxo)
    check r.isOk

  test "Gate 2 absent: regtest always enforces BIP-30 post-bip34Height (bip34Hash=zero)":
    ## Bug fixed: old code skipped BIP-30 for ALL chains once height >= bip34Height.
    ## Correct behaviour: regtest has bip34Hash=all-zeros → BIP30 stays enforced.
    let params = regtestParams()
    # bip34Height=1 on regtest; test at height=10 (post-bip34Height)
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 10'i32, zeroHash(), params, hasUtxo)
    check not r.isOk  # bip34Hash=zero → BIP-30 enforced
    check r.error == veBip30DuplicateOutput

  test "Gate 2 absent: testnet4 always enforces BIP-30 post-bip34Height (bip34Hash=zero)":
    let params = testnet4Params()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 100'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  # Gate 3: BIP34-implies-BIP30 limit (re-enable at h >= 1,983,702)

  test "Gate 3: h=1983702 re-enables BIP-30 scanning on mainnet":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 1_983_702'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  test "Gate 3: h=1983701 (just below limit) still skips on mainnet":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 1_983_701'i32, zeroHash(), params, hasUtxo)
    check r.isOk  # Post-BIP34, below limit → skip

  test "Gate 3: h=2000000 (well above limit) enforces BIP-30":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(tx)
    let hasUtxo = makeHasUtxoForTx(tx)
    let r = checkBip30(blk, 2_000_000'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  # Gates 4-10: UTXO scan covers ALL transactions and ALL outputs

  test "Gates 4-10: non-coinbase tx with duplicate UTXO is rejected":
    let params = mainnetParams()
    let cb = makeMinimalCoinbaseTx()
    let nonCb = makeNonCoinbaseTx()
    let blk = makeBlockWithTxs(@[cb, nonCb])
    # Only the non-coinbase tx's outputs collide
    let nonCbId = nonCb.txid()
    proc hasUtxo(op: OutPoint): bool {.gcsafe, raises: [].} =
      op.txid == TxId(nonCbId) and op.vout == 0
    let r = checkBip30(blk, 100_000'i32, zeroHash(), params, hasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

  test "Gates 4-10: multiple outputs — first collision triggers reject":
    let params = mainnetParams()
    let cb = makeMinimalCoinbaseTx()
    let blk = makeBlockWithCoinbase(cb)
    let r = checkBip30(blk, 100_000'i32, zeroHash(), params, alwaysHasUtxo)
    check not r.isOk
    check r.error == veBip30DuplicateOutput

# ---------------------------------------------------------------------------
# Suite: validateCoinbase — BIP-34 height encoding (Gates 5-7)
# ---------------------------------------------------------------------------

suite "validateCoinbase — BIP-34 coinbase height encoding":

  # BIP-34 is active at height >= bip34Height on mainnet (h=227931)

  test "Gate 5: below BIP-34 height — no height prefix required":
    let params = mainnetParams()
    # Any 2-100 byte scriptSig is fine at height < bip34Height
    let tx = makeMinimalCoinbaseTx(@[0x51'u8, 0x51])  # OP_1 OP_1, not a height
    let r = validateCoinbase(tx, 227_930'i32, params)
    check r.isOk

  test "Gate 5: at BIP-34 height — height prefix must match":
    let params = mainnetParams()
    # h=227931: CScript() << 227931
    # 227931 = 0x037a5b -> LE bytes: 5b 7a 03 — 3 bytes, high bit clear → no sign pad
    # Encoding: length byte (0x03) + [0x5b, 0x7a, 0x03]
    let heightBytes = encodeBip34Height(227_931'i32)
    let scriptSig = heightBytes & @[0x51'u8]  # pad to >= 2 bytes (already is)
    let tx = makeMinimalCoinbaseTx(scriptSig)
    let r = validateCoinbase(tx, 227_931'i32, params)
    check r.isOk

  test "Gate 6: wrong height bytes → bad-cb-height at BIP-34 height":
    let params = mainnetParams()
    # At h=227931, provide height 227930 instead
    let wrongHeightBytes = encodeBip34Height(227_930'i32)
    let tx = makeMinimalCoinbaseTx(wrongHeightBytes & @[0x51'u8])
    let r = validateCoinbase(tx, 227_931'i32, params)
    check not r.isOk
    check r.error == veBadCoinbase

  test "Gate 6: missing height prefix entirely → bad-cb-height":
    let params = mainnetParams()
    # At h=227931, provide a scriptSig that doesn't start with the height
    let tx = makeMinimalCoinbaseTx(@[0x51'u8, 0x51])  # OP_1 OP_1, no height
    let r = validateCoinbase(tx, 227_931'i32, params)
    check not r.isOk
    check r.error == veBadCoinbase

  # Gate 7: encodeBip34Height canonical CScriptNum encoding

  test "Gate 7: height=0 encodes as OP_0 (0x00)":
    let enc = encodeBip34Height(0'i32)
    check enc == @[0x00'u8]

  test "Gate 7: height=1 encodes as OP_1 (0x51)":
    let enc = encodeBip34Height(1'i32)
    check enc == @[0x51'u8]

  test "Gate 7: height=16 encodes as OP_16 (0x60)":
    let enc = encodeBip34Height(16'i32)
    check enc == @[0x60'u8]

  test "Gate 7: height=17 encodes as length-prefixed CScriptNum (0x01 0x11)":
    # 17 = 0x11 — one byte, high bit clear → no sign pad
    let enc = encodeBip34Height(17'i32)
    check enc == @[0x01'u8, 0x11'u8]

  test "Gate 7: height=127 encodes as 0x01 0x7f":
    # 127 = 0x7f — one byte, high bit clear
    let enc = encodeBip34Height(127'i32)
    check enc == @[0x01'u8, 0x7f'u8]

  test "Gate 7: height=128 encodes as 0x02 0x80 0x00 (sign-pad needed)":
    # 128 = 0x80 — high bit set → append 0x00 sign byte
    let enc = encodeBip34Height(128'i32)
    check enc == @[0x02'u8, 0x80'u8, 0x00'u8]

  test "Gate 7: height=255 encodes as 0x02 0xff 0x00":
    let enc = encodeBip34Height(255'i32)
    check enc == @[0x02'u8, 0xff'u8, 0x00'u8]

  test "Gate 7: height=256 encodes as 0x02 0x00 0x01":
    # 256 = 0x0100 LE → bytes [0x00, 0x01], high bit clear
    let enc = encodeBip34Height(256'i32)
    check enc == @[0x02'u8, 0x00'u8, 0x01'u8]

  test "Gate 7: height=227931 encodes correctly":
    # 227931 decimal = 0x037a5b hex; LE bytes: [0x5b, 0x7a, 0x03]
    # High bit of 0x03 is clear → no sign pad; length byte = 0x03
    let enc = encodeBip34Height(227_931'i32)
    check enc == @[0x03'u8, 0x5b'u8, 0x7a'u8, 0x03'u8]

  test "Gate 7: validateCoinbase scriptSig too short → bad-cb-height":
    let params = mainnetParams()
    # At height 300000, the encoding is 3 bytes (length prefix + 3 LE bytes = 4 total).
    # Provide only the length prefix without the height value.
    let heightFull = encodeBip34Height(300_000'i32)
    # Truncate to just the length byte (too short)
    let tx = makeMinimalCoinbaseTx(@[heightFull[0], 0x51'u8])
    let r = validateCoinbase(tx, 300_000'i32, params)
    check not r.isOk
    check r.error == veBadCoinbase

  # Regtest: BIP-34 active from genesis (bip34Height=1)

  test "Regtest h=1 requires height prefix":
    let params = regtestParams()
    let enc = encodeBip34Height(1'i32)
    let tx = makeMinimalCoinbaseTx(enc & @[0x51'u8])
    let r = validateCoinbase(tx, 1'i32, params)
    check r.isOk

  test "Regtest h=1 wrong prefix → rejected":
    let params = regtestParams()
    let wrongEnc = encodeBip34Height(2'i32)
    let tx = makeMinimalCoinbaseTx(wrongEnc & @[0x51'u8])
    let r = validateCoinbase(tx, 1'i32, params)
    check not r.isOk
    check r.error == veBadCoinbase

  # Coinbase size constraints (Gate independent of BIP-34)

  test "Coinbase scriptSig < 2 bytes is invalid":
    let params = mainnetParams()
    let tx = makeMinimalCoinbaseTx(@[0x51'u8])  # only 1 byte — below BIP-34 height but too short
    let r = validateCoinbase(tx, 100'i32, params)
    check not r.isOk
    check r.error == veBadCoinbaseSize

  test "Coinbase scriptSig of 100 bytes is valid":
    let params = mainnetParams()
    var scriptSig = newSeq[byte](100)
    scriptSig[0] = 0x51; scriptSig[1] = 0x51  # at least 2 bytes non-trivial
    let tx = makeMinimalCoinbaseTx(scriptSig)
    let r = validateCoinbase(tx, 100'i32, params)  # h=100 < bip34Height
    check r.isOk

  test "Coinbase scriptSig of 101 bytes is invalid (too long)":
    let params = mainnetParams()
    var scriptSig = newSeq[byte](101)
    scriptSig[0] = 0x51; scriptSig[1] = 0x51
    let tx = makeMinimalCoinbaseTx(scriptSig)
    let r = validateCoinbase(tx, 100'i32, params)
    check not r.isOk
    check r.error == veBadCoinbaseSize
