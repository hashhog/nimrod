## W77: BIP-141 witness commitment comprehensive audit.
##
## Tests all 12 gates of CheckWitnessMalleation:
##
##   G1  segwitActive branches the two code paths.
##   G2  Last occurrence scan: multiple commitment outputs → last wins.
##   G3  MINIMUM_WITNESS_COMMITMENT = 38 bytes enforced.
##   G4  Magic bytes 0x6a 0x24 0xaa 0x21 0xa9 0xed.
##   G5  Coinbase witness[0] must have exactly 1 item …
##   G6  … of exactly 32 bytes → "bad-witness-nonce-size".
##   G7  Coinbase wtxid is all-zeros in the witness merkle tree.
##   G8  Witness merkle root = ComputeMerkleRoot(wtxids).
##   G9  SHA256d(witnessRoot || nonce) must equal commitment bytes → "bad-witness-merkle-match".
##   G10 No commitment present while segwit active → no error.
##   G11 Segwit inactive + any witness data → "unexpected-witness".
##   G12 Block has at least 1 tx (asserted before call; not re-tested here).
##
## Reference: Bitcoin Core validation.cpp:3864-3916, consensus/validation.h:15,18,147-165,
##            consensus/merkle.cpp:76-85.

import unittest2
import std/[options]
import ../src/consensus/[validation, params]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing except computeMerkleRoot

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

const WitnessMagic: array[6, byte] = [0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]

proc makeCoinbaseTx(scriptSig: seq[byte] = @[0x03'u8, 0x01, 0x00, 0x00]): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: scriptSig,
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0
  )

proc makeCommitmentScript(commitment: array[32, byte]): seq[byte] =
  result = @WitnessMagic
  result.add(@commitment)

proc buildWitnessCommitment(txs: seq[Transaction], nonce: array[32, byte]): array[32, byte] =
  ## Compute the correct witness commitment value for a list of transactions.
  ## coinbase wtxid = all-zeros; rest use real wtxid.
  var wtxids: seq[array[32, byte]]
  wtxids.add(default(array[32, byte]))
  for i in 1 ..< txs.len:
    wtxids.add(array[32, byte](txs[i].wtxid()))
  computeWitnessCommitment(wtxids, nonce)

proc makeSimpleBlock(
  coinbase: Transaction,
  extraTxs: seq[Transaction] = @[],
  segwitActive: bool = true
): Block =
  ## Build a minimal valid block (no PoW check in tests).
  let allTxs = @[coinbase] & extraTxs
  var txHashes: seq[array[32, byte]]
  for tx in allTxs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: computeMerkleRoot(txHashes),
      timestamp: 1700000001'u32,
      bits: 0x207fffff'u32,
      nonce: 0'u32
    ),
    txs: allTxs
  )

# ---------------------------------------------------------------------------
# Suite
# ---------------------------------------------------------------------------

suite "W77: BIP-141 witness commitment (CheckWitnessMalleation)":

  # -------------------------------------------------------------------------
  # G10: segwit active, no commitment in coinbase → OK (no error required)
  # -------------------------------------------------------------------------
  test "G10: segwit active, no commitment → OK":
    let cb = makeCoinbaseTx()
    let blk = makeSimpleBlock(cb)
    # No commitment output, no witness data → should be fine
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

  # -------------------------------------------------------------------------
  # G11: segwit NOT active, witness data in any tx → "unexpected-witness"
  # -------------------------------------------------------------------------
  test "G11: segwit inactive + witness in coinbase → unexpected-witness":
    var cb = makeCoinbaseTx()
    # Give the coinbase a non-empty witness stack
    cb.witnesses = @[@[@[0x00'u8]]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = false)
    check (not res.isOk)
    check res.error == veUnexpectedWitness

  test "G11: segwit inactive + witness in non-coinbase tx → unexpected-witness":
    let cb = makeCoinbaseTx()
    var tx2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[])],
      witnesses: @[@[@[0xde'u8, 0xad'u8]]],
      lockTime: 0
    )
    let blk = makeSimpleBlock(cb, extraTxs = @[tx2])
    let res = checkWitnessMalleation(blk, segwitActive = false)
    check (not res.isOk)
    check res.error == veUnexpectedWitness

  test "G11: segwit inactive, no witnesses → OK":
    let cb = makeCoinbaseTx()
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = false)
    check res.isOk

  # -------------------------------------------------------------------------
  # G5/G6: witness nonce size validation
  # -------------------------------------------------------------------------
  test "G6: nonce stack has 0 items → bad-witness-nonce-size":
    let nonce = default(array[32, byte])
    let commitment = buildWitnessCommitment(@[makeCoinbaseTx()], nonce)
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    # Coinbase witness: stack with 0 items (empty witness for input 0)
    cb.witnesses = @[newSeq[seq[byte]]()]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veWitnessNonceSize

  test "G6: nonce stack has 2 items → bad-witness-nonce-size":
    let nonce = default(array[32, byte])
    let commitment = buildWitnessCommitment(@[makeCoinbaseTx()], nonce)
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    # Stack with 2 items instead of 1
    cb.witnesses = @[@[@nonce, @nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veWitnessNonceSize

  test "G6: nonce item is 31 bytes (too short) → bad-witness-nonce-size":
    let commitment = default(array[32, byte])
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    # Nonce is 31 bytes (wrong)
    var shortNonce: seq[byte] = newSeq[byte](31)
    cb.witnesses = @[@[shortNonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veWitnessNonceSize

  test "G6: nonce item is 33 bytes (too long) → bad-witness-nonce-size":
    let commitment = default(array[32, byte])
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    # Nonce is 33 bytes (wrong)
    var longNonce: seq[byte] = newSeq[byte](33)
    cb.witnesses = @[@[longNonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veWitnessNonceSize

  test "G6: coinbase has no witness (stack absent) → bad-witness-nonce-size":
    ## When a commitment output IS present, the coinbase MUST supply a nonce.
    ## Core validation.cpp:3878: witness_stack is read from vtx[0]->vin[0].scriptWitness.stack.
    let commitment = default(array[32, byte])
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    # witnesses seq is empty → effectively stack size 0
    cb.witnesses = @[]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veWitnessNonceSize

  # -------------------------------------------------------------------------
  # G9: hash mismatch → "bad-witness-merkle-match"
  # -------------------------------------------------------------------------
  test "G9: wrong commitment hash → bad-witness-merkle-match":
    var wrongCommitment: array[32, byte]
    wrongCommitment[0] = 0xff  # deliberately wrong
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(wrongCommitment)))
    # Correct nonce (32 zero bytes)
    let nonce = default(array[32, byte])
    cb.witnesses = @[@[@nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veBadWitnessCommitment

  # -------------------------------------------------------------------------
  # G7+G8+G9: correct commitment → OK (coinbase wtxid = all-zeros)
  # -------------------------------------------------------------------------
  test "G7/G8/G9: valid commitment, coinbase wtxid = zeros → OK":
    let nonce = default(array[32, byte])
    var cb = makeCoinbaseTx()
    # Build commitment: only coinbase in block → wtxids = [zeros]
    let commitment = buildWitnessCommitment(@[cb], nonce)
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    cb.witnesses = @[@[@nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

  test "G7/G8/G9: valid commitment with segwit non-coinbase tx → OK":
    ## Non-coinbase tx with witness data: wtxid != txid.
    ## The commitment must use GetWitnessHash() for non-coinbase txs.
    let nonce = default(array[32, byte])
    # Build a non-coinbase tx with witness data
    var tx2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(0), scriptPubKey: @[0x51'u8])],
      witnesses: @[@[@[0xca'u8, 0xfe'u8]]],
      lockTime: 0
    )
    var cb = makeCoinbaseTx()
    let allTxs = @[cb, tx2]
    let commitment = buildWitnessCommitment(allTxs, nonce)
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(commitment)))
    cb.witnesses = @[@[@nonce]]
    # Rebuild block with updated coinbase
    let allTxsFinal = @[cb, tx2]
    var txHashes: seq[array[32, byte]]
    for tx in allTxsFinal:
      txHashes.add(array[32, byte](tx.txid()))
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: BlockHash(default(array[32, byte])),
        merkleRoot: computeMerkleRoot(txHashes),
        timestamp: 1700000001'u32,
        bits: 0x207fffff'u32,
        nonce: 0'u32
      ),
      txs: allTxsFinal
    )
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

  # -------------------------------------------------------------------------
  # G3: Minimum script length = 38 bytes
  # -------------------------------------------------------------------------
  test "G3: script exactly 37 bytes (too short) → not recognized as commitment → G10 OK":
    ## A script of 37 bytes starting with the magic is NOT a valid commitment
    ## (below MINIMUM_WITNESS_COMMITMENT=38). findWitnessCommitment returns none.
    ## With segwit active and no commitment: OK (G10).
    var shortScript: seq[byte] = @WitnessMagic
    # Add only 31 bytes (total = 37, need 38 minimum)
    for i in 0..<31:
      shortScript.add(byte(i))
    var cb = makeCoinbaseTx()
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: shortScript))
    # No witness nonce needed (no commitment found)
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk  # no commitment found, no error

  test "G3: script exactly 38 bytes → recognized as commitment":
    let nonce = default(array[32, byte])
    var cb = makeCoinbaseTx()
    let commitment = buildWitnessCommitment(@[cb], nonce)
    # 38-byte script (exactly minimum)
    let script38 = makeCommitmentScript(commitment)  # 6 + 32 = 38 bytes
    check script38.len == 38
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: script38))
    cb.witnesses = @[@[@nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

  # -------------------------------------------------------------------------
  # G2: LAST occurrence scan — multiple commitment outputs
  # -------------------------------------------------------------------------
  test "G2: last commitment output wins when multiple are present":
    ## Core GetWitnessCommitmentIndex scans all outputs and records the last
    ## matching one (commitpos = o; without break). Nimrod uses countdown and
    ## returns first hit from the end = same semantic.
    ## This test places a WRONG commitment first and the CORRECT one last.
    let nonce = default(array[32, byte])
    var cb = makeCoinbaseTx()
    let correctCommitment = buildWitnessCommitment(@[cb], nonce)

    # First output: wrong commitment
    var wrongCommitment: array[32, byte]
    wrongCommitment[0] = 0xba
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(wrongCommitment)))
    # Second output: correct commitment (last one wins)
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(correctCommitment)))

    cb.witnesses = @[@[@nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk  # last (correct) commitment was used

  test "G2: last commitment wrong, first correct → reject":
    ## If the first is correct but the last (authoritative) is wrong, must reject.
    let nonce = default(array[32, byte])
    var cb = makeCoinbaseTx()
    let correctCommitment = buildWitnessCommitment(@[cb], nonce)

    var wrongCommitment: array[32, byte]
    wrongCommitment[0] = 0xba
    # First: correct
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(correctCommitment)))
    # Last: wrong (this is the one that counts)
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: makeCommitmentScript(wrongCommitment)))

    cb.witnesses = @[@[@nonce]]
    let blk = makeSimpleBlock(cb)
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veBadWitnessCommitment

  # -------------------------------------------------------------------------
  # BIP-22 reject string mapping
  # -------------------------------------------------------------------------
  test "bip22String: veWitnessNonceSize → bad-witness-nonce-size":
    check bip22String(veWitnessNonceSize) == "bad-witness-nonce-size"

  test "bip22String: veUnexpectedWitness → unexpected-witness":
    check bip22String(veUnexpectedWitness) == "unexpected-witness"

  test "bip22String: veBadWitnessCommitment → bad-witness-merkle-match":
    check bip22String(veBadWitnessCommitment) == "bad-witness-merkle-match"
