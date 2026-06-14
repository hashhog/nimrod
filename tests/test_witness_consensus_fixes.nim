## Non-vacuous regression tests for two witness consensus fixes.
##
## Finding D — Superfluous witness record (serialize.nim)
##   Bitcoin Core primitives/transaction.h:228-231:
##     if (!tx.HasWitness()) throw std::ios_base::failure("Superfluous witness record")
##   A tx encoded with the BIP144 segwit marker(0x00)+flag(0x01) but where
##   every input's witness stack is empty MUST be rejected at deserialization.
##   Before the fix nimrod silently accepted this encoding and produced a tx
##   object with witnesses = @[@[]] (one empty stack), treating it the same as
##   the legacy serialization → consensus split on txid/wtxid.
##
## Finding B — segwit-active no-commitment witness scan (validation.nim)
##   Bitcoin Core validation.cpp:3903-3913:
##     The scan "No witness data is allowed in blocks that don't commit to
##     witness data" runs whenever the commitment block is NOT found,
##     regardless of whether segwit is active.
##   Before the fix nimrod ran this scan ONLY in the segwit-inactive else
##   branch.  When segwit was active AND no 0xaa21a9ed commitment was present
##   nimrod returned ok() without scanning → a block with witness-carrying
##   non-coinbase txs and a coinbase lacking the commitment was ACCEPTED.
##
## Reference: bitcoin-core/src/primitives/transaction.h:228-231 (Finding D)
##            bitcoin-core/src/validation.cpp:3903-3913   (Finding B)
##            bitcoin-core/src/validation.cpp:3864-3916   (full function)

import unittest2
import ../src/primitives/[types, serialize]
import ../src/consensus/[validation, params]
import ../src/crypto/hashing

# ---------------------------------------------------------------------------
# Helpers shared by both suites
# ---------------------------------------------------------------------------

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    var nib: int
    let c = s[i * 2]
    if c >= '0' and c <= '9': nib = ord(c) - ord('0')
    elif c >= 'a' and c <= 'f': nib = ord(c) - ord('a') + 10
    elif c >= 'A' and c <= 'F': nib = ord(c) - ord('A') + 10
    let c2 = s[i * 2 + 1]
    if c2 >= '0' and c2 <= '9': nib = nib * 16 + ord(c2) - ord('0')
    elif c2 >= 'a' and c2 <= 'f': nib = nib * 16 + ord(c2) - ord('a') + 10
    elif c2 >= 'A' and c2 <= 'F': nib = nib * 16 + ord(c2) - ord('A') + 10
    result[i] = byte(nib)

proc makeCoinbase(extraWitness: seq[seq[byte]] = @[]): Transaction =
  ## Minimal coinbase tx.
  var cb = Transaction(
    version: 1,
    inputs: @[TxIn(
      prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
      scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
      sequence: 0xFFFFFFFF'u32
    )],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: @[0x51'u8])],
    witnesses: @[],
    lockTime: 0
  )
  if extraWitness.len > 0:
    cb.witnesses = @[extraWitness]
  cb

proc makeBlock(txs: seq[Transaction]): Block =
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))
  Block(
    header: BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1700000000'u32,
      bits: 0x207fffff'u32,
      nonce: 0'u32
    ),
    txs: txs
  )

# ---------------------------------------------------------------------------
# Finding D: Superfluous witness record
# ---------------------------------------------------------------------------

suite "Finding D — Superfluous witness record at deserialization":

  test "D1: canonical 63-byte all-empty-witness tx MUST be rejected":
    ## This is the exact test vector from the finding description.
    ## The tx has segwit marker 0x00 + flag 0x01, one input, one output,
    ## and a witness section with a single 0x00 (empty stack for input 0).
    ## Bitcoin Core rejects this as "Superfluous witness record".
    ## Pre-fix nimrod silently accepted it.
    let txHex = "0100000000010100000000000000000000000000000000000000000000000000000000000000000000000000ffffffff0100f2052a01000000000000000000"
    let txBytes = hexToBytes(txHex)
    check txBytes.len == 63  # sanity

    expect SerializationError:
      discard deserializeTransaction(txBytes)

  test "D2: segwit tx with at least one non-empty stack is ACCEPTED":
    ## Control case: a tx with the segwit marker set and a real non-empty
    ## witness item must continue to parse successfully.
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
      witnesses: @[@[@[0xca'u8, 0xfe'u8]]],  # one non-empty item
      lockTime: 0
    )
    let serialized = serialize(tx)
    # marker+flag must be present
    check serialized[4] == 0x00
    check serialized[5] == 0x01
    # must round-trip without error
    let decoded = deserializeTransaction(serialized)
    check decoded.witnesses.len == 1
    check decoded.witnesses[0].len == 1
    check decoded.witnesses[0][0] == @[0xca'u8, 0xfe'u8]

  test "D3: two inputs, both empty witness stacks → rejected":
    ## Multi-input variant: marker+flag present, two inputs, both witness
    ## stacks empty.  Must raise SerializationError.
    ##
    ## Build the encoding by hand:
    ##   version (4) + marker(1) + flag(1) + varint(2 inputs) +
    ##   input0 (41) + input1 (41) + varint(0 outputs) +
    ##   witness0 (varint 0 items = 0x00) + witness1 (0x00) +
    ##   locktime (4)
    var w = BinaryWriter()
    w.writeInt32LE(1)         # version
    w.writeUint8(0x00)        # marker
    w.writeUint8(0x01)        # flag
    w.writeCompactSize(2)     # 2 inputs
    # input 0: null outpoint, empty scriptSig, sequence 0xffffffff
    for _ in 0 ..< 32: w.writeUint8(0x00)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)
    w.writeUint32LE(0xFFFFFFFF'u32)
    # input 1: same
    for _ in 0 ..< 32: w.writeUint8(0x00)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)     # 0 outputs
    # witness for input 0: 0 items
    w.writeCompactSize(0)
    # witness for input 1: 0 items
    w.writeCompactSize(0)
    w.writeUint32LE(0)        # locktime

    expect SerializationError:
      discard deserializeTransaction(w.data)

  test "D4: two inputs, one empty + one non-empty witness → ACCEPTED":
    ## Only one input needs a non-empty stack for HasWitness() to be true.
    var w = BinaryWriter()
    w.writeInt32LE(1)
    w.writeUint8(0x00)
    w.writeUint8(0x01)
    w.writeCompactSize(2)
    for _ in 0 ..< 32: w.writeUint8(0x00)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)
    w.writeUint32LE(0xFFFFFFFF'u32)
    for _ in 0 ..< 32: w.writeUint8(0x00)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)
    w.writeUint32LE(0xFFFFFFFF'u32)
    w.writeCompactSize(0)  # 0 outputs
    # witness input 0: 0 items (empty)
    w.writeCompactSize(0)
    # witness input 1: 1 item, 2 bytes
    w.writeCompactSize(1)
    w.writeVarBytes(@[0xde'u8, 0xad'u8])
    w.writeUint32LE(0)

    let decoded = deserializeTransaction(w.data)
    check decoded.inputs.len == 2
    check decoded.witnesses.len == 2
    check decoded.witnesses[0].len == 0   # empty
    check decoded.witnesses[1].len == 1   # non-empty

# ---------------------------------------------------------------------------
# Finding B: segwit-active + no commitment → scan must still reject witnesses
# ---------------------------------------------------------------------------

suite "Finding B — segwit-active no-commitment witness scan":

  test "B1: segwit active, no commitment, non-coinbase tx has witness → unexpected-witness":
    ## This is the core regression: before the fix, nimrod accepted this block.
    ## Core validation.cpp:3903-3913 rejects it regardless of segwit-active/inactive.
    let cb = makeCoinbase()  # no commitment output, no witness
    var tx2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
      witnesses: @[@[@[0xca'u8, 0xfe'u8]]],  # non-empty witness, no commitment
      lockTime: 0
    )
    let blk = makeBlock(@[cb, tx2])
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veUnexpectedWitness

  test "B2: segwit active, no commitment, coinbase has witness → unexpected-witness":
    ## Same bug, but the coinbase itself carries a witness while there is
    ## no 0xaa21a9ed commitment output in the coinbase.
    var cb = makeCoinbase()
    cb.witnesses = @[@[@[0x00'u8]]]  # non-empty witness on coinbase, no commitment
    let blk = makeBlock(@[cb])
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check (not res.isOk)
    check res.error == veUnexpectedWitness

  test "B3: segwit active, no commitment, NO witness data anywhere → OK":
    ## Sanity check: blocks with no witness data and no commitment remain valid
    ## (G10 from the original comment: "no commitment present → no error").
    ## This test must PASS to confirm we have not over-corrected.
    let cb = makeCoinbase()
    let blk = makeBlock(@[cb])
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

  test "B4: segwit inactive, no commitment, non-coinbase tx has witness → unexpected-witness":
    ## Pre-existing G11 coverage retained: the scan must also fire when segwit
    ## is inactive.
    let cb = makeCoinbase()
    var tx2 = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0'u32),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[0x51'u8])],
      witnesses: @[@[@[0x01'u8]]],
      lockTime: 0
    )
    let blk = makeBlock(@[cb, tx2])
    let res = checkWitnessMalleation(blk, segwitActive = false)
    check (not res.isOk)
    check res.error == veUnexpectedWitness

  test "B5: segwit active, valid commitment + nonce → OK (early-return path still works)":
    ## The early-return after a successful commitment check must still fire;
    ## otherwise the scan would wrongly reject a block where the coinbase
    ## witness happens to look like witness-without-commitment.
    const WitnessMagic: array[6, byte] = [0x6a'u8, 0x24, 0xaa, 0x21, 0xa9, 0xed]
    let nonce = default(array[32, byte])
    var cb = makeCoinbase()
    # Build correct commitment for a single-coinbase block.
    var wtxids: seq[array[32, byte]]
    wtxids.add(default(array[32, byte]))  # coinbase wtxid = zeros
    let commitment = computeWitnessCommitment(wtxids, nonce)
    var commitScript: seq[byte] = @WitnessMagic
    commitScript.add(@commitment)
    cb.outputs.add(TxOut(value: Satoshi(0), scriptPubKey: commitScript))
    cb.witnesses = @[@[@nonce]]  # valid 32-byte nonce
    let blk = makeBlock(@[cb])
    let res = checkWitnessMalleation(blk, segwitActive = true)
    check res.isOk

when isMainModule:
  echo "Running witness consensus fix regression tests..."
