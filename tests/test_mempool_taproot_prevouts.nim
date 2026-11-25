## Mempool script checks see every input's spent output (2026-11-24 Neon
## audit of nimrod, finding 4).
##
## A BIP-341 signature (any hash type without ANYONECANPAY) commits to the
## amounts and scriptPubKeys of ALL inputs (sha_amounts, sha_scriptpubkeys).
## Core's PolicyScriptChecks / ConsensusScriptChecks hand the interpreter the
## full spent-output list (PrecomputedTransactionData, validation.cpp:1182 in
## v31.1). nimrod's mempool called verifyScript with only the current input's
## amount and scriptPubKey, so verifyWitnessProgram filled the others with 0
## sats and an empty script and every valid key-path spend in a tx with two or
## more inputs failed "Invalid Schnorr signature". Block validation passes both
## arrays and was not affected.

import unittest2
import std/[options, os, tempfiles]
import ../src/mempool/mempool
import ../src/storage/chainstate
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, secp256k1]
import ../src/script/interpreter

const Coin = 5_000_000_000'i64

proc mkPriv(b: byte): PrivateKey =
  for i in 0 ..< 32: result[i] = 0
  result[31] = b

proc xonly(priv: PrivateKey): array[32, byte] =
  let c = derivePublicKey(priv)
  for i in 0 ..< 32: result[i] = c[1 + i]

proc p2tr(priv: PrivateKey): seq[byte] =
  ## Witness v1 program = the raw x-only key (no TapTweak); signSchnorr with
  ## merkleRoot = none signs for exactly this key.
  @[0x51'u8, 0x20] & @(xonly(priv))

proc p2shTrue(): seq[byte] =
  let h = hash160(@[0x51'u8])
  @[0xa9'u8, 0x14] & @h & @[0x87'u8]

proc coinbaseTx(height: int32, spk: seq[byte]): Transaction =
  Transaction(
    version: 1,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xFFFFFFFF'u32),
                   scriptSig: @[0x01'u8, byte(height and 0xff), 0x01, 0],
                   sequence: 0xFFFFFFFF'u32)],
    outputs: @[TxOut(value: Satoshi(Coin), scriptPubKey: spk)],
    witnesses: @[], lockTime: 0)

proc blockOf(prev: BlockHash, height: int32, txs: seq[Transaction]): Block =
  var hs: seq[array[32, byte]]
  for t in txs: hs.add(array[32, byte](t.txid()))
  Block(header: BlockHeader(version: 4, prevBlock: prev,
                            merkleRoot: merkleRoot(hs),
                            timestamp: 1296688602'u32 + uint32(height * 600),
                            bits: 0x207fffff'u32, nonce: uint32(height)),
        txs: txs)

type Fx = object
  dir: string
  cs: ChainState
  mp: Mempool
  cb: seq[Transaction]
  keys: seq[PrivateKey]

proc setup(): Fx =
  let params = regtestParams()
  result.dir = createTempDir("nimrod_neon_mempool_taproot_", "")
  result.cs = newChainState(result.dir / "db", params)
  var prev = BlockHash(default(array[32, byte]))
  for h in 0 .. 110:
    let k = mkPriv(byte(0x40 + (h mod 8)))
    let c = coinbaseTx(int32(h), p2tr(k))
    let blk = blockOf(prev, int32(h), @[c])
    doAssert result.cs.connectBlock(blk, int32(h)).isOk
    result.cb.add(c)
    result.keys.add(k)
    prev = BlockHash(doubleSha256(serialize(blk.header)))
  result.mp = newMempool(result.cs, params)

proc teardown(f: var Fx) =
  f.cs.close()
  removeDir(f.dir)

proc keyPathSpend(f: Fx, heights: seq[int], hashType: uint8 = 0x00): Transaction =
  ## Spend coinbase output 0 of each block in `heights` with BIP-341 key-path
  ## signatures over the full prevout set.
  var tx = Transaction(version: 2, lockTime: 0)
  var amounts: seq[Satoshi]
  var spks: seq[seq[byte]]
  for h in heights:
    tx.inputs.add TxIn(prevOut: OutPoint(txid: f.cb[h].txid(), vout: 0),
                       scriptSig: @[], sequence: 0xFFFFFFFD'u32)
    amounts.add Satoshi(Coin)
    spks.add f.cb[h].outputs[0].scriptPubKey
  tx.outputs = @[TxOut(value: Satoshi(Coin * int64(heights.len) - 50_000),
                       scriptPubKey: p2shTrue())]
  tx.witnesses = newSeq[seq[seq[byte]]](heights.len)
  for i, h in heights:
    let sighash = computeSighashTaproot(tx, i, amounts, spks, hashType)
    var sig = @(signSchnorr(f.keys[h], sighash, none(array[32, byte])))
    if hashType != 0x00: sig.add hashType
    tx.witnesses[i] = @[sig]
  tx

suite "N4 mempool taproot key-path spends commit to every input's prevout":
  test "N4a: two P2TR inputs, SIGHASH_DEFAULT: accepted like Core":
    var f = setup()
    defer: f.teardown()
    let tx = f.keyPathSpend(@[1, 2])
    let r = f.mp.acceptTransaction(tx, newCryptoEngine())
    if not r.isOk: checkpoint r.error
    check r.isOk

  test "N4b: three P2TR inputs, SIGHASH_ALL: accepted like Core":
    var f = setup()
    defer: f.teardown()
    let tx = f.keyPathSpend(@[3, 4, 5], 0x01)
    let r = f.mp.acceptTransaction(tx, newCryptoEngine())
    if not r.isOk: checkpoint r.error
    check r.isOk

  test "N4c: control: a single P2TR input is accepted":
    var f = setup()
    defer: f.teardown()
    let tx = f.keyPathSpend(@[6])
    let r = f.mp.acceptTransaction(tx, newCryptoEngine())
    if not r.isOk: checkpoint r.error
    check r.isOk

  test "N4d: control: a wrong prevout amount in the signed message is still rejected":
    var f = setup()
    defer: f.teardown()
    var tx = f.keyPathSpend(@[7, 8])
    # Re-sign input 0 claiming input 1 holds 1 sat less: the real prevout set
    # no longer matches, so the signature must fail.
    let sighash = computeSighashTaproot(tx, 0, @[Satoshi(Coin), Satoshi(Coin - 1)],
      @[f.cb[7].outputs[0].scriptPubKey, f.cb[8].outputs[0].scriptPubKey], 0x00)
    tx.witnesses[0] = @[@(signSchnorr(f.keys[7], sighash, none(array[32, byte])))]
    let r = f.mp.acceptTransaction(tx, newCryptoEngine())
    check not r.isOk
