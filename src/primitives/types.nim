## Core Bitcoin primitive types
## Uses distinct types for type safety without runtime cost

import std/strutils
import std/sequtils
import std/hashes

type
  TxId* = distinct array[32, byte]
  BlockHash* = distinct array[32, byte]
  Satoshi* = distinct int64

  SerializationError* = object of CatchableError

# Borrow operators for TxId
proc `==`*(a, b: TxId): bool {.borrow.}
proc `$`*(a: TxId): string =
  result = ""
  for i in countdown(31, 0):
    result.add(toHex(array[32, byte](a)[i], 2).toLowerAscii)

proc hash*(a: TxId): Hash =
  ## Hash function for TxId (for use in Tables)
  hash(array[32, byte](a))

# Borrow operators for BlockHash
proc `==`*(a, b: BlockHash): bool {.borrow.}
proc `$`*(a: BlockHash): string =
  result = ""
  for i in countdown(31, 0):
    result.add(toHex(array[32, byte](a)[i], 2).toLowerAscii)

proc hash*(a: BlockHash): Hash =
  ## Hash function for BlockHash (for use in Tables)
  hash(array[32, byte](a))

# Borrow operators for Satoshi
proc `==`*(a, b: Satoshi): bool {.borrow.}
proc `<`*(a, b: Satoshi): bool {.borrow.}
proc `<=`*(a, b: Satoshi): bool {.borrow.}
proc `+`*(a, b: Satoshi): Satoshi {.borrow.}
proc `-`*(a, b: Satoshi): Satoshi {.borrow.}

# Bitcoin protocol structures
type
  OutPoint* = object
    txid*: TxId
    vout*: uint32

  TxIn* = object
    prevOut*: OutPoint
    scriptSig*: seq[byte]
    sequence*: uint32

  TxOut* = object
    value*: Satoshi
    scriptPubKey*: seq[byte]

  Transaction* = object
    version*: int32
    inputs*: seq[TxIn]
    outputs*: seq[TxOut]
    witnesses*: seq[seq[seq[byte]]]  ## Per-input witness stacks
    lockTime*: uint32

  BlockHeader* = object
    version*: int32
    prevBlock*: BlockHash
    merkleRoot*: array[32, byte]
    timestamp*: uint32
    bits*: uint32
    nonce*: uint32

  Block* = object
    header*: BlockHeader
    txs*: seq[Transaction]

# Constants
const
  COIN* = Satoshi(100_000_000)
  # Note: MaxMoney is defined in consensus/params.nim to avoid duplication

proc toSatoshi*(btc: float): Satoshi =
  Satoshi(int64(btc * 100_000_000))

proc toBtc*(s: Satoshi): float =
  float(int64(s)) / 100_000_000

proc isSegwit*(tx: Transaction): bool =
  ## Returns true if transaction has witness data
  tx.witnesses.len > 0 and tx.witnesses.anyIt(it.len > 0)

const
  ## MAX_SCRIPT_SIZE matches Bitcoin Core's `script.h:40` (= 10000). Outputs
  ## with a scriptPubKey larger than this are treated as provably unspendable
  ## and never enter the chainstate UTXO set.
  MaxScriptSizeBytes* = 10_000

proc isUnspendable*(scriptPubKey: openArray[byte]): bool {.inline.} =
  ## Mirrors `CScript::IsUnspendable()` in `bitcoin-core/src/script/script.h`:
  ##   return (size() > 0 && *begin() == OP_RETURN) || (size() > MAX_SCRIPT_SIZE);
  ##
  ## NOTE: empty scripts are NOT unspendable per Core (size() > 0 guard).
  ## OP_RETURN = 0x6a. Used by chainstate population (connectBlock /
  ## connectBlockIBD / applyBlock) and by createSnapshot as a defensive
  ## filter for legacy datadirs that may have OP_RETURN coins persisted.
  (scriptPubKey.len > 0 and scriptPubKey[0] == 0x6a'u8) or
    scriptPubKey.len > MaxScriptSizeBytes

func utxoMapKey*(txid: array[32, byte], vout: uint32): string {.inline.} =
  ## Compact BINARY key for the in-memory intra-block UTXO maps
  ## (validation / chainstate / undo).  36 bytes: 32-byte txid + 4-byte
  ## little-endian vout.
  ##
  ## PERF (2026-08-27): the previous idiom was
  ##   `$array[32, byte](txid) & ":" & $vout`
  ## which renders the txid through Nim's array `$` as a DECIMAL LIST —
  ## "[12, 45, 200, ...]" — roughly 160 characters, allocated and then hashed
  ## on EVERY outpoint insert and lookup.  On a modern ~1 MB block (≈4,400
  ## inputs) that dominated block validation: nimrod took >150 s where
  ## blockbrew took 0.43 s, haskoin 0.85 s and clearbit 2.72 s on the exact
  ## same block (distilled-corpus pack 419328).  These maps are function-local
  ## and NEVER persisted, so the encoding is free to change — no on-disk
  ## format implication.
  ##
  ## Injective, exactly like the string form: distinct (txid, vout) pairs map
  ## to distinct 36-byte keys.
  result = newString(36)
  for i in 0 ..< 32:
    result[i] = char(txid[i])
  result[32] = char(vout and 0xFF'u32)
  result[33] = char((vout shr 8) and 0xFF'u32)
  result[34] = char((vout shr 16) and 0xFF'u32)
  result[35] = char((vout shr 24) and 0xFF'u32)

func utxoMapKey*(txid: TxId, vout: uint32): string {.inline.} =
  utxoMapKey(array[32, byte](txid), vout)

func utxoMapKey*(txid: TxId, vout: int): string {.inline.} =
  utxoMapKey(array[32, byte](txid), uint32(vout))

func utxoMapKey*(txid: array[32, byte], vout: int): string {.inline.} =
  utxoMapKey(txid, uint32(vout))
