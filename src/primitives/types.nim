## Core Bitcoin primitive types
## Uses distinct types for type safety without runtime cost

import std/strutils
import std/sequtils

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

# Borrow operators for BlockHash
proc `==`*(a, b: BlockHash): bool {.borrow.}
proc `$`*(a: BlockHash): string =
  result = ""
  for i in countdown(31, 0):
    result.add(toHex(array[32, byte](a)[i], 2).toLowerAscii)

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
