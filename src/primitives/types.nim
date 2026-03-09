## Core Bitcoin primitive types
## Uses distinct types for type safety without runtime cost

type
  TxId* = distinct array[32, byte]
  BlockHash* = distinct array[32, byte]
  ScriptBytes* = distinct seq[byte]
  CompactSize* = distinct uint64
  Satoshi* = distinct int64

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

# ScriptBytes helpers
proc len*(s: ScriptBytes): int {.borrow.}
proc `[]`*(s: ScriptBytes, i: int): byte =
  seq[byte](s)[i]

# Bitcoin protocol structures
type
  OutPoint* = object
    txid*: TxId
    vout*: uint32

  TxIn* = object
    prevout*: OutPoint
    scriptSig*: ScriptBytes
    sequence*: uint32

  TxOut* = object
    value*: Satoshi
    scriptPubKey*: ScriptBytes

  Transaction* = object
    version*: int32
    inputs*: seq[TxIn]
    outputs*: seq[TxOut]
    lockTime*: uint32

  BlockHeader* = object
    version*: int32
    prevHash*: BlockHash
    merkleRoot*: array[32, byte]
    timestamp*: uint32
    bits*: uint32
    nonce*: uint32

  Block* = object
    header*: BlockHeader
    transactions*: seq[Transaction]

# Import for toHex
import std/strutils

# Constants
const
  COIN* = Satoshi(100_000_000)
  MAX_MONEY* = Satoshi(21_000_000 * 100_000_000)

proc toSatoshi*(btc: float): Satoshi =
  Satoshi(int64(btc * 100_000_000))

proc toBtc*(s: Satoshi): float =
  float(int64(s)) / 100_000_000
