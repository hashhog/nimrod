## Measurement harness: real per-entry memory cost of the IBD UTXO cache.
##
## Why this exists: `EstimatedEntryBytes` drives `evictCleanEntries`, the ONLY
## bound on the UTXO cache during IBD. If the constant underestimates the true
## cost, the computed cache size stays below the ceiling forever, eviction
## never fires, and RSS grows unbounded until the host OOMs. That is exactly
## what happened on the 2026-08-15 mainnet genesis rig (36.8M entries, 37 GiB
## RSS against a configured --dbcache=8192, eviction never fired once in 14
## flushes).
##
## This is NOT a unit test — it is a measurement tool. Run it to re-derive the
## constant when the entry types or the Nim allocator change:
##   nim c -d:release -r tests/measure_utxo_entry_bytes.nim
##
## It reports the MARGINAL cost per entry (RSS delta / entries added), which is
## the quantity eviction actually needs — fixed process overhead is irrelevant
## to "how much does one more coin cost me".

import std/[tables, strformat, strutils]
import ../src/primitives/types

proc rssBytes(): int =
  ## Resident set size of this process, in bytes.
  for line in lines("/proc/self/status"):
    if line.startsWith("VmRSS:"):
      let parts = line.splitWhitespace()
      return parseInt(parts[1]) * 1024
  0

type UtxoEntryLike = object
  ## Mirror of storage/chainstate.nim UtxoEntry (kept structurally identical;
  ## importing chainstate would drag in RocksDB for a pure-memory measurement).
  output: TxOut
  height: int32
  isCoinbase: bool

proc makeScript(kind: int): seq[byte] =
  ## Realistic mainnet output scripts by prevalence.
  case kind mod 4
  of 0: newSeq[byte](22)  # P2WPKH  — OP_0 <20>
  of 1: newSeq[byte](25)  # P2PKH   — DUP HASH160 <20> EQUALVERIFY CHECKSIG
  of 2: newSeq[byte](34)  # P2TR/P2WSH — OP_1 <32>
  else: newSeq[byte](23)  # P2SH    — HASH160 <20> EQUAL

proc main() =
  const N = 2_000_000
  var t = initTable[OutPoint, UtxoEntryLike]()

  # Touch the table once so its initial allocation is not counted as marginal.
  var warm: array[32, byte]
  warm[0] = 1
  t[OutPoint(txid: TxId(warm), vout: 0)] =
    UtxoEntryLike(output: TxOut(value: Satoshi(1), scriptPubKey: makeScript(0)),
                  height: 1, isCoinbase: false)

  let before = rssBytes()

  for i in 1 .. N:
    var raw: array[32, byte]
    # Spread keys across the hash space the way real txids do.
    raw[0] = byte(i and 0xff)
    raw[1] = byte((i shr 8) and 0xff)
    raw[2] = byte((i shr 16) and 0xff)
    raw[3] = byte((i shr 24) and 0xff)
    t[OutPoint(txid: TxId(raw), vout: uint32(i and 0x3))] =
      UtxoEntryLike(
        output: TxOut(value: Satoshi(i), scriptPubKey: makeScript(i)),
        height: int32(i mod 900_000),
        isCoinbase: (i mod 1000 == 0))

  let after = rssBytes()
  let perEntry = (after - before) div N

  echo &"entries inserted : {N}"
  echo &"RSS before       : {before div (1024*1024)} MiB"
  echo &"RSS after        : {after div (1024*1024)} MiB"
  echo &"RSS delta        : {(after - before) div (1024*1024)} MiB"
  echo &"MARGINAL BYTES/ENTRY : {perEntry}"
  echo ""
  echo &"table len        : {t.len}"
  echo "(compare against EstimatedEntryBytes in src/storage/chainstate.nim)"

main()
