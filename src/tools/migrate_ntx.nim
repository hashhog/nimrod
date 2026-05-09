## migrate_ntx.nim — One-shot backfill of BlockIndex.nTx from cfTxIndex.
##
## Usage (node MUST be stopped first):
##   nim c -d:release --path:. -o:bin/migrate_ntx src/tools/migrate_ntx.nim
##   ./bin/migrate_ntx <chainstate-path>

import std/[os, strutils, tables, times]
import ../storage/[chainstate, db]
import ../primitives/[types, serialize]

proc toHexStr(b: openArray[byte]): string =
  const hx = "0123456789abcdef"
  result = newStringOfCap(b.len * 2)
  for x in b:
    result.add(hx[(x shr 4) and 0xf])
    result.add(hx[x and 0xf])

proc main() =
  if paramCount() < 1:
    echo "Usage: migrate_ntx <chainstate-db-path>"
    quit(1)

  let dbPath = paramStr(1)
  echo "Opening RocksDB at: ", dbPath

  let cdb = openChainDb(dbPath)

  echo "Phase 1: Scanning cfTxIndex for max txIndex per block..."
  let t0 = epochTime()

  var maxTxIdx: Table[string, int32]  # blockHash hex → max txIndex seen
  var scanned = 0'i64

  for (key, value) in cdb.db.iterCf(cfTxIndex):
    inc scanned
    if scanned mod 5_000_000 == 0:
      stdout.write("  " & $(scanned div 1_000_000) & "M txs, " &
                   maxTxIdx.len.`$` & " blocks, " &
                   (epochTime() - t0).int.`$` & "s elapsed\n")
      stdout.flushFile()

    if value.len < 36:
      continue

    # TxLocation value: 32 bytes blockHash (LE stored hash) + 4 bytes txIndex LE
    let txIdx = int32(
      uint32(value[32]) or
      (uint32(value[33]) shl 8) or
      (uint32(value[34]) shl 16) or
      (uint32(value[35]) shl 24)
    )
    let bhKey = toHexStr(value[0 .. 31])
    let cur = maxTxIdx.getOrDefault(bhKey, -1'i32)
    if txIdx > cur:
      maxTxIdx[bhKey] = txIdx

  echo "Phase 1: ", scanned, " txs, ", maxTxIdx.len, " blocks in ",
       (epochTime()-t0).int, "s"

  echo "Phase 2: Updating BlockIndex nTx..."
  var updated, already, nodata = 0

  let batch = cdb.db.newWriteBatch()

  for (key, value) in cdb.db.iterCf(cfBlockIndex):
    if key.len != 32:
      continue  # Skip 4-byte height→hash entries

    var idx = deserializeBlockIndex(value)
    if idx.nTx != 0:
      inc already
      continue

    let bhKey = toHexStr(key)
    if bhKey notin maxTxIdx:
      inc nodata
      continue

    idx.nTx = maxTxIdx[bhKey] + 1
    batch.put(cfBlockIndex, key, serializeBlockIndex(idx))
    inc updated

  cdb.db.write(batch)
  batch.destroy()

  echo "Phase 2: updated=", updated, " already=", already, " noData=", nodata
  echo "Total: ", (epochTime()-t0).int, "s"

main()
