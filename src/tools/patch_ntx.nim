## patch_ntx.nim — Patch nTx for specific blocks in the block index.
##
## Usage (node MUST be stopped first):
##   nim c -d:release --path:src -o:bin/patch_ntx src/tools/patch_ntx.nim
##   ./bin/patch_ntx <chainstate-path> <hash-hex> <ntx> [<hash-hex> <ntx>...]
##
## Example for W57 corpus blocks:
##   ./bin/patch_ntx /data/.../chainstate \
##     00000000839a8e... 1 \
##     000000000000048b... 457 \
##     ...

import std/[os, strutils, parseutils]
import ../storage/[chainstate, db]
import ../primitives/[types, serialize]

proc hexToBytes32Display(displayHex: string): array[32, byte] =
  ## Convert a display-format block hash (big-endian reversed) to internal
  ## byte order (little-endian, as stored in RocksDB).
  ## Display: "00000000839a8e..." → internal: reversed byte array.
  for i in 0 ..< 32:
    result[31 - i] = byte(parseHexInt(displayHex[i*2 .. i*2+1]))

proc main() =
  if paramCount() < 3 or (paramCount() - 1) mod 2 != 0:
    echo "Usage: patch_ntx <chainstate-path> <hash> <nTx> [<hash> <nTx>...]"
    quit(1)

  let dbPath = paramStr(1)
  echo "Opening chainstate at: ", dbPath

  let cdb = openChainDb(dbPath)

  var i = 2
  while i <= paramCount() - 1:
    let hashHex = paramStr(i)
    let ntx     = parseInt(paramStr(i + 1))
    i += 2

    let hashBytes = hexToBytes32Display(hashHex)
    let key = @hashBytes  # blockKey uses raw 32-byte internal-order hash

    let dataOpt = cdb.db.get(cfBlockIndex, key)
    if dataOpt.isNone:
      echo "  WARN: BlockIndex not found for ", hashHex[0..15], "..."
      continue

    var idx = deserializeBlockIndex(dataOpt.get())
    let oldNtx = idx.nTx
    idx.nTx = int32(ntx)

    let batch = cdb.db.newWriteBatch()
    batch.put(cfBlockIndex, key, serializeBlockIndex(idx))
    cdb.db.write(batch)
    batch.destroy()

    echo "  Patched ", hashHex[0..15], "... nTx: ", oldNtx, " -> ", ntx

  echo "Done."

main()
