## Sighash test harness using Bitcoin Core sighash.json test vectors
## Loads all vectors from ouroboros/bitcoin/src/test/data/sighash.json,
## deserializes each transaction, computes the legacy sighash, and
## compares the result against the expected hash.

import std/[strutils, json, os]
import ../src/script/sighash
import ../src/primitives/types
import ../src/primitives/serialize

# ---------- helpers ----------

proc hexToBytes(hex: string): seq[byte] =
  if hex.len == 0:
    return @[]
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i * 2 .. i * 2 + 1]))

proc bytesToHex(bytes: openArray[byte]): string =
  result = ""
  for b in bytes:
    result.add(b.toHex(2).toLowerAscii)

# ---------- main ----------

proc main() =
  let testDataPath = "/home/max/hashhog/ouroboros/bitcoin/src/test/data/sighash.json"
  if not fileExists(testDataPath):
    echo "FATAL: test vector file not found: ", testDataPath
    quit(1)

  let content = readFile(testDataPath)
  let jsonData = parseJson(content)

  var total = 0
  var passed = 0
  var failed = 0
  var skipped = 0

  for item in jsonData:
    if item.kind != JArray or item.len != 5:
      continue
    # Skip header row
    if item[0].kind == JString and item[0].getStr().startsWith("raw_"):
      continue

    let rawTxHex = item[0].getStr()
    let scriptHex = item[1].getStr()
    let inputIdx = item[2].getInt()
    let hashType = cast[uint32](int32(item[3].getInt()))
    let expectedHex = item[4].getStr()

    inc total

    # Deserialize transaction
    var tx: Transaction
    try:
      let txBytes = hexToBytes(rawTxHex)
      tx = deserializeTransaction(txBytes)
    except:
      echo "FAIL vector ", total - 1, ": deserialization error: ", getCurrentExceptionMsg()
      inc failed
      continue

    # Parse subscript
    let scriptCode = hexToBytes(scriptHex)

    # Compute legacy sighash
    let hash = computeLegacySighash(tx, inputIdx, scriptCode, hashType)

    # Bitcoin Core displays hashes in big-endian (reversed)
    var hashReversed: array[32, byte]
    for j in 0 ..< 32:
      hashReversed[j] = hash[31 - j]
    let computedHex = bytesToHex(hashReversed)

    if computedHex == expectedHex:
      inc passed
    else:
      echo "FAIL vector ", total - 1, ":"
      echo "  expected: ", expectedHex
      echo "  got:      ", computedHex
      inc failed

  echo ""
  echo "=== Sighash test vectors ==="
  echo "Total:   ", total
  echo "Passed:  ", passed
  echo "Failed:  ", failed
  if skipped > 0:
    echo "Skipped: ", skipped
  if failed == 0:
    echo "ALL PASSED"
  else:
    quit(1)

when isMainModule:
  main()
