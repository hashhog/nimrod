## Bitcoin hashing functions
## SHA256, double-SHA256, RIPEMD160, and Hash160

import nimcrypto/[sha2, ripemd, hash]
import ../primitives/types

proc sha256*(data: openArray[byte]): array[32, byte] =
  var ctx: sha256
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

proc doubleSha256*(data: openArray[byte]): array[32, byte] =
  sha256(sha256(data))

proc ripemd160*(data: openArray[byte]): array[20, byte] =
  var ctx: ripemd160
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

proc hash160*(data: openArray[byte]): array[20, byte] =
  ## RIPEMD160(SHA256(data)) - used for Bitcoin addresses
  ripemd160(sha256(data))

proc txHash*(data: openArray[byte]): TxId =
  ## Compute transaction hash (double SHA256)
  TxId(doubleSha256(data))

proc blockHash*(data: openArray[byte]): BlockHash =
  ## Compute block header hash (double SHA256)
  BlockHash(doubleSha256(data))

proc merkleRoot*(hashes: seq[array[32, byte]]): array[32, byte] =
  ## Compute merkle root from a list of hashes
  if hashes.len == 0:
    return default(array[32, byte])

  if hashes.len == 1:
    return hashes[0]

  var level = hashes
  while level.len > 1:
    var nextLevel: seq[array[32, byte]]
    var i = 0
    while i < level.len:
      var combined: array[64, byte]
      copyMem(addr combined[0], addr level[i][0], 32)
      if i + 1 < level.len:
        copyMem(addr combined[32], addr level[i + 1][0], 32)
      else:
        # Duplicate last hash if odd number
        copyMem(addr combined[32], addr level[i][0], 32)
      nextLevel.add(doubleSha256(combined))
      i += 2
    level = nextLevel

  result = level[0]

proc computeMerkleRoot*(transactions: seq[array[32, byte]]): array[32, byte] =
  ## Compute merkle root from transaction hashes
  merkleRoot(transactions)
