## Bitcoin hashing functions
## SHA256, double-SHA256, RIPEMD160, and Hash160

import nimcrypto/[sha2, ripemd, hash]
import ../primitives/types

proc sha256Single*(data: openArray[byte]): array[32, byte] =
  ## Single SHA-256 hash
  var ctx: sha256
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

proc sha256*(data: openArray[byte]): array[32, byte] =
  ## Alias for sha256Single for compatibility
  sha256Single(data)

proc sha256d*(data: openArray[byte]): array[32, byte] =
  ## Double SHA-256 (Bitcoin standard)
  let first = sha256Single(data)
  sha256Single(first)

proc doubleSha256*(data: openArray[byte]): array[32, byte] =
  ## Alias for sha256d
  sha256d(data)

# ----------------------------------------------------------------------------
# Streaming double-SHA256 (Bitcoin Core's `HashWriter`)
#
# `bitcoin-core/src/hash.h::HashWriter::GetHash` accumulates bytes through a
# single `CSHA256` context, then on finalization runs `SHA256(SHA256(stream))`.
# Used by `CoinStatsHashType::HASH_SERIALIZED` (`coinstats.cpp:161-163`),
# which is what `loadtxoutset` checks the snapshot's UTXO content against
# (`validation.cpp:5901-5915`). MuHash3072 is a different code path
# (`gettxoutsetinfo hash_type=muhash`), NOT the assumeutxo strict gate.
# ----------------------------------------------------------------------------

type
  HashWriter* = object
    ctx: sha256

proc initHashWriter*(): HashWriter =
  result.ctx.init()

proc update*(hw: var HashWriter, data: openArray[byte]) =
  ## Feed bytes into the streaming SHA-256 context.
  hw.ctx.update(data)

proc finalizeHash*(hw: var HashWriter): array[32, byte] =
  ## Finalize as SHA256d (matches Core's `HashWriter::GetHash`):
  ##   first  = SHA256(stream)
  ##   result = SHA256(first)
  let first = hw.ctx.finish().data
  result = sha256Single(first)

proc ripemd160*(data: openArray[byte]): array[20, byte] =
  var ctx: ripemd160
  ctx.init()
  ctx.update(data)
  result = ctx.finish().data

proc hash160*(data: openArray[byte]): array[20, byte] =
  ## RIPEMD160(SHA256(data)) - used for Bitcoin addresses
  ripemd160(sha256(data))

# ----------------------------------------------------------------------------
# P2SH / P2WSH script-commitment verification (W31)
#
# Before a wallet signs a P2SH-wrapped or P2WSH input it MUST prove that the
# supplied redeemScript / witnessScript actually commits to the bytes of the
# scriptPubKey of the prevout. Skipping this check turns a forged
# redeemScript / witnessScript into a free signing oracle — the wallet would
# happily produce a signature against an attacker-chosen sighash.
#
# Reference: bitcoin-core/src/script/sign.cpp:ProduceSignature →
# the SignStep dispatch confirms `H160(redeem) == spk[2..21]` (TX_SCRIPTHASH)
# and `SHA256(witness) == spk[2..33]` (TX_WITNESS_V0_SCRIPTHASH) before
# calling SignSignature on the inner script. Camlcoin reference at
# `lib/wallet.ml:1262`: `Crypto.hash160 redeem |> Cstruct.equal script_hash`.
# ----------------------------------------------------------------------------

proc verifyP2SHCommitment*(redeemScript: openArray[byte],
                           p2shScriptPubKey: openArray[byte]): bool =
  ## True iff `p2shScriptPubKey` is a 23-byte
  ##   OP_HASH160 <0x14> <20-byte hash> OP_EQUAL
  ## and `hash160(redeemScript)` matches that 20-byte hash. Returns false
  ## (never raises) on any shape mismatch so callers can fail closed.
  if p2shScriptPubKey.len != 23: return false
  if p2shScriptPubKey[0] != 0xa9'u8: return false
  if p2shScriptPubKey[1] != 0x14'u8: return false
  if p2shScriptPubKey[22] != 0x87'u8: return false
  let h = hash160(redeemScript)
  for i in 0 ..< 20:
    if h[i] != p2shScriptPubKey[2 + i]: return false
  true

proc verifyP2WSHCommitment*(witnessScript: openArray[byte],
                            p2wshScriptPubKey: openArray[byte]): bool =
  ## True iff `p2wshScriptPubKey` is a 34-byte
  ##   OP_0 <0x20> <32-byte sha256>
  ## (native segwit-v0 P2WSH) and `sha256(witnessScript)` matches that
  ## 32-byte hash. Returns false on any shape mismatch.
  if p2wshScriptPubKey.len != 34: return false
  if p2wshScriptPubKey[0] != 0x00'u8: return false
  if p2wshScriptPubKey[1] != 0x20'u8: return false
  let h = sha256(witnessScript)
  for i in 0 ..< 32:
    if h[i] != p2wshScriptPubKey[2 + i]: return false
  true

proc verifyP2SHWrappedP2WSHCommitment*(witnessScript: openArray[byte],
                                       redeemScript: openArray[byte]): bool =
  ## True iff `redeemScript` is a 34-byte
  ##   OP_0 <0x20> <32-byte sha256>
  ## (the canonical P2SH-P2WSH redeemScript shape) and
  ## `sha256(witnessScript)` matches the embedded 32-byte hash.
  ##
  ## Combine with `verifyP2SHCommitment` to fully validate the
  ## scriptPubKey -> redeemScript -> witnessScript chain.
  if redeemScript.len != 34: return false
  if redeemScript[0] != 0x00'u8: return false
  if redeemScript[1] != 0x20'u8: return false
  let h = sha256(witnessScript)
  for i in 0 ..< 32:
    if h[i] != redeemScript[2 + i]: return false
  true

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
