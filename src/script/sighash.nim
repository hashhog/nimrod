## Bitcoin legacy sighash computation
## Implements FindAndDelete, OP_CODESEPARATOR handling, and all sighash modes
## Reference: Bitcoin Core script/interpreter.cpp SignatureHash()

import ../primitives/types
import ../primitives/serialize
import ../crypto/hashing

const
  SIGHASH_ALL* = 0x01'u32
  SIGHASH_NONE* = 0x02'u32
  SIGHASH_SINGLE* = 0x03'u32
  SIGHASH_ANYONECANPAY* = 0x80'u32
  SIGHASH_MASK* = 0x1f'u32

  OP_CODESEPARATOR* = 0xab'u8
  OP_PUSHDATA1* = 0x4c'u8
  OP_PUSHDATA2* = 0x4d'u8
  OP_PUSHDATA4* = 0x4e'u8

# FindAndDelete: Remove all occurrences of a signature from scriptCode
# This is critical for legacy sighash computation
# The signature is push-encoded (length prefix + data)
proc findAndDelete*(script: seq[byte], sig: seq[byte]): seq[byte] =
  ## Remove all occurrences of push-encoded sig from script
  ## This is Bitcoin Core's FindAndDelete algorithm
  ## It matches at opcode boundaries, not arbitrary byte positions
  if sig.len == 0:
    return script

  # Build the push-encoded signature we're looking for
  var pushEncodedSig: seq[byte]
  if sig.len <= 75:
    pushEncodedSig.add(byte(sig.len))
    pushEncodedSig.add(sig)
  elif sig.len <= 255:
    pushEncodedSig.add(OP_PUSHDATA1)
    pushEncodedSig.add(byte(sig.len))
    pushEncodedSig.add(sig)
  elif sig.len <= 65535:
    pushEncodedSig.add(OP_PUSHDATA2)
    pushEncodedSig.add(byte(sig.len and 0xff))
    pushEncodedSig.add(byte((sig.len shr 8) and 0xff))
    pushEncodedSig.add(sig)
  else:
    pushEncodedSig.add(OP_PUSHDATA4)
    pushEncodedSig.add(byte(sig.len and 0xff))
    pushEncodedSig.add(byte((sig.len shr 8) and 0xff))
    pushEncodedSig.add(byte((sig.len shr 16) and 0xff))
    pushEncodedSig.add(byte((sig.len shr 24) and 0xff))
    pushEncodedSig.add(sig)

  # Walk through script at opcode boundaries, skipping matches
  result = @[]
  var i = 0
  var lastCopyPos = 0

  while i < script.len:
    # Check if we have a match at this position
    if i + pushEncodedSig.len <= script.len:
      var matches = true
      for j in 0 ..< pushEncodedSig.len:
        if script[i + j] != pushEncodedSig[j]:
          matches = false
          break
      if matches:
        # Copy everything before the match
        for j in lastCopyPos ..< i:
          result.add(script[j])
        # Skip the match
        i += pushEncodedSig.len
        lastCopyPos = i
        continue

    # Skip this opcode
    let opcode = script[i]
    if opcode >= 0x01 and opcode <= 0x4b:
      # Direct push 1-75 bytes
      i += 1 + int(opcode)
    elif opcode == OP_PUSHDATA1 and i + 1 < script.len:
      let pushLen = int(script[i + 1])
      i += 2 + pushLen
    elif opcode == OP_PUSHDATA2 and i + 2 < script.len:
      let pushLen = int(script[i + 1]) or (int(script[i + 2]) shl 8)
      i += 3 + pushLen
    elif opcode == OP_PUSHDATA4 and i + 4 < script.len:
      let pushLen = int(script[i + 1]) or (int(script[i + 2]) shl 8) or
                    (int(script[i + 3]) shl 16) or (int(script[i + 4]) shl 24)
      i += 5 + pushLen
    else:
      i += 1

  # Copy remaining bytes
  for j in lastCopyPos ..< script.len:
    result.add(script[j])

# Remove all OP_CODESEPARATOR opcodes from script
proc removeCodeSeparators*(script: seq[byte]): seq[byte] =
  ## Remove all OP_CODESEPARATOR (0xab) opcodes from script
  ## Used in legacy sighash computation
  result = @[]
  var i = 0

  while i < script.len:
    let opcode = script[i]

    if opcode == OP_CODESEPARATOR:
      # Skip this opcode
      i += 1
      continue

    # Copy opcode and its data
    if opcode >= 0x01 and opcode <= 0x4b:
      # Direct push 1-75 bytes
      let pushLen = int(opcode)
      if i + 1 + pushLen <= script.len:
        for j in 0 .. pushLen:
          result.add(script[i + j])
      i += 1 + pushLen
    elif opcode == OP_PUSHDATA1 and i + 1 < script.len:
      let pushLen = int(script[i + 1])
      if i + 2 + pushLen <= script.len:
        for j in 0 ..< 2 + pushLen:
          result.add(script[i + j])
      i += 2 + pushLen
    elif opcode == OP_PUSHDATA2 and i + 2 < script.len:
      let pushLen = int(script[i + 1]) or (int(script[i + 2]) shl 8)
      if i + 3 + pushLen <= script.len:
        for j in 0 ..< 3 + pushLen:
          result.add(script[i + j])
      i += 3 + pushLen
    elif opcode == OP_PUSHDATA4 and i + 4 < script.len:
      let pushLen = int(script[i + 1]) or (int(script[i + 2]) shl 8) or
                    (int(script[i + 3]) shl 16) or (int(script[i + 4]) shl 24)
      if i + 5 + pushLen <= script.len:
        for j in 0 ..< 5 + pushLen:
          result.add(script[i + j])
      i += 5 + pushLen
    else:
      result.add(opcode)
      i += 1

# Get subscript starting after last OP_CODESEPARATOR
proc getSubscriptAfterCodeSeparator*(script: seq[byte], codesepPos: uint32): seq[byte] =
  ## Get the portion of script starting after the last OP_CODESEPARATOR
  ## codesepPos is the position AFTER the OP_CODESEPARATOR (or 0xFFFFFFFF if none)
  if codesepPos == 0xFFFFFFFF'u32 or int(codesepPos) > script.len:
    return script
  return script[int(codesepPos) ..< script.len]

# Legacy sighash computation
proc computeLegacySighash*(
  tx: Transaction,
  inputIndex: int,
  subscript: seq[byte],
  hashType: uint32
): array[32, byte] =
  ## Compute legacy (pre-segwit) sighash
  ## subscript should already have FindAndDelete applied and start after OP_CODESEPARATOR

  let baseType = hashType and SIGHASH_MASK
  let anyoneCanPay = (hashType and SIGHASH_ANYONECANPAY) != 0

  # Handle SIGHASH_SINGLE with out-of-range input index
  if baseType == SIGHASH_SINGLE:
    if inputIndex >= tx.outputs.len:
      # Return hash of 1 followed by 0s (uint256 == 1)
      var specialHash: array[32, byte]
      specialHash[0] = 1
      return specialHash

  var w = BinaryWriter()

  # Write version
  w.writeInt32LE(tx.version)

  # Write inputs
  if anyoneCanPay:
    # Only the input being signed
    w.writeCompactSize(1)
    w.writeOutPoint(tx.inputs[inputIndex].prevOut)
    # Write subscript with OP_CODESEPARATORs removed
    let cleanSubscript = removeCodeSeparators(subscript)
    w.writeVarBytes(cleanSubscript)
    w.writeUint32LE(tx.inputs[inputIndex].sequence)
  else:
    # All inputs
    w.writeCompactSize(uint64(tx.inputs.len))
    for i in 0 ..< tx.inputs.len:
      w.writeOutPoint(tx.inputs[i].prevOut)

      if i == inputIndex:
        # The input being signed: use subscript with OP_CODESEPARATORs removed
        let cleanSubscript = removeCodeSeparators(subscript)
        w.writeVarBytes(cleanSubscript)
      else:
        # Other inputs: empty scriptSig
        w.writeVarBytes(@[])

      # For SIGHASH_NONE and SIGHASH_SINGLE, other inputs get sequence 0
      if i != inputIndex and (baseType == SIGHASH_NONE or baseType == SIGHASH_SINGLE):
        w.writeUint32LE(0'u32)
      else:
        w.writeUint32LE(tx.inputs[i].sequence)

  # Write outputs
  case baseType
  of SIGHASH_NONE:
    # No outputs
    w.writeCompactSize(0)
  of SIGHASH_SINGLE:
    # Outputs 0..inputIndex, with empty outputs before inputIndex
    w.writeCompactSize(uint64(inputIndex + 1))
    for i in 0 ..< inputIndex:
      # Empty output: value = -1, empty script
      w.writeInt64LE(-1'i64)
      w.writeVarBytes(@[])
    # The matching output
    w.writeTxOut(tx.outputs[inputIndex])
  else:
    # SIGHASH_ALL: all outputs
    w.writeCompactSize(uint64(tx.outputs.len))
    for output in tx.outputs:
      w.writeTxOut(output)

  # Write locktime
  w.writeUint32LE(tx.lockTime)

  # Write hash type as 4-byte LE
  w.writeUint32LE(hashType)

  # Return double SHA256
  doubleSha256(w.data)

# Convenience function that applies FindAndDelete and handles OP_CODESEPARATOR
proc signatureHash*(
  tx: Transaction,
  inputIndex: int,
  scriptCode: seq[byte],
  signature: seq[byte],
  hashType: uint32,
  codesepPos: uint32 = 0xFFFFFFFF'u32
): array[32, byte] =
  ## Compute legacy sighash with proper FindAndDelete and OP_CODESEPARATOR handling
  ##
  ## Parameters:
  ##   tx: The transaction being signed
  ##   inputIndex: Index of the input being signed
  ##   scriptCode: The scriptPubKey or redeemScript being executed
  ##   signature: The signature (including hashtype byte) to FindAndDelete
  ##   hashType: The sighash type (last byte of signature)
  ##   codesepPos: Position after last OP_CODESEPARATOR, or 0xFFFFFFFF if none

  # Get subscript starting after last OP_CODESEPARATOR
  var subscript = getSubscriptAfterCodeSeparator(scriptCode, codesepPos)

  # FindAndDelete the signature from the subscript
  subscript = findAndDelete(subscript, signature)

  # Compute the sighash
  computeLegacySighash(tx, inputIndex, subscript, hashType)
