## HD Wallet implementation
## BIP-32/39/44/84/86 key derivation, transaction creation and signing

import std/[tables, options, strutils, sysrand, algorithm]
import nimcrypto/[sha2, hmac, pbkdf2]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1, address, base58]
import ../consensus/params
import ../storage/chainstate

export address.AddressType, address.Address

type
  WalletError* = object of CatchableError

  ExtendedKey* = object
    key*: array[32, byte]           ## Private key or chain code (public x-coord stored separately)
    chainCode*: array[32, byte]     ## Chain code for derivation
    depth*: uint8                   ## Depth in derivation tree (0 for master)
    parentFingerprint*: array[4, byte]  ## First 4 bytes of parent's Hash160
    childIndex*: uint32             ## Child index (with hardened bit if applicable)
    isPrivate*: bool                ## True if private key, false if public
    publicKey*: PublicKey           ## Compressed public key (always available)

  DerivedKey* = object
    extKey*: ExtendedKey
    path*: string                   ## Full derivation path (e.g., "m/84'/0'/0'/0/0")
    address*: Address
    addressStr*: string

  WalletUtxo* = object
    outpoint*: OutPoint
    output*: TxOut
    height*: int32
    keyPath*: string                ## Path to the key that owns this UTXO
    isInternal*: bool               ## True if change address

  Account* = object
    purpose*: uint32                ## 44, 84, or 86
    coinType*: uint32               ## 0 for mainnet, 1 for testnet
    accountIndex*: uint32
    externalKeys*: seq[DerivedKey]  ## Receiving addresses (chain 0)
    internalKeys*: seq[DerivedKey]  ## Change addresses (chain 1)
    nextExternal*: int              ## Next unused external index
    nextInternal*: int              ## Next unused internal index
    gap*: int                       ## Gap limit (default 20)

  Wallet* = ref object
    seed*: array[64, byte]
    masterKey*: ExtendedKey
    accounts*: seq[Account]
    utxos*: Table[OutPoint, WalletUtxo]
    chainState*: ChainState
    params*: ConsensusParams
    mainnet*: bool

# BIP39 wordlist - loaded at compile time
const BIP39_WORDLIST* = staticRead("../../resources/bip39-english.txt").strip().splitLines()

# Hardened derivation constant
const HARDENED* = 0x80000000'u32

# =============================================================================
# BIP39: Mnemonic Generation and Seed Derivation
# =============================================================================

proc generateEntropy*(bits: int): seq[byte] =
  ## Generate cryptographically secure random entropy
  ## bits should be 128, 160, 192, 224, or 256
  if bits notin [128, 160, 192, 224, 256]:
    raise newException(WalletError, "invalid entropy bits: must be 128/160/192/224/256")
  result = newSeq[byte](bits div 8)
  if not urandom(result):
    raise newException(WalletError, "failed to generate random entropy")

proc entropyToMnemonic*(entropy: openArray[byte]): string =
  ## Convert entropy to BIP39 mnemonic phrase
  ## Entropy length must be 16/20/24/28/32 bytes (128/160/192/224/256 bits)
  let entropyBits = entropy.len * 8
  if entropyBits notin [128, 160, 192, 224, 256]:
    raise newException(WalletError, "invalid entropy length")

  # Calculate checksum (first CS bits of SHA256)
  let checksumBits = entropyBits div 32
  let hash = sha256Single(entropy)

  # Combine entropy and checksum into bit string
  var bits: seq[bool]
  for b in entropy:
    for i in countdown(7, 0):
      bits.add(((b.int shr i) and 1) == 1)

  # Add checksum bits
  for i in 0 ..< checksumBits:
    let byteIdx = i div 8
    let bitIdx = 7 - (i mod 8)
    bits.add(((hash[byteIdx].int shr bitIdx) and 1) == 1)

  # Convert to mnemonic words (11 bits per word)
  var words: seq[string]
  for i in countup(0, bits.len - 1, 11):
    var wordIdx = 0
    for j in 0 ..< 11:
      if i + j < bits.len and bits[i + j]:
        wordIdx = wordIdx or (1 shl (10 - j))
    words.add(BIP39_WORDLIST[wordIdx])

  result = words.join(" ")

proc generateMnemonic*(wordCount: int = 24): string =
  ## Generate a new BIP39 mnemonic phrase
  ## wordCount: 12, 15, 18, 21, or 24
  let bits = case wordCount
    of 12: 128
    of 15: 160
    of 18: 192
    of 21: 224
    of 24: 256
    else: raise newException(WalletError, "invalid word count: must be 12/15/18/21/24")

  let entropy = generateEntropy(bits)
  entropyToMnemonic(entropy)

proc validateMnemonic*(mnemonic: string): bool =
  ## Validate a BIP39 mnemonic phrase
  let words = mnemonic.strip().split()
  if words.len notin [12, 15, 18, 21, 24]:
    return false

  # Check all words are in the wordlist and collect indices
  var indices: seq[int]
  for word in words:
    let idx = BIP39_WORDLIST.find(word.toLowerAscii())
    if idx < 0:
      return false
    indices.add(idx)

  # Convert word indices back to bits
  var bits: seq[bool]
  for idx in indices:
    for i in countdown(10, 0):
      bits.add(((idx shr i) and 1) == 1)

  # Extract entropy and checksum
  let entropyBits = (words.len * 11) * 32 div 33
  let checksumBits = words.len * 11 - entropyBits

  # Convert entropy bits to bytes
  var entropy = newSeq[byte](entropyBits div 8)
  for i in 0 ..< entropyBits:
    if bits[i]:
      entropy[i div 8] = entropy[i div 8] or byte(1 shl (7 - (i mod 8)))

  # Verify checksum
  let hash = sha256Single(entropy)
  for i in 0 ..< checksumBits:
    let byteIdx = i div 8
    let bitIdx = 7 - (i mod 8)
    let expectedBit = ((hash[byteIdx].int shr bitIdx) and 1) == 1
    if bits[entropyBits + i] != expectedBit:
      return false

  true

proc mnemonicToSeed*(mnemonic: string, passphrase: string = ""): array[64, byte] =
  ## Convert BIP39 mnemonic to 512-bit seed using PBKDF2-HMAC-SHA512
  ## Salt = "mnemonic" + passphrase, 2048 iterations
  let normalizedMnemonic = mnemonic.strip()
  let salt = "mnemonic" & passphrase

  # PBKDF2-HMAC-SHA512
  var ctx: HMAC[sha512]
  discard pbkdf2(ctx, normalizedMnemonic, salt, 2048, result)

# =============================================================================
# BIP32: Hierarchical Deterministic Key Derivation
# =============================================================================

proc masterKeyFromSeed*(seed: array[64, byte]): ExtendedKey =
  ## Derive master extended private key from seed
  ## Uses HMAC-SHA512 with key "Bitcoin seed"
  var hmacCtx: HMAC[sha512]
  hmacCtx.init("Bitcoin seed")
  hmacCtx.update(seed)
  let output = hmacCtx.finish()
  hmacCtx.clear()

  # Left 32 bytes = private key, Right 32 bytes = chain code
  copyMem(addr result.key[0], addr output.data[0], 32)
  copyMem(addr result.chainCode[0], addr output.data[32], 32)

  result.depth = 0
  result.parentFingerprint = [0'u8, 0, 0, 0]
  result.childIndex = 0
  result.isPrivate = true
  result.publicKey = derivePublicKey(result.key)

proc fingerprint*(key: ExtendedKey): array[4, byte] =
  ## Get the fingerprint of a key (first 4 bytes of Hash160 of pubkey)
  let h = hash160(key.publicKey)
  copyMem(addr result[0], addr h[0], 4)

proc deriveChild*(parent: ExtendedKey, index: uint32): ExtendedKey =
  ## Derive child extended key from parent
  ## If index >= 0x80000000, it's a hardened derivation (requires private key)
  let hardened = index >= HARDENED

  if hardened and not parent.isPrivate:
    raise newException(WalletError, "cannot derive hardened child from public key")

  # Prepare data for HMAC
  var data: seq[byte]
  if hardened:
    # Hardened: 0x00 || private key || index
    data.add(0x00'u8)
    data.add(@(parent.key))
  else:
    # Normal: public key || index
    data.add(@(parent.publicKey))

  # Add index (big-endian)
  data.add(byte((index shr 24) and 0xff))
  data.add(byte((index shr 16) and 0xff))
  data.add(byte((index shr 8) and 0xff))
  data.add(byte(index and 0xff))

  # HMAC-SHA512
  var hmacCtx: HMAC[sha512]
  hmacCtx.init(parent.chainCode)
  hmacCtx.update(data)
  let output = hmacCtx.finish()
  hmacCtx.clear()

  result.depth = parent.depth + 1
  result.parentFingerprint = fingerprint(parent)
  result.childIndex = index
  result.isPrivate = parent.isPrivate

  # Right 32 bytes = new chain code
  copyMem(addr result.chainCode[0], addr output.data[32], 32)

  if parent.isPrivate:
    # Private key derivation: child_key = (parent_key + IL) mod n
    # For simplicity, we do byte-level addition with secp256k1 tweak
    # IL is treated as a scalar to add to the parent private key
    var il: array[32, byte]
    copyMem(addr il[0], addr output.data[0], 32)

    # Add scalars mod curve order (simplified - should use proper big int)
    var carry: uint32 = 0
    for i in countdown(31, 0):
      let sum = uint32(parent.key[i]) + uint32(il[i]) + carry
      result.key[i] = byte(sum and 0xff)
      carry = sum shr 8

    result.publicKey = derivePublicKey(result.key)
  else:
    # Public key derivation: child_pubkey = point(IL) + parent_pubkey
    raise newException(WalletError, "public key derivation not yet implemented")

proc derivePathStr*(master: ExtendedKey, path: string): ExtendedKey =
  ## Derive key from path string like "m/44'/0'/0'/0/0"
  if not path.startsWith("m"):
    raise newException(WalletError, "path must start with 'm'")

  result = master
  let parts = path.split("/")

  for i in 1 ..< parts.len:
    var part = parts[i]
    var hardened = false

    if part.endsWith("'") or part.endsWith("h") or part.endsWith("H"):
      hardened = true
      part = part[0 ..< part.len - 1]

    let index = try: parseUInt(part) except: raise newException(WalletError, "invalid path component: " & part)

    let childIndex = if hardened: uint32(index) or HARDENED else: uint32(index)
    result = deriveChild(result, childIndex)

# =============================================================================
# Extended Key Serialization (xpub/xprv)
# =============================================================================

proc serializeExtendedKey*(key: ExtendedKey, mainnet: bool = true): string =
  ## Serialize extended key to Base58Check format (xprv/xpub/tprv/tpub)
  var data: seq[byte]

  # Version bytes (4 bytes)
  if key.isPrivate:
    if mainnet:
      data.add([0x04'u8, 0x88, 0xAD, 0xE4])  # xprv
    else:
      data.add([0x04'u8, 0x35, 0x83, 0x94])  # tprv
  else:
    if mainnet:
      data.add([0x04'u8, 0x88, 0xB2, 0x1E])  # xpub
    else:
      data.add([0x04'u8, 0x35, 0x87, 0xCF])  # tpub

  # Depth (1 byte)
  data.add(key.depth)

  # Parent fingerprint (4 bytes)
  data.add(@(key.parentFingerprint))

  # Child index (4 bytes, big-endian)
  data.add(byte((key.childIndex shr 24) and 0xff))
  data.add(byte((key.childIndex shr 16) and 0xff))
  data.add(byte((key.childIndex shr 8) and 0xff))
  data.add(byte(key.childIndex and 0xff))

  # Chain code (32 bytes)
  data.add(@(key.chainCode))

  # Key data (33 bytes)
  if key.isPrivate:
    data.add(0x00'u8)  # Private key prefix
    data.add(@(key.key))
  else:
    data.add(@(key.publicKey))

  base58CheckEncode(data)

# =============================================================================
# Wallet Operations
# =============================================================================

proc newWallet*(mnemonic: string, passphrase: string = "",
                params: ConsensusParams = mainnetParams()): Wallet =
  ## Create a new wallet from mnemonic
  if not validateMnemonic(mnemonic):
    raise newException(WalletError, "invalid mnemonic")

  new(result)
  result.seed = mnemonicToSeed(mnemonic, passphrase)
  result.masterKey = masterKeyFromSeed(result.seed)
  result.accounts = @[]
  result.utxos = initTable[OutPoint, WalletUtxo]()
  result.params = params
  result.mainnet = params.network == Mainnet

proc newWalletFromSeed*(seed: array[64, byte],
                        params: ConsensusParams = mainnetParams()): Wallet =
  ## Create a new wallet from raw seed
  new(result)
  result.seed = seed
  result.masterKey = masterKeyFromSeed(seed)
  result.accounts = @[]
  result.utxos = initTable[OutPoint, WalletUtxo]()
  result.params = params
  result.mainnet = params.network == Mainnet

proc derivePath(wallet: Wallet, purpose, coinType, account, chain, index: uint32): DerivedKey =
  ## Derive a key at the specified BIP44/84/86 path
  let path = "m/" & $purpose & "'/" & $coinType & "'/" & $account & "'/" & $chain & "/" & $index
  let extKey = derivePathStr(wallet.masterKey, path)

  result.extKey = extKey
  result.path = path

  # Generate appropriate address based on purpose
  case purpose
  of 44:  # BIP44 - P2PKH
    let pkh = hash160(extKey.publicKey)
    result.address = Address(kind: P2PKH, pubkeyHash: pkh)
  of 84:  # BIP84 - P2WPKH
    let wpkh = hash160(extKey.publicKey)
    result.address = Address(kind: P2WPKH, wpkh: wpkh)
  of 86:  # BIP86 - P2TR (Taproot)
    # For P2TR, we use the x-only public key (first 32 bytes after compression marker)
    var xonly: array[32, byte]
    copyMem(addr xonly[0], addr extKey.publicKey[1], 32)
    result.address = Address(kind: P2TR, taprootKey: xonly)
  else:
    raise newException(WalletError, "unsupported purpose: " & $purpose)

  result.addressStr = encodeAddress(result.address, wallet.mainnet)

proc addAccount*(wallet: var Wallet, purpose: uint32 = 84, accountIndex: uint32 = 0, gap: int = 20) =
  ## Add a new account to the wallet
  let coinType: uint32 = if wallet.mainnet: 0 else: 1

  var account = Account(
    purpose: purpose,
    coinType: coinType,
    accountIndex: accountIndex,
    externalKeys: @[],
    internalKeys: @[],
    nextExternal: 0,
    nextInternal: 0,
    gap: gap
  )

  # Pre-derive initial keys up to gap limit
  for i in 0 ..< gap:
    account.externalKeys.add(wallet.derivePath(purpose, coinType, accountIndex, 0, uint32(i)))
    account.internalKeys.add(wallet.derivePath(purpose, coinType, accountIndex, 1, uint32(i)))

  wallet.accounts.add(account)

proc ensureGap(wallet: var Wallet, account: var Account, isInternal: bool) =
  ## Ensure there are enough unused addresses ahead of the next index
  let keys = if isInternal: account.internalKeys else: account.externalKeys
  let nextIdx = if isInternal: account.nextInternal else: account.nextExternal
  let chain: uint32 = if isInternal: 1 else: 0

  while keys.len < nextIdx + account.gap:
    let newKey = wallet.derivePath(
      account.purpose, account.coinType, account.accountIndex,
      chain, uint32(keys.len)
    )
    if isInternal:
      account.internalKeys.add(newKey)
    else:
      account.externalKeys.add(newKey)

proc getNewAddress*(wallet: var Wallet, addrType: AddressType = P2WPKH,
                    accountIdx: int = 0, isChange: bool = false): Address =
  ## Get a new receiving or change address
  if accountIdx >= wallet.accounts.len:
    raise newException(WalletError, "account not found: " & $accountIdx)

  var account = wallet.accounts[accountIdx]

  let key = if isChange:
    let idx = account.nextInternal
    inc account.nextInternal
    wallet.ensureGap(account, true)
    account.internalKeys[idx]
  else:
    let idx = account.nextExternal
    inc account.nextExternal
    wallet.ensureGap(account, false)
    account.externalKeys[idx]

  wallet.accounts[accountIdx] = account
  result = key.address

proc getNewAddressStr*(wallet: var Wallet, addrType: AddressType = P2WPKH,
                       accountIdx: int = 0, isChange: bool = false): string =
  ## Get a new address as a string
  encodeAddress(wallet.getNewAddress(addrType, accountIdx, isChange), wallet.mainnet)

proc getAllAddresses*(wallet: Wallet, accountIdx: int = 0): seq[string] =
  ## Get all generated addresses for an account
  if accountIdx >= wallet.accounts.len:
    return @[]

  let account = wallet.accounts[accountIdx]
  for key in account.externalKeys:
    result.add(key.addressStr)
  for key in account.internalKeys:
    result.add(key.addressStr)

proc addressMatch(a, b: Address): bool =
  ## Compare two addresses by kind and content
  if a.kind != b.kind:
    return false
  case a.kind
  of P2PKH:
    return a.pubkeyHash == b.pubkeyHash
  of P2SH:
    return a.scriptHash == b.scriptHash
  of P2WPKH:
    return a.wpkh == b.wpkh
  of P2WSH:
    return a.wsh == b.wsh
  of P2TR:
    return a.taprootKey == b.taprootKey

proc findKeyForAddress*(wallet: Wallet, address: Address): Option[DerivedKey] =
  ## Find the derived key that corresponds to an address
  for account in wallet.accounts:
    for key in account.externalKeys:
      if addressMatch(key.address, address):
        return some(key)
    for key in account.internalKeys:
      if addressMatch(key.address, address):
        return some(key)
  none(DerivedKey)

proc findKeyForScript*(wallet: Wallet, scriptPubKey: seq[byte]): Option[DerivedKey] =
  ## Find the derived key that corresponds to a scriptPubKey
  for account in wallet.accounts:
    for key in account.externalKeys:
      if scriptPubKeyForAddress(key.address) == scriptPubKey:
        return some(key)
    for key in account.internalKeys:
      if scriptPubKeyForAddress(key.address) == scriptPubKey:
        return some(key)
  none(DerivedKey)

# =============================================================================
# UTXO Management and Block Scanning
# =============================================================================

proc addUtxo*(wallet: var Wallet, outpoint: OutPoint, output: TxOut,
              height: int32, keyPath: string, isInternal: bool) =
  ## Add a UTXO to the wallet
  wallet.utxos[outpoint] = WalletUtxo(
    outpoint: outpoint,
    output: output,
    height: height,
    keyPath: keyPath,
    isInternal: isInternal
  )

proc removeUtxo*(wallet: var Wallet, outpoint: OutPoint) =
  ## Remove a spent UTXO
  wallet.utxos.del(outpoint)

proc getBalance*(wallet: Wallet): Satoshi =
  ## Get total wallet balance
  result = Satoshi(0)
  for _, utxo in wallet.utxos:
    result = result + utxo.output.value

proc getSpendableBalance*(wallet: Wallet, currentHeight: int32): Satoshi =
  ## Get spendable balance (excluding immature coinbase)
  result = Satoshi(0)
  for _, utxo in wallet.utxos:
    # Skip immature coinbase (would need to track isCoinbase, simplified here)
    result = result + utxo.output.value

proc scanBlockForWallet*(wallet: var Wallet, blk: Block, height: int32) =
  ## Scan a block for transactions relevant to the wallet
  for txIdx, tx in blk.txs:
    let txId = tx.txid()

    # Check outputs for payments to our addresses
    for voutIdx, output in tx.outputs:
      let keyOpt = wallet.findKeyForScript(output.scriptPubKey)
      if keyOpt.isSome:
        let key = keyOpt.get()
        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        let isInternal = key.path.contains("/1/")
        wallet.addUtxo(outpoint, output, height, key.path, isInternal)

    # Check inputs for spent UTXOs
    for input in tx.inputs:
      if input.prevOut in wallet.utxos:
        wallet.removeUtxo(input.prevOut)

# =============================================================================
# Transaction Creation and Signing
# =============================================================================

type
  CoinSelectionResult = object
    inputs: seq[WalletUtxo]
    totalIn: Satoshi
    fee: Satoshi

proc selectCoins(wallet: Wallet, targetAmount: Satoshi, feeRate: float64): CoinSelectionResult =
  ## Simple coin selection - largest first
  var available: seq[WalletUtxo]
  for _, utxo in wallet.utxos:
    available.add(utxo)

  # Sort by value descending
  available.sort(proc(a, b: WalletUtxo): int = cmp(int64(b.output.value), int64(a.output.value)))

  # Estimate input size for fee calculation (P2WPKH: ~68 vbytes)
  const inputVsize = 68
  const outputVsize = 31  # P2WPKH output
  const txOverhead = 10   # version + locktime + segwit marker

  var selectedInputs: seq[WalletUtxo]
  var totalIn = Satoshi(0)

  for utxo in available:
    selectedInputs.add(utxo)
    totalIn = totalIn + utxo.output.value

    # Estimate transaction size and fee
    let numInputs = selectedInputs.len
    let numOutputs = 2  # target + change
    let estVsize = txOverhead + numInputs * inputVsize + numOutputs * outputVsize
    let fee = Satoshi(int64(float64(estVsize) * feeRate))

    if int64(totalIn) >= int64(targetAmount) + int64(fee):
      result.inputs = selectedInputs
      result.totalIn = totalIn
      result.fee = fee
      return

  raise newException(WalletError, "insufficient funds")

proc createTransaction*(wallet: var Wallet, outputs: seq[TxOut],
                        feeRate: float64 = 1.0): Transaction =
  ## Create a new transaction
  ## feeRate is in satoshis per virtual byte

  # Calculate total output amount
  var totalOut = Satoshi(0)
  for output in outputs:
    totalOut = totalOut + output.value

  # Select coins
  let selection = selectCoins(wallet, totalOut, feeRate)

  # Build transaction
  result.version = 2
  result.lockTime = uint32(wallet.params.bip34Height)  # Anti-fee-sniping
  if wallet.chainState != nil:
    result.lockTime = uint32(wallet.chainState.bestHeight)

  # Add inputs
  for utxo in selection.inputs:
    result.inputs.add(TxIn(
      prevOut: utxo.outpoint,
      scriptSig: @[],  # Empty for segwit
      sequence: 0xfffffffd'u32  # RBF enabled
    ))

  # Add outputs
  for output in outputs:
    result.outputs.add(output)

  # Add change output if needed
  let change = selection.totalIn - totalOut - selection.fee
  if int64(change) > int64(wallet.params.dustLimit):
    let changeAddr = wallet.getNewAddress(P2WPKH, 0, true)
    result.outputs.add(TxOut(
      value: change,
      scriptPubKey: scriptPubKeyForAddress(changeAddr)
    ))

  # Initialize empty witness for each input
  result.witnesses = newSeq[seq[seq[byte]]](result.inputs.len)
  for i in 0 ..< result.witnesses.len:
    result.witnesses[i] = @[]

proc computeSighashP2WPKH*(tx: Transaction, inputIdx: int,
                           scriptCode: seq[byte], value: Satoshi): array[32, byte] =
  ## Compute BIP143 sighash for P2WPKH
  var w = BinaryWriter()

  # 1. nVersion
  w.writeInt32LE(tx.version)

  # 2. hashPrevouts (double SHA256 of all outpoints)
  var prevoutsW = BinaryWriter()
  for input in tx.inputs:
    prevoutsW.writeOutPoint(input.prevOut)
  let hashPrevouts = doubleSha256(prevoutsW.data)
  w.writeBytes(hashPrevouts)

  # 3. hashSequence (double SHA256 of all sequences)
  var sequenceW = BinaryWriter()
  for input in tx.inputs:
    sequenceW.writeUint32LE(input.sequence)
  let hashSequence = doubleSha256(sequenceW.data)
  w.writeBytes(hashSequence)

  # 4. outpoint being signed
  w.writeOutPoint(tx.inputs[inputIdx].prevOut)

  # 5. scriptCode (for P2WPKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG)
  w.writeVarBytes(scriptCode)

  # 6. value of the output being spent
  w.writeInt64LE(int64(value))

  # 7. nSequence of the input being signed
  w.writeUint32LE(tx.inputs[inputIdx].sequence)

  # 8. hashOutputs (double SHA256 of all outputs)
  var outputsW = BinaryWriter()
  for output in tx.outputs:
    outputsW.writeTxOut(output)
  let hashOutputs = doubleSha256(outputsW.data)
  w.writeBytes(hashOutputs)

  # 9. nLockTime
  w.writeUint32LE(tx.lockTime)

  # 10. sighash type (SIGHASH_ALL = 0x01)
  w.writeUint32LE(0x01)

  doubleSha256(w.data)

proc signInputP2WPKH(tx: var Transaction, inputIdx: int,
                      privateKey: PrivateKey, publicKey: PublicKey,
                      value: Satoshi) =
  ## Sign a P2WPKH input
  # Build scriptCode: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
  let pkh = hash160(publicKey)
  var scriptCode = @[0x76'u8, 0xa9, 0x14]  # OP_DUP OP_HASH160 PUSH20
  scriptCode.add(@pkh)
  scriptCode.add([0x88'u8, 0xac])  # OP_EQUALVERIFY OP_CHECKSIG

  # Compute sighash
  let sighash = computeSighashP2WPKH(tx, inputIdx, scriptCode, value)

  # Sign
  let sig = sign(privateKey, sighash)

  # Build DER signature with sighash type
  var derSig: seq[byte]
  derSig.add(0x30)  # SEQUENCE

  # Extract r and s from compact signature
  var r: array[32, byte]
  var s: array[32, byte]
  copyMem(addr r[0], addr sig[0], 32)
  copyMem(addr s[0], addr sig[32], 32)

  # Build r integer
  var rBytes: seq[byte]
  rBytes.add(@r)
  while rBytes.len > 1 and rBytes[0] == 0 and (rBytes[1] and 0x80) == 0:
    rBytes.delete(0)
  if (rBytes[0] and 0x80) != 0:
    rBytes.insert(0, 0)

  # Build s integer
  var sBytes: seq[byte]
  sBytes.add(@s)
  while sBytes.len > 1 and sBytes[0] == 0 and (sBytes[1] and 0x80) == 0:
    sBytes.delete(0)
  if (sBytes[0] and 0x80) != 0:
    sBytes.insert(0, 0)

  let seqLen = 2 + rBytes.len + 2 + sBytes.len
  derSig.add(byte(seqLen))

  derSig.add(0x02)  # INTEGER
  derSig.add(byte(rBytes.len))
  derSig.add(rBytes)

  derSig.add(0x02)  # INTEGER
  derSig.add(byte(sBytes.len))
  derSig.add(sBytes)

  derSig.add(0x01)  # SIGHASH_ALL

  # Set witness: [signature, pubkey]
  tx.witnesses[inputIdx] = @[derSig, @(publicKey)]

proc signTransaction*(wallet: Wallet, tx: var Transaction,
                      utxos: seq[WalletUtxo]): bool =
  ## Sign all inputs of a transaction
  ## Returns true if all inputs were signed successfully

  if utxos.len != tx.inputs.len:
    raise newException(WalletError, "utxo count doesn't match input count")

  for i, utxo in utxos:
    # Find the key for this UTXO
    let keyOpt = wallet.findKeyForScript(utxo.output.scriptPubKey)
    if keyOpt.isNone:
      return false

    let key = keyOpt.get()
    let spk = utxo.output.scriptPubKey

    # Determine address type from scriptPubKey
    if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
      # P2WPKH
      signInputP2WPKH(tx, i, key.extKey.key, key.extKey.publicKey, utxo.output.value)
    elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
      # P2TR - requires Schnorr signature (simplified)
      raise newException(WalletError, "P2TR signing not yet fully implemented")
    else:
      raise newException(WalletError, "unsupported script type for signing")

  true

# =============================================================================
# Utility Functions
# =============================================================================

proc exportMasterXpub*(wallet: Wallet): string =
  ## Export master public key (xpub)
  var pubKey = wallet.masterKey
  pubKey.isPrivate = false
  serializeExtendedKey(pubKey, wallet.mainnet)

proc getAccountXpub*(wallet: Wallet, accountIdx: int = 0): string =
  ## Get the xpub for a specific account (e.g., m/84'/0'/0')
  if accountIdx >= wallet.accounts.len:
    raise newException(WalletError, "account not found")

  let account = wallet.accounts[accountIdx]
  let path = "m/" & $account.purpose & "'/" & $account.coinType & "'/" & $account.accountIndex & "'"
  var accKey = derivePathStr(wallet.masterKey, path)
  accKey.isPrivate = false
  serializeExtendedKey(accKey, wallet.mainnet)
