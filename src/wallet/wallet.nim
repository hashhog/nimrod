## HD Wallet implementation
## BIP-32/39/44/84/86 key derivation, transaction creation and signing

import std/[tables, options, strutils, sysrand, algorithm, times]
import nimcrypto/[sha2, hmac, pbkdf2]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1, address, base58]
import ../consensus/params
import ../storage/chainstate
import ./coinselection
import ./crypter
import ./db_sqlite

export address.AddressType, address.Address
export coinselection
export db_sqlite.WalletDb, db_sqlite.StoredKey, db_sqlite.StoredUtxo

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
    isCoinbase*: bool               ## True if from a coinbase transaction

  Account* = object
    purpose*: uint32                ## 44, 84, or 86
    coinType*: uint32               ## 0 for mainnet, 1 for testnet
    accountIndex*: uint32
    externalKeys*: seq[DerivedKey]  ## Receiving addresses (chain 0)
    internalKeys*: seq[DerivedKey]  ## Change addresses (chain 1)
    nextExternal*: int              ## Next unused external index
    nextInternal*: int              ## Next unused internal index
    gap*: int                       ## Gap limit (default 20)

  ## Address label entry
  AddressLabel* = object
    address*: string
    label*: string

  Wallet* = ref object
    seed*: array[64, byte]
    masterKey*: ExtendedKey
    accounts*: seq[Account]
    utxos*: Table[OutPoint, WalletUtxo]
    chainState*: ChainState
    params*: ConsensusParams
    mainnet*: bool
    # Encryption state
    isEncrypted*: bool              ## True if wallet is encrypted
    isLocked*: bool                 ## True if wallet is locked (key not in memory)
    encryptedSeed*: seq[byte]       ## Encrypted seed when wallet is encrypted
    encryptionSalt*: array[8, byte] ## Salt used for key derivation
    encryptionRounds*: int          ## Number of key derivation rounds
    masterKeyCache*: array[32, byte] ## Cached decryption key (cleared on lock)
    unlockExpiry*: int64            ## Unix timestamp when wallet auto-locks (0 = no expiry)
    # Labels
    labels*: Table[string, string]  ## Address -> label mapping

# BIP39 wordlist - loaded at compile time
const BIP39_WORDLIST* = staticRead("../../resources/bip39-english.txt").strip().splitLines()

# Hardened derivation constant
const HARDENED* = 0x80000000'u32

# Coinbase maturity - outputs can only be spent after this many confirmations
const CoinbaseMaturity* = 100

# Forward declarations
proc addAccount*(wallet: var Wallet, purpose: uint32 = 84, accountIndex: uint32 = 0, gap: int = 20)

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

proc newWallet*(mnemonic: string, params: ConsensusParams,
                mainnet: bool, chainState: ChainState): Wallet =
  ## Create a new wallet from mnemonic with explicit parameters
  if not validateMnemonic(mnemonic):
    raise newException(WalletError, "invalid mnemonic")

  new(result)
  result.seed = mnemonicToSeed(mnemonic)
  result.masterKey = masterKeyFromSeed(result.seed)
  result.accounts = @[]
  result.utxos = initTable[OutPoint, WalletUtxo]()
  result.params = params
  result.mainnet = mainnet
  result.chainState = chainState
  result.labels = initTable[string, string]()

  # Create default BIP84 (native segwit) account
  result.addAccount(84, 0, 20)

proc newWalletFromDb*(db: WalletDb, params: ConsensusParams,
                       mainnet: bool, chainState: ChainState): Wallet =
  ## Load a wallet from an existing database
  ## The wallet is reconstructed from stored keys and UTXOs
  new(result)
  result.accounts = @[]
  result.utxos = initTable[OutPoint, WalletUtxo]()
  result.params = params
  result.mainnet = mainnet
  result.chainState = chainState
  result.labels = initTable[string, string]()

  # Load encryption info if present
  let encInfo = db.getEncryption()
  if encInfo.isSome:
    let (encSeed, salt, rounds) = encInfo.get()
    result.isEncrypted = true
    result.isLocked = true
    result.encryptedSeed = encSeed
    result.encryptionSalt = salt
    result.encryptionRounds = rounds
  else:
    result.isEncrypted = false
    result.isLocked = false

  # Load UTXOs
  for stored in db.getUnspentUtxos():
    var outpoint: OutPoint
    outpoint.txid = TxId(stored.txid)
    outpoint.vout = stored.vout

    var output: TxOut
    output.value = Satoshi(stored.value)
    output.scriptPubKey = stored.scriptPubKey

    let wutxo = WalletUtxo(
      outpoint: outpoint,
      output: output,
      height: stored.height,
      keyPath: stored.keyPath,
      isInternal: stored.isInternal,
      isCoinbase: stored.isCoinbase
    )
    result.utxos[outpoint] = wutxo

  # Load labels
  for (address, label) in db.getAllLabels():
    result.labels[address] = label

  # Note: Keys are not loaded - they will be re-derived when needed
  # after the wallet is unlocked (for encrypted wallets) or on first use

proc derivePath(wallet: Wallet, purpose, coinType, account, chain, index: uint32): DerivedKey =
  ## Derive a key at the specified BIP44/49/84/86 path
  let path = "m/" & $purpose & "'/" & $coinType & "'/" & $account & "'/" & $chain & "/" & $index
  let extKey = derivePathStr(wallet.masterKey, path)

  result.extKey = extKey
  result.path = path

  # Generate appropriate address based on purpose
  case purpose
  of 44:  # BIP44 - P2PKH
    let pkh = hash160(extKey.publicKey)
    result.address = Address(kind: P2PKH, pubkeyHash: pkh)
  of 49:  # BIP49 - P2SH-P2WPKH (wrapped segwit)
    # The redeemScript is: OP_0 <20-byte-hash>
    # The scriptHash is: HASH160(redeemScript)
    let wpkh = hash160(extKey.publicKey)
    var redeemScript = @[0x00'u8, 0x14]  # OP_0 PUSH20
    redeemScript.add(@wpkh)
    let scriptHash = hash160(redeemScript)
    result.address = Address(kind: P2SH, scriptHash: scriptHash)
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
  let nextIdx = if isInternal: account.nextInternal else: account.nextExternal
  let chain: uint32 = if isInternal: 1 else: 0

  # Use the actual account fields (not a local copy) to check length
  while (if isInternal: account.internalKeys.len else: account.externalKeys.len) < nextIdx + account.gap:
    let currentLen = if isInternal: account.internalKeys.len else: account.externalKeys.len
    let newKey = wallet.derivePath(
      account.purpose, account.coinType, account.accountIndex,
      chain, uint32(currentLen)
    )
    if isInternal:
      account.internalKeys.add(newKey)
    else:
      account.externalKeys.add(newKey)

proc purposeForAddressType*(addrType: AddressType): uint32 =
  ## Get the BIP purpose number for an address type
  case addrType
  of P2PKH: 44
  of P2SH: 49   # P2SH-P2WPKH
  of P2WPKH: 84
  of P2TR: 86
  of P2WSH: 84  # Use same as P2WPKH for now

proc findOrCreateAccountForType*(wallet: var Wallet, addrType: AddressType): int =
  ## Find an existing account for the address type, or create one
  let purpose = purposeForAddressType(addrType)

  # Look for existing account with matching purpose
  for i, account in wallet.accounts:
    if account.purpose == purpose:
      return i

  # No matching account found, create one
  let coinType: uint32 = if wallet.mainnet: 0 else: 1
  let accountIndex: uint32 = 0
  let gap = 20

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
  wallet.accounts.len - 1

proc getNewAddress*(wallet: var Wallet, addrType: AddressType = P2WPKH,
                    accountIdx: int = -1, isChange: bool = false): Address =
  ## Get a new receiving or change address
  ## If accountIdx is -1, automatically find/create appropriate account for address type

  var actualIdx = accountIdx
  if actualIdx < 0:
    actualIdx = wallet.findOrCreateAccountForType(addrType)
  elif actualIdx >= wallet.accounts.len:
    raise newException(WalletError, "account not found: " & $accountIdx)

  var account = wallet.accounts[actualIdx]

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

  wallet.accounts[actualIdx] = account
  result = key.address

proc getNewAddressStr*(wallet: var Wallet, addrType: AddressType = P2WPKH,
                       accountIdx: int = -1, isChange: bool = false): string =
  ## Get a new address as a string
  encodeAddress(wallet.getNewAddress(addrType, accountIdx, isChange), wallet.mainnet)

proc getNewAddressByTypeName*(wallet: var Wallet, typeName: string,
                               isChange: bool = false): string =
  ## Get a new address by type name string (for RPC compatibility)
  ## Supported: "legacy", "p2sh-segwit", "bech32", "bech32m"
  let addrType = case typeName.toLowerAscii()
    of "legacy": P2PKH
    of "p2sh-segwit": P2SH  # P2SH-P2WPKH
    of "bech32": P2WPKH
    of "bech32m": P2TR
    else:
      raise newException(WalletError, "unknown address type: " & typeName)

  wallet.getNewAddressStr(addrType, -1, isChange)

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
              height: int32, keyPath: string, isInternal: bool,
              isCoinbase: bool = false) =
  ## Add a UTXO to the wallet
  wallet.utxos[outpoint] = WalletUtxo(
    outpoint: outpoint,
    output: output,
    height: height,
    keyPath: keyPath,
    isInternal: isInternal,
    isCoinbase: isCoinbase
  )

proc removeUtxo*(wallet: var Wallet, outpoint: OutPoint) =
  ## Remove a spent UTXO
  wallet.utxos.del(outpoint)

proc getBalance*(wallet: Wallet): Satoshi =
  ## Get total wallet balance
  result = Satoshi(0)
  for _, utxo in wallet.utxos:
    result = result + utxo.output.value

proc isMatureCoinbase*(utxo: WalletUtxo, currentHeight: int32): bool =
  ## Check if a coinbase UTXO has reached maturity
  ## Coinbase outputs require CoinbaseMaturity (100) confirmations
  if not utxo.isCoinbase:
    return true  # Non-coinbase outputs are always mature
  if utxo.height <= 0:
    return false  # Unconfirmed coinbase is never mature
  let confirmations = currentHeight - utxo.height + 1
  confirmations >= CoinbaseMaturity

proc getSpendableBalance*(wallet: Wallet, currentHeight: int32): Satoshi =
  ## Get spendable balance (excluding immature coinbase)
  result = Satoshi(0)
  for _, utxo in wallet.utxos:
    # Skip immature coinbase outputs
    if utxo.isMatureCoinbase(currentHeight):
      result = result + utxo.output.value

proc isCoinbaseTx*(tx: Transaction): bool =
  ## Check if a transaction is a coinbase transaction
  ## Coinbase has exactly one input with prevOut.txid all zeros and prevOut.vout = 0xFFFFFFFF
  if tx.inputs.len != 1:
    return false
  let input = tx.inputs[0]
  # Check if prevOut txid is all zeros
  var allZeros = true
  let txidBytes = array[32, byte](input.prevOut.txid)
  for b in txidBytes:
    if b != 0:
      allZeros = false
      break
  allZeros and input.prevOut.vout == 0xFFFFFFFF'u32

proc scanBlockForWallet*(wallet: var Wallet, blk: Block, height: int32) =
  ## Scan a block for transactions relevant to the wallet
  for txIdx, tx in blk.txs:
    let txId = tx.txid()
    let coinbase = tx.isCoinbaseTx()

    # Check outputs for payments to our addresses
    for voutIdx, output in tx.outputs:
      let keyOpt = wallet.findKeyForScript(output.scriptPubKey)
      if keyOpt.isSome:
        let key = keyOpt.get()
        let outpoint = OutPoint(txid: txId, vout: uint32(voutIdx))
        let isInternal = key.path.contains("/1/")
        wallet.addUtxo(outpoint, output, height, key.path, isInternal, coinbase)

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
    totalEffective: Satoshi
    fee: Satoshi
    needsChange: bool

proc getInputWeight(scriptPubKey: seq[byte]): int =
  ## Determine input weight based on scriptPubKey type
  if scriptPubKey.len == 22 and scriptPubKey[0] == 0x00 and scriptPubKey[1] == 0x14:
    # P2WPKH
    return P2WpkhInputWeight
  elif scriptPubKey.len == 34 and scriptPubKey[0] == 0x51 and scriptPubKey[1] == 0x20:
    # P2TR
    return P2TrInputWeight
  elif scriptPubKey.len == 25 and scriptPubKey[0] == 0x76 and scriptPubKey[1] == 0xa9:
    # P2PKH
    return P2PkhInputWeight
  elif scriptPubKey.len == 23 and scriptPubKey[0] == 0xa9 and scriptPubKey[1] == 0x14:
    # P2SH (assume P2SH-P2WPKH)
    return P2ShP2WpkhInputWeight
  else:
    # Default to P2WPKH
    return P2WpkhInputWeight

proc selectCoinsAdvanced(wallet: Wallet, targetAmount: Satoshi, feeRate: float64,
                          currentHeight: int32 = 0): CoinSelectionResult =
  ## Advanced coin selection using BnB and Knapsack algorithms
  ## Skips immature coinbase outputs when currentHeight > 0
  var selectableCoins: seq[SelectableCoin]

  # Convert wallet UTXOs to selectable coins
  for _, utxo in wallet.utxos:
    # Skip immature coinbase outputs
    if currentHeight > 0 and not utxo.isMatureCoinbase(currentHeight):
      continue

    let weight = getInputWeight(utxo.output.scriptPubKey)
    let coin = newSelectableCoin(
      utxo.outpoint,
      utxo.output.value,
      weight,
      feeRate,
      feeRate  # Using same rate for long-term estimate
    )
    if int64(coin.effectiveValue) > 0:
      selectableCoins.add(coin)

  if selectableCoins.len == 0:
    raise newException(WalletError, "no spendable UTXOs")

  # Calculate cost of change output
  let changeCost = Satoshi(int64((float64(P2WpkhOutputWeight) / 4.0 + float64(P2WpkhInputWeight) / 4.0) * feeRate))
  let minChange = Satoshi(max(int64(MinChangeValue), int64(changeCost)))

  # Run coin selection
  let selection = selectCoins(selectableCoins, targetAmount, changeCost, minChange)

  # Map selected coins back to wallet UTXOs
  for coin in selection.coins:
    for _, utxo in wallet.utxos:
      if utxo.outpoint == coin.outpoint:
        result.inputs.add(utxo)
        result.totalIn = Satoshi(int64(result.totalIn) + int64(utxo.output.value))
        break

  result.totalEffective = selection.totalEffectiveValue
  result.fee = selection.totalFee

  # Determine if change is needed
  let excess = int64(selection.totalEffectiveValue) - int64(targetAmount)
  result.needsChange = excess >= int64(minChange)

proc selectCoinsSimple(wallet: Wallet, targetAmount: Satoshi, feeRate: float64,
                        currentHeight: int32 = 0): CoinSelectionResult =
  ## Simple coin selection - largest first (fallback)
  ## Skips immature coinbase outputs when currentHeight > 0
  var available: seq[WalletUtxo]
  for _, utxo in wallet.utxos:
    # Skip immature coinbase outputs
    if currentHeight > 0 and not utxo.isMatureCoinbase(currentHeight):
      continue
    available.add(utxo)

  # Sort by value descending
  available.sort(proc(a, b: WalletUtxo): int = cmp(int64(b.output.value), int64(a.output.value)))

  # Estimate input size for fee calculation
  const outputVsize = 31  # P2WPKH output
  const txOverhead = 10   # version + locktime + segwit marker

  var selectedInputs: seq[WalletUtxo]
  var totalIn = Satoshi(0)

  for utxo in available:
    selectedInputs.add(utxo)
    totalIn = totalIn + utxo.output.value

    # Estimate transaction size and fee
    var totalInputVsize = 0
    for inp in selectedInputs:
      totalInputVsize += getInputWeight(inp.output.scriptPubKey) div 4

    let numOutputs = 2  # target + change
    let estVsize = txOverhead + totalInputVsize + numOutputs * outputVsize
    let fee = Satoshi(int64(float64(estVsize) * feeRate))

    if int64(totalIn) >= int64(targetAmount) + int64(fee):
      result.inputs = selectedInputs
      result.totalIn = totalIn
      result.fee = fee
      result.needsChange = true
      return

  raise newException(WalletError, "insufficient funds")

proc createTransaction*(wallet: var Wallet, outputs: seq[TxOut],
                        feeRate: float64 = 1.0,
                        useAdvancedCoinSelection: bool = true): Transaction =
  ## Create a new transaction
  ## feeRate is in satoshis per virtual byte
  ## useAdvancedCoinSelection: use BnB/Knapsack (true) or largest-first (false)
  ## Automatically skips immature coinbase outputs

  # Calculate total output amount
  var totalOut = Satoshi(0)
  for output in outputs:
    totalOut = totalOut + output.value

  # Get current height for coinbase maturity check
  let currentHeight = if wallet.chainState != nil:
    wallet.chainState.bestHeight
  else:
    0'i32

  # Select coins (skipping immature coinbase)
  let selection = if useAdvancedCoinSelection:
    try:
      selectCoinsAdvanced(wallet, totalOut, feeRate, currentHeight)
    except CoinSelectionError:
      # Fall back to simple selection
      selectCoinsSimple(wallet, totalOut, feeRate, currentHeight)
  else:
    selectCoinsSimple(wallet, totalOut, feeRate, currentHeight)

  # Build transaction
  result.version = 2
  result.lockTime = uint32(wallet.params.bip34Height)  # Anti-fee-sniping
  if wallet.chainState != nil:
    result.lockTime = uint32(wallet.chainState.bestHeight)

  # Add inputs
  for utxo in selection.inputs:
    result.inputs.add(TxIn(
      prevOut: utxo.outpoint,
      scriptSig: @[],  # Empty for segwit (filled in for P2SH-P2WPKH)
      sequence: 0xfffffffd'u32  # RBF enabled
    ))

  # Add outputs
  for output in outputs:
    result.outputs.add(output)

  # Add change output if needed
  let change = selection.totalIn - totalOut - selection.fee
  if selection.needsChange and int64(change) > int64(wallet.params.dustLimit):
    # Use same address type as first output for change
    var changeAddrType = P2WPKH
    if outputs.len > 0:
      let spk = outputs[0].scriptPubKey
      if spk.len == 22 and spk[0] == 0x00:
        changeAddrType = P2WPKH
      elif spk.len == 34 and spk[0] == 0x51:
        changeAddrType = P2TR
      elif spk.len == 25 and spk[0] == 0x76:
        changeAddrType = P2PKH
      elif spk.len == 23 and spk[0] == 0xa9:
        changeAddrType = P2SH

    let changeAddr = wallet.getNewAddress(changeAddrType, -1, true)
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

# =============================================================================
# Wallet Encryption
# =============================================================================

proc encryptWallet*(wallet: var Wallet, passphrase: string): bool =
  ## Encrypt the wallet with a passphrase
  ## Returns true on success, false if already encrypted
  ## Reference: Bitcoin Core wallet/wallet.cpp EncryptWallet
  if wallet.isEncrypted:
    raise newException(WalletError, "wallet is already encrypted")

  if passphrase.len == 0:
    raise newException(WalletError, "passphrase cannot be empty")

  # Generate salt for key derivation
  wallet.encryptionSalt = generateSalt()
  wallet.encryptionRounds = DefaultKeyDerivationRounds

  # Derive encryption key from passphrase
  let (encKey, _) = bytesToKeySha512Aes(wallet.encryptionSalt, passphrase,
                                         wallet.encryptionRounds)

  # Encrypt the seed
  let crypter = newWalletCrypter()
  let iv = generateIv()

  # Use the seed's hash as IV prefix for deterministic decryption
  var fullIv: array[32, byte]
  copyMem(addr fullIv[0], addr iv[0], 16)

  wallet.encryptedSeed = encryptSecret(encKey, wallet.seed, fullIv)

  # Prepend the IV to the encrypted data so we can decrypt later
  var encryptedWithIv = newSeq[byte](16 + wallet.encryptedSeed.len)
  copyMem(addr encryptedWithIv[0], addr iv[0], 16)
  copyMem(addr encryptedWithIv[16], addr wallet.encryptedSeed[0], wallet.encryptedSeed.len)
  wallet.encryptedSeed = encryptedWithIv

  # Clear the plaintext seed from memory
  for i in 0 ..< wallet.seed.len:
    wallet.seed[i] = 0

  wallet.isEncrypted = true
  wallet.isLocked = true

  # Clear the master key cache
  for i in 0 ..< wallet.masterKeyCache.len:
    wallet.masterKeyCache[i] = 0

  true

proc unlockWallet*(wallet: var Wallet, passphrase: string, timeout: int = 0): bool =
  ## Unlock an encrypted wallet for a specified duration
  ## timeout: seconds until auto-lock (0 = no auto-lock)
  ## Returns true on success
  ## Reference: Bitcoin Core wallet/wallet.cpp Unlock
  if not wallet.isEncrypted:
    raise newException(WalletError, "wallet is not encrypted")

  if not wallet.isLocked:
    # Already unlocked, just update expiry
    if timeout > 0:
      wallet.unlockExpiry = getTime().toUnix() + int64(timeout)
    else:
      wallet.unlockExpiry = 0
    return true

  # Derive encryption key from passphrase
  let (encKey, _) = bytesToKeySha512Aes(wallet.encryptionSalt, passphrase,
                                         wallet.encryptionRounds)

  # Extract IV from encrypted seed
  if wallet.encryptedSeed.len < 17:  # 16 bytes IV + at least 1 byte data
    raise newException(WalletError, "invalid encrypted seed data")

  var iv: array[16, byte]
  copyMem(addr iv[0], addr wallet.encryptedSeed[0], 16)

  var fullIv: array[32, byte]
  copyMem(addr fullIv[0], addr iv[0], 16)

  # Decrypt the seed
  let encryptedPart = wallet.encryptedSeed[16 ..< wallet.encryptedSeed.len]
  try:
    let decrypted = decryptSecret(encKey, encryptedPart, fullIv)
    if decrypted.len != 64:
      return false

    # Restore the seed
    copyMem(addr wallet.seed[0], addr decrypted[0], 64)

    # Restore master key
    wallet.masterKey = masterKeyFromSeed(wallet.seed)

    # Cache the encryption key for signing operations
    wallet.masterKeyCache = encKey

    wallet.isLocked = false

    # Set unlock expiry
    if timeout > 0:
      wallet.unlockExpiry = getTime().toUnix() + int64(timeout)
    else:
      wallet.unlockExpiry = 0

    true
  except CrypterError:
    false

proc lockWallet*(wallet: var Wallet) =
  ## Lock the wallet, clearing sensitive data from memory
  ## Reference: Bitcoin Core wallet/wallet.cpp Lock
  if not wallet.isEncrypted:
    raise newException(WalletError, "wallet is not encrypted")

  if wallet.isLocked:
    return

  # Clear sensitive data
  for i in 0 ..< wallet.seed.len:
    wallet.seed[i] = 0

  for i in 0 ..< wallet.masterKeyCache.len:
    wallet.masterKeyCache[i] = 0

  for i in 0 ..< wallet.masterKey.key.len:
    wallet.masterKey.key[i] = 0

  wallet.isLocked = true
  wallet.unlockExpiry = 0

proc changePassphrase*(wallet: var Wallet, oldPassphrase: string,
                        newPassphrase: string): bool =
  ## Change the wallet encryption passphrase
  ## Returns true on success
  ## Reference: Bitcoin Core wallet/wallet.cpp ChangeWalletPassphrase
  if not wallet.isEncrypted:
    raise newException(WalletError, "wallet is not encrypted")

  if newPassphrase.len == 0:
    raise newException(WalletError, "new passphrase cannot be empty")

  # First unlock with old passphrase
  let wasLocked = wallet.isLocked
  if wallet.isLocked:
    if not wallet.unlockWallet(oldPassphrase):
      return false

  # Generate new salt
  let newSalt = generateSalt()

  # Derive new encryption key
  let (newEncKey, _) = bytesToKeySha512Aes(newSalt, newPassphrase,
                                            wallet.encryptionRounds)

  # Re-encrypt the seed with new key
  let iv = generateIv()
  var fullIv: array[32, byte]
  copyMem(addr fullIv[0], addr iv[0], 16)

  let newEncrypted = encryptSecret(newEncKey, wallet.seed, fullIv)

  # Prepend the IV
  var encryptedWithIv = newSeq[byte](16 + newEncrypted.len)
  copyMem(addr encryptedWithIv[0], addr iv[0], 16)
  copyMem(addr encryptedWithIv[16], addr newEncrypted[0], newEncrypted.len)

  # Update wallet state
  wallet.encryptedSeed = encryptedWithIv
  wallet.encryptionSalt = newSalt
  wallet.masterKeyCache = newEncKey

  # Re-lock if it was locked before
  if wasLocked:
    wallet.lockWallet()

  true

proc checkUnlockExpiry*(wallet: var Wallet) =
  ## Check if the wallet unlock has expired and lock if necessary
  if wallet.isEncrypted and not wallet.isLocked and wallet.unlockExpiry > 0:
    if getTime().toUnix() >= wallet.unlockExpiry:
      wallet.lockWallet()

proc isWalletLocked*(wallet: Wallet): bool =
  ## Check if wallet operations requiring private keys are available
  if not wallet.isEncrypted:
    return false
  wallet.isLocked

# =============================================================================
# Address Labels
# =============================================================================

proc setLabel*(wallet: var Wallet, address: string, label: string) =
  ## Set a label for an address
  ## Reference: Bitcoin Core wallet/wallet.cpp SetAddressBook
  if label.len == 0:
    # Empty label removes the label
    wallet.labels.del(address)
  else:
    wallet.labels[address] = label

proc getLabel*(wallet: Wallet, address: string): string =
  ## Get the label for an address
  ## Returns empty string if no label set
  wallet.labels.getOrDefault(address, "")

proc getAddressesByLabel*(wallet: Wallet, label: string): seq[string] =
  ## Get all addresses with a specific label
  result = @[]
  for address, addrLabel in wallet.labels:
    if addrLabel == label:
      result.add(address)

proc listLabels*(wallet: Wallet): seq[string] =
  ## List all unique labels
  var labelSet: Table[string, bool]
  for _, label in wallet.labels:
    labelSet[label] = true
  result = @[]
  for label, _ in labelSet:
    result.add(label)

proc getImmatureBalance*(wallet: Wallet, currentHeight: int32): Satoshi =
  ## Get total immature coinbase balance
  result = Satoshi(0)
  for _, utxo in wallet.utxos:
    if utxo.isCoinbase and not utxo.isMatureCoinbase(currentHeight):
      result = result + utxo.output.value
