## HD Wallet implementation
## BIP-32/39/44/84/86 key derivation, transaction creation and signing

import std/[tables, options, strutils, sysrand, algorithm, times]
import nimcrypto/[sha2, hmac, pbkdf2]
import ../primitives/[types, serialize]
import ../crypto/[hashing, secp256k1, address, base58]
import ../consensus/params
import ../script/interpreter
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

  ## A single credit (output to the wallet) or debit (wallet input spent) leg
  ## of a wallet-relevant transaction. Mirrors Bitcoin Core's COutputEntry —
  ## one entry per relevant vout (receive) or per debited destination (send).
  WalletTxDetail* = object
    scriptPubKey*: seq[byte]  ## Output script of this leg (address extracted at RPC)
    isSend*: bool           ## true = a "send" leg (wallet debited, output to a
                            ## non-change destination); false = "receive" leg
                            ## (output paid TO the wallet)
    isMine*: bool           ## true if this output pays the wallet
    amount*: Satoshi        ## Always the POSITIVE leg amount; sign applied at RPC
    vout*: uint32           ## Output index this leg refers to

  ## A wallet's record of one on-chain transaction it participated in.
  ## Populated at block-connect scan time (scanBlockForWallet) and removed at
  ## block-disconnect (unscanBlockForWallet), mirroring Bitcoin Core's
  ## CWalletTx in mapWallet. This is the persistent transaction-history ledger
  ## that backs listtransactions / gettransaction — distinct from the live
  ## UTXO set (Wallet.utxos), which only knows about *unspent* coins and so
  ## cannot answer "show me the send I made".
  WalletTxRecord* = object
    txid*: TxId
    isCoinbase*: bool
    credit*: Satoshi        ## sum of output values paid TO the wallet
    debit*: Satoshi         ## sum of prevout values the wallet SPENT
    valueOut*: Satoshi      ## sum of ALL output values of the tx (for fee calc)
    fromMe*: bool           ## true if the wallet contributed any input (a send)
    height*: int32          ## block height this tx was confirmed at (0 = none)
    blockHash*: BlockHash   ## hash of the confirming block
    blockTime*: int64       ## confirming block's header timestamp
    blockIndex*: int        ## position within the block (0-based)
    time*: int64            ## wallet-local time the tx was first seen
    details*: seq[WalletTxDetail]  ## per-leg credit/debit breakdown
    rawTx*: seq[byte]       ## full (witness) serialization, for the "hex" field

  Wallet* = ref object
    seed*: array[64, byte]
    masterKey*: ExtendedKey
    accounts*: seq[Account]
    ## Keys imported by importprivkey (NOT derived from the HD seed). Each is a
    ## standalone DerivedKey carrying a hand-built ExtendedKey (the imported
    ## 32-byte privkey + its derived pubkey) and the address(es) that pay it.
    ## Mirrors Bitcoin Core's legacy keystore (CWallet::ImportPrivKeys): the key
    ## lives in the keystore alongside the HD-derived keys, so findKeyForScript
    ## matches its scripts and the wallet can both credit and spend its coins.
    ## Held separately from `accounts` so reseedAccounts (sethdseed keypool
    ## flush) never wipes an imported key.
    importedKeys*: seq[DerivedKey]
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
    # Transaction history (backs listtransactions / gettransaction).
    # txHistory: txid -> record; txOrder: txids in first-seen (scan) order so
    # listtransactions can return "most recent last / first N most recent"
    # deterministically without relying on Table iteration order.
    txHistory*: Table[TxId, WalletTxRecord]
    txOrder*: seq[TxId]

# BIP39 wordlist - loaded at compile time
const BIP39_WORDLIST* = staticRead("../../resources/bip39-english.txt").strip().splitLines()

# Hardened derivation constant
const HARDENED* = 0x80000000'u32

# Coinbase maturity - outputs can only be spent after this many confirmations
const CoinbaseMaturity* = 100

# Forward declarations
proc addAccount*(wallet: var Wallet, purpose: uint32 = 84, accountIndex: uint32 = 0, gap: int = 20)

# BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data).
# Duplicated locally (also in script/interpreter.nim) to keep the wallet
# free of any interpreter dep.
proc walletTaggedHash*(tag: string, data: openArray[byte]): array[32, byte] =
  let tagHash = sha256(cast[seq[byte]](tag))
  var preimage = newSeq[byte](64 + data.len)
  for i in 0 ..< 32: preimage[i] = tagHash[i]
  for i in 0 ..< 32: preimage[32 + i] = tagHash[i]
  for i in 0 ..< data.len: preimage[64 + i] = data[i]
  sha256(preimage)

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

proc masterKeyFromSeedRaw*(seed: openArray[byte]): ExtendedKey =
  ## Derive master extended private key from a variable-length raw seed.
  ## BIP-32 specifies HMAC-SHA512(key="Bitcoin seed", data=seed_bytes) over
  ## the raw byte string of the seed (16, 32 or 64 bytes per the spec).
  ## The fixed-size masterKeyFromSeed wrapper above always passes 64 bytes;
  ## official BIP-32 test vectors use 16-byte and other sizes, so this
  ## variant is provided for tests / interop.
  var hmacCtx: HMAC[sha512]
  hmacCtx.init("Bitcoin seed")
  hmacCtx.update(seed)
  let output = hmacCtx.finish()
  hmacCtx.clear()

  copyMem(addr result.key[0], addr output.data[0], 32)
  copyMem(addr result.chainCode[0], addr output.data[32], 32)
  result.depth = 0
  result.parentFingerprint = [0'u8, 0, 0, 0]
  result.childIndex = 0
  result.isPrivate = true
  result.publicKey = derivePublicKey(result.key)

proc neuter*(key: ExtendedKey): ExtendedKey =
  ## Return the public-only ("neutered") form of an extended key.
  ## Same chain code, depth, parentFingerprint and childIndex; private key
  ## bytes zeroed; isPrivate=false; publicKey unchanged.
  result = key
  result.isPrivate = false
  for i in 0 ..< 32:
    result.key[i] = 0

proc fingerprint*(key: ExtendedKey): array[4, byte] =
  ## Get the fingerprint of a key (first 4 bytes of Hash160 of pubkey)
  let h = hash160(key.publicKey)
  copyMem(addr result[0], addr h[0], 4)

proc deriveChild*(parent: ExtendedKey, index: uint32): ExtendedKey =
  ## Derive child extended key from parent
  ## If index >= 0x80000000, it's a hardened derivation (requires private key)
  ##
  ## BIP-32 retry contract (W161 BUG-4): if libsecp rejects the IL+parent
  ## tweak (because parse256(IL) >= n OR the resulting key is zero / the
  ## point at infinity), the spec mandates "proceed with the next value
  ## for i". We honour that here by looping on the requested child index
  ## without crossing the hardened/unhardened boundary. Probability per
  ## iteration is ~2^-127, so in practice the loop body runs once. See
  ## bitcoin-core/src/key.cpp::CExtKey::Derive +
  ## bitcoin-core/src/wallet/scriptpubkeyman.cpp::DescriptorScriptPubKeyMan::TopUp.
  ##
  ## BIP-32 depth invariant (W161 BUG-5): parent depth MUST be < 0xFF;
  ## otherwise we would silently wrap to 0 and produce an xprv whose
  ## serialised form claims depth=0 (a master-key marker), a fake-master
  ## footgun. See bitcoin-core/src/key.cpp::CExtKey::Derive line 483.

  # W161 BUG-5: depth-byte overflow guard. Core: `if (nDepth == 0xFF) return false`.
  if parent.depth == 0xFF'u8:
    raise newException(WalletError,
      "BIP-32 max derivation depth (255) reached; cannot derive deeper child")

  let hardened = index >= HARDENED

  if hardened and not parent.isPrivate:
    raise newException(WalletError, "cannot derive hardened child from public key")

  # W161 BUG-4: loop on the requested child index per BIP-32 spec.
  # Boundaries: hardened indexes live in [HARDENED, 2^32); unhardened in
  # [0, HARDENED). Wrapping past either edge is a spec violation and must
  # raise rather than silently cross into the other regime.
  var curIndex = index
  while true:
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
    data.add(byte((curIndex shr 24) and 0xff))
    data.add(byte((curIndex shr 16) and 0xff))
    data.add(byte((curIndex shr 8) and 0xff))
    data.add(byte(curIndex and 0xff))

    # HMAC-SHA512
    var hmacCtx: HMAC[sha512]
    hmacCtx.init(parent.chainCode)
    hmacCtx.update(data)
    let output = hmacCtx.finish()
    hmacCtx.clear()

    # IL = left 32 bytes of HMAC output, used as the additive tweak for
    # both CKD_priv and CKD_pub. libsecp's tweak_add primitives return
    # None when parse256(IL) >= n OR the resulting key is invalid (zero
    # seckey / point at infinity); on either rejection BIP-32 says
    # "proceed with the next value for i".
    var il: array[32, byte]
    copyMem(addr il[0], addr output.data[0], 32)

    if parent.isPrivate:
      # Private key derivation: child_key = (parent_key + IL) mod n.
      # Mirrors bitcoin-core/src/key.cpp::CKey::Derive.
      let tweaked = tweakSeckeyAdd(parent.key, il)
      if tweaked.isSome:
        result.depth = parent.depth + 1
        result.parentFingerprint = fingerprint(parent)
        result.childIndex = curIndex
        result.isPrivate = parent.isPrivate
        copyMem(addr result.chainCode[0], addr output.data[32], 32)
        result.key = tweaked.get()
        result.publicKey = derivePublicKey(result.key)
        return
    else:
      # Public key derivation: child_pubkey = parent_pubkey + IL*G.
      let tweakedPk = tweakPubkeyAdd(parent.publicKey, il)
      if tweakedPk.isSome:
        result.depth = parent.depth + 1
        result.parentFingerprint = fingerprint(parent)
        result.childIndex = curIndex
        result.isPrivate = parent.isPrivate
        copyMem(addr result.chainCode[0], addr output.data[32], 32)
        result.publicKey = tweakedPk.get()
        # No private key in xpub-only derivation; leave result.key zeroed
        # (default array init) and isPrivate = false (already set above).
        return

    # Libsecp rejected; bump curIndex per BIP-32 retry contract.
    # Preserve hardened/unhardened semantics: do not cross the boundary.
    if hardened:
      if curIndex == high(uint32):
        raise newException(WalletError,
          "BIP-32 retry exhausted hardened index space (reached 2^32)")
    else:
      if curIndex == HARDENED - 1'u32:
        raise newException(WalletError,
          "BIP-32 retry would cross unhardened/hardened boundary (reached 2^31 - 1)")
    curIndex = curIndex + 1'u32

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
  of 86:  # BIP86 - P2TR (Taproot, single-key, no script tree)
    # Per BIP-86 the address output key is the *tweaked* x-only key:
    #   internal_key P = compressed_pubkey[1..33]   (drop the parity byte)
    #   t            = tagged_hash("TapTweak", P)   (empty merkle root)
    #   Q            = P + t * G
    # Sending coins to the raw internal x-only key (the previous behavior
    # here) makes the output unspendable by any compliant signer because
    # no one ever derives Q from those funds.
    var internalXonly: array[32, byte]
    copyMem(addr internalXonly[0], addr extKey.publicKey[1], 32)
    let tweak = walletTaggedHash("TapTweak", internalXonly)
    let tweaked = tweakXonlyPubkey(internalXonly, tweak)
    result.address = Address(kind: P2TR, taprootKey: tweaked[0])
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

proc reseedAccounts(wallet: var Wallet) =
  ## Re-derive every account's keys from the wallet's current masterKey.
  ## Account *structure* (purpose / coinType / accountIndex / gap) is
  ## preserved; the derived external/internal keys are regenerated from the
  ## new master and the next-index cursors are reset to 0. Used by
  ## setHdSeed so address derivation becomes deterministic w.r.t. the new
  ## seed (mirrors the keypool-flush half of Core's sethdseed).
  for ai in 0 ..< wallet.accounts.len:
    var acc = wallet.accounts[ai]
    let purpose = acc.purpose
    let coinType = acc.coinType
    let accountIndex = acc.accountIndex
    let gap = if acc.gap > 0: acc.gap else: 20
    acc.externalKeys = @[]
    acc.internalKeys = @[]
    acc.nextExternal = 0
    acc.nextInternal = 0
    for i in 0 ..< gap:
      acc.externalKeys.add(wallet.derivePath(purpose, coinType, accountIndex, 0, uint32(i)))
      acc.internalKeys.add(wallet.derivePath(purpose, coinType, accountIndex, 1, uint32(i)))
    wallet.accounts[ai] = acc

proc setHdSeed*(wallet: var Wallet, seed: openArray[byte]) =
  ## Restore-from-seed: replace the wallet's HD seed + master key with the
  ## given raw seed bytes and re-derive all keys deterministically.
  ## Reference: Bitcoin Core wallet sethdseed (CWallet::SetHDSeed +
  ## keypool flush). The raw seed is run through BIP-32
  ## HMAC-SHA512(key="Bitcoin seed", data=seed) — same primitive as a
  ## BIP-39 mnemonic-derived seed — so feeding the identical seed twice
  ## yields a byte-identical master key and therefore byte-identical
  ## addresses across the entire derivation tree.
  if seed.len < 16 or seed.len > 64:
    raise newException(WalletError, "seed must be 16-64 bytes")
  # Cache the seed (zero-pad / truncate into the fixed 64-byte slot for the
  # encrypted-on-disk path; derivation itself uses the raw bytes below).
  for i in 0 ..< wallet.seed.len:
    wallet.seed[i] = if i < seed.len: seed[i] else: 0'u8
  wallet.masterKey = masterKeyFromSeedRaw(seed)
  # If the wallet has no accounts yet (e.g. created blank), seed the default
  # BIP-84 native-segwit account so getnewaddress works immediately.
  if wallet.accounts.len == 0:
    wallet.addAccount(84, 0, 20)
  else:
    wallet.reseedAccounts()

proc setHdSeedFromMnemonic*(wallet: var Wallet, mnemonic: string,
                            passphrase: string = "") =
  ## Convenience restore: BIP-39 mnemonic -> 64-byte seed -> setHdSeed.
  if not validateMnemonic(mnemonic):
    raise newException(WalletError, "invalid mnemonic")
  let s = mnemonicToSeed(mnemonic, passphrase)
  wallet.setHdSeed(s)

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
  # Imported (non-HD) keys: matched the same way so importprivkey'd coins are
  # credited at block-connect / rescan and remain spendable. Mirrors Core's
  # single keystore that holds derived + imported keys together.
  for key in wallet.importedKeys:
    if scriptPubKeyForAddress(key.address) == scriptPubKey:
      return some(key)
  none(DerivedKey)

proc importPrivateKey*(wallet: var Wallet, privKey: PrivateKey,
                       compressed: bool = true): seq[string] =
  ## Add a raw private key (decoded from a WIF) to the wallet keystore as an
  ## imported (non-HD) key, registering the address(es) it can be spent to so
  ## findKeyForScript matches them at block-connect / rescan time. Returns the
  ## list of address strings now owned by the wallet for this key.
  ##
  ## Reference: Bitcoin Core wallet/rpc/backup.cpp importprivkey ->
  ## CWallet::ImportPrivKeys / AddKeyPubKey: the key enters the same keystore as
  ## HD-derived keys, and the wallet learns to recognise the standard scripts
  ## that pay it. We register the native-segwit (P2WPKH) and legacy (P2PKH)
  ## forms — the two single-key standard outputs a regtest payer can target —
  ## so coins sent to either are credited and spendable.
  let pub = derivePublicKey(privKey)
  let pkh = hash160(pub)

  # Build the standalone ExtendedKey wrapping the imported scalar. depth/index
  # are unused for an imported key (it is not part of any derivation path); we
  # only need key + publicKey for signing and address derivation.
  var extKey: ExtendedKey
  extKey.key = privKey
  extKey.publicKey = pub
  extKey.depth = 0
  extKey.parentFingerprint = [0'u8, 0, 0, 0]
  extKey.childIndex = 0
  extKey.isPrivate = true

  result = @[]

  proc addImported(wallet: var Wallet, addr0: Address): string =
    let spk = scriptPubKeyForAddress(addr0)
    # Idempotent: don't double-register a script we already own.
    if wallet.findKeyForScript(spk).isSome:
      return encodeAddress(addr0, wallet.mainnet)
    let dk = DerivedKey(
      extKey: extKey,
      path: "imported",
      address: addr0,
      addressStr: encodeAddress(addr0, wallet.mainnet))
    wallet.importedKeys.add(dk)
    dk.addressStr

  # Native segwit (the wallet's default getnewaddress type) and legacy P2PKH.
  result.add(wallet.addImported(Address(kind: P2WPKH, wpkh: pkh)))
  result.add(wallet.addImported(Address(kind: P2PKH, pubkeyHash: pkh)))

proc encodeWIF*(privKey: PrivateKey, mainnet: bool, compressed: bool = true): string =
  ## Encode a 32-byte private key as a WIF string. Layout (Base58Check):
  ##   [version=0x80 mainnet / 0xEF testnet] || 32-byte key || (0x01 if compressed)
  ## Reference: Bitcoin Core key_io.cpp EncodeSecret.
  var payload: seq[byte] = @[]
  payload.add(if mainnet: 0x80'u8 else: 0xEF'u8)
  payload.add(@privKey)
  if compressed:
    payload.add(0x01'u8)
  base58CheckEncode(payload)

proc dumpPrivKey*(wallet: Wallet, address: string): Option[string] =
  ## Return the WIF private key for an address the wallet owns, or none if the
  ## address is not in the wallet (or is watch-only). Reference: Bitcoin Core
  ## wallet/rpc/backup.cpp dumpprivkey -> CWallet::GetKey + EncodeSecret.
  let spk =
    try: scriptPubKeyForAddress(decodeAddress(address))
    except CatchableError: return none(string)
  let keyOpt = wallet.findKeyForScript(spk)
  if keyOpt.isNone or not keyOpt.get().extKey.isPrivate:
    return none(string)
  some(encodeWIF(keyOpt.get().extKey.key, wallet.mainnet, compressed = true))

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
  ## Check if a coinbase UTXO has reached maturity for the WALLET.
  ##
  ## Bitcoin Core's wallet (CWallet::GetTxBlocksToMaturity, wallet.cpp:3333)
  ## treats a coinbase as immature while
  ##   GetBlocksToMaturity = max(0, (COINBASE_MATURITY+1) - chain_depth) > 0,
  ## i.e. it is spendable only once chain_depth >= COINBASE_MATURITY + 1
  ## (chain_depth == confirmations == currentHeight - height + 1).
  ##
  ## This is deliberately one block MORE conservative than the mempool's
  ## maturity gate (which spends at tip+1, i.e. accepts confirmations >=
  ## COINBASE_MATURITY).  Using the wallet rule here guarantees coin-selection
  ## never offers a coin the mempool would later reject with
  ## bad-txns-premature-spend-of-coinbase, and makes getbalance match Core
  ## (at tip 101 after mining 101, only the height-1 coinbase is mature -> 50
  ## BTC, not the height-2 coinbase which is still 1 block short).
  if not utxo.isCoinbase:
    return true  # Non-coinbase outputs are always mature
  if utxo.height <= 0:
    return false  # Unconfirmed coinbase is never mature
  let confirmations = currentHeight - utxo.height + 1
  confirmations >= CoinbaseMaturity + 1

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

proc buildTxAmounts(wallet: Wallet, tx: Transaction,
                    inputValues: openArray[Satoshi]):
    tuple[credit, debit, valueOut: Satoshi, fromMe: bool,
          details: seq[WalletTxDetail]] =
  ## Compute the wallet's credit / debit / value-out / from-me / per-leg detail
  ## breakdown for a transaction, mirroring Bitcoin Core's CachedTxGetAmounts
  ## (wallet/receive.cpp:139). `inputValues` supplies the value of each input
  ## that the wallet owns (0 for inputs it does not own); the sum is the debit.
  var debit = Satoshi(0)
  for v in inputValues:
    debit = debit + v
  let fromMe = int64(debit) > 0

  var credit = Satoshi(0)
  var valueOut = Satoshi(0)
  var details: seq[WalletTxDetail]
  for voutIdx, output in tx.outputs:
    valueOut = valueOut + output.value
    let keyOpt = wallet.findKeyForScript(output.scriptPubKey)
    let ismine = keyOpt.isSome
    let isChange = ismine and keyOpt.get().path.contains("/1/")
    if ismine:
      credit = credit + output.value
    # Per Core CachedTxGetAmounts: emit a leg only if (we sent and it's not
    # change) or (the output is ours).
    if fromMe:
      if isChange:
        continue  # include_change=false (listtransactions/gettransaction default)
      details.add(WalletTxDetail(
        scriptPubKey: output.scriptPubKey,
        isSend: true,
        isMine: ismine,
        amount: output.value,
        vout: uint32(voutIdx)))
    elif ismine:
      details.add(WalletTxDetail(
        scriptPubKey: output.scriptPubKey,
        isSend: false,
        isMine: true,
        amount: output.value,
        vout: uint32(voutIdx)))
  (credit, debit, valueOut, fromMe, details)

proc recordOutgoingTx*(wallet: var Wallet, tx: Transaction,
                       inputValues: openArray[Satoshi], firstSeen: int64) =
  ## Record a transaction the wallet just CREATED + broadcast (sendtoaddress),
  ## before it confirms. Mirrors Bitcoin Core's CWallet::CommitTransaction,
  ## which inserts the wtx into mapWallet at commit time with its from-me debit
  ## and fee already known. This MUST happen at send time because
  ## handleSendToAddress optimistically removes the spent UTXOs from the live
  ## ledger (so coin-selection cannot reuse them) — by the time the confirming
  ## block is scanned, the prevout values are gone, so the block scan alone
  ## could not tell the tx apart from a plain receive of the change output.
  ## The later block-connect scan upgrades this record with block info.
  let txId = tx.txid()
  let amounts = wallet.buildTxAmounts(tx, inputValues)
  if int64(amounts.credit) == 0 and not amounts.fromMe:
    return
  if txId notin wallet.txHistory:
    wallet.txOrder.add(txId)
  wallet.txHistory[txId] = WalletTxRecord(
    txid: txId,
    isCoinbase: false,
    credit: amounts.credit,
    debit: amounts.debit,
    valueOut: amounts.valueOut,
    fromMe: amounts.fromMe,
    height: 0,            # unconfirmed until a block scan upgrades it
    blockTime: 0,
    blockIndex: 0,
    time: firstSeen,
    details: amounts.details,
    rawTx: serialize(tx, includeWitness = true))

proc recordWalletTx(wallet: var Wallet, tx: Transaction, txId: TxId,
                    coinbase: bool, blk: Block, height: int32,
                    blockIndex: int) =
  ## Build (or refresh) the transaction-history record for a wallet-relevant
  ## tx confirmed in a block, and store it in wallet.txHistory. Mirrors Bitcoin
  ## Core's CachedTxGetAmounts (wallet/receive.cpp:139): a tx is recorded if it
  ## credits the wallet (an output is ours) and/or debits the wallet (an input
  ## spends one of our UTXOs). Debits are valued from the wallet's own UTXO
  ## ledger at scan time — the prevouts the wallet spent are still present iff
  ## this is the wallet's first sight of the tx (this proc runs BEFORE the
  ## removeUtxo pass in scanBlockForWallet).
  ##
  ## If the tx was already recorded at send time (recordOutgoingTx) the live
  ## ledger no longer holds its prevouts (sendtoaddress pre-removed them), so a
  ## ledger-only recompute would mis-classify the spend as a pure receive of
  ## the change. We therefore PRESERVE the from-me debit/credit/details from the
  ## existing record and only upgrade the confirmation fields here.
  var inputValues: seq[Satoshi]
  for input in tx.inputs:
    if input.prevOut in wallet.utxos:
      inputValues.add(wallet.utxos[input.prevOut].output.value)

  let bHash = blockHash(serialize(blk.header))

  if txId in wallet.txHistory and wallet.txHistory[txId].fromMe:
    # Already recorded (send time) with correct from-me amounts — just confirm.
    var rec = wallet.txHistory[txId]
    rec.height = height
    rec.blockHash = bHash
    rec.blockTime = int64(blk.header.timestamp)
    rec.blockIndex = blockIndex
    wallet.txHistory[txId] = rec
    return

  let amounts = wallet.buildTxAmounts(tx, inputValues)
  # Only record txs that actually touch the wallet (credit or debit).
  if int64(amounts.credit) == 0 and not amounts.fromMe:
    return

  let firstSeen = if txId in wallet.txHistory: wallet.txHistory[txId].time
                  else: int64(blk.header.timestamp)
  if txId notin wallet.txHistory:
    wallet.txOrder.add(txId)
  wallet.txHistory[txId] = WalletTxRecord(
    txid: txId,
    isCoinbase: coinbase,
    credit: amounts.credit,
    debit: amounts.debit,
    valueOut: amounts.valueOut,
    fromMe: amounts.fromMe,
    height: height,
    blockHash: bHash,
    blockTime: int64(blk.header.timestamp),
    blockIndex: blockIndex,
    time: firstSeen,
    details: amounts.details,
    rawTx: serialize(tx, includeWitness = true))

proc scanBlockForWallet*(wallet: var Wallet, blk: Block, height: int32) =
  ## Scan a block for transactions relevant to the wallet
  for txIdx, tx in blk.txs:
    let txId = tx.txid()
    let coinbase = tx.isCoinbaseTx()

    # Record the wallet transaction-history entry BEFORE mutating the UTXO
    # ledger, so debit legs can be valued from the still-present prevouts.
    wallet.recordWalletTx(tx, txId, coinbase, blk, height, txIdx)

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

proc unscanBlockForWallet*(wallet: var Wallet, blk: Block, height: int32) =
  ## Reverse of scanBlockForWallet for a block being disconnected during a
  ## reorg. Symmetric to the UTXO unscan: removes any transaction-history
  ## records this block contributed so listtransactions/gettransaction never
  ## report a tx that is no longer in the active chain. Mirrors Bitcoin Core's
  ## CWallet::blockDisconnected, which marks the affected wtx unconfirmed; here
  ## we simply drop the confirmed record (nimrod's wallet does not track
  ## mempool-pending wtxs, so a disconnected confirmed tx leaves the history).
  for tx in blk.txs:
    let txId = tx.txid()
    if txId in wallet.txHistory:
      wallet.txHistory.del(txId)
      let idx = wallet.txOrder.find(txId)
      if idx >= 0:
        wallet.txOrder.delete(idx)

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
                           scriptCode: seq[byte], value: Satoshi,
                           hashType: uint32 = uint32(SIGHASH_ALL)): array[32, byte] =
  ## Compute BIP-143 sighash for a P2WPKH input.
  ##
  ## Thin wrapper over the canonical interpreter implementation
  ## (`script/interpreter.computeSighashSegwitV0`). Previously this
  ## proc had a hand-rolled body that hard-coded `hashType = 0x01`
  ## (SIGHASH_ALL), silently mis-signing any non-default sighash.
  ## See W27-B / `CORE-PARITY-AUDIT/_fix-verification-methodology-2026-05-04.md`.
  computeSighashSegwitV0(tx, inputIdx, scriptCode, value, hashType)

proc compactSigToDer(sig: Signature, hashType: uint32): seq[byte] =
  ## Encode a compact (r||s) ECDSA signature as DER + sighash-type byte.
  ##
  ## Output shape: 0x30 <seqLen> 0x02 <rLen> <r> 0x02 <sLen> <s> <hashType>.
  ## Big-endian INTs are stripped of leading 0x00 unless the next byte has
  ## bit 0x80 set (per DER); that also forces a leading 0x00 if the high
  ## bit of the most-significant byte is set.
  ##
  ## Factored out from `signInputP2WPKH` (W29-E) so all four spend types
  ## share one DER encoder.
  var r: array[32, byte]
  var s: array[32, byte]
  copyMem(addr r[0], addr sig[0], 32)
  copyMem(addr s[0], addr sig[32], 32)

  var rBytes: seq[byte]
  rBytes.add(@r)
  while rBytes.len > 1 and rBytes[0] == 0 and (rBytes[1] and 0x80) == 0:
    rBytes.delete(0)
  if (rBytes[0] and 0x80) != 0:
    rBytes.insert(0, 0)

  var sBytes: seq[byte]
  sBytes.add(@s)
  while sBytes.len > 1 and sBytes[0] == 0 and (sBytes[1] and 0x80) == 0:
    sBytes.delete(0)
  if (sBytes[0] and 0x80) != 0:
    sBytes.insert(0, 0)

  result = @[]
  result.add(0x30)  # SEQUENCE
  let seqLen = 2 + rBytes.len + 2 + sBytes.len
  result.add(byte(seqLen))
  result.add(0x02)  # INTEGER (r)
  result.add(byte(rBytes.len))
  result.add(rBytes)
  result.add(0x02)  # INTEGER (s)
  result.add(byte(sBytes.len))
  result.add(sBytes)
  # Append sighash-type byte (low 8 bits, e.g. SIGHASH_ALL = 0x01).
  result.add(byte(hashType and 0xff))

proc pushScript(s: openArray[byte]): seq[byte] =
  ## Wrap a script blob in a Bitcoin-script push opcode (PUSHDATA*).
  ##
  ## - len <  0x4c       : <len> <data>
  ## - len <= 0xff       : 0x4c <len> <data>      (OP_PUSHDATA1)
  ## - len <= 0xffff     : 0x4d <len LE16> <data> (OP_PUSHDATA2)
  ## - else              : 0x4e <len LE32> <data> (OP_PUSHDATA4)
  ##
  ## Used to wrap redeemScripts inside scriptSig and witnessScripts inside
  ## scriptSig pushes (for P2SH-P2WSH).
  result = @[]
  if s.len < 0x4c:
    result.add(byte(s.len))
  elif s.len <= 0xff:
    result.add(0x4c)
    result.add(byte(s.len))
  elif s.len <= 0xffff:
    result.add(0x4d)
    result.add(byte(s.len and 0xff))
    result.add(byte((s.len shr 8) and 0xff))
  else:
    result.add(0x4e)
    result.add(byte(s.len and 0xff))
    result.add(byte((s.len shr 8) and 0xff))
    result.add(byte((s.len shr 16) and 0xff))
    result.add(byte((s.len shr 24) and 0xff))
  for b in s:
    result.add(b)

proc signInputP2WPKH*(tx: var Transaction, inputIdx: int,
                      privateKey: PrivateKey, publicKey: PublicKey,
                      value: Satoshi,
                      hashType: uint32 = uint32(SIGHASH_ALL)) =
  ## Sign a P2WPKH input.
  ##
  ## `hashType` defaults to SIGHASH_ALL for backwards compatibility.
  ## Any combination of SIGHASH_{ALL,NONE,SINGLE} optionally OR'd with
  ## SIGHASH_ANYONECANPAY is accepted; the byte is appended to the DER
  ## signature on the witness stack.
  # Build scriptCode: OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG
  let pkh = hash160(publicKey)
  var scriptCode = @[0x76'u8, 0xa9, 0x14]  # OP_DUP OP_HASH160 PUSH20
  scriptCode.add(@pkh)
  scriptCode.add([0x88'u8, 0xac])  # OP_EQUALVERIFY OP_CHECKSIG

  # Compute sighash with the requested hashType (was hard-coded SIGHASH_ALL).
  let sighash = computeSighashP2WPKH(tx, inputIdx, scriptCode, value, hashType)

  # Sign
  let sig = sign(privateKey, sighash)
  let derSig = compactSigToDer(sig, hashType)

  # Set witness: [signature, pubkey]
  tx.witnesses[inputIdx] = @[derSig, @(publicKey)]

proc signInputP2PKH*(tx: var Transaction, inputIdx: int,
                     privateKey: PrivateKey, publicKey: PublicKey,
                     hashType: uint32 = uint32(SIGHASH_ALL)) =
  ## Sign a legacy P2PKH input (BIP-62).
  ##
  ## scriptCode is the prevout's scriptPubKey shape:
  ##   OP_DUP OP_HASH160 <hash160(pubkey)> OP_EQUALVERIFY OP_CHECKSIG
  ##
  ## Output:
  ##   tx.inputs[inputIdx].scriptSig = <sig+hashType> <pubkey>
  ##   tx.witnesses[inputIdx] = []
  ##
  ## Cross-impl reference: blockbrew SignTxInputP2PKH (W27-D 5d9d942),
  ## camlcoin sign_p2pkh, lunarblock W28 a977878.
  let pkh = hash160(publicKey)
  var scriptCode = @[0x76'u8, 0xa9, 0x14]
  scriptCode.add(@pkh)
  scriptCode.add([0x88'u8, 0xac])

  let sighash = computeSighashLegacy(tx, inputIdx, scriptCode, hashType)
  let sig = sign(privateKey, sighash)
  let derSig = compactSigToDer(sig, hashType)

  # Build scriptSig: <push sig+hashType> <push pubkey>
  var scriptSig: seq[byte]
  scriptSig.add(byte(derSig.len))
  scriptSig.add(derSig)
  scriptSig.add(byte(publicKey.len))
  scriptSig.add(@publicKey)
  tx.inputs[inputIdx].scriptSig = scriptSig
  # Legacy: empty witness for this input.
  tx.witnesses[inputIdx] = @[]

proc signInputP2SHP2WPKH*(tx: var Transaction, inputIdx: int,
                          privateKey: PrivateKey, publicKey: PublicKey,
                          value: Satoshi,
                          hashType: uint32 = uint32(SIGHASH_ALL)) =
  ## Sign a wrapped-segwit (BIP49) P2SH-P2WPKH input.
  ##
  ## - redeemScript = OP_0 <hash160(pubkey)>           (22 bytes)
  ## - scriptSig    = <push redeemScript>              (single push)
  ## - witness      = [<sig+hashType>, <pubkey>]       (BIP-143)
  ##
  ## BIP-143 vector 4 (Core's test) covers this exact shape.
  let wpkh = hash160(publicKey)
  var redeemScript = @[0x00'u8, 0x14]  # OP_0 PUSH20
  redeemScript.add(@wpkh)

  # Inner witness signing matches P2WPKH: scriptCode is the implicit
  # P2PKH-shaped form, NOT the redeemScript itself. (BIP-143 §"Native witness
  # — P2WPKH or P2SH-P2WPKH": scriptCode is the canonical P2PKH script of
  # the witness program's hash.)
  var scriptCode = @[0x76'u8, 0xa9, 0x14]  # OP_DUP OP_HASH160 PUSH20
  scriptCode.add(@wpkh)
  scriptCode.add([0x88'u8, 0xac])  # OP_EQUALVERIFY OP_CHECKSIG

  let sighash = computeSighashSegwitV0(tx, inputIdx, scriptCode, value, hashType)
  let sig = sign(privateKey, sighash)
  let derSig = compactSigToDer(sig, hashType)

  # scriptSig is just one push: the redeemScript.
  tx.inputs[inputIdx].scriptSig = pushScript(redeemScript)
  # Witness like P2WPKH: [signature, pubkey].
  tx.witnesses[inputIdx] = @[derSig, @(publicKey)]

proc signInputP2WSH*(tx: var Transaction, inputIdx: int,
                     privateKeys: openArray[PrivateKey],
                     witnessScript: openArray[byte],
                     value: Satoshi,
                     hashType: uint32 = uint32(SIGHASH_ALL),
                     isMultisig: bool = true) =
  ## Sign a native P2WSH input.
  ##
  ## scriptCode = witnessScript (BIP-143 §"P2WSH").
  ##
  ## For multisig (default): emits witness
  ##   [OP_0, sig1+hashType, ..., sigM+hashType, witnessScript]
  ## where the leading empty element is the CHECKMULTISIG dummy. Each
  ## supplied private key produces one signature in the order given;
  ## CHECKMULTISIG verifies signatures in pubkey order, so the caller
  ## is responsible for ordering `privateKeys` to match the order the
  ## corresponding pubkeys appear in `witnessScript`.
  ##
  ## For non-multisig (e.g. single OP_CHECKSIG witnessScript), pass
  ## `isMultisig = false`. Witness is then
  ##   [sig+hashType, witnessScript]
  ## (no CHECKMULTISIG dummy).
  ##
  ## Wave 28 (lunarblock a977878) used the same shape for the 2-of-3 gate.
  doAssert privateKeys.len >= 1, "signInputP2WSH: need >= 1 private key"
  let sighash = computeSighashSegwitV0(tx, inputIdx, witnessScript,
                                       value, hashType)

  var witness: seq[seq[byte]] = @[]
  if isMultisig:
    witness.add(@[])  # CHECKMULTISIG bug: leading dummy.
  for i in 0 ..< privateKeys.len:
    let sig = sign(privateKeys[i], sighash)
    witness.add(compactSigToDer(sig, hashType))
  witness.add(@witnessScript)

  tx.inputs[inputIdx].scriptSig = @[]
  tx.witnesses[inputIdx] = witness

proc signInputP2SHP2WSH*(tx: var Transaction, inputIdx: int,
                         privateKeys: openArray[PrivateKey],
                         witnessScript: openArray[byte],
                         value: Satoshi,
                         hashType: uint32 = uint32(SIGHASH_ALL),
                         isMultisig: bool = true) =
  ## Sign a wrapped P2SH-P2WSH input.
  ##
  ## - redeemScript = OP_0 <sha256(witnessScript)>     (34 bytes)
  ## - scriptSig    = <push redeemScript>
  ## - witness      = same as native P2WSH (sighash uses witnessScript as
  ##                  scriptCode, NOT the redeemScript)
  ##
  ## BIP-143 vector 6 covers this exact shape.
  let wsHash = sha256(witnessScript)
  var redeemScript = @[0x00'u8, 0x20]  # OP_0 PUSH32
  redeemScript.add(@wsHash)

  let sighash = computeSighashSegwitV0(tx, inputIdx, witnessScript,
                                       value, hashType)

  var witness: seq[seq[byte]] = @[]
  if isMultisig:
    witness.add(@[])
  for i in 0 ..< privateKeys.len:
    let sig = sign(privateKeys[i], sighash)
    witness.add(compactSigToDer(sig, hashType))
  witness.add(@witnessScript)

  tx.inputs[inputIdx].scriptSig = pushScript(redeemScript)
  tx.witnesses[inputIdx] = witness

proc signInputP2TR*(tx: var Transaction, inputIdx: int,
                    privateKey: PrivateKey,
                    amounts: seq[Satoshi],
                    scriptPubKeys: seq[seq[byte]],
                    hashType: uint32 = 0'u32) =
  ## Sign a BIP-86 P2TR keypath-spend input (single-key, NO script tree).
  ##
  ## Closes 6-WAVE single-bug carry-forward W127 BUG / W158-W161 (longest
  ## in fleet history). Replaces the prior raise "P2TR signing not yet
  ## fully implemented" -> previously a P2TR UTXO received by the wallet
  ## was unspendable -> funds-burn-via-DEPOSIT.
  ##
  ## - `inputIdx`       : index of the input to sign
  ## - `privateKey`     : 32-byte raw seckey for this input's prevout
  ## - `amounts`        : per-input prevout values (BIP-341 SIGHASH input)
  ## - `scriptPubKeys`  : per-input prevout scriptPubKeys
  ## - `hashType`       : 0x00 = SIGHASH_DEFAULT (BIP-341, omit byte from
  ##                     witness); otherwise SIGHASH_ALL / NONE / SINGLE
  ##                     (optionally OR'd with ANYONECANPAY), appended as
  ##                     the 65th byte per BIP-341.
  ##
  ## BIP-86 keypath spend produces:
  ##   witness = [<sig>]   (single element, 64 or 65 bytes)
  ##   scriptSig = <empty>
  ##
  ## Reference: bitcoin-core/src/script/sign.cpp (CreateTaprootScriptSig),
  ## key.cpp:549-563 (KeyPair::SignSchnorr).
  doAssert amounts.len == tx.inputs.len, "signInputP2TR: amounts vs inputs len mismatch"
  doAssert scriptPubKeys.len == tx.inputs.len, "signInputP2TR: spks vs inputs len mismatch"

  # BIP-341 sighash. computeSighashTaproot already handles
  # SIGHASH_DEFAULT == 0x00 -> behaves as SIGHASH_ALL for the digest while
  # the witness omits the byte (encoded below).
  let sighash = computeSighashTaproot(
    tx, inputIdx, amounts, scriptPubKeys, uint8(hashType),
    extFlag = 0, annex = @[],
    tapleafHash = default(array[32, byte]),
    codesepPos = 0xFFFFFFFF'u32
  )

  # BIP-86 keypath spend: TapTweak with EMPTY merkle root. Pass an all-zero
  # merkle root array (signSchnorr treats all-zero == "empty merkle root").
  let emptyRoot: array[32, byte] = default(array[32, byte])
  let sig = signSchnorr(privateKey, sighash, some(emptyRoot))

  # BIP-341 witness shape: [sig] only. Sig is 64 bytes for SIGHASH_DEFAULT,
  # 65 bytes (with appended hashtype byte) for any other type.
  var witnessElem: seq[byte]
  for b in sig: witnessElem.add(b)
  if hashType != 0'u32:
    witnessElem.add(byte(hashType and 0xff))

  tx.inputs[inputIdx].scriptSig = @[]
  tx.witnesses[inputIdx] = @[witnessElem]

proc signTransaction*(wallet: Wallet, tx: var Transaction,
                      utxos: seq[WalletUtxo],
                      hashTypes: seq[uint32] = @[]): bool =
  ## Sign all inputs of a transaction.
  ## `hashTypes` (optional) — per-input sighash flag. If empty, defaults to
  ## SIGHASH_ALL for every input. If non-empty, must have the same length as
  ## `utxos` (one entry per input) and is the natural plumbing point for
  ## PSBT's `PSBT_IN_SIGHASH_TYPE` (`psbt.nim:110`).
  ## Returns true if all inputs were signed successfully.

  if utxos.len != tx.inputs.len:
    raise newException(WalletError, "utxo count doesn't match input count")
  if hashTypes.len != 0 and hashTypes.len != utxos.len:
    raise newException(WalletError, "hashTypes length must match utxos length")

  # Pre-collect all prevout amounts + scriptPubKeys for BIP-341 sighash
  # (taproot sighash hashes ALL prevout values + spks, not just per-input).
  var allAmounts: seq[Satoshi] = @[]
  var allSpks: seq[seq[byte]] = @[]
  for u in utxos:
    allAmounts.add(u.output.value)
    allSpks.add(u.output.scriptPubKey)

  for i, utxo in utxos:
    let hashType = if hashTypes.len == 0: uint32(SIGHASH_ALL) else: hashTypes[i]

    # Find the key for this UTXO
    let keyOpt = wallet.findKeyForScript(utxo.output.scriptPubKey)
    if keyOpt.isNone:
      return false

    let key = keyOpt.get()
    let spk = utxo.output.scriptPubKey

    # Determine address type from scriptPubKey.
    #
    # The wallet-only path can sign anything decodable from scriptPubKey
    # alone: P2WPKH (BIP49/BIP84) and legacy P2PKH (BIP44). P2SH-P2WPKH /
    # P2WSH / P2SH-P2WSH need caller-supplied redeemScript/witnessScript
    # and are routed through `handleSignRawTransactionWithWallet` instead.
    if spk.len == 22 and spk[0] == 0x00 and spk[1] == 0x14:
      # P2WPKH (BIP49/84 native witness program)
      signInputP2WPKH(tx, i, key.extKey.key, key.extKey.publicKey,
                      utxo.output.value, hashType)
    elif spk.len == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and
         spk[2] == 0x14 and spk[23] == 0x88 and spk[24] == 0xac:
      # P2PKH (BIP44 legacy): OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
      signInputP2PKH(tx, i, key.extKey.key, key.extKey.publicKey, hashType)
    elif spk.len == 34 and spk[0] == 0x51 and spk[1] == 0x20:
      # P2TR BIP-86 keypath spend (wallet-derived single-key, no script tree).
      # Closes 6-WAVE Schnorr-sign-missing carry-forward W127->W161
      # (longest single-bug tracking in fleet history). Calls signInputP2TR
      # which uses signSchnorr with TapTweak of the BIP-86 empty merkle root.
      # SIGHASH_DEFAULT (0x00) is BIP-341 recommended; caller can override
      # via `hashTypes` (e.g. SIGHASH_ALL = 0x01 -> appended hashtype byte).
      let trHashType = if hashTypes.len == 0: 0'u32  # BIP-341 SIGHASH_DEFAULT
                       else: hashTypes[i]
      signInputP2TR(tx, i, key.extKey.key, allAmounts, allSpks, trHashType)
    elif spk.len == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and
         spk[22] == 0x87:
      # Bare P2SH (OP_HASH160 <20> OP_EQUAL): need redeemScript from caller;
      # route through signrawtransactionwithwallet (which accepts a
      # `redeemScript` field on each prevtxs entry).
      raise newException(WalletError,
        "P2SH signing requires redeemScript; use signrawtransactionwithwallet")
    elif spk.len == 34 and spk[0] == 0x00 and spk[1] == 0x20:
      # Native P2WSH: need witnessScript from caller; route through RPC.
      raise newException(WalletError,
        "P2WSH signing requires witnessScript; use signrawtransactionwithwallet")
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
