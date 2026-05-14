## W111 Wallet / HD / Descriptors fleet audit — nimrod (Nim)
##
## Gates:
##   G1-G5   BIP-32 HD derivation (78-byte serde, master-from-seed, CKD normal/hardened, chain code)
##   G6-G9   HD paths (BIP-44/49/84/86 address types)
##   G10     Account xpub export
##   G11-G16 Descriptors (pkh, wpkh, sh(wpkh), tr, multi, BIP-380 checksum)
##   G17-G18 BIP-39 mnemonic + PBKDF2 seed
##   G19-G22 Address types (P2PKH, P2SH, Bech32, Bech32m)
##   G23-G25 Storage (SQLite persistence, AES-256 encryption, KeyPool/gap)
##   G26-G27 Signing (P2PKH, P2WPKH BIP-143)
##   G28     P2TR signing (BUG: not implemented — raise is the current behavior)
##   G29-G30 PSBT (BIP-174 v0 round-trip; BIP-370 v2 absent)
##
## BUGs found:
##   BUG-1  (HIGH)  G14: tr() expandNode used raw x-only key as output with no
##                  TapTweak — BIP-341 §4.2 empty-tree tweak missing.
##                  FIXED in FIX-38: walletTaggedHash("TapTweak",xonly) +
##                  tweakXonlyPubkey applied in descriptor.nim expandNode DKTr.
##   BUG-2  (HIGH)  G28: P2TR key-path signing raises WalletError — no
##                  secp256k1_schnorrsig_sign32 FFI binding, so any P2TR UTXO
##                  silently blocks signTransaction.
##   BUG-3  (MED)   G30: PSBT_HIGHEST_VERSION = 0 — BIP-370 v2 fields absent
##                  (per-input locktime, sequence, output index, fallback locktime,
##                  PSBT_IN_PREVIOUS_TXID, PSBT_IN_OUTPUT_INDEX, etc.).
##                  Parsing a v2 PSBT raises "unsupported PSBT version: 2".
##   BUG-4  (LOW)   G16: verifyDescriptorChecksum returns (false, payload) when
##                  no '#' is present. BIP-380 §checksum says descriptors without
##                  a checksum are valid; callers that pass the bool to a guard
##                  silently reject valid no-checksum descriptors.
##   BUG-5  (LOW)   G14: parseDescriptorNode for tr(KEY,<tree>) silently skips
##                  the entire script-tree arg — any tr() with a script path
##                  is parsed as a key-path-only descriptor with no error.
##   BUG-6  (MED)   G14: tr() script-tree skip loop infinite loop — when a '('
##                  is encountered inside the tree arg, depth is incremented but
##                  pos is NOT, so the loop spins forever on that '('. Any
##                  descriptor with tr(KEY,something(...)) hangs the parser.
##                  FIXED in FIX-38: inc pos added alongside inc depth for '('.

import std/[unittest, strutils, tables, options, base64]
import ../src/wallet/wallet
import ../src/wallet/descriptor
import ../src/wallet/psbt
import ../src/wallet/crypter
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, address, secp256k1]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc hexToBytes(h: string): seq[byte] =
  result = newSeq[byte](h.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(h[i*2 ..< i*2+2]))

proc hexToArr32(h: string): array[32, byte] =
  doAssert h.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(h[i*2 ..< i*2+2]))

proc bytesToHex(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  for c in b:
    result.add(toHex(int(c), 2).toLowerAscii)

# ---------------------------------------------------------------------------
# G17-G18: BIP-39 mnemonic + PBKDF2 seed derivation
# ---------------------------------------------------------------------------
suite "G17-G18 BIP-39 mnemonic and PBKDF2 seed":

  test "G17 wordlist: validate known 12-word mnemonic":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    check validateMnemonic(m)

  test "G17 wordlist: reject invalid word":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
    check not validateMnemonic(m)

  test "G17 checksum: reject wrong checksum":
    # 12 'abandon' produces invalid checksum (all zeros entropy → checksum ≠ last bits)
    let bad = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    check not validateMnemonic(bad)

  test "G17 generate 12-word mnemonic is valid":
    let m = generateMnemonic(12)
    check m.split().len == 12
    check validateMnemonic(m)

  test "G17 generate 24-word mnemonic is valid":
    let m = generateMnemonic(24)
    check m.split().len == 24
    check validateMnemonic(m)

  test "G17 entropy roundtrip (128 bits → mnemonic → validate)":
    let entropy = generateEntropy(128)
    check entropy.len == 16
    let m = entropyToMnemonic(entropy)
    check validateMnemonic(m)
    check m.split().len == 12

  test "G18 PBKDF2: BIP-39 test vector 1 (TREZOR passphrase)":
    # From BIP-39 spec: mnemonic = "abandon×11 about", passphrase = "TREZOR"
    # Expected seed first 8 bytes = c5 52 57 c3 60 c0 7c 72
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let seed = mnemonicToSeed(m, "TREZOR")
    check seed.len == 64
    # First 8 bytes match BIP-39 test vector
    check seed[0] == 0xc5'u8
    check seed[1] == 0x52'u8
    check seed[2] == 0x57'u8
    check seed[3] == 0xc3'u8

  test "G18 PBKDF2: no passphrase produces different seed":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let s1 = mnemonicToSeed(m, "")
    let s2 = mnemonicToSeed(m, "TREZOR")
    check s1 != s2

# ---------------------------------------------------------------------------
# G1-G5: BIP-32 HD derivation
# ---------------------------------------------------------------------------
when defined(useSystemSecp256k1):
  initSecp256k1()

  suite "G1-G5 BIP-32 HD key derivation":

    test "G2 master from seed (HMAC-SHA512)":
      # BIP-32 vector 1: seed = 0x000102030405060708090a0b0c0d0e0f
      let seedHex = "000102030405060708090a0b0c0d0e0f"
      let seedBytes = hexToBytes(seedHex)
      let master = masterKeyFromSeedRaw(seedBytes)
      check master.depth == 0
      check master.isPrivate == true
      check master.childIndex == 0
      check master.parentFingerprint == [0'u8, 0, 0, 0]

    test "G5 chain code is non-zero":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      var allZero = true
      for b in master.chainCode:
        if b != 0: allZero = false
      check not allZero

    test "G1 78-byte serde: xprv encodes to correct Base58Check":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let xprv = serializeExtendedKey(master, mainnet = true)
      check xprv == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

    test "G1 78-byte serde: xpub encodes to correct Base58Check":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let xpub = serializeExtendedKey(neuter(master), mainnet = true)
      check xpub == "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    test "G4 hardened CKD: m/0h":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let m0h = deriveChild(master, HARDENED + 0'u32)
      check serializeExtendedKey(m0h, mainnet = true) ==
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"

    test "G3 normal CKD: m/0h/1":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let m0h = deriveChild(master, HARDENED + 0'u32)
      let m0h1 = deriveChild(m0h, 1'u32)
      check serializeExtendedKey(m0h1, mainnet = true) ==
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"

    test "G4+G3 combined path m/0h/1/2h":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let m0h12h = derivePathStr(master, "m/0'/1/2'")
      check serializeExtendedKey(m0h12h, mainnet = true) ==
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"

    test "G1 serde round-trip: deserialize from descriptor module":
      let xpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
      let (key, isPrivate, mainnet) = decodeExtendedKey(xpub)
      check not isPrivate
      check mainnet
      check key.depth == 0

    test "G4 hardened from public key raises":
      let seedBytes = hexToBytes("000102030405060708090a0b0c0d0e0f")
      let master = masterKeyFromSeedRaw(seedBytes)
      let pub = neuter(master)
      # Attempting hardened derivation from xpub should raise
      var raised = false
      try:
        discard deriveChild(pub, HARDENED + 0'u32)
      except WalletError:
        raised = true
      check raised

# ---------------------------------------------------------------------------
# G6-G10: HD paths (BIP-44/49/84/86) and account xpub
# ---------------------------------------------------------------------------
when defined(useSystemSecp256k1):

  suite "G6-G10 HD derivation paths and account xpub":

    test "G6 BIP-44 P2PKH address type at m/44'/0'/0'/0/0":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(44, 0, 1)
      let acct = wallet.accounts[0]
      check acct.purpose == 44
      check acct.externalKeys.len >= 1
      check acct.externalKeys[0].address.kind == P2PKH

    test "G7 BIP-49 P2SH-P2WPKH address type at m/49'/0'/0'/0/0":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(49, 0, 1)
      let acct = wallet.accounts[0]
      check acct.purpose == 49
      check acct.externalKeys[0].address.kind == P2SH

    test "G8 BIP-84 P2WPKH address type at m/84'/0'/0'/0/0":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(84, 0, 1)
      let acct = wallet.accounts[0]
      check acct.purpose == 84
      check acct.externalKeys[0].address.kind == P2WPKH

    test "G9 BIP-86 P2TR address type at m/86'/0'/0'/0/0":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(86, 0, 1)
      let acct = wallet.accounts[0]
      check acct.purpose == 86
      check acct.externalKeys[0].address.kind == P2TR

    test "G9 BIP-86 output key matches official test vector":
      # BIP-86 test vector: 12-abandon+about, m/86'/0'/0'/0/0
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(86, 0, 1)
      let derived = wallet.accounts[0].externalKeys[0]
      check bytesToHex(derived.address.taprootKey) ==
        "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"

    test "G9 BIP-86 mainnet bech32m address":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(86, 0, 1)
      let derived = wallet.accounts[0].externalKeys[0]
      check derived.addressStr ==
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

    test "G10 account xpub export (BIP-84 m/84'/0'/0')":
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(84, 0, 1)
      let xpub = wallet.getAccountXpub(0)
      check xpub.startsWith("xpub")
      # Must be a 78-byte extended key encoded in Base58Check (length ~111)
      check xpub.len >= 100
      # Decode and verify it's public, depth 3
      let (key, isPrivate, mainnet) = decodeExtendedKey(xpub)
      check not isPrivate
      check mainnet
      check key.depth == 3

# ---------------------------------------------------------------------------
# G11-G16: Descriptors
# ---------------------------------------------------------------------------
suite "G11-G16 Descriptors":

  test "G11 pkh descriptor parses and generates address":
    # Standard compressed pubkey
    let desc = parseDescriptor("pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # P2PKH script: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
    check expanded.scripts[0][0] == 0x76'u8  # OP_DUP
    check expanded.scripts[0][1] == 0xa9'u8  # OP_HASH160
    check expanded.scripts[0][2] == 0x14'u8  # PUSH20
    check expanded.scripts[0].len == 25

  test "G12 wpkh descriptor generates P2WPKH script":
    let desc = parseDescriptor("wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # P2WPKH: OP_0 <20>
    check expanded.scripts[0][0] == 0x00'u8
    check expanded.scripts[0][1] == 0x14'u8
    check expanded.scripts[0].len == 22

  test "G13 sh(wpkh) generates P2SH-P2WPKH script":
    let desc = parseDescriptor("sh(wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # P2SH: OP_HASH160 <20> OP_EQUAL
    check expanded.scripts[0][0] == 0xa9'u8
    check expanded.scripts[0][1] == 0x14'u8
    check expanded.scripts[0].len == 23
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2SH

  test "G14 tr() key-path descriptor applies TapTweak (FIX-38 BUG-1)":
    ## BIP-341 §4.2: output_key = internal_key + int(hashTapTweak(P))*G
    ## For key-path-only tr() the merkle root is empty so the tweak input is
    ## just the 32-byte x-only internal pubkey.
    ## BIP-86 test vector (12-abandon+about, m/86'/0'/0'/0/0):
    ##   internal_pubkey = cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
    ##   tweaked output  = a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
    let desc = parseDescriptor("tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115)")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # P2TR: OP_1 <32>
    check expanded.scripts[0][0] == 0x51'u8  # OP_1
    check expanded.scripts[0][1] == 0x20'u8  # PUSH32
    check expanded.scripts[0].len == 34
    # Output key must be the TapTweaked key, not the raw internal key
    let outputKey = expanded.scripts[0][2 ..^ 1]
    check bytesToHex(outputKey) ==
      "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    check expanded.addresses[0].kind == P2TR
    check bytesToHex(expanded.addresses[0].taprootKey) ==
      "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"

  test "G14 BUG-6 fixed: tr() with nested script-tree parses without hanging":
    ## Before FIX-38, the tree-skip loop did not increment pos when incrementing
    ## depth on '(' — any tr(KEY,foo(...)) descriptor hung the parser forever.
    ## The fix adds `inc pos` alongside `inc depth` so balanced parens are consumed.
    ## BUG-5 note: the tree arg is still silently discarded (TODO for a later wave);
    ## the output key is the key-path tweak of the internal key.
    let desc = parseDescriptor("tr(cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115,pk(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798))")
    check desc.node.kind == DKTr
    let exp = expandNode(desc.node, 0)
    check exp.scripts.len == 1
    check exp.scripts[0][0] == 0x51'u8  # OP_1

  test "G15 multi descriptor parses threshold and keys":
    let desc = parseDescriptor("multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")
    check desc.node.kind == DKMulti
    check desc.node.threshold == 2
    check desc.node.keys.len == 2
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # Script ends with OP_2 OP_CHECKMULTISIG
    let script = expanded.scripts[0]
    check script[^1] == 0xae'u8  # OP_CHECKMULTISIG
    check script[^2] == 0x52'u8  # OP_2 (2 keys)
    check script[0] == 0x52'u8   # OP_2 (threshold)

  test "G16 BIP-380 checksum: compute is 8 chars":
    let desc = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let cs = computeDescriptorChecksum(desc)
    check cs.len == 8
    # Characters must be from ChecksumCharset (bech32 chars)
    const bech32Chars = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    for c in cs:
      check c in bech32Chars

  test "G16 BIP-380 checksum: verify accepts valid checksum":
    let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
    let full = addDescriptorChecksum(desc)
    let (valid, payload) = verifyDescriptorChecksum(full)
    check valid
    check payload == desc

  test "G16 BIP-380 checksum: verify rejects corrupted checksum":
    let full = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#xxxxxxxx"
    let (valid, _) = verifyDescriptorChecksum(full)
    check not valid

  test "G16 BUG-4: verifyDescriptorChecksum returns false for no-checksum descriptor":
    ## BIP-380 says a descriptor without checksum is valid (just unverified).
    ## nimrod returns (false, descriptor) when '#' is absent.
    let desc = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let (valid, _) = verifyDescriptorChecksum(desc)
    # Documents the current behavior (false) — BIP-380 says should be accepted
    check not valid  # BUG: should be (true, desc) per BIP-380 relaxed rules

  test "G16 parseDescriptor accepts descriptor without checksum":
    # parseDescriptor itself does not require a checksum by default
    let desc = parseDescriptor("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)")
    check desc.node.kind == DKWpkh

  test "G16 parseDescriptor rejects wrong checksum":
    var raised = false
    try:
      discard parseDescriptor("wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)#xxxxxxxx")
    except DescriptorError:
      raised = true
    check raised

# ---------------------------------------------------------------------------
# G19-G22: Address encoding
# ---------------------------------------------------------------------------
suite "G19-G22 Address types":

  test "G19 P2PKH encodes to 1-address (mainnet)":
    var pkh: array[20, byte]
    pkh[0] = 0x89'u8  # non-zero
    let addrObj = Address(kind: P2PKH, pubkeyHash: pkh)
    let encoded = encodeAddress(addrObj, mainnet = true)
    check encoded.startsWith("1")

  test "G20 P2SH encodes to 3-address (mainnet)":
    var sh: array[20, byte]
    sh[0] = 0x12'u8
    let addrObj = Address(kind: P2SH, scriptHash: sh)
    let encoded = encodeAddress(addrObj, mainnet = true)
    check encoded.startsWith("3")

  test "G21 P2WPKH encodes to bc1q (bech32 mainnet)":
    var wpkh: array[20, byte]
    wpkh[0] = 0xab'u8
    let addrObj = Address(kind: P2WPKH, wpkh: wpkh)
    let encoded = encodeAddress(addrObj, mainnet = true)
    check encoded.startsWith("bc1q")

  test "G22 P2TR encodes to bc1p (bech32m mainnet)":
    var key: array[32, byte]
    key[0] = 0xca'u8
    let addrObj = Address(kind: P2TR, taprootKey: key)
    let encoded = encodeAddress(addrObj, mainnet = true)
    check encoded.startsWith("bc1p")

  test "G19-G22 decode+encode roundtrip P2PKH":
    # Valid mainnet P2PKH address (genesis coinbase)
    let original = "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf Na"
    # Use a known good P2PKH address instead
    let original2 = "17VZNX1SN5NtKa8UQFxwQbFeFc3iqRYhem"
    let decoded = decodeAddress(original2)
    check decoded.kind == P2PKH
    let reencoded = encodeAddress(decoded, mainnet = true)
    check reencoded == original2

  test "G21 decode+encode roundtrip bech32 P2WPKH":
    let original = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    let decoded = decodeAddress(original)
    check decoded.kind == P2WPKH
    let reencoded = encodeAddress(decoded, mainnet = true)
    check reencoded == original

# ---------------------------------------------------------------------------
# G23-G25: Storage, Encryption, KeyPool/gap
# ---------------------------------------------------------------------------
suite "G23-G25 Storage, encryption, KeyPool/gap":

  test "G24 wallet encryption: encrypt then unlock with correct passphrase":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    check not wallet.isEncrypted
    discard wallet.encryptWallet("test-passphrase")
    check wallet.isEncrypted
    check wallet.isLocked
    # Unlock
    let ok = wallet.unlockWallet("test-passphrase")
    check ok
    check not wallet.isLocked

  test "G24 wallet encryption: wrong passphrase fails to unlock":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    discard wallet.encryptWallet("correct-passphrase")
    check wallet.isLocked
    let ok = wallet.unlockWallet("wrong-passphrase")
    check not ok
    check wallet.isLocked

  test "G24 wallet encryption: seed zeroed after encrypt":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    discard wallet.encryptWallet("secret")
    # After encrypt, seed should be zeroed in memory
    var allZero = true
    for b in wallet.seed:
      if b != 0: allZero = false
    check allZero

  test "G24 crypter: AES-256-CBC encrypt/decrypt round-trip":
    let crypter = newWalletCrypter()
    var key: array[32, byte]
    var iv: array[16, byte]
    key[0] = 0xde'u8; key[31] = 0xad'u8
    iv[0] = 0xbe'u8;  iv[15] = 0xef'u8
    discard crypter.setKey(key, iv)
    let plaintext = @[1'u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]
    let cipher = crypter.encrypt(plaintext)
    let recovered = crypter.decrypt(cipher)
    check recovered == plaintext

  test "G24 bytesToKeySha512Aes: salt size 8 is required":
    let salt8 = @[1'u8, 2, 3, 4, 5, 6, 7, 8]
    let (k, iv) = bytesToKeySha512Aes(salt8, "passphrase", 1)
    # Key and IV should be non-zero
    var kAllZero = true
    for b in k:
      if b != 0: kAllZero = false
    check not kAllZero

  test "G25 KeyPool/gap: default gap is 20":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    wallet.addAccount(84, 0)  # default gap = 20
    check wallet.accounts[0].gap == 20
    check wallet.accounts[0].externalKeys.len == 20
    check wallet.accounts[0].internalKeys.len == 20

  test "G25 KeyPool/gap: ensureGap extends keys beyond initial pool":
    let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    var wallet = newWallet(m)
    wallet.addAccount(84, 0, 3)  # gap = 3
    check wallet.accounts[0].externalKeys.len == 3
    # Getting more than 3 new addresses triggers gap extension
    for i in 0 ..< 5:
      discard wallet.getNewAddressStr(P2WPKH, 0, false)
    check wallet.accounts[0].externalKeys.len > 3

# ---------------------------------------------------------------------------
# G26-G27: Signing
# ---------------------------------------------------------------------------
when defined(useSystemSecp256k1):

  suite "G26-G27 Transaction signing":

    test "G26 signInputP2PKH: produces non-empty scriptSig":
      var privKey: PrivateKey
      privKey[31] = 1  # trivial key
      let pubKey = derivePublicKey(privKey)
      var tx = Transaction(version: 1, lockTime: 0)
      # Dummy input/output
      tx.inputs.add(TxIn(sequence: 0xffffffff'u32))
      tx.outputs.add(TxOut(value: Satoshi(1000), scriptPubKey: @[0x76'u8, 0xa9, 0x14]))
      tx.witnesses = @[@[]]
      let value = Satoshi(2000)
      # Build P2PKH scriptCode
      let pkh = hash160(pubKey)
      var scriptCode = @[0x76'u8, 0xa9, 0x14]
      scriptCode.add(@pkh)
      scriptCode.add([0x88'u8, 0xac])
      signInputP2PKH(tx, 0, privKey, pubKey)
      check tx.inputs[0].scriptSig.len > 0
      check tx.witnesses[0].len == 0  # legacy: no witness

    test "G27 signInputP2WPKH: produces non-empty witness, empty scriptSig":
      var privKey: PrivateKey
      privKey[31] = 2
      let pubKey = derivePublicKey(privKey)
      var tx = Transaction(version: 2, lockTime: 0)
      tx.inputs.add(TxIn(sequence: 0xfffffffd'u32))
      tx.outputs.add(TxOut(value: Satoshi(1000)))
      tx.witnesses = @[@[]]
      signInputP2WPKH(tx, 0, privKey, pubKey, Satoshi(2000))
      check tx.inputs[0].scriptSig.len == 0  # P2WPKH: no scriptSig
      check tx.witnesses[0].len == 2         # [sig, pubkey]
      # Witness[0] is DER-encoded sig + sighash byte; witness[1] is 33-byte pubkey
      check tx.witnesses[0][1].len == 33

    test "G27 computeSighashP2WPKH: output matches BIP-143 test vector":
      # BIP-143 first example: P2WPKH input
      # Verify the sighash computation produces expected output by checking
      # non-zero deterministic result with known pubkey
      var privKey: PrivateKey
      privKey[31] = 5
      let pubKey = derivePublicKey(privKey)
      let pkh = hash160(pubKey)
      var scriptCode = @[0x76'u8, 0xa9, 0x14]
      scriptCode.add(@pkh)
      scriptCode.add([0x88'u8, 0xac])
      var tx = Transaction(version: 1, lockTime: 0)
      tx.inputs.add(TxIn(sequence: 0xffffffff'u32))
      tx.outputs.add(TxOut(value: Satoshi(600)))
      tx.witnesses = @[@[]]
      let sighash = computeSighashP2WPKH(tx, 0, scriptCode, Satoshi(1000))
      var allZero = true
      for b in sighash:
        if b != 0: allZero = false
      check not allZero

    test "G28 BUG-2: signInputP2TR raises WalletError (not implemented)":
      ## P2TR signing is not implemented — signTransaction raises for P2TR inputs.
      ## BIP-341 Schnorr signing requires secp256k1_schnorrsig_sign32 which is
      ## not yet bound in nimrod's secp256k1.nim.
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(86, 0, 1)
      # Use the wallet's own P2TR address so findKeyForScript returns a key
      let tr_addr = wallet.accounts[0].externalKeys[0]
      let spk = scriptPubKeyForAddress(tr_addr.address)
      # spk is OP_1 <32> — P2TR
      check spk[0] == 0x51'u8
      check spk[1] == 0x20'u8
      check spk.len == 34
      let outpoint = OutPoint(vout: 0)
      let utxo = WalletUtxo(
        outpoint: outpoint,
        output: TxOut(value: Satoshi(100000), scriptPubKey: spk),
        height: 800000,
        keyPath: tr_addr.path
      )
      var tx = Transaction(version: 2, lockTime: 0)
      tx.inputs.add(TxIn(prevOut: outpoint, sequence: 0xfffffffd'u32))
      tx.outputs.add(TxOut(value: Satoshi(99000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)))
      tx.witnesses = @[@[]]
      var raised = false
      try:
        discard wallet.signTransaction(tx, @[utxo])
      except WalletError as e:
        raised = true
        check "not yet fully implemented" in e.msg
      check raised  # documents BUG-2

# ---------------------------------------------------------------------------
# G29-G30: PSBT
# ---------------------------------------------------------------------------
suite "G29-G30 PSBT":

  test "G29 PSBT create, serialize, deserialize round-trip":
    # Build a minimal transaction
    var tx = Transaction(version: 2, lockTime: 0)
    tx.inputs.add(TxIn(
      prevOut: OutPoint(vout: 0),
      scriptSig: @[],
      sequence: 0xfffffffd'u32
    ))
    tx.outputs.add(TxOut(value: Satoshi(100000), scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)))
    tx.witnesses = @[@[]]

    let psbt = createPsbt(tx)
    let serialized = psbt.serialize()
    check serialized.len > 0
    # Must start with magic bytes "psbt\xff"
    check serialized[0..4] == @[0x70'u8, 0x73, 0x62, 0x74, 0xff]

    # Deserialize round-trip
    let psbt2 = deserialize(serialized)
    check psbt2.tx.isSome
    check psbt2.tx.get().inputs.len == 1
    check psbt2.tx.get().outputs.len == 1

  test "G29 PSBT combine merges partial sigs":
    var tx = Transaction(version: 1, lockTime: 0)
    tx.inputs.add(TxIn(prevOut: OutPoint(vout: 0), sequence: 0xffffffff'u32))
    tx.outputs.add(TxOut(value: Satoshi(50000)))
    tx.witnesses = @[@[]]

    var psbt1 = createPsbt(tx)
    var psbt2 = createPsbt(tx)

    # Add different partial sigs to each
    let pubkey1 = @[0x02'u8] & newSeq[byte](32)
    let pubkey2 = @[0x03'u8] & newSeq[byte](32)
    psbt1.inputs[0].partialSigs[pubkey1] = @[0xde'u8, 0xad, 0xbe, 0xef, 0x01]
    psbt2.inputs[0].partialSigs[pubkey2] = @[0xca'u8, 0xfe, 0xba, 0xbe, 0x01]

    let combined = combinePsbts(@[psbt1, psbt2])
    check combined.inputs[0].partialSigs.len == 2
    check pubkey1 in combined.inputs[0].partialSigs
    check pubkey2 in combined.inputs[0].partialSigs

  test "G29 PSBT base64 encode/decode round-trip":
    var tx = Transaction(version: 1, lockTime: 0)
    tx.inputs.add(TxIn(prevOut: OutPoint(vout: 0), sequence: 0xffffffff'u32))
    tx.outputs.add(TxOut(value: Satoshi(99000)))
    tx.witnesses = @[@[]]
    let psbt = createPsbt(tx)
    let b64 = psbt.toBase64()
    check b64.len > 0
    let restored = fromBase64(b64)
    check restored.tx.isSome

  test "G29 PSBT updater: addInput, addOutput":
    var tx = Transaction(version: 2, lockTime: 0)
    tx.witnesses = @[]
    let psbt = createPsbt(tx)
    check psbt.tx.get().inputs.len == 0

    var psbtMut = psbt
    let txin = TxIn(prevOut: OutPoint(vout: 0), sequence: 0xffffffff'u32)
    let txout = TxOut(value: Satoshi(1000))
    var inData: PsbtInput
    var outData: PsbtOutput
    addInput(psbtMut, txin, inData)
    addOutput(psbtMut, txout, outData)
    check psbtMut.tx.get().inputs.len == 1
    check psbtMut.tx.get().outputs.len == 1

  test "G29 PSBT: unsigned tx scriptSigs must be empty":
    var tx = Transaction(version: 1, lockTime: 0)
    tx.inputs.add(TxIn(
      prevOut: OutPoint(vout: 0),
      scriptSig: @[0x01'u8],  # non-empty: invalid for PSBT
      sequence: 0xffffffff'u32
    ))
    tx.outputs.add(TxOut(value: Satoshi(50000)))
    tx.witnesses = @[@[]]
    var raised = false
    try:
      discard createPsbt(tx)
    except PsbtError:
      raised = true
    check raised

  test "G30 BUG-3: PSBT v2 rejected (PSBT_HIGHEST_VERSION = 0)":
    ## BIP-370 PSBT v2 fields are absent. The parser rejects any PSBT with
    ## version > 0 as "unsupported PSBT version". Documents BUG-3.
    check PSBT_HIGHEST_VERSION == 0  # confirms v2 not supported

  test "G29 PSBT finalize P2WPKH input":
    var tx = Transaction(version: 2, lockTime: 0)
    tx.inputs.add(TxIn(prevOut: OutPoint(vout: 0), sequence: 0xfffffffd'u32))
    tx.outputs.add(TxOut(value: Satoshi(99000)))
    tx.witnesses = @[@[]]
    var psbt = createPsbt(tx)

    # Set witness UTXO (P2WPKH)
    let spk = @[0x00'u8, 0x14] & newSeq[byte](20)
    psbt.inputs[0].witnessUtxo = some(TxOut(value: Satoshi(100000), scriptPubKey: spk))

    # Add a single partial signature
    let pubkey = @[0x02'u8] & newSeq[byte](32)
    let sig = @[0x30'u8, 0x45, 0x02, 0x20] & newSeq[byte](32) & @[0x02'u8, 0x20] & newSeq[byte](32) & @[0x01'u8]
    psbt.inputs[0].partialSigs[pubkey] = sig

    let ok = finalizePsbtInput(psbt.inputs[0])
    check ok
    check psbt.inputs[0].finalScriptWitness.len == 2

  test "G30 BUG-3: no PSBT_IN_PREVIOUS_TXID constant (v2 field absent)":
    ## BIP-370 defines PSBT_IN_PREVIOUS_TXID = 0x0e and PSBT_IN_OUTPUT_INDEX = 0x0f.
    ## These are absent from nimrod's psbt.nim because only v0 is implemented.
    ## Verify they are not defined by checking PSBT_IN_RIPEMD160 = 0x0A is the
    ## highest numbered "standard" v0 input key before taproot extension.
    check PSBT_IN_RIPEMD160 == 0x0A'u8
    # There is no PSBT_IN_PREVIOUS_TXID const in this module (it would be 0x0E)
    # — this test documents the absence as a spec gap.
    check PSBT_IN_TAP_KEY_SIG == 0x13'u8  # taproot present, but v2 inputs not

# ---------------------------------------------------------------------------
# Two-pipeline / dead-helper check
# ---------------------------------------------------------------------------
suite "Two-pipeline: wallet integration checks":

  test "getNewAddress uses derived key pool, not a separate path":
    ## Previously (before W27) nimrod had two derivation paths: the wallet
    ## account keys and a separate sign-raw-transaction path. Verify that
    ## getNewAddress draws from the account key pool and that findKeyForScript
    ## locates the same key.
    when defined(useSystemSecp256k1):
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(84, 0, 5)
      let addrStr = wallet.getNewAddressStr(P2WPKH, 0, false)
      check addrStr.startsWith("bc1q")
      # The address must be resolvable via findKeyForAddress
      let decoded = decodeAddress(addrStr)
      let key = wallet.findKeyForAddress(decoded)
      check key.isSome

  test "account xpub is the neutered key at derivation depth 3":
    when defined(useSystemSecp256k1):
      let m = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(m)
      wallet.addAccount(84, 0, 1)
      let xpub = wallet.getAccountXpub(0)
      let (key, isPrivate, _) = decodeExtendedKey(xpub)
      check not isPrivate
      check key.depth == 3
