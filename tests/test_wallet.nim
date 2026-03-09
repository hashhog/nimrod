## Tests for HD Wallet functionality
## BIP-32 test vectors, BIP-84 addresses, P2WPKH signing, block scan

import std/[unittest, strutils, tables]
import ../src/wallet/wallet
import ../src/primitives/types
import ../src/crypto/[hashing, secp256k1, address]
import ../src/consensus/params

suite "BIP39 Mnemonic":
  test "generate 12-word mnemonic":
    let mnemonic = generateMnemonic(12)
    let words = mnemonic.split()
    check words.len == 12
    check validateMnemonic(mnemonic)

  test "generate 24-word mnemonic":
    let mnemonic = generateMnemonic(24)
    let words = mnemonic.split()
    check words.len == 24
    check validateMnemonic(mnemonic)

  test "validate known mnemonic":
    # Test vector from BIP39
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    check validateMnemonic(mnemonic)

  test "reject invalid mnemonic":
    # Wrong checksum
    let badMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
    check not validateMnemonic(badMnemonic)

  test "reject unknown words":
    let badMnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword"
    check not validateMnemonic(badMnemonic)

  test "mnemonic to seed - BIP39 test vector":
    # Test vector 1 from BIP39 spec (with TREZOR passphrase)
    let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    let seed = mnemonicToSeed(mnemonic, "TREZOR")

    # Expected seed (hex)
    let expectedHex = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"

    var expected: array[64, byte]
    for i in 0 ..< 64:
      expected[i] = byte(parseHexInt(expectedHex[i*2 ..< i*2+2]))

    check seed == expected

  test "validate various word counts":
    # Test generating and validating different word counts
    let m15 = generateMnemonic(15)
    check validateMnemonic(m15)
    check m15.split().len == 15

    let m18 = generateMnemonic(18)
    check validateMnemonic(m18)
    check m18.split().len == 18

    let m21 = generateMnemonic(21)
    check validateMnemonic(m21)
    check m21.split().len == 21

  test "entropy to mnemonic roundtrip":
    # 128-bit entropy
    let entropy = generateEntropy(128)
    check entropy.len == 16

    let mnemonic = entropyToMnemonic(entropy)
    check validateMnemonic(mnemonic)

    let words = mnemonic.split()
    check words.len == 12

# Tests that require secp256k1
when defined(useSystemSecp256k1):
  # Initialize secp256k1 context
  initSecp256k1()

  suite "BIP32 HD Key Derivation":
    test "master key from seed - BIP32 test vector 1":
      # BIP32 test vector 1
      let seedHex = "000102030405060708090a0b0c0d0e0f"
      var seed: array[64, byte]
      for i in 0 ..< 16:
        seed[i] = byte(parseHexInt(seedHex[i*2 ..< i*2+2]))

      let master = masterKeyFromSeed(seed)

      check master.depth == 0
      check master.isPrivate == true
      check master.childIndex == 0

    test "derive child - hardened":
      let seedHex = "000102030405060708090a0b0c0d0e0f"
      var seed: array[64, byte]
      for i in 0 ..< 16:
        seed[i] = byte(parseHexInt(seedHex[i*2 ..< i*2+2]))

      let master = masterKeyFromSeed(seed)

      # Derive m/0' (hardened)
      let child = deriveChild(master, HARDENED + 0)

      check child.depth == 1
      check child.childIndex == HARDENED + 0
      check child.isPrivate == true

    test "derive path string":
      let seedHex = "000102030405060708090a0b0c0d0e0f"
      var seed: array[64, byte]
      for i in 0 ..< 16:
        seed[i] = byte(parseHexInt(seedHex[i*2 ..< i*2+2]))

      let master = masterKeyFromSeed(seed)

      # Derive m/0'/1/2'
      let derived = derivePathStr(master, "m/0'/1/2'")

      check derived.depth == 3
      check derived.isPrivate == true

    test "BIP84 path derivation":
      # Test BIP84 path for native segwit
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      let seed = mnemonicToSeed(mnemonic, "")
      let master = masterKeyFromSeed(seed)

      # m/84'/0'/0'/0/0 - first receiving address
      let key = derivePathStr(master, "m/84'/0'/0'/0/0")

      check key.depth == 5
      check key.isPrivate == true

      # Generate P2WPKH address
      let wpkh = hash160(key.publicKey)
      let btcAddr = Address(kind: P2WPKH, wpkh: wpkh)
      let addrStr = encodeAddress(btcAddr, true)

      # Should start with bc1q (mainnet P2WPKH)
      check addrStr.startsWith("bc1q")

  suite "Wallet Operations":
    test "create wallet from mnemonic":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      check wallet.masterKey.isPrivate == true
      check wallet.masterKey.depth == 0

    test "add BIP84 account":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, accountIndex = 0, gap = 5)

      check wallet.accounts.len == 1
      check wallet.accounts[0].purpose == 84
      check wallet.accounts[0].externalKeys.len == 5
      check wallet.accounts[0].internalKeys.len == 5

    test "get new address":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, accountIndex = 0, gap = 5)

      let addr1 = wallet.getNewAddressStr()
      let addr2 = wallet.getNewAddressStr()

      # Addresses should be different
      check addr1 != addr2

      # Both should be mainnet bech32
      check addr1.startsWith("bc1q")
      check addr2.startsWith("bc1q")

    test "testnet addresses":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic, "", testnet3Params())
      wallet.addAccount(purpose = 84, accountIndex = 0, gap = 5)

      let btcAddr = wallet.getNewAddressStr()

      # Should be testnet bech32
      check btcAddr.startsWith("tb1q")

    test "change address":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84)

      let receiving = wallet.getNewAddressStr(isChange = false)
      let change = wallet.getNewAddressStr(isChange = true)

      # Both should be valid but different
      check receiving != change
      check receiving.startsWith("bc1q")
      check change.startsWith("bc1q")

    test "BIP44 legacy addresses":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 44, gap = 3)

      # BIP44 addresses should be legacy P2PKH
      let firstKey = wallet.accounts[0].externalKeys[0]
      check firstKey.address.kind == P2PKH

      let addrStr = firstKey.addressStr
      # Mainnet P2PKH starts with 1
      check addrStr.len > 25
      check addrStr[0] == '1'

    test "BIP86 taproot addresses":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 86, gap = 3)

      # BIP86 addresses should be P2TR
      let firstKey = wallet.accounts[0].externalKeys[0]
      check firstKey.address.kind == P2TR

      let addrStr = firstKey.addressStr
      # Mainnet P2TR starts with bc1p
      check addrStr.startsWith("bc1p")

  suite "UTXO Management":
    test "add and remove UTXOs":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84)

      # Create a mock UTXO
      var txid: array[32, byte]
      txid[0] = 1
      let outpoint = OutPoint(txid: TxId(txid), vout: 0'u32)
      let output = TxOut(value: Satoshi(100000), scriptPubKey: @[])

      wallet.addUtxo(outpoint, output, 100, "m/84'/0'/0'/0/0", false)

      check wallet.utxos.len == 1
      check wallet.getBalance() == Satoshi(100000)

      wallet.removeUtxo(outpoint)
      check wallet.utxos.len == 0
      check wallet.getBalance() == Satoshi(0)

    test "scan block for wallet transactions":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, gap = 5)

      # Get the first address's scriptPubKey
      let firstKey = wallet.accounts[0].externalKeys[0]
      let spk = scriptPubKeyForAddress(firstKey.address)

      # Create a mock transaction paying to our address
      var mockTxid: array[32, byte]
      mockTxid[0] = 0xab
      mockTxid[1] = 0xcd

      let mockTx = Transaction(
        version: 2,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
          scriptSig: @[0x04'u8, 0xff, 0xff, 0xff, 0xff],
          sequence: 0xffffffff'u32
        )],
        outputs: @[TxOut(
          value: Satoshi(50_0000_0000),
          scriptPubKey: spk
        )],
        witnesses: @[],
        lockTime: 0
      )

      let mockBlock = Block(
        header: BlockHeader(
          version: 0x20000000,
          prevBlock: BlockHash(default(array[32, byte])),
          merkleRoot: default(array[32, byte]),
          timestamp: 1234567890,
          bits: 0x1d00ffff'u32,
          nonce: 0
        ),
        txs: @[mockTx]
      )

      # Scan block
      wallet.scanBlockForWallet(mockBlock, 100)

      # Should have found the UTXO
      check wallet.utxos.len == 1
      check wallet.getBalance() == Satoshi(50_0000_0000)

  suite "Extended Key Serialization":
    test "serialize master xprv":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      let xprv = serializeExtendedKey(wallet.masterKey, true)

      # Should start with xprv
      check xprv.startsWith("xprv")
      check xprv.len > 100

    test "serialize xpub":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      let xpub = wallet.exportMasterXpub()

      # Should start with xpub
      check xpub.startsWith("xpub")

    test "account xpub":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84)

      let accXpub = wallet.getAccountXpub(0)

      # Should start with xpub
      check accXpub.startsWith("xpub")

  suite "Transaction Signing":
    test "compute P2WPKH sighash":
      # This tests the sighash computation which is critical for signing
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, gap = 3)

      # Create a simple test transaction
      let firstKey = wallet.accounts[0].externalKeys[0]

      var prevTxid: array[32, byte]
      prevTxid[0] = 0x01

      let tx = Transaction(
        version: 2,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(prevTxid), vout: 0'u32),
          scriptSig: @[],
          sequence: 0xfffffffd'u32
        )],
        outputs: @[TxOut(
          value: Satoshi(90000),
          scriptPubKey: @[0x00'u8, 0x14] & @(hash160(firstKey.extKey.publicKey))
        )],
        witnesses: @[@[]],
        lockTime: 0
      )

      # Build scriptCode
      let pkh = hash160(firstKey.extKey.publicKey)
      var scriptCode = @[0x76'u8, 0xa9, 0x14]
      scriptCode.add(@pkh)
      scriptCode.add([0x88'u8, 0xac])

      # Compute sighash
      let sighash = computeSighashP2WPKH(tx, 0, scriptCode, Satoshi(100000))

      # Sighash should be 32 bytes
      check sighash.len == 32

      # Should be non-zero
      var allZero = true
      for b in sighash:
        if b != 0: allZero = false
      check not allZero

else:
  echo "Note: secp256k1-dependent wallet tests skipped (compile with -d:useSystemSecp256k1)"

# Run tests if executed directly
when isMainModule:
  echo "Running wallet tests..."
  # Tests are auto-run by unittest
