## Tests for wallet encryption
## AES-256-CBC encryption, passphrase-based key derivation

import std/[unittest, strutils]
import ../src/wallet/crypter
import ../src/wallet/wallet
import ../src/primitives/types
import ../src/consensus/params
import ../src/crypto/secp256k1

suite "Wallet Crypter":
  test "key derivation from passphrase":
    let salt = [0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    let (key, iv) = bytesToKeySha512Aes(salt, "test password", 1000)

    # Key and IV should be non-zero
    var keyAllZero = true
    for b in key:
      if b != 0: keyAllZero = false
    check not keyAllZero

    var ivAllZero = true
    for b in iv:
      if b != 0: ivAllZero = false
    check not ivAllZero

    # Same input should produce same output
    let (key2, iv2) = bytesToKeySha512Aes(salt, "test password", 1000)
    check key == key2
    check iv == iv2

    # Different passphrase should produce different output
    let (key3, _) = bytesToKeySha512Aes(salt, "different password", 1000)
    check key != key3

    # Different salt should produce different output
    let salt2 = [0x08'u8, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
    let (key4, _) = bytesToKeySha512Aes(salt2, "test password", 1000)
    check key != key4

  test "encrypt and decrypt roundtrip":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("my secret passphrase", salt)

    let plaintext = "Hello, Bitcoin!"
    var plaintextBytes: seq[byte] = @[]
    for c in plaintext:
      plaintextBytes.add(byte(c))

    let ciphertext = crypter.encrypt(plaintextBytes)

    # Ciphertext should be different from plaintext
    check ciphertext != plaintextBytes

    # Ciphertext should be padded to block size
    check ciphertext.len mod 16 == 0

    # Decrypt
    let decrypted = crypter.decrypt(ciphertext)
    check decrypted == plaintextBytes

  test "encrypt empty data":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("passphrase", salt)

    let empty: seq[byte] = @[]
    let encrypted = crypter.encrypt(empty)
    check encrypted.len == 0

    let decrypted = crypter.decrypt(empty)
    check decrypted.len == 0

  test "encrypt 32-byte seed":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("wallet passphrase", salt)

    # Simulate a 32-byte private key
    var seed: array[32, byte]
    for i in 0 ..< 32:
      seed[i] = byte(i)

    let ciphertext = crypter.encrypt(@seed)

    # Should be 48 bytes (32 + padding to next block)
    check ciphertext.len == 48

    let decrypted = crypter.decrypt(ciphertext)
    check decrypted.len == 32
    for i in 0 ..< 32:
      check decrypted[i] == byte(i)

  test "encrypt 64-byte seed":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("wallet passphrase", salt)

    # Simulate a 64-byte HD seed
    var seed: array[64, byte]
    for i in 0 ..< 64:
      seed[i] = byte(i)

    let ciphertext = crypter.encrypt(@seed)

    # Should be 80 bytes (64 + padding to next block)
    check ciphertext.len == 80

    let decrypted = crypter.decrypt(ciphertext)
    check decrypted.len == 64
    for i in 0 ..< 64:
      check decrypted[i] == byte(i)

  test "wrong passphrase produces wrong decryption":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("correct password", salt)

    let plaintext = @[0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    let ciphertext = crypter.encrypt(plaintext)

    # Try to decrypt with wrong password
    let wrongCrypter = newWalletCrypter()
    check wrongCrypter.setKeyFromPassphrase("wrong password", salt)

    # Decryption will "succeed" but produce garbage
    # (or fail due to padding errors in some cases)
    try:
      let decrypted = wrongCrypter.decrypt(ciphertext)
      check decrypted != plaintext
    except CrypterError:
      # Invalid padding is expected with wrong key
      check true

  test "clearKey removes key from memory":
    let crypter = newWalletCrypter()
    let salt = generateSalt()
    check crypter.setKeyFromPassphrase("passphrase", salt)
    check crypter.keySet

    crypter.clearKey()
    check not crypter.keySet

    # All key bytes should be zero
    for b in crypter.key:
      check b == 0
    for b in crypter.iv:
      check b == 0

  test "encryptSecret and decryptSecret":
    var masterKey: array[32, byte]
    for i in 0 ..< 32:
      masterKey[i] = byte(i + 1)

    var iv: array[32, byte]
    for i in 0 ..< 32:
      iv[i] = byte(i * 2)

    let secret = @[0x11'u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]

    let encrypted = encryptSecret(masterKey, secret, iv)
    let decrypted = decryptSecret(masterKey, encrypted, iv)

    check decrypted == secret

  test "generateSalt produces random bytes":
    let salt1 = generateSalt()
    let salt2 = generateSalt()

    # Two salts should be different (with overwhelming probability)
    check salt1 != salt2

    # Salt should be 8 bytes
    check salt1.len == 8
    check salt2.len == 8

  test "generateIv produces random bytes":
    let iv1 = generateIv()
    let iv2 = generateIv()

    # Two IVs should be different
    check iv1 != iv2

    # IV should be 16 bytes
    check iv1.len == 16
    check iv2.len == 16

when defined(useSystemSecp256k1):
  initSecp256k1()

  suite "Wallet Encryption":
    test "encrypt wallet":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      check not wallet.isEncrypted
      check not wallet.isLocked

      discard wallet.encryptWallet("test passphrase")

      check wallet.isEncrypted
      check wallet.isLocked
      check wallet.encryptedSeed.len > 0

      # Seed should be cleared
      var seedCleared = true
      for b in wallet.seed:
        if b != 0: seedCleared = false
      check seedCleared

    test "encrypt already encrypted wallet fails":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      discard wallet.encryptWallet("passphrase")

      expect WalletError:
        discard wallet.encryptWallet("another passphrase")

    test "unlock wallet with correct passphrase":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      # Remember original seed
      var originalSeed: array[64, byte]
      originalSeed = wallet.seed

      discard wallet.encryptWallet("my passphrase")
      check wallet.isLocked

      check wallet.unlockWallet("my passphrase")
      check not wallet.isLocked

      # Seed should be restored
      check wallet.seed == originalSeed

    test "unlock wallet with wrong passphrase fails":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      discard wallet.encryptWallet("correct passphrase")

      check not wallet.unlockWallet("wrong passphrase")
      check wallet.isLocked

    test "lock wallet":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      discard wallet.encryptWallet("passphrase")
      discard wallet.unlockWallet("passphrase")

      check not wallet.isLocked

      wallet.lockWallet()

      check wallet.isLocked

      # Seed should be cleared again
      var seedCleared = true
      for b in wallet.seed:
        if b != 0: seedCleared = false
      check seedCleared

    test "change passphrase":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      # Remember original seed
      var originalSeed: array[64, byte]
      originalSeed = wallet.seed

      discard wallet.encryptWallet("old passphrase")

      check wallet.changePassphrase("old passphrase", "new passphrase")

      # Should now work with new passphrase
      check wallet.unlockWallet("new passphrase")
      check wallet.seed == originalSeed

      # Old passphrase should not work
      wallet.lockWallet()
      check not wallet.unlockWallet("old passphrase")

    test "isWalletLocked":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      # Unencrypted wallet is never "locked"
      check not wallet.isWalletLocked()

      discard wallet.encryptWallet("passphrase")
      check wallet.isWalletLocked()

      discard wallet.unlockWallet("passphrase")
      check not wallet.isWalletLocked()

      wallet.lockWallet()
      check wallet.isWalletLocked()
