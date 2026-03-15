## Tests for address labels

import std/[unittest, tables, algorithm, options]
import ../src/wallet/wallet
import ../src/wallet/db_sqlite
import ../src/primitives/types
import ../src/consensus/params

when defined(useSystemSecp256k1):
  import ../src/crypto/secp256k1
  initSecp256k1()

  suite "Address Labels - In Memory":
    test "set and get label":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

      wallet.setLabel(address, "my savings")
      check wallet.getLabel(address) == "my savings"

    test "get label for unlabeled address returns empty":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      check wallet.getLabel("bc1qunknownaddress") == ""

    test "update existing label":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

      wallet.setLabel(address, "first label")
      check wallet.getLabel(address) == "first label"

      wallet.setLabel(address, "updated label")
      check wallet.getLabel(address) == "updated label"

    test "remove label with empty string":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      let address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"

      wallet.setLabel(address, "my label")
      check wallet.getLabel(address) == "my label"

      wallet.setLabel(address, "")
      check wallet.getLabel(address) == ""

    test "getAddressesByLabel returns all matching addresses":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      wallet.setLabel("bc1addr1", "work")
      wallet.setLabel("bc1addr2", "work")
      wallet.setLabel("bc1addr3", "personal")
      wallet.setLabel("bc1addr4", "work")

      var workAddrs = wallet.getAddressesByLabel("work")
      workAddrs.sort()
      check workAddrs.len == 3
      check "bc1addr1" in workAddrs
      check "bc1addr2" in workAddrs
      check "bc1addr4" in workAddrs

      let personalAddrs = wallet.getAddressesByLabel("personal")
      check personalAddrs.len == 1
      check "bc1addr3" in personalAddrs

    test "listLabels returns all unique labels":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      wallet.setLabel("addr1", "work")
      wallet.setLabel("addr2", "work")
      wallet.setLabel("addr3", "personal")
      wallet.setLabel("addr4", "savings")

      var labels = wallet.listLabels()
      labels.sort()
      check labels.len == 3
      check "personal" in labels
      check "savings" in labels
      check "work" in labels

    test "listLabels on empty wallet returns empty":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)

      check wallet.listLabels().len == 0

suite "Address Labels - Database":
  test "save and get label":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    wdb.saveLabel("bc1qtest123", "my label")
    check wdb.getLabel("bc1qtest123") == "my label"

    wdb.close()

  test "get nonexistent label returns empty":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    check wdb.getLabel("bc1qunknown") == ""

    wdb.close()

  test "update label":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    wdb.saveLabel("bc1qtest", "first")
    check wdb.getLabel("bc1qtest") == "first"

    wdb.saveLabel("bc1qtest", "second")
    check wdb.getLabel("bc1qtest") == "second"

    wdb.close()

  test "delete label with empty string":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    wdb.saveLabel("bc1qtest", "my label")
    check wdb.getLabel("bc1qtest") == "my label"

    wdb.saveLabel("bc1qtest", "")
    check wdb.getLabel("bc1qtest") == ""

    wdb.close()

  test "getAddressesByLabel":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    wdb.saveLabel("addr1", "work")
    wdb.saveLabel("addr2", "work")
    wdb.saveLabel("addr3", "personal")

    var workAddrs = wdb.getAddressesByLabel("work")
    workAddrs.sort()
    check workAddrs.len == 2
    check "addr1" in workAddrs
    check "addr2" in workAddrs

    wdb.close()

  test "getAllLabels":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    wdb.saveLabel("addr1", "label1")
    wdb.saveLabel("addr2", "label2")
    wdb.saveLabel("addr3", "label3")

    let all = wdb.getAllLabels()
    check all.len == 3

    wdb.close()

suite "Encryption Storage - Database":
  test "save and get encryption parameters":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    let encryptedSeed = @[0x01'u8, 0x02, 0x03, 0x04, 0x05]
    let salt: array[8, byte] = [0x11'u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
    let rounds = 25000

    wdb.saveEncryption(encryptedSeed, salt, rounds)

    let result = wdb.getEncryption()
    check result.isSome

    let (storedSeed, storedSalt, storedRounds) = result.get()
    check storedSeed == encryptedSeed
    check storedSalt == salt
    check storedRounds == rounds

    wdb.close()

  test "get encryption when not set returns none":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    let result = wdb.getEncryption()
    check result.isNone

    wdb.close()

suite "Coinbase Tracking - Database":
  test "save and load UTXO with coinbase flag":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    var txid: array[32, byte]
    txid[0] = 0xab

    # Save a coinbase UTXO
    let utxo = StoredUtxo(
      txid: txid,
      vout: 0,
      value: 5000000000,
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20),
      height: 100,
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: true,
      spentInTxid: none(array[32, byte])
    )

    wdb.saveUtxo(utxo)

    let utxos = wdb.getUnspentUtxos()
    check utxos.len == 1
    check utxos[0].isCoinbase == true
    check utxos[0].value == 5000000000

    wdb.close()

  test "save non-coinbase UTXO":
    var wdb = newWalletDb(":memory:")
    wdb.open()

    var txid: array[32, byte]
    txid[0] = 0xcd

    let utxo = StoredUtxo(
      txid: txid,
      vout: 1,
      value: 100000,
      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20),
      height: 200,
      keyPath: "m/84'/0'/0'/0/1",
      isInternal: false,
      isCoinbase: false,
      spentInTxid: none(array[32, byte])
    )

    wdb.saveUtxo(utxo)

    let utxos = wdb.getUnspentUtxos()
    check utxos.len == 1
    check utxos[0].isCoinbase == false

    wdb.close()
