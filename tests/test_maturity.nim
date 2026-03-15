## Tests for coinbase maturity enforcement
## Coinbase outputs require 100 confirmations before spending

import std/[unittest, tables]
import ../src/wallet/wallet
import ../src/primitives/types
import ../src/crypto/[hashing, address, secp256k1]
import ../src/consensus/params

suite "Coinbase Maturity":
  test "CoinbaseMaturity constant is 100":
    check CoinbaseMaturity == 100

  test "non-coinbase UTXO is always mature":
    var utxo = WalletUtxo(
      outpoint: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      output: TxOut(value: Satoshi(100000), scriptPubKey: @[]),
      height: 1,
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: false
    )
    # Non-coinbase is mature at any height
    check utxo.isMatureCoinbase(1)
    check utxo.isMatureCoinbase(50)
    check utxo.isMatureCoinbase(100)
    check utxo.isMatureCoinbase(1000)

  test "coinbase UTXO requires 100 confirmations":
    var utxo = WalletUtxo(
      outpoint: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      output: TxOut(value: Satoshi(5000000000), scriptPubKey: @[]),
      height: 100,
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: true
    )

    # At height 100, coinbase at height 100 has 1 confirmation
    check not utxo.isMatureCoinbase(100)

    # At height 150, coinbase at height 100 has 51 confirmations
    check not utxo.isMatureCoinbase(150)

    # At height 198, coinbase at height 100 has 99 confirmations
    check not utxo.isMatureCoinbase(198)

    # At height 199, coinbase at height 100 has 100 confirmations (mature!)
    check utxo.isMatureCoinbase(199)

    # At height 200+, still mature
    check utxo.isMatureCoinbase(200)
    check utxo.isMatureCoinbase(1000)

  test "unconfirmed coinbase is never mature":
    var utxo = WalletUtxo(
      outpoint: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      output: TxOut(value: Satoshi(5000000000), scriptPubKey: @[]),
      height: 0,  # Unconfirmed
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: true
    )

    check not utxo.isMatureCoinbase(0)
    check not utxo.isMatureCoinbase(100)
    check not utxo.isMatureCoinbase(1000)

  test "coinbase with negative height is never mature":
    var utxo = WalletUtxo(
      outpoint: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
      output: TxOut(value: Satoshi(5000000000), scriptPubKey: @[]),
      height: -1,
      keyPath: "m/84'/0'/0'/0/0",
      isInternal: false,
      isCoinbase: true
    )

    check not utxo.isMatureCoinbase(100)

  test "isCoinbaseTx detection":
    # Coinbase transaction has single input with null prevout
    var coinbaseTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32),
        scriptSig: @[0x04'u8, 0x01, 0x02, 0x03, 0x04],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(5000000000),
        scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)
      )],
      witnesses: @[],
      lockTime: 0
    )
    check coinbaseTx.isCoinbaseTx()

    # Regular transaction is not coinbase
    var regularTx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), vout: 0),
        scriptSig: @[],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(100000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )
    check not regularTx.isCoinbaseTx()

    # Transaction with multiple inputs is not coinbase
    var multiInputTx = Transaction(
      version: 2,
      inputs: @[
        TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32), scriptSig: @[], sequence: 0xFFFFFFFF'u32),
        TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xFFFFFFFF'u32), scriptSig: @[], sequence: 0xFFFFFFFF'u32)
      ],
      outputs: @[],
      witnesses: @[],
      lockTime: 0
    )
    check not multiInputTx.isCoinbaseTx()

when defined(useSystemSecp256k1):
  initSecp256k1()

  suite "Coinbase Maturity - Wallet Integration":
    test "getSpendableBalance excludes immature coinbase":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, gap = 3)

      # Add a mature regular UTXO
      var txid1: array[32, byte]
      txid1[0] = 1
      wallet.addUtxo(
        OutPoint(txid: TxId(txid1), vout: 0),
        TxOut(value: Satoshi(100000), scriptPubKey: @[]),
        100,
        "m/84'/0'/0'/0/0",
        false,
        false  # not coinbase
      )

      # Add an immature coinbase UTXO
      var txid2: array[32, byte]
      txid2[0] = 2
      wallet.addUtxo(
        OutPoint(txid: TxId(txid2), vout: 0),
        TxOut(value: Satoshi(5000000000), scriptPubKey: @[]),
        150,
        "m/84'/0'/0'/0/1",
        false,
        true  # coinbase
      )

      # At height 200, coinbase at 150 has 51 confirmations (immature)
      check wallet.getSpendableBalance(200) == Satoshi(100000)

      # Total balance includes both
      check wallet.getBalance() == Satoshi(5000100000)

      # At height 249, coinbase becomes mature (100 confirmations)
      check wallet.getSpendableBalance(249) == Satoshi(5000100000)

    test "getImmatureBalance returns only immature coinbase":
      let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 84, gap = 3)

      # Add a regular UTXO
      var txid1: array[32, byte]
      txid1[0] = 1
      wallet.addUtxo(
        OutPoint(txid: TxId(txid1), vout: 0),
        TxOut(value: Satoshi(100000), scriptPubKey: @[]),
        100,
        "m/84'/0'/0'/0/0",
        false,
        false
      )

      # Add a coinbase UTXO at height 150
      var txid2: array[32, byte]
      txid2[0] = 2
      wallet.addUtxo(
        OutPoint(txid: TxId(txid2), vout: 0),
        TxOut(value: Satoshi(5000000000), scriptPubKey: @[]),
        150,
        "m/84'/0'/0'/0/1",
        false,
        true
      )

      # At height 200, coinbase is immature
      check wallet.getImmatureBalance(200) == Satoshi(5000000000)

      # At height 249, coinbase is mature
      check wallet.getImmatureBalance(249) == Satoshi(0)
