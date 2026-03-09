## Tests for consensus rules

import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/types

suite "consensus params":
  test "mainnet genesis hash":
    let params = mainnetParams()
    check params.network == Mainnet
    check params.p2pPort == 8333
    check params.rpcPort == 8332

  test "testnet params":
    let params = testnet3Params()
    check params.network == Testnet3
    check params.p2pPort == 18333

  test "regtest params":
    let params = regtestParams()
    check params.network == Regtest
    check params.subsidyHalvingInterval == 150

  test "block subsidy halving":
    let params = mainnetParams()

    # Block 0: 50 BTC
    check getBlockSubsidy(0, params) == Satoshi(50_00000000)

    # Block 209999: still 50 BTC
    check getBlockSubsidy(209999, params) == Satoshi(50_00000000)

    # Block 210000: 25 BTC
    check getBlockSubsidy(210000, params) == Satoshi(25_00000000)

    # Block 420000: 12.5 BTC
    check getBlockSubsidy(420000, params) == Satoshi(12_50000000)

    # Block 630000: 6.25 BTC
    check getBlockSubsidy(630000, params) == Satoshi(6_25000000)

suite "transaction validation":
  test "transaction must have inputs":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[],
      outputs: @[TxOut(value: Satoshi(100), scriptPubKey: ScriptBytes(@[]))],
      lockTime: 0
    )
    let result = checkTransaction(tx, params)
    check result.valid == false
    check "no inputs" in result.error

  test "transaction must have outputs":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: ScriptBytes(@[]),
        sequence: 0xFFFFFFFF
      )],
      outputs: @[],
      lockTime: 0
    )
    let result = checkTransaction(tx, params)
    check result.valid == false
    check "no outputs" in result.error

  test "output value cannot exceed max money":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: ScriptBytes(@[]),
        sequence: 0xFFFFFFFF
      )],
      outputs: @[TxOut(
        value: Satoshi(int64(MAX_MONEY) + 1),
        scriptPubKey: ScriptBytes(@[])
      )],
      lockTime: 0
    )
    let result = checkTransaction(tx, params)
    check result.valid == false

  test "valid basic transaction":
    let params = mainnetParams()
    let tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
        scriptSig: ScriptBytes(@[0x01]),
        sequence: 0xFFFFFFFF
      )],
      outputs: @[TxOut(
        value: Satoshi(100_000),
        scriptPubKey: ScriptBytes(@[0x76, 0xa9])
      )],
      lockTime: 0
    )
    let result = checkTransaction(tx, params)
    check result.valid == true

  test "coinbase detection":
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF
        ),
        scriptSig: ScriptBytes(@[0x03, 0x01, 0x00, 0x00]),
        sequence: 0xFFFFFFFF
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: ScriptBytes(@[])
      )],
      lockTime: 0
    )
    check isCoinbase(coinbase) == true

    let regular = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevout: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: ScriptBytes(@[]),
        sequence: 0xFFFFFFFF
      )],
      outputs: @[TxOut(
        value: Satoshi(100),
        scriptPubKey: ScriptBytes(@[])
      )],
      lockTime: 0
    )
    check isCoinbase(regular) == false
