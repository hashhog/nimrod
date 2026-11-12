## gettransaction.details for a send-to-self (wallet-cause-D).
##
## CONTROL: `nim c -r tests/selfsend_details/test_selfsend_details.nim`
##
## Core CachedTxGetAmounts (wallet/receive.cpp), used by ListTransactions:
## when the wallet paid for the tx, change is skipped, every other output is a
## "send" leg and every owned non-change output is ALSO a "receive" leg. A
## payment to a second own address is therefore [send, receive]; nimrod
## recorded only the send leg.

import unittest2
import std/[tables, options]
import ../../src/wallet/wallet
import ../../src/consensus/params
import ../../src/primitives/[types, serialize]
import ../../src/crypto/address

const Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

proc mkBlock(txs: seq[Transaction]): Block =
  Block(
    header: BlockHeader(version: 0x20000000,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]), timestamp: 1234567890,
      bits: 0x1d00ffff'u32, nonce: 0),
    txs: txs)

proc spendRecord(toSelf: bool): WalletTxRecord =
  var w = newWallet(Mnemonic, "", regtestParams())
  let recv = w.getNewAddress(P2WPKH)
  let second = w.getNewAddress(P2WPKH)
  let change = w.getNewAddress(P2WPKH, -1, true)
  let recvSpk = scriptPubKeyForAddress(recv)
  let secondSpk = scriptPubKeyForAddress(second)
  let changeSpk = scriptPubKeyForAddress(change)
  let foreignSpk = @[0x00'u8, 0x14] & newSeq[byte](20)

  let funding = Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                                     vout: 0xffffffff'u32),
                   scriptSig: @[0x04'u8, 0xff, 0xff, 0xff, 0xff],
                   sequence: 0xffffffff'u32)],
    outputs: @[TxOut(value: Satoshi(5_000_000_000), scriptPubKey: recvSpk)],
    witnesses: @[], lockTime: 0)
  w.scanBlockForWallet(mkBlock(@[funding]), 1)

  let dest = if toSelf: secondSpk else: foreignSpk
  let spend = Transaction(version: 2,
    inputs: @[TxIn(prevOut: OutPoint(txid: funding.txid(), vout: 0),
                   scriptSig: @[], sequence: 0xfffffffd'u32)],
    outputs: @[TxOut(value: Satoshi(100_000_000), scriptPubKey: dest),
               TxOut(value: Satoshi(3_999_990_000), scriptPubKey: changeSpk)],
    witnesses: @[], lockTime: 0)
  w.scanBlockForWallet(mkBlock(@[spend]), 2)
  doAssert spend.txid() in w.txHistory
  w.txHistory[spend.txid()]

suite "gettransaction details for a send-to-self":
  test "send-to-self records a send leg and a receive leg, never change":
    let rec = spendRecord(toSelf = true)
    check rec.fromMe
    var sends, recvs = 0
    for d in rec.details:
      if d.isSend: inc sends
      elif d.isMine: inc recvs
      check d.vout == 0          # the change output (vout 1) is in neither
    check sends == 1
    check recvs == 1
    check rec.details.len == 2

  test "control: send to a foreign script is one send leg":
    let rec = spendRecord(toSelf = false)
    check rec.details.len == 1
    check rec.details[0].isSend
    check not rec.details[0].isMine
    check rec.details[0].vout == 0
