## The testnet4 genesis block is BIP-94's, not mainnet's (2026-11-24 Neon
## audit of nimrod, finding 10).
##
## Core CTestNet4Params (kernel/chainparams.cpp, v31.1) builds genesis with
##   pszTimestamp = "03/May/2024 000000000000000000001ebd58c244970b3aa9d783bb001011fbe8ea8e98e00e"
##   output       = <33 zero bytes> OP_CHECKSIG
## giving merkle root 7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e
## and hash 00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043.
## nimrod's buildGenesisBlock used mainnet's coinbase message and pubkey for
## every network, so a fresh testnet4 node stored height 0 under the wrong hash
## and could not connect testnet4 block 1 (prevBlock = the real genesis).

import unittest2
import std/strutils
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

proc displayHex(a: array[32, byte]): string =
  for i in countdown(31, 0): result.add toHex(int(a[i]), 2).toLowerAscii()

suite "N10 testnet4 genesis block":
  test "N10a: testnet4 genesis merkle root is Core's 7aa0a7ae...":
    let g = buildGenesisBlock(testnet4Params())
    check displayHex(g.header.merkleRoot) ==
      "7aa0a7ae1e223414cb807e40cd57e667b718e42aaf9306db9102fe28912b7b4e"

  test "N10b: testnet4 genesis hash equals params.genesisBlockHash (00000000da84...)":
    let p = testnet4Params()
    let g = buildGenesisBlock(p)
    let h = BlockHash(doubleSha256(serialize(g.header)))
    check h == p.genesisBlockHash
    check displayHex(array[32, byte](h)) ==
      "00000000da84f2bafbbc53dee25a72ae507ff4914b867c565be350b0da8bf043"
    check verifyGenesisBlock(g, p)

  test "N10c: control: mainnet, testnet3, signet and regtest genesis still match":
    for p in [mainnetParams(), testnet3Params(), signetParams(), regtestParams()]:
      let g = buildGenesisBlock(p)
      check BlockHash(doubleSha256(serialize(g.header))) == p.genesisBlockHash
