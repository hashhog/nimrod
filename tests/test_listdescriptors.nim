## listdescriptors wallet RPC — unit-level functional test
##
## Verifies nimrod's `listdescriptors` handler matches Bitcoin Core v31.99's
## output shape (bitcoin-core/src/wallet/rpc/backup.cpp listdescriptors):
##
##   { wallet_name: <string>,
##     descriptors: [ { desc: <string WITH trailing #checksum>,
##                      timestamp: <int>,
##                      active: <bool>,
##                      range: [<int>,<int>] (ranged only),
##                      next: <int>, next_index: <int> (ranged only) }, ... ] }
##   descriptors sorted by descriptor string. `internal` is emitted only for
##   active descriptors; nimrod's importdescriptors store is watch-only and
##   never active, so `active`==false and `internal` is omitted for all.
##
## Strategy: NO full node, NO regtest node bind. We spin up an in-memory
## regtest RpcServer + WalletManager + a disable-private-keys ("watch-only")
## wallet, populate the descriptor store via the real handleImportDescriptors,
## then call handleListDescriptors directly and assert the shape + a correct
## BCH checksum (cross-checked against the impl's own computeDescriptorChecksum).
##
## Run ONLY this test:
##   nim c --nimcache:/tmp -r tests/test_listdescriptors.nim

import std/[os, options, tables, unittest, strutils, json, algorithm]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/wallet
import ../src/wallet/manager
import ../src/wallet/descriptor
import ../src/crypto/secp256k1

proc hexOf(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

# Deterministic test key (valid secp256k1 scalar).
proc testPriv(last: byte): PrivateKey =
  for i in 0 ..< 31:
    result[i] = byte(i + 1)
  result[31] = last

proc chk(payload: string): string =
  ## Append the impl's own BCH checksum (the same routine the handler uses).
  payload & "#" & computeDescriptorChecksum(payload)

proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
  let mp = newMempool(cs, params)
  let fe = newFeeEstimator()
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = mp,
    peerManager = nil,
    feeEstimator = fe,
    params = params
  )

# One rig per test: regtest chainstate + manager + watch-only wallet "wo".
template withRig(dirName: string, body: untyped) =
  let testDir = getTempDir() / dirName
  if dirExists(testDir): removeDir(testDir)
  createDir(testDir)
  defer:
    try: removeDir(testDir) except OSError: discard
  let dbDir = testDir / "cs"
  createDir(dbDir)
  let regtest {.inject.} = regtestParams()
  var cs = newChainState(dbDir, regtest)
  defer: cs.close()
  if cs.bestHeight < 0:
    let genesis = buildGenesisBlock(regtest)
    doAssert cs.connectBlock(genesis, 0).isOk
  let rpc {.inject.} = mkRpc(cs, regtest)
  var wm {.inject.} = newWalletManager(testDir, regtest, cs)
  defer: wm.close()
  rpc.walletManager = wm
  discard wm.createWallet("wo", WalletCreateOptions(
    disablePrivateKeys: true, blank: true, descriptors: true))
  # Route handler wallet lookups to "wo".
  rpc.currentWalletName = "wo"
  body

# A standard BIP-84 xpub (reused from tests/test_descriptor.nim).
const TestXpub =
  "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"

suite "listdescriptors RPC (Core-parity shape + checksum)":

  test "empty wallet -> wallet_name + empty descriptors array":
    withRig("nimrod_listdesc_empty"):
      let res = rpc.handleListDescriptors(newJArray())
      check res.kind == JObject
      check res.hasKey("wallet_name")
      check res["wallet_name"].getStr() == "wo"
      check res.hasKey("descriptors")
      check res["descriptors"].kind == JArray
      check res["descriptors"].len == 0

  test "non-ranged descriptors: desc(with checksum) + timestamp + active=false":
    withRig("nimrod_listdesc_nonranged"):
      let pub = derivePublicKey(testPriv(0x11))
      let wpkhDesc = chk("wpkh(" & hexOf(pub) & ")")
      let addrA = deriveAddresses(parseDescriptor(wpkhDesc), 0, 1, false)[0]
      let addrDesc = chk("addr(" & addrA & ")")

      let imp = rpc.handleImportDescriptors(%*[[
        {"desc": wpkhDesc, "timestamp": 1700000000},
        {"desc": addrDesc, "timestamp": 1700000001, "label": "wo"}
      ]])
      check imp.kind == JArray
      for el in imp:
        check el["success"].getBool() == true

      let res = rpc.handleListDescriptors(newJArray())
      check res["wallet_name"].getStr() == "wo"
      let descs = res["descriptors"]
      check descs.kind == JArray
      check descs.len == 2

      # Sorted by descriptor string (Core backup.cpp:541-543).
      var seen = newSeq[string]()
      for d in descs:
        check d.kind == JObject
        check d.hasKey("desc")
        check d.hasKey("timestamp")
        check d.hasKey("active")
        check d["active"].getBool() == false
        # watch-only/non-active -> internal omitted, no range fields.
        check (not d.hasKey("internal"))
        check (not d.hasKey("range"))
        check (not d.hasKey("next"))
        check (not d.hasKey("next_index"))
        # desc carries a trailing #checksum and it must be valid.
        let s = d["desc"].getStr()
        let hashPos = s.rfind('#')
        check hashPos > 0
        let payload = s[0 ..< hashPos]
        let cksum = s[hashPos + 1 .. ^1]
        check cksum.len == 8
        check cksum == computeDescriptorChecksum(payload)
        seen.add(s)

      # Both imported descriptors are present and the array is sorted.
      var expected = @[wpkhDesc, addrDesc]
      expected.sort()
      check seen == expected

      # The wpkh entry kept its exact import timestamp.
      for d in descs:
        if d["desc"].getStr() == wpkhDesc:
          check d["timestamp"].getInt() == 1700000000

  test "ranged descriptor: range=[0,N] + next/next_index, isRange shape":
    withRig("nimrod_listdesc_ranged"):
      let rangedDesc = chk("wpkh(" & TestXpub & "/0/*)")
      let imp = rpc.handleImportDescriptors(%*[[
        {"desc": rangedDesc, "timestamp": 1700000002, "range": [0, 4]}
      ]])
      check imp.kind == JArray
      check imp[0]["success"].getBool() == true

      let res = rpc.handleListDescriptors(newJArray())
      let descs = res["descriptors"]
      check descs.len == 1
      let d = descs[0]
      check d["desc"].getStr() == rangedDesc
      check d["active"].getBool() == false
      check (not d.hasKey("internal"))
      # range + next/next_index present for ranged descriptors.
      check d.hasKey("range")
      check d["range"].kind == JArray
      check d["range"].len == 2
      check d["range"][0].getInt() == 0
      check d["range"][1].getInt() == 4   # inclusive end (Core range_end-1)
      check d.hasKey("next")
      check d.hasKey("next_index")
      # imported descriptor next_index defaults to range_start (0) — Core
      # backup.cpp:185.
      check d["next"].getInt() == 0
      check d["next_index"].getInt() == 0
      check d["next"].getInt() == d["next_index"].getInt()
      # checksum on the ranged desc is valid too.
      let s = d["desc"].getStr()
      let hp = s.rfind('#')
      check s[hp + 1 .. ^1] == computeDescriptorChecksum(s[0 ..< hp])

  test "private=true on a watch-only wallet -> RPC_WALLET_ERROR (Core parity)":
    withRig("nimrod_listdesc_priv"):
      var code = 0
      try:
        discard rpc.handleListDescriptors(%*[true])
      except RpcError as e:
        code = e.code
      check code == RpcWalletError  # -4
