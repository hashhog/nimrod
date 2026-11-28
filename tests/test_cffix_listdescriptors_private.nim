## cffix-nimrod-listdescriptors-private
##
## Imported private descriptors must not sit in the wallet database in
## plaintext, and `listdescriptors` must return the PUBLIC form unless the
## caller asks for `private=true` on an unlocked wallet.
##
## Finding (fingerprint nimrod/wallet/imported-private-descriptor-plaintext-
## listdescriptors): importdescriptors stored the raw descriptor, WIF or xprv
## included, in the watched_descriptors table whatever the encryption state,
## and listdescriptors emitted that string with no private/lock gating.
##
## Core (bitcoin-core/src/wallet/rpc/backup.cpp):
##   * importdescriptors calls EnsureWalletIsUnlocked before any element
##     (:383) -> RPC_WALLET_UNLOCK_NEEDED (-13).
##   * listdescriptors returns GetDescriptorString(priv=false) by default;
##     private=true calls EnsureWalletIsUnlocked first (:504).
##   * descriptor keys are stored encrypted in an encrypted wallet.
##
## Run ONLY this test:
##   nim c -r tests/test_cffix_listdescriptors_private.nim

import unittest2
import std/[os, options, tables, strutils, json]
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server
import ../src/wallet/wallet
import ../src/wallet/manager
import ../src/wallet/descriptor
import ../src/crypto/secp256k1

const Pass = "correct horse"

proc hexOf(data: openArray[byte]): string =
  for b in data:
    result.add(toHex(int(b), 2).toLowerAscii)

proc testPriv(last: byte): PrivateKey =
  for i in 0 ..< 31:
    result[i] = byte(i + 1)
  result[31] = last

proc chk(payload: string): string =
  payload & "#" & computeDescriptorChecksum(payload)

proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
  newRpcServer(
    port = 18443'u16,
    chainState = cs,
    mempool = newMempool(cs, params),
    peerManager = nil,
    feeEstimator = newFeeEstimator(),
    params = params)

proc rpcCode(rpc: RpcServer, m: string, params: JsonNode): int =
  ## The RPC error code of a call, or 0 when it succeeded.
  try:
    discard rpc.handleMethod(m, params)
    0
  except RpcError as e:
    e.code

proc descStrings(res: JsonNode): seq[string] =
  for d in res["descriptors"]:
    result.add(d["desc"].getStr())

proc dbRows(rpc: RpcServer, name: string): seq[string] =
  let lw = rpc.walletManager.getWallet(name).get()
  for row in lw.db.getWatchedDescriptors():
    result.add(row.descriptor)

proc dbFileHas(dir, name, needle: string): bool =
  readFile(dir / "wallets" / name / "wallet.db").find(needle) >= 0

# One rig per test: regtest chainstate + manager + a private-keys wallet "ew".
template withRig(dirName: string, body: untyped) =
  let testDir {.inject.} = getTempDir() / dirName
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
    doAssert cs.connectBlock(buildGenesisBlock(regtest), 0).isOk
  let rpc {.inject.} = mkRpc(cs, regtest)
  var wm {.inject.} = newWalletManager(testDir, regtest, cs)
  defer: wm.close()
  rpc.walletManager = wm
  discard wm.createWallet("ew", WalletCreateOptions(
    blank: true, descriptors: true))
  rpc.currentWalletName = "ew"
  let priv {.inject.} = testPriv(0x21)
  let wif {.inject.} = encodeWIF(priv, mainnet = false)
  let privDesc {.inject.} = chk("wpkh(" & wif & ")")
  let pubDesc {.inject.} = chk("wpkh(" & hexOf(derivePublicKey(priv)) & ")")
  body

proc importOne(rpc: RpcServer, desc: string): JsonNode =
  rpc.handleImportDescriptors(%*[[{"desc": desc, "timestamp": 1}]])

suite "cffix listdescriptors private: no plaintext keys, gated private form":

  test "encrypted wallet: listdescriptors() after lock has no WIF, nor does the db row":
    withRig("nimrod_cffix_ldp_lock"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      let imp = rpc.importOne(privDesc)
      check imp[0]["success"].getBool()
      check rpc.rpcCode("walletlock", newJArray()) == 0
      let res = rpc.handleListDescriptors(newJArray())
      let descs = descStrings(res)
      check descs.len == 1
      for d in descs:
        check wif notin d
      check descs == @[pubDesc]
      # The persisted row is the public form too.
      let rows = rpc.dbRows("ew")
      check rows.len == 1
      for r in rows:
        check wif notin r
      check (not dbFileHas(testDir, "ew", wif))
      # The in-memory watch entry (getaddressinfo / listunspent parent_desc)
      # holds the public form as well.
      let spk = deriveScripts(parseDescriptor(privDesc))[0]
      let w = wm.getWallet("ew").get().wallet
      check w.watchedScripts.hasKey(spk)
      check w.watchedScripts[spk].descriptor == pubDesc

  test "listdescriptors(true) on a locked wallet is refused with -13":
    withRig("nimrod_cffix_ldp_privlocked"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check rpc.rpcCode("walletlock", newJArray()) == 0
      check rpc.rpcCode("listdescriptors", %[true]) == -13

  test "importdescriptors on a locked wallet is refused with -13 and stores nothing":
    withRig("nimrod_cffix_ldp_implocked"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("importdescriptors",
        %*[[{"desc": privDesc, "timestamp": 1}]]) == -13
      check rpc.dbRows("ew").len == 0
      check (not dbFileHas(testDir, "ew", wif))

  test "unencrypted wallet: listdescriptors() is public, the db row has no WIF":
    withRig("nimrod_cffix_ldp_plainwallet"):
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check descStrings(rpc.handleListDescriptors(newJArray())) == @[pubDesc]
      for r in rpc.dbRows("ew"):
        check wif notin r

  test "control: listdescriptors(true) unlocked returns the private form":
    withRig("nimrod_cffix_ldp_privok"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check rpc.importOne(privDesc)[0]["success"].getBool()
      let res = rpc.handleMethod("listdescriptors", %[true])
      check descStrings(res) == @[privDesc]

  test "control: unencrypted wallet listdescriptors(true) returns the private form":
    withRig("nimrod_cffix_ldp_plainpriv"):
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]

  test "encryptwallet after import: key not in the db, private form back after unlock":
    withRig("nimrod_cffix_ldp_encafter"):
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check (not dbFileHas(testDir, "ew", wif))
      check descStrings(rpc.handleListDescriptors(newJArray())) == @[pubDesc]
      check rpc.rpcCode("listdescriptors", %[true]) == -13
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]

  test "reload of an encrypted wallet: script still watched, private form after unlock":
    withRig("nimrod_cffix_ldp_reload"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check rpc.importOne(privDesc)[0]["success"].getBool()
      let spk = deriveScripts(parseDescriptor(privDesc))[0]
      discard wm.unloadWallet("ew")
      discard wm.loadWallet("ew")
      let w = wm.getWallet("ew").get().wallet
      check w.isLocked
      check w.watchedScripts.hasKey(spk)
      check descStrings(rpc.handleListDescriptors(newJArray())) == @[pubDesc]
      check rpc.rpcCode("listdescriptors", %[true]) == -13
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]

  test "walletpassphrasechange keeps the imported private form recoverable":
    withRig("nimrod_cffix_ldp_passchange"):
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check rpc.rpcCode("walletlock", newJArray()) == 0
      check rpc.rpcCode("walletpassphrasechange", %[Pass, "battery staple"]) == 0
      discard wm.unloadWallet("ew")
      discard wm.loadWallet("ew")
      check rpc.rpcCode("walletpassphrase", %[%"battery staple", %60]) == 0
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]

  test "sethdseed keeps the imported private form recoverable":
    withRig("nimrod_cffix_ldp_sethdseed"):
      check rpc.importOne(privDesc)[0]["success"].getBool()
      check rpc.rpcCode("sethdseed",
        %[%true, %"000102030405060708090a0b0c0d0e0f"]) == 0
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]
      discard wm.unloadWallet("ew")
      discard wm.loadWallet("ew")
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]

  test "xprv with a hardened path: public form is the normalized xpub":
    withRig("nimrod_cffix_ldp_xprv"):
      # A tprv whose path starts with hardened steps. The listed public form
      # must carry no tprv and must expand to the same scripts.
      let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
      let d = chk("wpkh(" & tprv & "/84h/1h/0h/0/*)")
      let imp = rpc.handleImportDescriptors(%*[[
        {"desc": d, "timestamp": 1, "range": 3}]])
      check imp[0]["success"].getBool()
      let descs = descStrings(rpc.handleListDescriptors(newJArray()))
      check descs.len == 1
      check "tprv" notin descs[0]
      check "tpub" in descs[0]
      for r in rpc.dbRows("ew"):
        check "tprv" notin r
      # Same scripts as the private form over the imported range.
      let pubParsed = parseDescriptor(descs[0])
      let privParsed = parseDescriptor(d)
      for i in 0 .. 3:
        check deriveScripts(pubParsed, i, 1) == deriveScripts(privParsed, i, 1)
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[d]
      # Exact shape, as Core's ToNormalizedString prints it: the hardened
      # steps move into the origin, the xpub is the m/84h/1h/0h key.
      let (root, _, _) = decodeExtendedKey(tprv)
      var acct = root
      for idx in [84'u32 or 0x80000000'u32, 1'u32 or 0x80000000'u32,
                  0'u32 or 0x80000000'u32]:
        acct = deriveChild(acct, idx)
      let expected = chk("wpkh([" & hexOf(fingerprint(root)) & "/84h/1h/0h]" &
                         serializeExtendedKey(neuter(acct), false) & "/0/*)")
      check descs == @[expected]

  test "tr(WIF): the public form is the x-only key and watches the same output":
    withRig("nimrod_cffix_ldp_tr"):
      let d = chk("tr(" & wif & ")")
      check rpc.importOne(d)[0]["success"].getBool()
      let xonly = hexOf(derivePublicKey(priv)[1 .. 32])
      let descs = descStrings(rpc.handleListDescriptors(newJArray()))
      check descs == @[chk("tr(" & xonly & ")")]
      check deriveScripts(parseDescriptor(descs[0])) ==
            deriveScripts(parseDescriptor(d))
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[d]

  test "hardened wildcard (/*h): reload of a locked wallet watches after unlock":
    withRig("nimrod_cffix_ldp_hwild"):
      # xpub/*h cannot expand without the private key, so the reload must
      # use the sealed private form, which needs the wallet unlocked.
      let tprv = "tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK"
      let d = chk("wpkh(" & tprv & "/1h/*h)")
      check rpc.rpcCode("encryptwallet", %[Pass]) == 0
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      check rpc.handleImportDescriptors(%*[[
        {"desc": d, "timestamp": 1, "range": 2}]])[0]["success"].getBool()
      let spks = deriveScripts(parseDescriptor(d), 0, 3)
      check spks.len == 3
      let listed = descStrings(rpc.handleListDescriptors(newJArray()))
      check listed.len == 1
      check "tprv" notin listed[0]
      check (not dbFileHas(testDir, "ew", tprv))
      discard wm.unloadWallet("ew")
      discard wm.loadWallet("ew")
      var w = wm.getWallet("ew").get().wallet
      check w.isLocked
      # Locked: the seed is not in memory, so these are not watched yet.
      check (not w.watchedScripts.hasKey(spks[0]))
      check rpc.rpcCode("walletpassphrase", %[%Pass, %60]) == 0
      w = wm.getWallet("ew").get().wallet
      for spk in spks:
        check w.watchedScripts.hasKey(spk)
        if w.watchedScripts.hasKey(spk):
          check w.watchedScripts[spk].descriptor == listed[0]
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[d]

  test "legacy plaintext row from an older build is listed public and migrated":
    withRig("nimrod_cffix_ldp_legacy"):
      # An older build wrote the private string straight into the table.
      let lw = wm.getWallet("ew").get()
      lw.db.saveWatchedDescriptor(privDesc, "", 1, 0)
      check descStrings(rpc.handleListDescriptors(newJArray())) == @[pubDesc]
      discard wm.unloadWallet("ew")
      discard wm.loadWallet("ew")
      for r in rpc.dbRows("ew"):
        check wif notin r
      check descStrings(rpc.handleListDescriptors(newJArray())) == @[pubDesc]
      check descStrings(rpc.handleMethod("listdescriptors", %[true])) == @[privDesc]
