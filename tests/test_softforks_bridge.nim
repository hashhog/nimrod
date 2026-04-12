## Regtest round-trip test: getblockchaininfo.softforks vs getdeploymentinfo.deployments
##
## Both RPCs must read from the single buildDeployments helper.  This test
## starts an in-memory regtest node, calls both RPCs, and asserts that every
## fork present in both responses has identical field values.
##
## Fields compared per fork id:
##   active, type, height (buried forks), bip9.start_time, bip9.timeout,
##   bip9.min_activation_height, bip9.status, bip9.since, bip9.status_next
##
## Run with:
##   nim c -r tests/test_softforks_bridge.nim
##
## Or via the full suite:
##   nim c -r tests/test_all.nim

import std/[json, os, tempfiles, strutils]
import unittest2
import ../src/consensus/params
import ../src/storage/chainstate
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/rpc/server

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

proc toHexLocal(data: openArray[byte]): string =
  result = ""
  for b in data:
    result.add(strutils.toHex(b, 2).toLowerAscii)

proc reverseHexLocal(hex: string): string =
  result = ""
  var i = hex.len - 2
  while i >= 0:
    result.add(hex[i .. i + 1])
    i -= 2

# ---------------------------------------------------------------------------
# The actual comparison logic
# ---------------------------------------------------------------------------

proc compareDeployments(softforks: JsonNode, deployments: JsonNode) =
  ## For each id that appears in BOTH objects, assert every shared field
  ## is identical.  Fail with an informative message on any mismatch.

  let sharedKeys = block:
    var ks: seq[string]
    for k in softforks.keys:
      if deployments.hasKey(k):
        ks.add(k)
    ks

  check sharedKeys.len > 0  # there must be at least some shared keys

  for id in sharedKeys:
    let sf = softforks[id]
    let di = deployments[id]

    # "type" and "active" must always match
    check sf["type"].getStr() == di["type"].getStr()
    check sf["active"].getBool() == di["active"].getBool()

    let forkType = sf["type"].getStr()

    if forkType == "buried":
      # height must match
      check sf["height"].getInt() == di["height"].getInt()

    elif forkType == "bip9":
      # bip9 sub-object must exist in both and have identical fields
      check sf.hasKey("bip9")
      check di.hasKey("bip9")

      let sfBip9 = sf["bip9"]
      let diBip9 = di["bip9"]

      check sfBip9["start_time"].getBiggestInt()            == diBip9["start_time"].getBiggestInt()
      check sfBip9["timeout"].getBiggestInt()               == diBip9["timeout"].getBiggestInt()
      check sfBip9["min_activation_height"].getInt()        == diBip9["min_activation_height"].getInt()
      check sfBip9["status"].getStr()                       == diBip9["status"].getStr()
      check sfBip9["since"].getInt()                        == diBip9["since"].getInt()
      check sfBip9["status_next"].getStr()                  == diBip9["status_next"].getStr()

      # "bit" is only present in STARTED or LOCKED_IN — check presence matches
      let sfHasBit = sfBip9.hasKey("bit")
      let diHasBit = diBip9.hasKey("bit")
      check sfHasBit == diHasBit
      if sfHasBit and diHasBit:
        check sfBip9["bit"].getInt() == diBip9["bit"].getInt()

# ---------------------------------------------------------------------------
# Test suites
# ---------------------------------------------------------------------------

suite "softforks bridge: getblockchaininfo and getdeploymentinfo share one data source":

  var rpc: RpcServer
  var cs: ChainState
  var tempDir: string
  let params = regtestParams()

  setup:
    tempDir = createTempDir("nimrod_sfbridge_", "_regtest")
    cs = newChainState(tempDir, params)

    # Initialize with genesis block if needed (same pattern as test_regtest.nim)
    if cs.bestHeight < 0:
      let genesis = buildGenesisBlock(params)
      let res = cs.connectBlock(genesis, 0)
      doAssert res.isOk, "Failed to connect genesis"

    let mp = newMempool(cs, params)
    let fe = newFeeEstimator()
    rpc = newRpcServer(
      port         = 18443'u16,
      chainState   = cs,
      mempool      = mp,
      peerManager  = nil,
      feeEstimator = fe,
      params       = params
    )

  teardown:
    cs.close()
    removeDir(tempDir)

  test "getblockchaininfo response contains softforks key":
    let info = rpc.handleGetBlockchainInfo()
    check info.hasKey("softforks")
    check info["softforks"].kind == JObject
    check info["softforks"].len > 0

  test "getdeploymentinfo response contains deployments key":
    let depInfo = rpc.handleGetDeploymentInfo(newJArray())
    check depInfo.hasKey("deployments")
    check depInfo["deployments"].kind == JObject
    check depInfo["deployments"].len > 0

  test "softforks and deployments agree on all shared fields at chain tip":
    ## Core assertion: both RPCs produce identical deployment state because
    ## they both call buildDeployments with the same block hash and height.
    let info    = rpc.handleGetBlockchainInfo()
    let depInfo = rpc.handleGetDeploymentInfo(newJArray())

    let softforks   = info["softforks"]
    let deployments = depInfo["deployments"]

    compareDeployments(softforks, deployments)

  test "both RPCs include all expected fork ids":
    let expected = ["bip34", "bip65", "bip66", "csv", "segwit", "testdummy", "taproot"]
    let info    = rpc.handleGetBlockchainInfo()
    let depInfo = rpc.handleGetDeploymentInfo(newJArray())

    let sf = info["softforks"]
    let di = depInfo["deployments"]

    for id in expected:
      check sf.hasKey(id)
      check di.hasKey(id)

  test "buried forks active from genesis on regtest agree across both RPCs":
    ## On regtest, csv and segwit heights are 0, so they must be active
    ## immediately.  Both RPCs must agree.
    let info    = rpc.handleGetBlockchainInfo()
    let depInfo = rpc.handleGetDeploymentInfo(newJArray())

    for id in ["csv", "segwit"]:
      check info["softforks"][id]["active"].getBool() == true
      check depInfo["deployments"][id]["active"].getBool() == true
      check info["softforks"][id]["active"].getBool() ==
            depInfo["deployments"][id]["active"].getBool()

  test "taproot is active on regtest (AlwaysActive BIP9) in both RPCs":
    let info    = rpc.handleGetBlockchainInfo()
    let depInfo = rpc.handleGetDeploymentInfo(newJArray())

    check info["softforks"]["taproot"]["active"].getBool() == true
    check depInfo["deployments"]["taproot"]["active"].getBool() == true

  test "getdeploymentinfo at explicit tip hash matches getblockchaininfo.softforks":
    ## Pass the tip hash explicitly to getdeploymentinfo; must produce same
    ## deployment state as getblockchaininfo (which always uses tip).
    let tipHash = reverseHexLocal(toHexLocal(array[32, byte](cs.bestBlockHash)))

    var explicitParams = newJArray()
    explicitParams.add(%tipHash)
    let depInfoExplicit = rpc.handleGetDeploymentInfo(explicitParams)
    let info            = rpc.handleGetBlockchainInfo()

    compareDeployments(info["softforks"], depInfoExplicit["deployments"])
