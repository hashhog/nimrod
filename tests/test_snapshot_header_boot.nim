## Control: snapshot-boot header chain must sit on the assumeUTXO base,
## not genesis.
##
## After `--load-snapshot` at a campaign rung, writeSnapshotActivationIndex
## sets bestHeight to the base but persists no BlockIndex rows for the
## pre-base band. loadHeaderChainFromDb then stops at genesis, so
## getblockchaininfo.headers stays 0 and getheaders is seeded at a hash
## the header chain does not hold — every peer batch is unconnecting
## ("header-sync STALLED at 0 < base"). rustoshi / blockbrew / camlcoin /
## hotbuns graft campaign `base_tail_headers` so the header chain presents
## the snapshot base immediately.
##
## Command (fails if persistAssumeutxoBaseHeaders is a no-op):
##   nim c -r tests/test_snapshot_header_boot.nim

import unittest2
import std/[os, strutils, options, sequtils, tables]
import ../src/network/sync
import ../src/consensus/params
import ../src/storage/[chainstate, snapshot]
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

const CampaignEnvVar = "HASHHOG_CAMPAIGN_ASSUMEUTXO"

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc toDisplayHex(h: BlockHash): string =
  let a = array[32, byte](h)
  for i in countdown(31, 0):
    result.add(a[i].toHex(2).toLowerAscii)

proc toDisplayHex32(a: array[32, byte]): string =
  for i in countdown(31, 0):
    result.add(a[i].toHex(2).toLowerAscii)

proc headerToHex(h: BlockHeader): string =
  let raw = serialize(h)
  for b in raw:
    result.add(b.toHex(2).toLowerAscii)

proc mineHeader(prev: BlockHash, ts: uint32, bits: uint32): BlockHeader =
  result = BlockHeader(
    version: 1,
    prevBlock: prev,
    merkleRoot: default(array[32, byte]),
    timestamp: ts,
    bits: bits,
    nonce: 0
  )
  while not validateHeaderPoW(result):
    result.nonce += 1

proc mineBand(startHash: BlockHash, startTime: uint32, count: int): seq[BlockHeader] =
  result = @[]
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    let hdr = mineHeader(prev, ts, 0x207fffff'u32)
    result.add(hdr)
    prev = hashOf(hdr)

suite "snapshot-boot header chain starts at the assumeUTXO base":
  setup:
    delEnv(CampaignEnvVar)

  teardown:
    delEnv(CampaignEnvVar)

  test "without persist, reload stays at genesis though bestHeight is the base":
    ## THE regression. Activation writes the height slot but no header
    ## bytes, so loadHeaderChainFromDb stops at genesis.
    let p = regtestParams()
    let path = "/tmp/nimrod_snap_hdr_boot_nopersist"
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let genesis = buildGenesisBlock(p)
    let band = mineBand(p.genesisBlockHash, genesis.header.timestamp, 3)
    cdb.bestHeight = 10
    cdb.bestBlockHash = hashOf(band[^1])
    # Height slot only — what writeSnapshotActivationIndex does without a
    # graft. Heights 1..9 are missing, so the forward walk stops at 1.
    cdb.putHeightIndex(10'i32, hashOf(band[^1]))

    let hc = loadHeaderChainFromDb(cdb, p)
    check hc.tipHeight == 0
    check hc.tip == p.genesisBlockHash

  test "persist + reload presents the snapshot base, holes below the tail":
    let p = regtestParams()
    let path = "/tmp/nimrod_snap_hdr_boot_persist"
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    let genesis = buildGenesisBlock(p)
    let band = mineBand(p.genesisBlockHash, genesis.header.timestamp, 3)
    # Band is heights 8,9,10 — skip 1..7 to mimic a campaign tail.
    # First tail header links to genesis so the min-difficulty ancestor
    # walk on regtest can terminate (a 2027-header campaign band never
    # needs to). Heights 1..7 stay holes.
    let tail = mineBand(p.genesisBlockHash, genesis.header.timestamp + 4800, 3)
    let baseHash = hashOf(tail[^1])
    let baseHeight = 10'i32

    var cw = calculateWork(genesis.header.bits)
    for i in 1 .. 7:
      cw = addWork(cw, calculateWork(0x207fffff'u32))
    for hdr in tail:
      cw = addWork(cw, calculateWork(hdr.bits))

    let data = AssumeutxoData(
      height: baseHeight,
      hashSerialized: default(array[32, byte]),
      chainTxCount: 11'u64,
      blockhash: baseHash,
      chainwork: cw,
      baseTailHeaders: tail
    )
    check persistAssumeutxoBaseHeaders(cdb, data) == 3

    cdb.bestHeight = baseHeight
    cdb.bestBlockHash = baseHash

    let hc = loadHeaderChainFromDb(cdb, p)
    check hc.tipHeight == baseHeight
    check hc.tip == baseHash
    check hc.headers.len == int(baseHeight) + 1
    check hc.getHeaderByHeight(baseHeight).isSome
    check hc.getHeaderByHeight(baseHeight).get() == tail[^1]
    check hc.getHeaderByHeight(9).isSome
    check hc.getHeaderByHeight(8).isSome
    check hc.getHeaderByHeight(1).isNone
    check hc.getHeaderByHeight(7).isNone
    check len(hc.byHash) < hc.headers.len
    check not isZeroWork(hc.totalWork)

  test "campaign JSON ancestry is parsed and a connecting header is Direct":
    let p0 = regtestParams()
    let genesis = buildGenesisBlock(p0)
    let tail = mineBand(p0.genesisBlockHash, genesis.header.timestamp + 4800, 3)
    let baseHash = hashOf(tail[^1])
    let baseHeight = 10'i32

    var cw = calculateWork(genesis.header.bits)
    for i in 1 .. 7:
      cw = addWork(cw, calculateWork(0x207fffff'u32))
    for hdr in tail:
      cw = addWork(cw, calculateWork(hdr.bits))

    let testDir = getTempDir() / "nimrod_snap_hdr_boot_campaign"
    createDir(testDir)
    defer: (try: removeDir(testDir) except OSError: discard)
    let campaignPath = testDir / "campaign.json"
    let tailsJson = tail.mapIt("\"" & headerToHex(it) & "\"").join(", ")
    writeFile(campaignPath,
      "[{\"height\": " & $baseHeight &
      ", \"blockhash\": \"" & toDisplayHex(baseHash) &
      "\", \"hash_serialized\": \"" & "33".repeat(32) &
      "\", \"m_chain_tx_count\": 11" &
      ", \"base_header\": \"" & headerToHex(tail[^1]) &
      "\", \"chainwork\": \"" & toDisplayHex32(cw) &
      "\", \"base_tail_headers\": [" & tailsJson & "]}]")

    putEnv(CampaignEnvVar, campaignPath)
    var p = regtestParams()
    let builtin = p.assumeutxoData.len
    loadCampaignAssumeutxo(p)
    check p.assumeutxoData.len == builtin + 1
    let added = p.assumeutxoData[^1]
    check added.height == baseHeight
    check added.blockhash == baseHash
    check added.baseTailHeaders.len == 3
    check added.chainwork == cw

    let path = "/tmp/nimrod_snap_hdr_boot_sm"
    removeDir(path)
    let cdb = openChainDb(path)
    defer:
      var c = cdb
      c.close()
      removeDir(path)

    check persistAssumeutxoBaseHeaders(cdb, added) == 3
    cdb.bestHeight = baseHeight
    cdb.bestBlockHash = baseHash

    let sm = newSyncManager(nil, cdb, p)
    check sm.headerChain.tipHeight == baseHeight
    check sm.headerTipHeight == baseHeight
    check sm.locatorStartHeight() == baseHeight
    check sm.buildBlockLocator()[0] == array[32, byte](baseHash)

    # A header that extends the grafted base must CONNECT, not go
    # unconnecting — that is the stall. Raise minimumChainWork so a
    # dense from-genesis batch would PRESYNC; the grafted tip-extend
    # path must still be Direct.
    sm.minimumChainWork = initUInt256()
    sm.minimumChainWork.limbs[3] = 1'u64
    let next = mineHeader(baseHash, tail[^1].timestamp + 600, 0x207fffff'u32)
    let cls = sm.classifyHeaderBatch(@[next])
    check cls.routing == hbrDirect
    check cls.connectHash == baseHash
    check cls.connectHeight == baseHeight

    let accepted = sm.processHeaders(@[next])
    check accepted == 1
    check sm.headerChain.tipHeight == baseHeight + 1
    check sm.headerChain.tip == hashOf(next)
