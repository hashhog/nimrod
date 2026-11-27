## cffix-nimrod-time-too-new-no-punish: a header rejected only because its
## timestamp is too far in the future must not get the relaying peer banned.
##
## Core: ContextualCheckBlockHeader rejects a header with
## nTime > now + MAX_FUTURE_BLOCK_TIME as BLOCK_TIME_FUTURE "time-too-new"
## (validation.cpp:4108), and MaybePunishNodeForBlock deliberately does NOT
## punish that result (net_processing.cpp:1943,
## `case BlockValidationResult::BLOCK_TIME_FUTURE: break;`).  The header may be
## valid in a couple of hours, or our clock may be the one that is wrong, so
## the sender is not at fault.
##
## nimrod's handleHeaders exempted only the "cannot evaluate diffbits" token
## and sent every other validateHeader rejection to
## misbehavingPeer(ScoreInvalidBlockHeader = 100) -- an instant ban for a
## header that is merely early.
##
## Regtest params, active chain at height 300 (minimumChainWork is zero, so a
## tip extension takes the direct path into validateHeader).  The control
## proves the same harness still bans a genuinely invalid header
## (bad-diffbits), so the attack test is measuring the exemption and not a
## harness that never bans anyone.

import unittest2
import chronos
import std/[tables, times, os]
import ../src/network/sync
import ../src/network/headerssync
import ../src/network/peermanager
import ../src/network/peer
import ../src/network/messages
import ../src/consensus/params
import ../src/primitives/[types, serialize, uint256]
import ../src/crypto/hashing

proc hashOf(h: BlockHeader): BlockHash =
  BlockHash(doubleSha256(serialize(h)))

proc mine(hdr: var BlockHeader) =
  while not validateHeaderPoW(hdr):
    hdr.nonce += 1

proc buildHeaderChain(startHash: BlockHash, startTime: uint32,
                      count: int): seq[BlockHeader] =
  result = @[]
  var prev = startHash
  var ts = startTime
  for i in 0 ..< count:
    ts += 600
    var hdr = BlockHeader(version: 1, prevBlock: prev,
                          merkleRoot: default(array[32, byte]),
                          timestamp: ts, bits: 0x207fffff'u32, nonce: 0)
    mine(hdr)
    result.add(hdr)
    prev = hashOf(hdr)

proc syncManagerAtGenesis(params: ConsensusParams): SyncManager =
  let genesis = buildGenesisBlock(params)
  let genesisHash = params.genesisBlockHash
  result = SyncManager(
    state: ssIdle,
    headerChain: initHeaderChain(genesis.header, genesisHash),
    params: params,
    headerTip: genesisHash,
    headerTipHeight: 0,
    chainTipNoState: genesisHash,
    chainTipHeightNoState: 0,
    peerHeadersSync: initTable[int64, HeadersSyncState](),
    headersPresyncStats: initTable[int64, HeadersPresyncStats](),
    presyncBestPeer: -1,
    presyncBestWork: initUInt256(),
    minimumChainWork: initUInt256(params.minimumChainWork),
    unconnectingHeaders: initTable[int64, int]()
  )

proc extendActiveChain(sm: SyncManager, headers: seq[BlockHeader]) =
  for h in headers:
    let hash = hashOf(h)
    let idx = sm.headerChain.headers.len
    sm.headerChain.headers.add(h)
    sm.headerChain.hashes.add(hash)
    sm.headerChain.byHash[hash] = idx
    sm.headerChain.totalWork = addWork(sm.headerChain.totalWork,
                                       calculateWork(h.bits))
    sm.headerChain.tip = hash
    sm.headerChain.tipHeight = int32(idx)
    sm.headerTip = hash
    sm.headerTipHeight = int32(idx)
  sm.chainTip = sm.headerChain.tip
  sm.chainTipHeight = sm.headerChain.tipHeight

type Fixture = object
  params: ConsensusParams
  pm: PeerManager
  peer: Peer
  sm: SyncManager
  chainA: seq[BlockHeader]

proc scratchDir(): string =
  ## A private datadir per process.  The ban manager persists banlist.json in
  ## the datadir, so a shared one ("/tmp") carries bans from earlier runs and
  ## other test files into this one, and a "not banned" check could then fail
  ## (or a "banned" control pass) for a reason that has nothing to do with the
  ## code under test.
  getTempDir() / ("nimrod-cffix-ttn-" & $getCurrentProcessId())

proc setup300(ip: string): Fixture =
  result.params = regtestParams()
  removeDir(scratchDir())
  createDir(scratchDir())
  result.pm = newPeerManager(result.params, 8, 2, 117, scratchDir())
  result.peer = newPeer(ip, 8333, result.params, pdInbound)
  result.peer.services = NodeNetwork or NodeWitness
  result.pm.peers[ip & ":8333"] = result.peer
  result.sm = syncManagerAtGenesis(result.params)
  result.sm.peerManager = result.pm
  let genesisTime = buildGenesisBlock(result.params).header.timestamp
  result.chainA = buildHeaderChain(result.params.genesisBlockHash,
                                   genesisTime, 300)
  result.sm.extendActiveChain(result.chainA)
  doAssert not result.pm.isBanned(ip), "fixture must start with an empty ban list"

proc tipExtension(f: Fixture, timestamp: uint32,
                  bits = 0x207fffff'u32): BlockHeader =
  result = BlockHeader(version: 1, prevBlock: hashOf(f.chainA[^1]),
                       merkleRoot: default(array[32, byte]),
                       timestamp: timestamp, bits: bits, nonce: 0)
  mine(result)

proc nowPlus(secs: int64): uint32 =
  uint32(getTime().toUnix() + secs)

const TooNew = int64(MaxFutureBlockTime) + 60
  ## now + 7260: past Core's limit (nTime > now + 7200).  The 60 s margin over
  ## the minimal now+7201 keeps the test from flaking when the wall-clock
  ## second ticks between building the header and validateHeader's getTime().

suite "time-too-new header: dropped, peer not punished (Core BLOCK_TIME_FUTURE)":

  teardown:
    removeDir(scratchDir())

  test "tip-extending header more than 7200 s ahead is dropped and the peer is not punished":
    var f = setup300("203.0.113.81")
    let hdr = f.tipExtension(nowPlus(TooNew))
    waitFor f.sm.handleHeaders(f.peer, @[hdr])
    # Dropped: the active header chain did not move.
    check f.sm.headerChain.tipHeight == 300
    check not f.sm.headerChain.hasHeader(hashOf(hdr))
    # Not punished: Core's MaybePunishNodeForBlock breaks on BLOCK_TIME_FUTURE.
    # (nimrod's misbehaving() follows Core PR #25974: any call sets
    # shouldDisconnect; misbehaviorScore no longer accumulates, so the flag and
    # the ban list are what a punishment leaves behind.)
    check not f.peer.shouldDisconnect
    check not f.pm.isBanned(f.peer.address)

  test "validateHeader names the rejection with Core's time-too-new token":
    var f = setup300("203.0.113.82")
    let hdr = f.tipExtension(nowPlus(TooNew))
    let (valid, error) = validateHeader(hdr, f.sm.headerChain, 301, f.params,
                                        minPowChecked = true)
    check not valid
    check error == "time-too-new"
    when declared(isNoPunishHeaderError):
      check isNoPunishHeaderError(error)

  test "boundary: a header at exactly now+7200 is still accepted":
    ## Core rejects only nTime > now + MAX_FUTURE_BLOCK_TIME.  Deterministic:
    ## the clock only moves forward between nowPlus() and validateHeader's
    ## getTime(), so the header is never more than 7200 s ahead when checked.
    var f = setup300("203.0.113.83")
    let hdr = f.tipExtension(nowPlus(int64(MaxFutureBlockTime)))
    waitFor f.sm.handleHeaders(f.peer, @[hdr])
    check f.sm.headerChain.tipHeight == 301
    check not f.peer.shouldDisconnect
    check not f.pm.isBanned(f.peer.address)

  test "time-too-new from a non-sync peer leaves the sync peer and state alone":
    ## Core ProcessHeadersMessage returns after MaybePunishNodeForBlock without
    ## touching the header-sync state (net_processing.cpp:3093).  Dropping the
    ## sync peer here would let any peer interrupt sync with another one, and
    ## re-select a still-connected sender in a getheaders loop.
    var f = setup300("203.0.113.86")
    let syncer = newPeer("203.0.113.87", 8333, f.params, pdOutbound)
    syncer.services = NodeNetwork or NodeWitness
    f.pm.peers["203.0.113.87:8333"] = syncer
    f.sm.syncPeer = syncer
    f.sm.state = ssSyncingHeaders
    let hdr = f.tipExtension(nowPlus(TooNew))
    waitFor f.sm.handleHeaders(f.peer, @[hdr])
    check f.sm.headerChain.tipHeight == 300
    # Compared through a bool: on failure unittest2 prints each operand, and
    # `$` of the nil Peer master leaves here would SIGSEGV the whole run.
    let syncPeerKept = f.sm.syncPeer == syncer
    check syncPeerKept
    check f.sm.state == ssSyncingHeaders
    check not f.peer.shouldDisconnect
    check not f.pm.isBanned(f.peer.address)

  test "control: a bad-diffbits header from the same harness is still punished":
    var f = setup300("203.0.113.84")
    # Regtest never retargets, so the required nBits is the parent's
    # 0x207fffff.  0x207ffffe is under powLimit (passes the batch PoW gate) but
    # is not the required value -> Core "bad-diffbits", BLOCK_INVALID_HEADER.
    let hdr = f.tipExtension(f.chainA[^1].timestamp + 600, bits = 0x207ffffe'u32)
    waitFor f.sm.handleHeaders(f.peer, @[hdr])
    check f.sm.headerChain.tipHeight == 300
    check f.peer.shouldDisconnect
    check f.pm.isBanned(f.peer.address)

  test "control: a header failing MTP (time-too-old) is still punished":
    var f = setup300("203.0.113.85")
    let hdr = f.tipExtension(f.chainA[0].timestamp)
    waitFor f.sm.handleHeaders(f.peer, @[hdr])
    check f.sm.headerChain.tipHeight == 300
    check f.peer.shouldDisconnect
    check f.pm.isBanned(f.peer.address)
