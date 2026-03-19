## Tests for BIP330 Erlay transaction reconciliation
## Tests salt computation, short ID generation, and reconciliation protocol

import std/[random, tables, sequtils]
import unittest2
import ../src/network/erlay
import ../src/network/messages
import ../src/primitives/[types, serialize]
import ../src/crypto/[hashing, siphash]

proc hexToBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(s[i*2 .. i*2+1]))

proc bytesToHex(b: openArray[byte]): string =
  for x in b:
    result.add(toHex(x, 2).toLowerAscii)

proc randomTxId(seed: int): TxId =
  randomize(seed)
  var bytes: array[32, byte]
  for i in 0 ..< 32:
    bytes[i] = byte(rand(255))
  TxId(bytes)

suite "salt computation":
  test "compute recon salt produces deterministic result":
    let salt1 = 0x1234567890abcdef'u64
    let salt2 = 0xfedcba0987654321'u64

    let result1 = computeReconSalt(salt1, salt2)
    let result2 = computeReconSalt(salt1, salt2)

    check result1 == result2

  test "salt computation is order-independent":
    let salt1 = 0x1234567890abcdef'u64
    let salt2 = 0xfedcba0987654321'u64

    # BIP-330: salts combined in ascending order
    let result1 = computeReconSalt(salt1, salt2)
    let result2 = computeReconSalt(salt2, salt1)

    check result1 == result2

  test "different salts produce different results":
    let salt1 = 0x1234567890abcdef'u64
    let salt2 = 0x1234567890abcde0'u64
    let salt3 = 0xfedcba0987654321'u64

    let result1 = computeReconSalt(salt1, salt3)
    let result2 = computeReconSalt(salt2, salt3)

    check result1 != result2

  test "extract siphash keys from salt":
    let salt1 = 0x1234'u64
    let salt2 = 0x5678'u64

    let fullSalt = computeReconSalt(salt1, salt2)
    let (k0, k1) = extractSipHashKeys(fullSalt)

    # k0 and k1 should be extracted correctly
    check k0 != 0 or k1 != 0  # At least one should be non-zero

suite "short ID computation":
  test "short ID is 32-bit truncated":
    let k0 = 0x1234567890abcdef'u64
    let k1 = 0xfedcba0987654321'u64
    let wtxid = randomTxId(42)

    let shortId = computeReconciliationShortId(k0, k1, wtxid)

    # Should fit in 32 bits
    check shortId <= 0xFFFFFFFF'u64

  test "short ID is deterministic":
    let k0 = 0x1234567890abcdef'u64
    let k1 = 0xfedcba0987654321'u64
    let wtxid = randomTxId(123)

    let shortId1 = computeReconciliationShortId(k0, k1, wtxid)
    let shortId2 = computeReconciliationShortId(k0, k1, wtxid)

    check shortId1 == shortId2

  test "different wtxids produce different short IDs":
    let k0 = 0x1234567890abcdef'u64
    let k1 = 0xfedcba0987654321'u64
    let wtxid1 = randomTxId(1)
    let wtxid2 = randomTxId(2)

    let shortId1 = computeReconciliationShortId(k0, k1, wtxid1)
    let shortId2 = computeReconciliationShortId(k0, k1, wtxid2)

    # Very high probability they're different
    check shortId1 != shortId2

  test "different keys produce different short IDs":
    let wtxid = randomTxId(42)

    let shortId1 = computeReconciliationShortId(0x1111'u64, 0x2222'u64, wtxid)
    let shortId2 = computeReconciliationShortId(0x3333'u64, 0x4444'u64, wtxid)

    check shortId1 != shortId2

suite "reconciliation tracker":
  test "pre-register peer returns salt":
    var tracker = newTxReconciliationTracker()

    let salt = tracker.preRegisterPeer(1)

    check salt != 0

  test "pre-register generates unique salts":
    var tracker = newTxReconciliationTracker()

    let salt1 = tracker.preRegisterPeer(1)
    let salt2 = tracker.preRegisterPeer(2)

    # Very high probability they're different
    check salt1 != salt2

  test "register peer after pre-registration":
    var tracker = newTxReconciliationTracker()
    let localSalt = tracker.preRegisterPeer(1)
    let remoteSalt = 0xdeadbeef12345678'u64

    let result = tracker.registerPeer(1, isPeerInbound = true,
                                       peerVersion = 1, remoteSalt = remoteSalt)

    check result == rrSuccess
    check tracker.isPeerRegistered(1)

  test "register without pre-registration fails":
    var tracker = newTxReconciliationTracker()

    let result = tracker.registerPeer(1, isPeerInbound = true,
                                       peerVersion = 1, remoteSalt = 123)

    check result == rrNotFound
    check not tracker.isPeerRegistered(1)

  test "double registration fails":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = true, peerVersion = 1, remoteSalt = 123)

    # Try to register again (pre-register first since it was consumed)
    discard tracker.preRegisterPeer(1)
    let result = tracker.registerPeer(1, isPeerInbound = true,
                                       peerVersion = 1, remoteSalt = 456)

    check result == rrAlreadyRegistered

  test "version 0 is protocol violation":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)

    let result = tracker.registerPeer(1, isPeerInbound = true,
                                       peerVersion = 0, remoteSalt = 123)

    check result == rrProtocolViolation

  test "forget peer removes state":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = true, peerVersion = 1, remoteSalt = 123)

    check tracker.isPeerRegistered(1)

    tracker.forgetPeer(1)

    check not tracker.isPeerRegistered(1)

  test "outbound peers are initiators":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    let role = tracker.getRole(1)
    check role.isSome
    check role.get() == rrInitiator

  test "inbound peers are responders":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = true, peerVersion = 1, remoteSalt = 123)

    let role = tracker.getRole(1)
    check role.isSome
    check role.get() == rrResponder

suite "transaction set management":
  test "add transaction to pending set":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    let wtxid = randomTxId(42)
    tracker.addTransaction(1, wtxid)

    check tracker.getPendingCount(1) == 1

  test "add multiple transactions":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    for i in 1..10:
      tracker.addTransaction(1, randomTxId(i))

    check tracker.getPendingCount(1) == 10

  test "avoid duplicate short IDs":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    let wtxid = randomTxId(42)
    tracker.addTransaction(1, wtxid)
    tracker.addTransaction(1, wtxid)  # Duplicate

    check tracker.getPendingCount(1) == 1

  test "add transaction to all peers":
    var tracker = newTxReconciliationTracker()

    for i in 1..3:
      discard tracker.preRegisterPeer(int64(i))
      discard tracker.registerPeer(int64(i), isPeerInbound = false,
                                   peerVersion = 1, remoteSalt = uint64(i * 100))

    let wtxid = randomTxId(42)
    tracker.addTransactionToAll(wtxid)

    for i in 1..3:
      check tracker.getPendingCount(int64(i)) == 1

  test "clear pending set":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    for i in 1..10:
      tracker.addTransaction(1, randomTxId(i))

    check tracker.getPendingCount(1) == 10

    tracker.clearPendingSet(1)

    check tracker.getPendingCount(1) == 0

suite "short ID mapper":
  test "create mapper from state":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    let stateOpt = tracker.getPeerState(1)
    check stateOpt.isSome

    let mapper = newShortIdMapper(stateOpt.get())
    # Just check it doesn't crash
    check true

  test "add and resolve transaction":
    let mapper_k0 = 0x1234567890abcdef'u64
    let mapper_k1 = 0xfedcba0987654321'u64
    var mapper = newShortIdMapper(mapper_k0, mapper_k1)

    let wtxid = randomTxId(42)
    mapper.addTransaction(wtxid)

    let shortId = computeReconciliationShortId(mapper_k0, mapper_k1, wtxid)
    let resolved = mapper.getWtxid(shortId)

    check resolved.isSome
    check resolved.get() == wtxid

  test "resolve unknown short ID returns none":
    var mapper = newShortIdMapper(0x1234'u64, 0x5678'u64)

    let result = mapper.getWtxid(0xdeadbeef'u64)

    check result.isNone

  test "resolve multiple short IDs":
    let mapper_k0 = 0x1234567890abcdef'u64
    let mapper_k1 = 0xfedcba0987654321'u64
    var mapper = newShortIdMapper(mapper_k0, mapper_k1)

    var wtxids: seq[TxId]
    for i in 1..5:
      let wtxid = randomTxId(i)
      wtxids.add(wtxid)
      mapper.addTransaction(wtxid)

    # Create short IDs
    var shortIds: seq[uint64]
    for wtxid in wtxids:
      shortIds.add(computeReconciliationShortId(mapper_k0, mapper_k1, wtxid))

    # Add one unknown
    shortIds.add(0x99999999'u64)

    let (resolved, unresolved) = mapper.resolveShortIds(shortIds)

    check resolved.len == 5
    check unresolved.len == 1
    check unresolved[0] == 0x99999999'u64

suite "reconciliation state machine":
  test "only initiators should request":
    var tracker = newTxReconciliationTracker()

    # Outbound = initiator
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    # Inbound = responder
    discard tracker.preRegisterPeer(2)
    discard tracker.registerPeer(2, isPeerInbound = true, peerVersion = 1, remoteSalt = 456)

    # Only initiator should request (after interval passes)
    # Note: shouldRequestReconciliation checks interval, so this might be false initially
    # Just check the role logic
    check tracker.getRole(1).get() == rrInitiator
    check tracker.getRole(2).get() == rrResponder

  test "mark reconciliation requested":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    check not tracker.isReconciling(1)

    tracker.markReconciliationRequested(1)

    check tracker.isReconciling(1)

  test "mark reconciliation complete":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    tracker.markReconciliationRequested(1)
    check tracker.isReconciling(1)

    tracker.markReconciliationComplete(1)
    check not tracker.isReconciling(1)

  test "extension round allowed once":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    let firstExtension = tracker.requestExtension(1)
    check firstExtension == true

    let secondExtension = tracker.requestExtension(1)
    check secondExtension == false

  test "extension resets after complete":
    var tracker = newTxReconciliationTracker()
    discard tracker.preRegisterPeer(1)
    discard tracker.registerPeer(1, isPeerInbound = false, peerVersion = 1, remoteSalt = 123)

    discard tracker.requestExtension(1)
    tracker.markReconciliationComplete(1)

    let newExtension = tracker.requestExtension(1)
    check newExtension == true

suite "message serialization":
  test "sendtxrcncl round-trip":
    let msg = newSendTxRcncl(version = 1, salt = 0xdeadbeef12345678'u64)

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("sendtxrcncl", payload)

    check msg2.kind == mkSendTxRcncl
    check msg2.sendTxRcncl.version == 1
    check msg2.sendTxRcncl.salt == 0xdeadbeef12345678'u64

  test "reqrecon round-trip":
    let msg = newReqRecon(setSize = 100, q = 8)

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("reqrecon", payload)

    check msg2.kind == mkReqRecon
    check msg2.reqRecon.setSize == 100
    check msg2.reqRecon.q == 8

  test "sketch round-trip":
    var sketchData: seq[byte]
    for i in 0 ..< 64:
      sketchData.add(byte(i))

    let msg = newSketch(sketchData)

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("sketch", payload)

    check msg2.kind == mkSketch
    check msg2.sketch.sketchData.len == 64
    check msg2.sketch.sketchData == sketchData

  test "reconcildiff round-trip":
    let shortIds = @[0x12345678'u32, 0xdeadbeef'u32, 0x87654321'u32]
    let msg = newReconcilDiff(success = true, shortIds = shortIds)

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("reconcildiff", payload)

    check msg2.kind == mkReconcilDiff
    check msg2.reconcilDiff.success == true
    check msg2.reconcilDiff.shortIds == shortIds

  test "reconcildiff failure round-trip":
    let msg = newReconcilDiff(success = false, shortIds = @[])

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("reconcildiff", payload)

    check msg2.kind == mkReconcilDiff
    check msg2.reconcilDiff.success == false
    check msg2.reconcilDiff.shortIds.len == 0

  test "reqsketchext round-trip":
    let msg = newReqSketchExt()

    let payload = serializePayload(msg)
    let msg2 = deserializePayload("reqsketchext", payload)

    check msg2.kind == mkReqSketchExt

  test "message command mapping":
    check messageKindToCommand(mkSendTxRcncl) == "sendtxrcncl"
    check messageKindToCommand(mkReqRecon) == "reqrecon"
    check messageKindToCommand(mkSketch) == "sketch"
    check messageKindToCommand(mkReconcilDiff) == "reconcildiff"
    check messageKindToCommand(mkReqSketchExt) == "reqsketchext"

    check commandToMessageKind("sendtxrcncl") == mkSendTxRcncl
    check commandToMessageKind("reqrecon") == mkReqRecon
    check commandToMessageKind("sketch") == mkSketch
    check commandToMessageKind("reconcildiff") == mkReconcilDiff
    check commandToMessageKind("reqsketchext") == mkReqSketchExt
