## ZeroMQ notification publisher
## Real-time notifications for blocks, transactions, and sequence events
## Reference: Bitcoin Core src/zmq/zmqpublishnotifier.cpp

import std/[strutils, options, tables]
import chronicles
import ../primitives/[types, serialize]
import ../crypto/hashing

# ZMQ library name varies by platform
when defined(windows):
  const zmqLib = "libzmq.dll"
elif defined(macosx):
  const zmqLib = "libzmq.dylib"
else:
  const zmqLib = "libzmq.so(|.5|.4|.3)"

# ZMQ FFI bindings
{.push importc, dynlib: zmqLib.}

proc zmq_ctx_new(): pointer
proc zmq_ctx_term(context: pointer): cint
proc zmq_socket(context: pointer, `type`: cint): pointer
proc zmq_close(socket: pointer): cint
proc zmq_bind(socket: pointer, endpoint: cstring): cint
proc zmq_setsockopt(socket: pointer, option_name: cint, option_value: pointer, option_len: csize_t): cint
proc zmq_msg_init_size(msg: pointer, size: csize_t): cint
proc zmq_msg_data(msg: pointer): pointer
proc zmq_msg_send(msg: pointer, socket: pointer, flags: cint): cint
proc zmq_msg_close(msg: pointer): cint
proc zmq_version(major: ptr cint, minor: ptr cint, patch: ptr cint)

{.pop.}

const
  # ZMQ socket types
  ZMQ_PUB* = 1.cint

  # ZMQ socket options
  ZMQ_SNDHWM* = 23.cint      # Send high water mark
  ZMQ_TCP_KEEPALIVE* = 34.cint
  ZMQ_LINGER* = 17.cint
  ZMQ_IPV6* = 42.cint

  # ZMQ send flags
  ZMQ_SNDMORE* = 2.cint

  # Default send high water mark (1000 messages)
  DEFAULT_ZMQ_SNDHWM* = 1000.cint

  # ZMQ message struct size (64 bytes on most systems)
  ZMQ_MSG_SIZE = 64

# ZMQ topic names matching Bitcoin Core
const
  MSG_HASHBLOCK* = "hashblock"
  MSG_HASHTX* = "hashtx"
  MSG_RAWBLOCK* = "rawblock"
  MSG_RAWTX* = "rawtx"
  MSG_SEQUENCE* = "sequence"

# Sequence notification labels
const
  SEQ_ADDED* = 'A'      # Transaction added to mempool
  SEQ_REMOVED* = 'R'    # Transaction removed from mempool
  SEQ_CONNECTED* = 'C'  # Block connected
  SEQ_DISCONNECTED* = 'D' # Block disconnected

type
  ZmqNotifierType* = enum
    zntHashBlock
    zntHashTx
    zntRawBlock
    zntRawTx
    zntSequence

  ZmqNotifier* = ref object
    ## A single ZMQ publisher for one topic
    notifierType*: ZmqNotifierType
    address*: string
    socket: pointer
    sequence: uint32        # Per-notifier sequence number
    highWaterMark: cint

  ZmqNotificationInterface* = ref object
    ## Manages all ZMQ notifiers
    context: pointer
    notifiers: seq[ZmqNotifier]
    addressToSocket: Table[string, pointer]  # Share sockets for same address
    getBlockByHash*: proc(hash: BlockHash): Option[Block]

  ZmqConfig* = object
    ## Configuration parsed from command line
    hashBlockAddresses*: seq[string]
    hashTxAddresses*: seq[string]
    rawBlockAddresses*: seq[string]
    rawTxAddresses*: seq[string]
    sequenceAddresses*: seq[string]
    highWaterMarks*: Table[string, int]

proc topicName*(notifierType: ZmqNotifierType): string =
  case notifierType
  of zntHashBlock: MSG_HASHBLOCK
  of zntHashTx: MSG_HASHTX
  of zntRawBlock: MSG_RAWBLOCK
  of zntRawTx: MSG_RAWTX
  of zntSequence: MSG_SEQUENCE

proc notifierTypeName*(notifierType: ZmqNotifierType): string =
  case notifierType
  of zntHashBlock: "pubhashblock"
  of zntHashTx: "pubhashtx"
  of zntRawBlock: "pubrawblock"
  of zntRawTx: "pubrawtx"
  of zntSequence: "pubsequence"

# ZMQ message buffer type
type ZmqMsg = array[ZMQ_MSG_SIZE, byte]

proc writeLE32*(data: var openArray[byte], offset: int, value: uint32) =
  ## Write uint32 in little-endian format
  data[offset] = byte(value and 0xFF)
  data[offset + 1] = byte((value shr 8) and 0xFF)
  data[offset + 2] = byte((value shr 16) and 0xFF)
  data[offset + 3] = byte((value shr 24) and 0xFF)

proc writeLE64*(data: var openArray[byte], offset: int, value: uint64) =
  ## Write uint64 in little-endian format
  for i in 0 ..< 8:
    data[offset + i] = byte((value shr (i * 8)) and 0xFF)

proc reverseBytes*(hash: array[32, byte]): array[32, byte] =
  ## Reverse hash bytes for ZMQ (display order -> internal order)
  for i in 0 ..< 32:
    result[31 - i] = hash[i]

proc sendMultipart(socket: pointer, topic: string, body: openArray[byte],
                   seqNum: uint32): bool =
  ## Send a 3-part ZMQ message: [topic][body][sequence]
  var msg: ZmqMsg

  # Part 1: Topic
  if zmq_msg_init_size(addr msg[0], csize_t(topic.len)) != 0:
    warn "ZMQ: failed to init topic message"
    return false

  copyMem(zmq_msg_data(addr msg[0]), unsafeAddr topic[0], topic.len)

  if zmq_msg_send(addr msg[0], socket, ZMQ_SNDMORE) == -1:
    warn "ZMQ: failed to send topic"
    discard zmq_msg_close(addr msg[0])
    return false

  discard zmq_msg_close(addr msg[0])

  # Part 2: Body
  if zmq_msg_init_size(addr msg[0], csize_t(body.len)) != 0:
    warn "ZMQ: failed to init body message"
    return false

  if body.len > 0:
    copyMem(zmq_msg_data(addr msg[0]), unsafeAddr body[0], body.len)

  if zmq_msg_send(addr msg[0], socket, ZMQ_SNDMORE) == -1:
    warn "ZMQ: failed to send body"
    discard zmq_msg_close(addr msg[0])
    return false

  discard zmq_msg_close(addr msg[0])

  # Part 3: Sequence number (LE uint32)
  var seqBytes: array[4, byte]
  writeLE32(seqBytes, 0, seqNum)

  if zmq_msg_init_size(addr msg[0], 4) != 0:
    warn "ZMQ: failed to init sequence message"
    return false

  copyMem(zmq_msg_data(addr msg[0]), addr seqBytes[0], 4)

  if zmq_msg_send(addr msg[0], socket, 0) == -1:
    warn "ZMQ: failed to send sequence"
    discard zmq_msg_close(addr msg[0])
    return false

  discard zmq_msg_close(addr msg[0])
  return true

proc sendZmqMessage*(notifier: var ZmqNotifier, topic: string,
                     data: openArray[byte]): bool =
  ## Send a ZMQ message with topic, data, and sequence number
  if notifier.socket == nil:
    return false

  result = sendMultipart(notifier.socket, topic, data, notifier.sequence)

  if result:
    # Increment sequence number after successful send
    inc notifier.sequence

proc initialize*(notifier: var ZmqNotifier, context: pointer,
                 addressToSocket: var Table[string, pointer]): bool =
  ## Initialize a notifier's socket
  if notifier.address in addressToSocket:
    # Reuse existing socket for this address
    notifier.socket = addressToSocket[notifier.address]
    debug "ZMQ: reusing socket", address = notifier.address,
          notifierType = notifier.notifierType.notifierTypeName
    return true

  # Create new socket
  notifier.socket = zmq_socket(context, ZMQ_PUB)
  if notifier.socket == nil:
    error "ZMQ: failed to create socket"
    return false

  # Set high water mark
  var hwm = notifier.highWaterMark
  if zmq_setsockopt(notifier.socket, ZMQ_SNDHWM, addr hwm, csize_t(sizeof(cint))) != 0:
    error "ZMQ: failed to set high water mark"
    discard zmq_close(notifier.socket)
    return false

  # Set TCP keepalive
  var keepalive: cint = 1
  if zmq_setsockopt(notifier.socket, ZMQ_TCP_KEEPALIVE, addr keepalive, csize_t(sizeof(cint))) != 0:
    error "ZMQ: failed to set TCP keepalive"
    discard zmq_close(notifier.socket)
    return false

  # Bind to address
  if zmq_bind(notifier.socket, notifier.address.cstring) != 0:
    error "ZMQ: failed to bind", address = notifier.address
    discard zmq_close(notifier.socket)
    return false

  addressToSocket[notifier.address] = notifier.socket
  info "ZMQ: notifier ready", notifierType = notifier.notifierType.notifierTypeName,
       address = notifier.address
  return true

proc shutdown*(notifier: var ZmqNotifier, addressToSocket: var Table[string, pointer]) =
  ## Shutdown a notifier
  if notifier.socket == nil:
    return

  # Check if other notifiers share this socket
  var socketUseCount = 0
  for (address, sock) in addressToSocket.pairs:
    if sock == notifier.socket:
      inc socketUseCount

  if socketUseCount <= 1:
    # Last user of this socket, close it
    var linger: cint = 0
    discard zmq_setsockopt(notifier.socket, ZMQ_LINGER, addr linger, csize_t(sizeof(cint)))
    discard zmq_close(notifier.socket)
    addressToSocket.del(notifier.address)
    debug "ZMQ: closed socket", address = notifier.address

  notifier.socket = nil

proc newZmqConfig*(): ZmqConfig =
  ZmqConfig(
    hashBlockAddresses: @[],
    hashTxAddresses: @[],
    rawBlockAddresses: @[],
    rawTxAddresses: @[],
    sequenceAddresses: @[],
    highWaterMarks: initTable[string, int]()
  )

proc hasNotifiers*(config: ZmqConfig): bool =
  config.hashBlockAddresses.len > 0 or
  config.hashTxAddresses.len > 0 or
  config.rawBlockAddresses.len > 0 or
  config.rawTxAddresses.len > 0 or
  config.sequenceAddresses.len > 0

proc newZmqNotificationInterface*(
  config: ZmqConfig,
  getBlockByHash: proc(hash: BlockHash): Option[Block]
): ZmqNotificationInterface =
  ## Create a new ZMQ notification interface from config
  result = ZmqNotificationInterface(
    context: nil,
    notifiers: @[],
    addressToSocket: initTable[string, pointer](),
    getBlockByHash: getBlockByHash
  )

  # Add notifiers from config
  for addr in config.hashBlockAddresses:
    let hwm = config.highWaterMarks.getOrDefault(addr & "-hashblock", DEFAULT_ZMQ_SNDHWM.int)
    result.notifiers.add(ZmqNotifier(
      notifierType: zntHashBlock,
      address: addr,
      socket: nil,
      sequence: 0,
      highWaterMark: hwm.cint
    ))

  for addr in config.hashTxAddresses:
    let hwm = config.highWaterMarks.getOrDefault(addr & "-hashtx", DEFAULT_ZMQ_SNDHWM.int)
    result.notifiers.add(ZmqNotifier(
      notifierType: zntHashTx,
      address: addr,
      socket: nil,
      sequence: 0,
      highWaterMark: hwm.cint
    ))

  for addr in config.rawBlockAddresses:
    let hwm = config.highWaterMarks.getOrDefault(addr & "-rawblock", DEFAULT_ZMQ_SNDHWM.int)
    result.notifiers.add(ZmqNotifier(
      notifierType: zntRawBlock,
      address: addr,
      socket: nil,
      sequence: 0,
      highWaterMark: hwm.cint
    ))

  for addr in config.rawTxAddresses:
    let hwm = config.highWaterMarks.getOrDefault(addr & "-rawtx", DEFAULT_ZMQ_SNDHWM.int)
    result.notifiers.add(ZmqNotifier(
      notifierType: zntRawTx,
      address: addr,
      socket: nil,
      sequence: 0,
      highWaterMark: hwm.cint
    ))

  for addr in config.sequenceAddresses:
    let hwm = config.highWaterMarks.getOrDefault(addr & "-sequence", DEFAULT_ZMQ_SNDHWM.int)
    result.notifiers.add(ZmqNotifier(
      notifierType: zntSequence,
      address: addr,
      socket: nil,
      sequence: 0,
      highWaterMark: hwm.cint
    ))

proc initialize*(zmq: var ZmqNotificationInterface): bool =
  ## Initialize all ZMQ notifiers
  if zmq.notifiers.len == 0:
    return true  # Nothing to initialize

  # Get ZMQ version
  var major, minor, patch: cint
  zmq_version(addr major, addr minor, addr patch)
  info "ZMQ: version", major = major, minor = minor, patch = patch

  # Create context
  zmq.context = zmq_ctx_new()
  if zmq.context == nil:
    error "ZMQ: failed to create context"
    return false

  # Initialize each notifier
  for i in 0 ..< zmq.notifiers.len:
    if not zmq.notifiers[i].initialize(zmq.context, zmq.addressToSocket):
      error "ZMQ: failed to initialize notifier",
            notifierType = zmq.notifiers[i].notifierType.notifierTypeName
      return false

  info "ZMQ: notification interface initialized", notifierCount = zmq.notifiers.len
  return true

proc shutdown*(zmq: var ZmqNotificationInterface) =
  ## Shutdown all ZMQ notifiers
  if zmq.context == nil:
    return

  info "ZMQ: shutting down notification interface"

  for i in 0 ..< zmq.notifiers.len:
    zmq.notifiers[i].shutdown(zmq.addressToSocket)

  discard zmq_ctx_term(zmq.context)
  zmq.context = nil

proc getActiveNotifiers*(zmq: ZmqNotificationInterface): seq[tuple[
  notifierType: string, address: string, hwm: int
]] =
  ## Get list of active notifiers for RPC
  for notifier in zmq.notifiers:
    result.add((
      notifierType: notifier.notifierType.notifierTypeName,
      address: notifier.address,
      hwm: notifier.highWaterMark.int
    ))

# ============================================================================
# Block Notifications
# ============================================================================

proc notifyBlock*(zmq: var ZmqNotificationInterface, blockHash: BlockHash) =
  ## Notify hashblock subscribers of a new block
  ## Called when tip is updated (not during IBD)

  # Reverse bytes for wire format (Bitcoin Core displays big-endian, wire is little)
  let hashBytes = reverseBytes(array[32, byte](blockHash))

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntHashBlock:
      if zmq.notifiers[i].sendZmqMessage(MSG_HASHBLOCK, hashBytes):
        debug "ZMQ: published hashblock", hash = $blockHash
      else:
        warn "ZMQ: failed to publish hashblock"

proc notifyRawBlock*(zmq: var ZmqNotificationInterface, blockHash: BlockHash) =
  ## Notify rawblock subscribers with full serialized block
  if zmq.getBlockByHash == nil:
    return

  let blockOpt = zmq.getBlockByHash(blockHash)
  if blockOpt.isNone:
    warn "ZMQ: failed to get block for rawblock notification", hash = $blockHash
    return

  let blockData = blockOpt.get().serialize()

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntRawBlock:
      if zmq.notifiers[i].sendZmqMessage(MSG_RAWBLOCK, blockData):
        debug "ZMQ: published rawblock", hash = $blockHash, size = blockData.len
      else:
        warn "ZMQ: failed to publish rawblock"

proc notifyBlockConnect*(zmq: var ZmqNotificationInterface, blockHash: BlockHash) =
  ## Notify sequence subscribers of block connection
  # Format: [32-byte hash (reversed)][1-byte label 'C']
  var data: array[33, byte]
  let hashBytes = reverseBytes(array[32, byte](blockHash))
  copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
  data[32] = byte(SEQ_CONNECTED)

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntSequence:
      if zmq.notifiers[i].sendZmqMessage(MSG_SEQUENCE, data):
        debug "ZMQ: published sequence block connect", hash = $blockHash
      else:
        warn "ZMQ: failed to publish sequence block connect"

proc notifyBlockDisconnect*(zmq: var ZmqNotificationInterface, blockHash: BlockHash) =
  ## Notify sequence subscribers of block disconnection
  # Format: [32-byte hash (reversed)][1-byte label 'D']
  var data: array[33, byte]
  let hashBytes = reverseBytes(array[32, byte](blockHash))
  copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
  data[32] = byte(SEQ_DISCONNECTED)

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntSequence:
      if zmq.notifiers[i].sendZmqMessage(MSG_SEQUENCE, data):
        debug "ZMQ: published sequence block disconnect", hash = $blockHash
      else:
        warn "ZMQ: failed to publish sequence block disconnect"

# ============================================================================
# Transaction Notifications
# ============================================================================

proc notifyTransaction*(zmq: var ZmqNotificationInterface, tx: Transaction) =
  ## Notify hashtx subscribers of a transaction
  let txid = tx.txid()
  let hashBytes = reverseBytes(array[32, byte](txid))

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntHashTx:
      if zmq.notifiers[i].sendZmqMessage(MSG_HASHTX, hashBytes):
        debug "ZMQ: published hashtx", txid = $txid
      else:
        warn "ZMQ: failed to publish hashtx"

proc notifyRawTransaction*(zmq: var ZmqNotificationInterface, tx: Transaction) =
  ## Notify rawtx subscribers with full serialized transaction (with witness)
  let txData = tx.serialize(includeWitness = true)

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntRawTx:
      let txid = tx.txid()
      if zmq.notifiers[i].sendZmqMessage(MSG_RAWTX, txData):
        debug "ZMQ: published rawtx", txid = $txid, size = txData.len
      else:
        warn "ZMQ: failed to publish rawtx"

proc notifyTransactionAcceptance*(zmq: var ZmqNotificationInterface,
                                   tx: Transaction, mempoolSequence: uint64) =
  ## Notify sequence subscribers of mempool acceptance
  # Format: [32-byte txid (reversed)][1-byte label 'A'][8-byte mempool sequence (LE)]
  let txid = tx.txid()
  var data: array[41, byte]
  let hashBytes = reverseBytes(array[32, byte](txid))
  copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
  data[32] = byte(SEQ_ADDED)
  writeLE64(data, 33, mempoolSequence)

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntSequence:
      if zmq.notifiers[i].sendZmqMessage(MSG_SEQUENCE, data):
        debug "ZMQ: published sequence tx acceptance", txid = $txid,
              mempoolSeq = mempoolSequence
      else:
        warn "ZMQ: failed to publish sequence tx acceptance"

proc notifyTransactionRemoval*(zmq: var ZmqNotificationInterface,
                                tx: Transaction, mempoolSequence: uint64) =
  ## Notify sequence subscribers of mempool removal
  # Format: [32-byte txid (reversed)][1-byte label 'R'][8-byte mempool sequence (LE)]
  let txid = tx.txid()
  var data: array[41, byte]
  let hashBytes = reverseBytes(array[32, byte](txid))
  copyMem(addr data[0], unsafeAddr hashBytes[0], 32)
  data[32] = byte(SEQ_REMOVED)
  writeLE64(data, 33, mempoolSequence)

  for i in 0 ..< zmq.notifiers.len:
    if zmq.notifiers[i].notifierType == zntSequence:
      if zmq.notifiers[i].sendZmqMessage(MSG_SEQUENCE, data):
        debug "ZMQ: published sequence tx removal", txid = $txid,
              mempoolSeq = mempoolSequence
      else:
        warn "ZMQ: failed to publish sequence tx removal"

# ============================================================================
# Combined Notification Helpers
# ============================================================================

proc notifyTip*(zmq: var ZmqNotificationInterface, blockHash: BlockHash,
                isInitialDownload: bool = false) =
  ## Called when the chain tip is updated
  ## Notifies hashblock, rawblock, and sequence (block connect)
  ## Skip during initial block download
  if isInitialDownload:
    return

  zmq.notifyBlock(blockHash)
  zmq.notifyRawBlock(blockHash)
  zmq.notifyBlockConnect(blockHash)

proc notifyBlockConnected*(zmq: var ZmqNotificationInterface, blk: Block,
                            blockHash: BlockHash, isInitialDownload: bool = false) =
  ## Called when a block is connected to the chain
  ## Notifies all transactions in the block, then block connect
  if isInitialDownload:
    return

  # Notify all transactions in the block
  for tx in blk.txs:
    zmq.notifyTransaction(tx)
    zmq.notifyRawTransaction(tx)

  # Notify block events
  zmq.notifyBlock(blockHash)
  zmq.notifyRawBlock(blockHash)
  zmq.notifyBlockConnect(blockHash)

proc notifyBlockDisconnected*(zmq: var ZmqNotificationInterface, blk: Block,
                               blockHash: BlockHash) =
  ## Called when a block is disconnected (reorg)
  ## Notifies transactions (re-entered mempool) and block disconnect
  for tx in blk.txs:
    zmq.notifyTransaction(tx)
    zmq.notifyRawTransaction(tx)

  zmq.notifyBlockDisconnect(blockHash)

proc notifyMempoolAccept*(zmq: var ZmqNotificationInterface, tx: Transaction,
                          mempoolSequence: uint64) =
  ## Called when a transaction is accepted to mempool
  zmq.notifyTransaction(tx)
  zmq.notifyRawTransaction(tx)
  zmq.notifyTransactionAcceptance(tx, mempoolSequence)

proc notifyMempoolRemove*(zmq: var ZmqNotificationInterface, tx: Transaction,
                          mempoolSequence: uint64) =
  ## Called when a transaction is removed from mempool (not due to block inclusion)
  zmq.notifyTransactionRemoval(tx, mempoolSequence)
