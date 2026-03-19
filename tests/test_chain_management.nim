## Chain Management tests
## Tests invalidateblock, reconsiderblock, and preciousblock functionality

import unittest2
import std/[os, options, strutils, tables]
import ../src/storage/[db, chainstate]
import ../src/consensus/[params, chain]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

const TestDbPath = "/tmp/nimrod_chain_mgmt_test"

proc cleanupTestDb() =
  if dirExists(TestDbPath):
    removeDir(TestDbPath)

proc makeTestTransaction(
  prevTxid: TxId,
  prevVout: uint32,
  value: int64,
  isCoinbase: bool = false,
  height: int32 = 0
): Transaction =
  ## Create a simple test transaction
  if isCoinbase:
    # BIP34: coinbase must include block height
    var scriptSig: seq[byte]
    if height == 0:
      scriptSig = @[byte(0x01), 0x00]  # Height 0
    elif height <= 0x7f:
      scriptSig = @[byte(0x01), byte(height)]
    elif height <= 0x7fff:
      scriptSig = @[byte(0x02), byte(height and 0xff), byte((height shr 8) and 0xff)]
    else:
      scriptSig = @[byte(0x03), byte(height and 0xff), byte((height shr 8) and 0xff), byte((height shr 16) and 0xff)]

    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),
          vout: 0xFFFFFFFF'u32
        ),
        scriptSig: scriptSig,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x76), 0xa9, 0x14] & @(array[20, byte](default(array[20, byte]))) & @[byte(0x88), 0xac]
      )],
      witnesses: @[],
      lockTime: 0
    )
  else:
    result = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: prevTxid, vout: prevVout),
        scriptSig: @[byte(0x00)],
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(
        value: Satoshi(value),
        scriptPubKey: @[byte(0x00), 0x14] & @(array[20, byte](default(array[20, byte])))
      )],
      witnesses: @[],
      lockTime: 0
    )

proc merkleRoot(txHashes: seq[array[32, byte]]): array[32, byte] =
  ## Simple merkle root computation
  if txHashes.len == 0:
    return default(array[32, byte])
  if txHashes.len == 1:
    return txHashes[0]

  var level = txHashes
  while level.len > 1:
    var nextLevel: seq[array[32, byte]]
    var i = 0
    while i < level.len:
      var combined: array[64, byte]
      copyMem(addr combined[0], unsafeAddr level[i][0], 32)
      if i + 1 < level.len:
        copyMem(addr combined[32], unsafeAddr level[i + 1][0], 32)
      else:
        copyMem(addr combined[32], unsafeAddr level[i][0], 32)
      nextLevel.add(doubleSha256(combined))
      i += 2
    level = nextLevel

  result = level[0]

proc makeTestBlock(prevHash: BlockHash, height: int32, txs: seq[Transaction]): Block =
  ## Create a test block with the given transactions
  var txHashes: seq[array[32, byte]]
  for tx in txs:
    txHashes.add(array[32, byte](tx.txid()))

  result = Block(
    header: BlockHeader(
      version: 1,
      prevBlock: prevHash,
      merkleRoot: merkleRoot(txHashes),
      timestamp: 1231006505 + uint32(height * 600),
      bits: 0x207fffff'u32,  # Regtest difficulty
      nonce: uint32(height)
    ),
    txs: txs
  )

proc makeSimpleBlock(prevHash: BlockHash, height: int32): Block =
  ## Create a simple block with just a coinbase
  let coinbase = makeTestTransaction(TxId(default(array[32, byte])), 0, 5000000000, true, height)
  makeTestBlock(prevHash, height, @[coinbase])

proc getBlockHash(blk: Block): BlockHash =
  let headerBytes = serialize(blk.header)
  BlockHash(doubleSha256(headerBytes))

suite "invalidateblock":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "cannot invalidate genesis block":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Connect genesis block
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    let connectResult = cs.connectBlock(genesis, 0)
    check connectResult.isOk

    # Try to invalidate genesis - should fail
    let result = cs.invalidateBlock(genesisHash)
    check not result.isOk
    check result.error == cmeCannotInvalidateGenesis

  test "invalidate block not on active chain":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Build a chain: genesis -> block1
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    discard cs.connectBlock(genesis, 0)

    let block1 = makeSimpleBlock(genesisHash, 1)
    let block1Hash = getBlockHash(block1)
    discard cs.connectBlock(block1, 1)

    check cs.bestHeight == 1
    check cs.bestBlockHash == block1Hash

    # Create an alternative block at height 1 (not connected to chain)
    # This simulates a fork that never became the main chain
    var altBlock = makeSimpleBlock(genesisHash, 1)
    altBlock.header.nonce = 99999  # Different nonce = different hash
    let altBlockHash = getBlockHash(altBlock)

    # Store the alt block in the index but don't update the height->hash mapping
    # (it's a known block but not on the active chain)
    # We use db.db.put directly to avoid overwriting the active chain's height mapping
    let altIdx = BlockIndex(
      hash: altBlockHash,
      height: 1,
      status: bsValidated,
      prevHash: genesisHash,
      header: altBlock.header,
      totalWork: default(array[32, byte]),
      failureFlags: BLOCK_NO_FAILURE,
      sequenceId: 0
    )
    # Only store by hash, NOT by height (this keeps the active chain mapping intact)
    var w = BinaryWriter()
    w.writeBlockHash(altIdx.hash)
    w.writeInt32LE(altIdx.height)
    w.writeUint8(uint8(ord(altIdx.status)))
    w.writeBlockHash(altIdx.prevHash)
    w.writeBlockHeader(altIdx.header)
    w.writeBytes(altIdx.totalWork)
    w.writeInt32LE(altIdx.undoPos.fileNum)
    w.writeInt32LE(altIdx.undoPos.pos)
    w.writeUint8(uint8(altIdx.failureFlags))
    w.writeInt32LE(altIdx.sequenceId)
    cs.db.db.put(cfBlockIndex, blockKey(array[32, byte](altBlockHash)), w.data)

    # Verify the active chain height->hash mapping is still block1
    let heightHash = cs.db.getBlockHashByHeight(1)
    check heightHash.isSome
    check heightHash.get() == block1Hash

    # Invalidate the alt block (not on active chain)
    let result = cs.invalidateBlock(altBlockHash)
    check result.isOk

    # Check it's marked as invalid
    let flagsOpt = cs.getBlockFailureStatus(altBlockHash)
    check flagsOpt.isSome
    check flagsOpt.get().hasFlag(BLOCK_FAILED_VALID)

    # Active chain should be unchanged (still at block1)
    check cs.bestHeight == 1
    check cs.bestBlockHash == block1Hash

  test "invalidate block on active chain disconnects it":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Build a chain: genesis -> block1 -> block2
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    discard cs.connectBlock(genesis, 0)

    let block1 = makeSimpleBlock(genesisHash, 1)
    let block1Hash = getBlockHash(block1)
    discard cs.connectBlock(block1, 1)

    let block2 = makeSimpleBlock(block1Hash, 2)
    let block2Hash = getBlockHash(block2)
    discard cs.connectBlock(block2, 2)

    check cs.bestHeight == 2
    check cs.bestBlockHash == block2Hash

    # Invalidate block1 - should disconnect both block1 and block2
    let result = cs.invalidateBlock(block1Hash)
    check result.isOk

    # Chain should be rewound to genesis
    check cs.bestHeight == 0
    check cs.bestBlockHash == genesisHash

    # Both block1 and block2 should be marked as invalid
    let flags1 = cs.getBlockFailureStatus(block1Hash)
    check flags1.isSome
    check flags1.get().hasFlag(BLOCK_FAILED_VALID)

  test "invalidate non-existent block fails":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    let fakeHash = BlockHash(default(array[32, byte]))
    let result = cs.invalidateBlock(fakeHash)
    check not result.isOk
    check result.error == cmeBlockNotFound

suite "reconsiderblock":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "reconsider clears failure flags":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Build a chain: genesis -> block1
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    discard cs.connectBlock(genesis, 0)

    let block1 = makeSimpleBlock(genesisHash, 1)
    let block1Hash = getBlockHash(block1)
    discard cs.connectBlock(block1, 1)

    # Invalidate block1
    let invalidateResult = cs.invalidateBlock(block1Hash)
    check invalidateResult.isOk

    # Verify it's invalid
    var flags = cs.getBlockFailureStatus(block1Hash)
    check flags.isSome
    check flags.get().hasFlag(BLOCK_FAILED_VALID)

    # Reconsider block1
    let reconsiderResult = cs.reconsiderBlock(block1Hash)
    check reconsiderResult.isOk

    # Verify flags are cleared
    flags = cs.getBlockFailureStatus(block1Hash)
    check flags.isSome
    check not flags.get().isFailed()

  test "reconsider non-existent block fails":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    let fakeHash = BlockHash(default(array[32, byte]))
    let result = cs.reconsiderBlock(fakeHash)
    check not result.isOk
    check result.error == cmeBlockNotFound

suite "preciousblock":
  setup:
    cleanupTestDb()

  teardown:
    cleanupTestDb()

  test "precious block sets negative sequence ID":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Build a chain: genesis -> block1
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    discard cs.connectBlock(genesis, 0)

    let block1 = makeSimpleBlock(genesisHash, 1)
    let block1Hash = getBlockHash(block1)
    discard cs.connectBlock(block1, 1)

    # Check initial sequence ID
    var idx = cs.db.getBlockIndex(block1Hash).get()
    check idx.sequenceId == 0

    # Mark as precious
    let result = cs.preciousBlock(block1Hash)
    check result.isOk

    # Check sequence ID is now negative
    idx = cs.db.getBlockIndex(block1Hash).get()
    check idx.sequenceId < 0

  test "multiple precious calls decrement sequence ID":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    # Build a chain: genesis -> block1 -> block2
    let genesis = makeSimpleBlock(BlockHash(default(array[32, byte])), 0)
    let genesisHash = getBlockHash(genesis)
    discard cs.connectBlock(genesis, 0)

    let block1 = makeSimpleBlock(genesisHash, 1)
    let block1Hash = getBlockHash(block1)
    discard cs.connectBlock(block1, 1)

    let block2 = makeSimpleBlock(block1Hash, 2)
    let block2Hash = getBlockHash(block2)
    discard cs.connectBlock(block2, 2)

    # Mark block1 as precious
    discard cs.preciousBlock(block1Hash)
    var idx1 = cs.db.getBlockIndex(block1Hash).get()
    let seqId1 = idx1.sequenceId

    # Mark block2 as precious
    discard cs.preciousBlock(block2Hash)
    var idx2 = cs.db.getBlockIndex(block2Hash).get()
    let seqId2 = idx2.sequenceId

    # block2's sequence ID should be even lower (more precious)
    check seqId2 < seqId1

  test "precious non-existent block fails":
    var cs = newChainState(TestDbPath, regtestParams())
    defer: cs.close()

    let fakeHash = BlockHash(default(array[32, byte]))
    let result = cs.preciousBlock(fakeHash)
    check not result.isOk
    check result.error == cmeBlockNotFound

suite "BlockFailureFlags":
  test "flag operations":
    var flags = BLOCK_NO_FAILURE

    check not flags.isFailed()
    check not flags.hasFlag(BLOCK_FAILED_VALID)
    check not flags.hasFlag(BLOCK_FAILED_CHILD)

    flags.setFlag(BLOCK_FAILED_VALID)
    check flags.isFailed()
    check flags.hasFlag(BLOCK_FAILED_VALID)
    check not flags.hasFlag(BLOCK_FAILED_CHILD)

    flags.setFlag(BLOCK_FAILED_CHILD)
    check flags.hasFlag(BLOCK_FAILED_VALID)
    check flags.hasFlag(BLOCK_FAILED_CHILD)

    flags.clearFlag(BLOCK_FAILED_VALID)
    check flags.isFailed()  # Still has FAILED_CHILD
    check not flags.hasFlag(BLOCK_FAILED_VALID)
    check flags.hasFlag(BLOCK_FAILED_CHILD)

    flags.clearFlag(BLOCK_FAILED_CHILD)
    check not flags.isFailed()
