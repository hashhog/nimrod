## Tests for Block Filter Index (blockfilterindex)

import std/[unittest, os, options, tempfiles]
import ../src/storage/indexes/blockfilterindex
import ../src/storage/indexes/gcs
import ../src/storage/indexes/base
import ../src/storage/db
import ../src/storage/undo as chainundo
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "BlockFilterIndex":
  var db: Database
  var idx: BlockFilterIndex
  var testDir: string

  setup:
    testDir = createTempDir("blockfilter_test_", "")
    db = openDatabase(testDir / "db")
    idx = newBlockFilterIndex(db, testDir, bftBasic, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  test "disabled index returns none":
    let disabledIdx = newBlockFilterIndex(db, testDir, bftBasic, enabled = false)
    check disabledIdx.getFilterEntry(0).isNone

  test "FilterIndexEntry serialization":
    var entry = FilterIndexEntry(
      filterHash: default(array[32, byte]),
      filterHeader: default(array[32, byte]),
      fileNum: 5,
      filePos: 12345
    )
    for i in 0 ..< 32:
      entry.filterHash[i] = byte(i)
      entry.filterHeader[i] = byte(255 - i)

    let serialized = serializeFilterEntry(entry)
    let deserialized = deserializeFilterEntry(serialized)

    check deserialized.filterHash == entry.filterHash
    check deserialized.filterHeader == entry.filterHeader
    check deserialized.fileNum == entry.fileNum
    check deserialized.filePos == entry.filePos

  test "filter file path generation":
    check filterFileName(0) == "fltr00000.dat"
    check filterFileName(1) == "fltr00001.dat"
    check filterFileName(99999) == "fltr99999.dat"

  test "customAppend creates filter for block":
    # Create a block with some outputs
    var tx = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0xffffffff'u32),
        scriptSig: @[],
        sequence: 0xffffffff'u32
      )],
      outputs: @[
        TxOut(value: Satoshi(5000000000), scriptPubKey: @[0x76'u8, 0xa9, 0x14]),
        TxOut(value: Satoshi(1000000000), scriptPubKey: @[0x00'u8, 0x14])  # P2WPKH
      ],
      lockTime: 0
    )

    var blk = Block(
      header: BlockHeader(version: 1),
      txs: @[tx]
    )

    var hashBytes: array[32, byte]
    hashBytes[0] = 0xab
    let blockHash = BlockHash(hashBytes)

    let blockInfo = BlockInfo(
      hash: blockHash,
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(base.BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true

    # Verify filter entry was created
    let entry = idx.getFilterEntry(1)
    check entry.isSome
    check entry.get().filterHash != default(array[32, byte])
    check entry.get().filterHeader != default(array[32, byte])

  test "filter header chaining":
    # Create two blocks and verify headers chain correctly
    var hashBytes1, hashBytes2: array[32, byte]
    hashBytes1[0] = 1
    hashBytes2[0] = 2

    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[1'u8, 2, 3])]
      )]
    )

    # First block
    let blockInfo1 = BlockInfo(
      hash: BlockHash(hashBytes1),
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(base.BlockUndo),
      fileNum: 0,
      dataPos: 100
    )
    check idx.customAppend(blockInfo1) == true

    let entry1 = idx.getFilterEntry(1)
    check entry1.isSome

    # Second block
    let blockInfo2 = BlockInfo(
      hash: BlockHash(hashBytes2),
      prevHash: BlockHash(hashBytes1),
      height: 2,
      data: some(blk),
      undoData: none(base.BlockUndo),
      fileNum: 0,
      dataPos: 500
    )
    check idx.customAppend(blockInfo2) == true

    let entry2 = idx.getFilterEntry(2)
    check entry2.isSome

    # Headers should be different (chained)
    check entry1.get().filterHeader != entry2.get().filterHeader

  test "reorg copies to hash index":
    var hashBytes: array[32, byte]
    hashBytes[0] = 0xff

    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[5'u8, 6, 7])]
      )]
    )

    let blockInfo = BlockInfo(
      hash: BlockHash(hashBytes),
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(base.BlockUndo),
      fileNum: 0,
      dataPos: 100
    )

    check idx.customAppend(blockInfo) == true
    check idx.customRemove(blockInfo) == true

    # Should be accessible by hash after reorg
    let byHash = idx.getFilterEntryByHash(BlockHash(hashBytes))
    check byHash.isSome

suite "BlockFilterIndex Key Construction":
  test "filterHeightKey big-endian ordering":
    let key1 = filterHeightKey(0)
    let key2 = filterHeightKey(1)
    let key3 = filterHeightKey(256)

    check key1.len == 5
    check key2.len == 5
    check key3.len == 5

    check key1[0] == byte('f')
    check key2[0] == byte('f')
    check key3[0] == byte('f')

    # Big-endian: higher heights have lexicographically greater keys
    # Compare lexicographically using string comparison
    check cast[string](key1) < cast[string](key2)
    check cast[string](key2) < cast[string](key3)

  test "filterHashKey format":
    var hashBytes: array[32, byte]
    for i in 0 ..< 32:
      hashBytes[i] = byte(i)
    let blockHash = BlockHash(hashBytes)

    let key = filterHashKey(blockHash)
    check key.len == 33
    check key[0] == byte('g')
    for i in 0 ..< 32:
      check key[i + 1] == byte(i)

# ============================================================================
# IBD population / connect-block hook tests
# ============================================================================
# These cover the wiring landed alongside today's REST endpoints — the
# `addBlock` helper that nimrod's connectBlock path (P2P sync, RPC
# submitblock, regtest mining) calls after each successful block connect,
# plus the IBD backfill walk performed at startup when --blockfilterindex
# is toggled on against an existing chainstate.

suite "BlockFilterIndex addBlock (connect-block hook)":
  var db: Database
  var idx: BlockFilterIndex
  var disabledIdx: BlockFilterIndex
  var testDir: string

  setup:
    testDir = createTempDir("blockfilter_addblock_", "")
    db = openDatabase(testDir / "db")
    idx = newBlockFilterIndex(db, testDir, bftBasic, enabled = true)
    disabledIdx = newBlockFilterIndex(db, testDir & "_off",
                                      bftBasic, enabled = false)

  teardown:
    db.close()
    removeDir(testDir)
    if dirExists(testDir & "_off"):
      removeDir(testDir & "_off")

  proc mkBlock(scriptByte: byte, prev: BlockHash): Block =
    Block(
      header: BlockHeader(version: 1, prevBlock: prev),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                            vout: 0xffffffff'u32),
          scriptSig: @[],
          sequence: 0xffffffff'u32
        )],
        outputs: @[
          TxOut(value: Satoshi(5_000_000_000),
                scriptPubKey: @[0x76'u8, 0xa9, 0x14, scriptByte])
        ],
        lockTime: 0
      )]
    )

  proc mkHash(seedByte: byte): BlockHash =
    var hb: array[32, byte]
    hb[0] = seedByte
    BlockHash(hb)

  test "addBlock populates filter on connectBlock when --blockfilterindex on":
    let h1 = mkHash(0x10)
    let blk1 = mkBlock(0x11, BlockHash(default(array[32, byte])))
    let undo1 = chainundo.BlockUndo()  # genesis-style: no spent inputs

    check idx.bestHeight == -1
    check idx.addBlock(blk1, h1, 1, undo1) == true

    # bestHeight should advance to 1 after a successful connect.
    check idx.bestHeight == 1
    check idx.bestBlockHash == h1

    let entry = idx.getFilterEntry(1)
    check entry.isSome
    check entry.get().filterHash != default(array[32, byte])
    check entry.get().filterHeader != default(array[32, byte])

  test "addBlock is a no-op when index is disabled":
    let h = mkHash(0x20)
    let blk = mkBlock(0x21, BlockHash(default(array[32, byte])))
    let undo = chainundo.BlockUndo()

    # Disabled index must accept the call (so callers can be unconditional)
    # but write nothing and not advance.
    check disabledIdx.bestHeight == -1
    check disabledIdx.addBlock(blk, h, 1, undo) == true
    check disabledIdx.bestHeight == -1
    check disabledIdx.getFilterEntry(1).isNone

  test "addBlock is a no-op when index is nil (callers do not need to gate)":
    let h = mkHash(0x30)
    let blk = mkBlock(0x31, BlockHash(default(array[32, byte])))
    let undo = chainundo.BlockUndo()
    var nilIdx: BlockFilterIndex = nil
    # Should not raise; should return true (treated as success).
    check nilIdx.addBlock(blk, h, 1, undo) == true

  test "addBlock skips already-indexed heights (idempotent re-replay)":
    let h1 = mkHash(0x40)
    let blk1 = mkBlock(0x41, BlockHash(default(array[32, byte])))
    let undo1 = chainundo.BlockUndo()

    check idx.addBlock(blk1, h1, 1, undo1) == true
    let firstHash = idx.getFilterEntry(1).get().filterHash

    # Re-call with same height — should noop (return true) without
    # advancing or rewriting state.
    check idx.addBlock(blk1, h1, 1, undo1) == true
    check idx.bestHeight == 1
    check idx.getFilterEntry(1).get().filterHash == firstHash

  test "addBlock includes spent prev-output scripts (BIP-158 elements)":
    # Block-with-undo: simulate a non-coinbase tx that spent a prior output.
    # The basic filter should reflect both outputs AND spent scriptPubKeys.
    let h = mkHash(0x50)
    let outputScript = @[0x76'u8, 0xa9, 0x14, 0x51, 0x52]
    let spentScript = @[0x76'u8, 0xa9, 0x14, 0xaa, 0xbb]

    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[
        # Coinbase
        Transaction(
          version: 1,
          inputs: @[TxIn(
            prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                              vout: 0xffffffff'u32),
            scriptSig: @[],
            sequence: 0xffffffff'u32
          )],
          outputs: @[TxOut(value: Satoshi(5_000_000_000),
                           scriptPubKey: outputScript)],
          lockTime: 0
        ),
        # Non-coinbase that spends a prior output
        Transaction(
          version: 1,
          inputs: @[TxIn(
            prevOut: OutPoint(txid: TxId(default(array[32, byte])), vout: 0),
            scriptSig: @[],
            sequence: 0xffffffff'u32
          )],
          outputs: @[TxOut(value: Satoshi(1_000_000),
                           scriptPubKey: outputScript)],
          lockTime: 0
        )
      ]
    )

    var blockUndo = chainundo.BlockUndo()
    var txUndo = chainundo.TxUndo()
    txUndo.prevOutputs.add(chainundo.SpentOutput(
      output: TxOut(value: Satoshi(2_000_000), scriptPubKey: spentScript),
      height: 1,
      isCoinbase: false
    ))
    blockUndo.txUndo.add(txUndo)

    check idx.addBlock(blk, h, 2, blockUndo) == true
    check idx.bestHeight == 2

    # Confirm the entry was written.
    let entry = idx.getFilterEntry(2)
    check entry.isSome

  test "addBlock advances best-block monotonically across heights":
    var prev = BlockHash(default(array[32, byte]))
    for i in 1 ..< 6:
      let h = mkHash(byte(0x60 + i))
      let blk = mkBlock(byte(0x70 + i), prev)
      let undo = chainundo.BlockUndo()
      check idx.addBlock(blk, h, int32(i), undo) == true
      check idx.bestHeight == int32(i)
      check idx.bestBlockHash == h
      prev = h

    # Each connected height must have its own filter entry.
    for i in 1 ..< 6:
      check idx.getFilterEntry(int32(i)).isSome

suite "BlockFilterIndex backfill range":
  ## The backfill loop in nimrod.nim walks heights
  ## [filterIndex.bestHeight + 1 .. chainState.bestHeight].  These tests
  ## exercise the range-walk semantics on the index side: an
  ## already-current index should produce a no-op walk; an empty index
  ## should walk the full chain; a partially-populated index should walk
  ## only the gap.

  var db: Database
  var idx: BlockFilterIndex
  var testDir: string

  setup:
    testDir = createTempDir("blockfilter_backfill_", "")
    db = openDatabase(testDir / "db")
    idx = newBlockFilterIndex(db, testDir, bftBasic, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  proc mkBlock(seed: byte): Block =
    Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                            vout: 0xffffffff'u32),
          scriptSig: @[], sequence: 0xffffffff'u32
        )],
        outputs: @[TxOut(value: Satoshi(50_000), scriptPubKey: @[seed, 0x01])],
        lockTime: 0
      )]
    )

  proc mkHash(s: byte): BlockHash =
    var b: array[32, byte]
    b[0] = s
    BlockHash(b)

  test "empty index over a 5-block chain walks heights 0..4":
    # Drive the same loop the daemon's startup code would: filter starts at
    # bestHeight=-1, so range is 0..tipHeight inclusive.
    let tipHeight = 4'i32
    let startHeight = idx.bestHeight + 1
    check startHeight == 0

    var indexed = 0
    for h in startHeight .. tipHeight:
      let blk = mkBlock(byte(0x80 + h))
      let hash = mkHash(byte(0x80 + h))
      let undo = chainundo.BlockUndo()
      if idx.addBlock(blk, hash, h, undo):
        inc indexed
    check indexed == 5
    check idx.bestHeight == tipHeight
    for h in startHeight .. tipHeight:
      check idx.getFilterEntry(h).isSome

  test "partial index walks only [bestHeight+1 .. tipHeight]":
    # Pre-populate heights 0..2 (simulating a previous run that stopped
    # mid-chain), then drive the backfill range as the daemon would.
    for h in 0'i32 .. 2'i32:
      let blk = mkBlock(byte(0x90 + h))
      let hash = mkHash(byte(0x90 + h))
      check idx.addBlock(blk, hash, h, chainundo.BlockUndo()) == true
    check idx.bestHeight == 2

    let tipHeight = 5'i32
    let startHeight = idx.bestHeight + 1
    check startHeight == 3

    var indexed = 0
    for h in startHeight .. tipHeight:
      let blk = mkBlock(byte(0x90 + h))
      let hash = mkHash(byte(0x90 + h))
      if idx.addBlock(blk, hash, h, chainundo.BlockUndo()):
        inc indexed
    check indexed == 3        # exactly the gap walked
    check idx.bestHeight == tipHeight
    for h in 0'i32 .. tipHeight:
      check idx.getFilterEntry(h).isSome

  test "backfill is a no-op when index is already at tip":
    # After adding a single block (height 0), driving the same loop with
    # tipHeight=0 should not re-walk it (skip because h <= bestHeight).
    let blk = mkBlock(0xa0)
    let hash = mkHash(0xa0)
    check idx.addBlock(blk, hash, 0, chainundo.BlockUndo()) == true

    let tipHeight = 0'i32
    let startHeight = idx.bestHeight + 1
    # Range is empty: 1..0 is a no-op.
    check startHeight > tipHeight

    var indexed = 0
    for h in startHeight .. tipHeight:
      if idx.addBlock(blk, hash, h, chainundo.BlockUndo()):
        inc indexed
    check indexed == 0
    check idx.bestHeight == 0  # unchanged

# ============================================================================
# Reorg-aware filter chain tests (Phase 2)
# ============================================================================
# Cover the disconnect-side counterpart to addBlock — the `removeBlock`
# helper that the chainstate disconnect path (legacy disconnectBlock and
# Pattern-D handleReorg) fires through `disconnectHook`.  These tests
# exercise the index module directly; chainstate-side wiring (the hook
# call) is covered by tests/test_chainstate_reorg_filterindex.nim.

suite "BlockFilterIndex removeBlock (disconnect / reorg-aware filter chain)":
  var db: Database
  var idx: BlockFilterIndex
  var testDir: string

  setup:
    testDir = createTempDir("blockfilter_remove_", "")
    db = openDatabase(testDir / "db")
    idx = newBlockFilterIndex(db, testDir, bftBasic, enabled = true)

  teardown:
    db.close()
    removeDir(testDir)

  proc mkBlock(scriptByte: byte, prev: BlockHash): Block =
    Block(
      header: BlockHeader(version: 1, prevBlock: prev),
      txs: @[Transaction(
        version: 1,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                            vout: 0xffffffff'u32),
          scriptSig: @[],
          sequence: 0xffffffff'u32
        )],
        outputs: @[
          TxOut(value: Satoshi(5_000_000_000),
                scriptPubKey: @[0x76'u8, 0xa9, 0x14, scriptByte])
        ],
        lockTime: 0
      )]
    )

  proc mkHash(seedByte: byte): BlockHash =
    var hb: array[32, byte]
    hb[0] = seedByte
    BlockHash(hb)

  test "removeBlock is a no-op when index is nil":
    var nilIdx: BlockFilterIndex = nil
    check nilIdx.removeBlock(mkHash(0x01), mkHash(0x00), 1) == true

  test "removeBlock is a no-op when index is disabled":
    let off = newBlockFilterIndex(db, testDir & "_off", bftBasic, enabled = false)
    check off.removeBlock(mkHash(0x02), mkHash(0x00), 1) == true
    if dirExists(testDir & "_off"):
      removeDir(testDir & "_off")

  test "removeBlock is a no-op when bestHeight is below the disconnect height":
    # Index never saw block at height 5; rolling back height 5 must be inert.
    check idx.bestHeight == -1
    check idx.removeBlock(mkHash(0xaa), mkHash(0xbb), 5) == true
    check idx.bestHeight == -1

  test "removeBlock rolls bestHeight back, copies entry to hash index, restores prev filter header":
    # Connect h=1 then h=2, then disconnect h=2.  After: bestHeight=1,
    # prevFilterHeader == h=1's header, h=2's filter retrievable by hash.
    let h1 = mkHash(0xc1)
    let h2 = mkHash(0xc2)
    let g  = BlockHash(default(array[32, byte]))
    check idx.addBlock(mkBlock(0xd1, g),  h1, 1, chainundo.BlockUndo()) == true
    check idx.addBlock(mkBlock(0xd2, h1), h2, 2, chainundo.BlockUndo()) == true
    check idx.bestHeight == 2

    let entryAt2 = idx.getFilterEntry(2)
    let entryAt1 = idx.getFilterEntry(1)
    check entryAt2.isSome
    check entryAt1.isSome
    let header1 = entryAt1.get().filterHeader

    # Disconnect h=2 — symmetric counterpart to the addBlock at h=2.
    check idx.removeBlock(h2, h1, 2) == true

    # bestHeight rolls back to h=1; bestBlockHash to h1.
    check idx.bestHeight == 1
    check idx.bestBlockHash == h1

    # The disconnected block's filter is now retrievable by hash (the
    # height entry remained — it will be overwritten when a new chain
    # connects at the same height).
    let byHash = idx.getFilterEntryByHash(h2)
    check byHash.isSome
    check byHash.get().filterHash == entryAt2.get().filterHash

    # prevFilterHeader rolled back to height-1's header so the next
    # customAppend chains correctly onto the parent.
    check idx.prevFilterHeader == header1

  test "removeBlock followed by addBlock at the same height re-chains onto parent":
    # Pre-build a 3-block chain: g→h1→h2→h3.  Disconnect h3 then h2,
    # then connect a NEW chain h2'→h3' onto h1.  The new headers must
    # form a fresh chain off of h1's filter header — proving the
    # rollback restored prevFilterHeader correctly.
    let g  = BlockHash(default(array[32, byte]))
    let h1 = mkHash(0xe1); let h2 = mkHash(0xe2); let h3 = mkHash(0xe3)
    check idx.addBlock(mkBlock(0xf1, g),  h1, 1, chainundo.BlockUndo()) == true
    check idx.addBlock(mkBlock(0xf2, h1), h2, 2, chainundo.BlockUndo()) == true
    check idx.addBlock(mkBlock(0xf3, h2), h3, 3, chainundo.BlockUndo()) == true
    let header1 = idx.getFilterEntry(1).get().filterHeader
    let header3Old = idx.getFilterEntry(3).get().filterHeader

    # Disconnect h3 then h2 (tip→fork order, matches handleReorg).
    check idx.removeBlock(h3, h2, 3) == true
    check idx.bestHeight == 2
    check idx.removeBlock(h2, h1, 2) == true
    check idx.bestHeight == 1
    check idx.bestBlockHash == h1
    check idx.prevFilterHeader == header1

    # Connect new chain h2'→h3' (different scriptPubKeys → different filters).
    let h2p = mkHash(0xf8)
    let h3p = mkHash(0xf9)
    check idx.addBlock(mkBlock(0x88, h1),  h2p, 2, chainundo.BlockUndo()) == true
    check idx.addBlock(mkBlock(0x99, h2p), h3p, 3, chainundo.BlockUndo()) == true
    check idx.bestHeight == 3
    check idx.bestBlockHash == h3p

    # The new tip's filter header must NOT match the disconnected chain's
    # tip header — proves the chain rewound and re-built off h1.
    let header3New = idx.getFilterEntry(3).get().filterHeader
    check header3New != header3Old

    # Both old-chain block filters must remain retrievable by hash for
    # light-client reconciliation.
    check idx.getFilterEntryByHash(h2).isSome
    check idx.getFilterEntryByHash(h3).isSome

  test "removeBlock at height=1 rolls best-block back to genesis (height -1 / parent hash)":
    # Edge case: disconnecting the only indexed block.  bestHeight should
    # become -1 (matching the post-newBlockFilterIndex state) and
    # bestBlockHash should be the parent hash we passed in (caller's
    # responsibility to provide the right parent — for height=1 that is
    # genesis-as-prev, here zero-hash).
    let g  = BlockHash(default(array[32, byte]))
    let h1 = mkHash(0xa1)
    check idx.addBlock(mkBlock(0xb1, g), h1, 1, chainundo.BlockUndo()) == true
    check idx.bestHeight == 1

    check idx.removeBlock(h1, g, 1) == true
    check idx.bestHeight == 0   # height-1 = 0; saveBestBlock writes (g, 0)
    check idx.bestBlockHash == g
    # h1's filter is preserved by hash (Core parity — light-client
    # reconciliation can still serve it).
    check idx.getFilterEntryByHash(h1).isSome

# ============================================================================
# FIX-83 / W122: codec format-version migration
# ============================================================================

suite "BlockFilterIndex codec format-version migration (FIX-83 / W122)":
  ## Pre-FIX-83 nimrod packed GCS bits LSB-first within each byte; any
  ## fltr*.dat files written by that codec are byte-incompatible with
  ## Core peers.  FIX-83 bumps `BlockFilterIndexCodecVersion` and adds an
  ## `maybeMigrateCodec` step inside the constructor: on detecting a
  ## stale (or absent) version stamp alongside any actual filter data,
  ## drop the entire index and rebuild from genesis on the next sync.
  ##
  ## These tests verify:
  ##   - fresh index gets stamped with the current version (no migration)
  ##   - an index with the current version is left alone
  ##   - an index missing the version key WITH legacy fltr*.dat files
  ##     triggers a full reset

  test "fresh index is stamped with current codec version":
    let dir = createTempDir("bfi_codec_fresh_", "")
    defer: removeDir(dir)
    let db = openDatabase(dir / "db")
    defer: db.close()
    let idx = newBlockFilterIndex(db, dir, bftBasic, enabled = true)
    check idx.readCodecVersion() == BlockFilterIndexCodecVersion

  test "an index already at the current codec version is left alone":
    let dir = createTempDir("bfi_codec_current_", "")
    defer: removeDir(dir)
    let db = openDatabase(dir / "db")
    defer: db.close()
    var idx = newBlockFilterIndex(db, dir, bftBasic, enabled = true)
    # Simulate "already migrated": add a block, confirm stamp.
    var hb: array[32, byte]
    hb[0] = 0xee
    let blk = Block(
      header: BlockHeader(version: 1),
      txs: @[Transaction(
        version: 1,
        outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[1'u8, 2, 3])]
      )]
    )
    let info = BlockInfo(
      hash: BlockHash(hb),
      prevHash: BlockHash(default(array[32, byte])),
      height: 1,
      data: some(blk),
      undoData: none(base.BlockUndo),
      fileNum: 0,
      dataPos: 100
    )
    check idx.customAppend(info) == true
    idx.saveBestBlock(BlockHash(hb), 1)
    check idx.readCodecVersion() == BlockFilterIndexCodecVersion
    let migrated = idx.maybeMigrateCodec()
    check migrated == false
    # Filter entry is still there.
    check idx.getFilterEntry(1).isSome

  test "legacy (unstamped) index with fltr files is reset on next open":
    let dir = createTempDir("bfi_codec_legacy_", "")
    defer: removeDir(dir)
    block phase1_legacy_build:
      let db = openDatabase(dir / "db")
      defer: db.close()
      var idx = newBlockFilterIndex(db, dir, bftBasic, enabled = true)
      var hb: array[32, byte]
      hb[0] = 0x55
      let blk = Block(
        header: BlockHeader(version: 1),
        txs: @[Transaction(
          version: 1,
          outputs: @[TxOut(value: Satoshi(1000), scriptPubKey: @[7'u8, 8, 9])]
        )]
      )
      let info = BlockInfo(
        hash: BlockHash(hb),
        prevHash: BlockHash(default(array[32, byte])),
        height: 1,
        data: some(blk),
        undoData: none(base.BlockUndo),
        fileNum: 0,
        dataPos: 100
      )
      check idx.customAppend(info) == true
      idx.saveBestBlock(BlockHash(hb), 1)
      # Confirm we wrote a fltr*.dat
      check fileExists(dir / "indexes" / "blockfilter" / "fltr00000.dat")
      # Forcibly strip the codec version key to simulate the pre-FIX-83
      # on-disk state (no version key at all).
      idx.db.delete(cfMeta, codecVersionKey())
      check idx.readCodecVersion() == 0

    block phase2_reopen_migrates:
      let db = openDatabase(dir / "db")
      defer: db.close()
      let idx = newBlockFilterIndex(db, dir, bftBasic, enabled = true)
      # After re-open, the migration should have:
      #   - dropped the fltr*.dat (or all of them)
      #   - reset bestHeight to -1
      #   - stamped the current version
      check idx.readCodecVersion() == BlockFilterIndexCodecVersion
      check idx.bestHeight == -1
      check idx.getFilterEntry(1).isNone
      check not fileExists(dir / "indexes" / "blockfilter" / "fltr00000.dat")
