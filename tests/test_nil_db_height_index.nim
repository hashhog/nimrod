## Pin for the corpus-replay SIGSEGV (2026-08-27): getBlockHashByHeight passed
## a nil db handle straight into the RocksDB C API when queried with no
## persisted store (harness/offline contexts — the phaseb checkblock shim runs
## the REAL validateBlock, whose checkBip30 BIP-34 ancestor probe resolves
## through this proc; every post-227835 mainnet pack crashed the shim).
## An uncatchable SIGSEGV, so no try/except upstream could contain it.
## FAILS AT PARENT: this test process dies with SIGSEGV instead of asserting.
## The guard returns none(BlockHash) -> checkBip30 keeps BIP-30 ENFORCED
## (the documented conservative fail-safe).
import std/[options, tables]
import ../src/primitives/types
import ../src/storage/chainstate

proc main() =
  var cdb = ChainDb()           # no db handle, empty in-memory index
  doAssert cdb.db == nil
  let r = cdb.getBlockHashByHeight(227835'i32)
  doAssert r.isNone, "nil-db height lookup must report no-row, not crash"
  # In-memory IBD index still answers without a db.
  var h: array[32, byte]; h[0] = 0xAB
  cdb.ibdIndexByHeight[100'i32] = BlockHash(h)
  let r2 = cdb.getBlockHashByHeight(100'i32)
  doAssert r2.isSome and r2.get() == BlockHash(h)
  echo "nil-db height-index guard OK"

main()

## Companion pin (2026-08-28): getBlockIndex has the SAME nil-db hazard, and
## an unresolvable parent must TERMINATE an ancestor walk rather than spin.
## The corpus exposed this as a >150s hang on every difficulty-retarget
## boundary (packs 419328 / 481824 / 709632, all height %% 2016 == 0) where
## getNextWorkRequired walks back 2016 blocks: the shim's deepest synthetic
## header self-linked, so `while cur.height > targetHeight` never advanced.
## FAILS AT PARENT: nil-db getBlockIndex segfaults the test process.
proc mainIdx() =
  var cdb = ChainDb()
  doAssert cdb.db == nil
  var h: array[32, byte]; h[0] = 0x5A
  doAssert cdb.getBlockIndex(BlockHash(h)).isNone,
    "nil-db block-index lookup must report no-row, not crash"
  # In-memory shadow still answers without a db.
  cdb.ibdIndexByHash[BlockHash(h)] = BlockIndex(hash: BlockHash(h), height: 7)
  let got = cdb.getBlockIndex(BlockHash(h))
  doAssert got.isSome and got.get().height == 7
  echo "nil-db block-index guard OK"

mainIdx()
