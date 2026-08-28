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
