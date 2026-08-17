## Micro-benchmark: raw ECDSA verification throughput on THIS box.
##
## Purpose: settle whether signature verification is nimrod's IBD bottleneck.
##
## Context (2026-08-16): the mainnet genesis rig runs ~1,200 blk/h in the 800k
## range while sitting at 410% CPU of a possible 3200%, with 15 verify workers
## configured. nimrod links libsecp256k1 via FFI — the same library Bitcoin Core
## uses — so if signature verification dominated, the pool would be saturated.
## This measures what one core actually achieves here, so the per-block
## verification cost can be set against the ~3s/block observed.
##
## Uses the module's own `benchEcdsaVerify` rather than a hand-rolled loop, so
## the number is the project's own instrument.
##
## Run: nim c -d:release -r tests/bench_ecdsa_throughput.nim

import std/strformat
import ../src/crypto/secp256k1

const
  ITERS = 50_000
  ## MEASURED from real mainnet block 838705 (parsed from the archival blk
  ## files): 2,586 txs, 3,646 non-coinbase inputs, ~1 signature each.
  SIGS_PER_BLOCK = 3_646
  ## Observed rig throughput in the same height range.
  OBSERVED_BLOCK_MS = 3_000.0
  WORKERS = 15

proc main() =
  initSecp256k1()
  let perSec = benchEcdsaVerify(ITERS)

  let oneCoreMs = float(SIGS_PER_BLOCK) / perSec * 1000.0
  let poolMs = oneCoreMs / float(WORKERS)

  echo &"ECDSA verify/sec (1 core) : {perSec:.0f}"
  echo ""
  echo &"{SIGS_PER_BLOCK} sigs on 1 core        : {oneCoreMs:.0f} ms"
  echo &"{SIGS_PER_BLOCK} sigs across {WORKERS} workers: {poolMs:.0f} ms"
  echo &"observed time per block   : {OBSERVED_BLOCK_MS:.0f} ms"
  echo ""
  echo &"=> signature verification is at most {oneCoreMs/OBSERVED_BLOCK_MS*100:.1f}% of block time serially,"
  echo &"   and {poolMs/OBSERVED_BLOCK_MS*100:.2f}% once spread across the pool."
  echo "   Everything else is coin resolution, DB reads, and bookkeeping."

main()
