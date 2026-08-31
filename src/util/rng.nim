## nimrod's random number source.
##
## WHY THIS MODULE EXISTS
##
## The network layer used to call `std/random`'s `randomize()` immediately
## before almost every `rand()` — eleven sites across relay, peer, bip324,
## erlay, peermanager and proxy. Two problems, neither of them "the numbers are
## predictable" (they are not: Nim 2.2.8's `initRand()` seeds from
## `sysrand.urandom` and then jumps the base state, so every reseed yields a
## well-separated, cryptographically-seeded stream).
##
## 1. A DATA RACE. `std/random`'s default generator is a plain global. The
##    stdlib says so itself, at lib/pure/random.nim:114:
##        # racy for multi-threading but good enough for now:
##        var state = DefaultRandSeed
##    It is not a threadvar and it is not locked. nimrod builds with
##    `--threads:on` and runs the chronos network loop alongside dedicated RPC,
##    REST and wallet-reconcile threads; `wallet/coinselection.nim` calls
##    `shuffle` on that same global while the network layer draws from it.
##    Concurrent writes to the 128-bit state are undefined behaviour.
##
## 2. UNTESTABILITY. Reseeding on every call makes the generator impossible to
##    pin: `randomize(seed)` in a test is overwritten by the next production
##    call. That is why `tests/test_feefilter.nim` had to assert a DISTRIBUTION
##    instead of a value, and why it was flaky roughly one run in eight — it is
##    what made nimrod's suite report 18 or 19 failures depending on the run.
##    Bitcoin Core has the same randomness here and solves it by holding one
##    `FastRandomContext` and passing `fDeterministic=true` in its own test
##    (src/test/feerounder_tests.cpp).
##
## The generator here is THREAD-LOCAL, so there is no shared state to race on,
## and seeded ONCE per thread from the same OS entropy `randomize()` used —
## which is also what the stdlib docstring asks for: "This proc only needs to be
## called once, and it should be called before the first usage."

import std/random
export random

var tlRand {.threadvar.}: Rand
var tlSeeded {.threadvar.}: bool

proc nodeRng*(): var Rand =
  ## The calling thread's generator, seeded on first use.
  if not tlSeeded:
    tlRand = initRand()   # sysrand.urandom, then skipRandomNumbers
    tlSeeded = true
  tlRand

proc seedNodeRngForTest*(seed: int64) =
  ## Pin this thread's generator so a test can assert VALUES rather than a
  ## distribution. Test-only: production never calls this, and because the
  ## generator is thread-local it cannot leak into another thread.
  tlRand = initRand(seed)
  tlSeeded = true
