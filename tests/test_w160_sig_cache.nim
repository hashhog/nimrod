## W160 BUG-11 — SigCache key composition regression test
##
## The previous cache key was SHA256(nonce || wtxid || inputIdx || flags),
## which is structurally insufficient for tapscript-multisig inputs that
## run multiple OP_CHECKSIG calls against different (sig, pubkey, sighash)
## tuples within a single input.
##
## Concrete exploit shape (per the W160 audit):
##   1. First Schnorr verify in a tapscript multisig succeeds and caches
##      `(wtxid, inputIdx, flags) -> true`.
##   2. Second OP_CHECKSIG in the SAME input is invoked with a different
##      sig + pubkey + sighash combination — under the old key, the lookup
##      short-circuits to `true` and libsecp is never called, silently
##      accepting an invalid signature.
##
## Fix (W160 BUG-11): cache key now folds in (sighash, pubkey, sig) per
## Core's ComputeEntryECDSA / ComputeEntrySchnorr (sigcache.cpp:39-50). The
## previous (wtxid, inputIdx, flags) overloads are retained as
## backward-compatibility shims for older tests; both forms map to distinct
## cache slots provided their identifying inputs differ.

import unittest2
import ../src/perf/sig_cache

suite "W160 BUG-11 — SigCache key folds in sighash + pubkey + sig":

  test "different sighash for the same pubkey + sig is a cache miss":
    ## Exact analogue of the tapscript-multisig exploit: a single (sig,
    ## pubkey) combo may be presented against two different sighashes
    ## (e.g. SIGHASH_ALL vs SIGHASH_ANYONECANPAY|SIGHASH_SINGLE). The
    ## second presentation MUST not piggy-back on the first cache entry.
    let cache = newSigCache(100)
    var sighashA, sighashB: array[32, byte]
    for i in 0 ..< 32:
      sighashA[i] = byte(i)
      sighashB[i] = byte(31 - i)
    let pubkey: array[32, byte] = [byte 0x02, 0xaa, 0xbb, 0xcc, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let sig: array[64, byte] = [byte 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    cache.insert(sighashA, pubkey, sig)
    check cache.lookup(sighashA, pubkey, sig) == true
    check cache.lookup(sighashB, pubkey, sig) == false  ## DIFFERENT sighash → MISS

  test "different pubkey for the same sighash + sig is a cache miss":
    ## Closes the "first valid Schnorr sig covers subsequent OP_CHECKSIG calls
    ## with arbitrary different pubkeys" tapscript-multisig short-circuit.
    let cache = newSigCache(100)
    var sighash: array[32, byte]
    sighash[0] = 0xde; sighash[1] = 0xad
    let pubkeyA: array[32, byte] = [byte 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let pubkeyB: array[32, byte] = [byte 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let sig: array[64, byte] = [byte 0x99, 0xaa, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    cache.insert(sighash, pubkeyA, sig)
    check cache.lookup(sighash, pubkeyA, sig) == true
    check cache.lookup(sighash, pubkeyB, sig) == false  ## DIFFERENT pubkey → MISS

  test "different sig for the same sighash + pubkey is a cache miss":
    ## Edge case: same (sighash, pubkey) but malleated sig bytes. Under the
    ## old (wtxid, inputIdx, flags) key, the cache would happily reuse the
    ## valid-sig verdict for an invalid sig.
    let cache = newSigCache(100)
    var sighash: array[32, byte]
    sighash[0] = 0xca; sighash[1] = 0xfe
    let pubkey: array[32, byte] = [byte 0x03, 0xab, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let sigA: array[64, byte] = [byte 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let sigB: array[64, byte] = [byte 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    cache.insert(sighash, pubkey, sigA)
    check cache.lookup(sighash, pubkey, sigA) == true
    check cache.lookup(sighash, pubkey, sigB) == false  ## DIFFERENT sig → MISS

  test "identical (sighash, pubkey, sig) hits the cache":
    ## The fix MUST not break the legitimate cache-hit case: re-presenting
    ## the same verified (sighash, pubkey, sig) MUST short-circuit.
    let cache = newSigCache(100)
    var sighash: array[32, byte]
    sighash[0] = 0x55
    let pubkey: array[32, byte] = [byte 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    let sig: array[64, byte] = [byte 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    cache.insert(sighash, pubkey, sig)
    check cache.lookup(sighash, pubkey, sig) == true
    check cache.lookup(sighash, pubkey, sig) == true  ## stable on repeated lookups

  test "legacy (wtxid, inputIdx, flags) shim is preserved for older callers":
    ## The old API is kept as a shim so existing W105 tests keep compiling.
    ## Distinct (wtxid, inputIdx, flags) tuples still map to distinct slots.
    let cache = newSigCache(100)
    var wtxid: array[32, byte]
    wtxid[0] = 0xAA
    cache.insert(wtxid, 0'u32, 0b0001'u32)
    check cache.lookup(wtxid, 0'u32, 0b0001'u32) == true
    check cache.lookup(wtxid, 1'u32, 0b0001'u32) == false  ## different input idx
    check cache.lookup(wtxid, 0'u32, 0b0010'u32) == false  ## different flags
