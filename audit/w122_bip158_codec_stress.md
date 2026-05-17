# W122 — BIP-158 GCS codec stress-vector audit (nimrod)

Date: 2026-05-17
Audit type: discovery
Target: `src/storage/indexes/gcs.nim` and downstream BIP-157 P2P / REST.
Driver: haskoin W121 addendum BUG-16 — "Core's `blockfilters.json` does
not exercise quotients ≥ 64, so impls passing that fixture may still
mis-encode in the haskoin-flagged stress regime."

## Status

**BUG FOUND — P0-CDIV (consensus / wire divergence).**

Nimrod's BIP-158 Golomb-Rice codec packs bits **LSB-first within each
byte**.  Bitcoin Core (and BIP-158 by spec, via `BitStreamWriter` in
`bitcoin-core/src/streams.h`) packs **MSB-first within each byte**.
These two bit orderings produce **different encoded filter bytes** for
every non-trivial Golomb-Rice value, even though both round-trip the
same logical content within their own ecosystem.

Concrete: the testnet3 genesis block (Core `blockfilters.json[0]`):
- Core expected encoded filter:  `019dfca8`
- Nimrod produced encoded filter: `0155fe0e`

The downstream effect is total wire / on-disk incompatibility with
every other BIP-158 implementation that follows Core (and with Core
itself):
- `BlockFilter::encoded` bytes diverge → on-disk `fltr00000.dat` files
  are not Core-readable / writable.
- `getFilterHash = SHA256d(encoded)` diverges → the BIP-157 cfheaders
  chain diverges at genesis and never reconciles with the network.
- BIP-157 wire messages (`cfilter`, `cfheaders`, `cfcheckpt`) emitted
  by nimrod are unreadable by Core peers (and vice versa).  Per the
  G20 P1-CDIV path in `peer.nim::validateGetCFiltersRequest`, this
  could even trigger Core to flag nimrod as a misbehaving peer.
- REST endpoint `/rest/blockfilter/...` payloads served by nimrod
  return bytes that are not Core-compatible for any client expecting
  the BIP-158 standard.

The bug had not been caught before because:

1. Nimrod's existing test in `test_gcs.nim` ("Core test vectors") only
   checks `SHA256d` and round-trip behavior; it never compares the
   raw encoded bytes to `019dfca8`.  The only check at line 499 is
   `encoded[0] == 0x01'u8` (the CompactSize prefix), which is shared
   across both bit orderings.
2. `test_w121_compact_filters.nim` G10 was explicitly flagged
   MISSING ("BIP-158 Core test-vector regression battery") — the
   audit-time absence assertion held precisely because no such test
   existed.  This W122 wave is the first to construct the missing
   regression and observe it fail.

## Stress-vector matrix

Each row encodes `x = q << 19` (P = BIP-158 basic, P=19) with zero
remainder.  "Core MSB" was computed manually from BIP-158's bit
spec; "Nimrod LSB" was observed from `golombRiceEncode`.

| q   | bits = q+1+19 | Core MSB-first         | Nimrod LSB-first       | match |
|-----|---------------|------------------------|------------------------|-------|
| 0   | 20            | `000000`               | `000000`               | yes\* |
| 1   | 21            | `800000`               | `010000`               | NO    |
| 5   | 25            | `f8000000`             | `1f000000`             | NO    |
| 63  | 83            | `fffffffffffffffe000000` | `ffffffffffffff7f000000` | NO  |
| 64  | 84            | `ffffffffffffffff000000` | `ffffffffffffffff000000` | yes\* |
| 65  | 85            | `ffffffffffffffff800000` | `ffffffffffffffff010000` | NO  |
| 100 | 120           | `fffffffffffffffffffffffff00000` | `ffffffffffffffffffffffff0f0000` | NO |
| 200 | 220           | `…ff000000`             | `…ff000000`             | yes\* |
| 1000| 1020          | `…ff000000`             | `…ff000000`             | yes\* |

\* "yes" rows are pure coincidence: when every byte is `0x00` or
`0xff` (all bits same), LSB-first and MSB-first packing produce
byte-identical output.  Every interesting / boundary case
(q=1,5,63,65,100) diverges.

## Roots — where the bit-order bug lives

`src/storage/indexes/gcs.nim`:

```nim
# Line 79: LSB-first packing
proc writeBits*(w: var BitWriter, value: uint64, bits: int) =
  ...
  w.data[^1] = w.data[^1] or byte(bitsToWrite shl w.bitPos)
  w.bitPos = (w.bitPos + toWrite) mod 8
  ...

# Line 109: LSB-first reading
proc readBit*(r: var BitReader): uint64 =
  let bit = (r.data[r.pos] shr r.bitPos) and 1
  r.bitPos += 1
  ...
```

Compare to Core `src/streams.h:329-344`:

```cpp
// MSB-first packing — places nbits at offset from MOST SIGNIFICANT bit
void Write(uint64_t data, int nbits) {
    while (nbits > 0) {
        int bits = std::min(8 - m_offset, nbits);
        m_buffer |= (data << (64 - nbits)) >> (64 - 8 + m_offset);
        m_offset += bits;
        nbits -= bits;
        if (m_offset == 8) Flush();
    }
}
```

The comment on `m_offset` (Core, streams.h:313-315) is explicit:
"The next bit to be written to is at this offset from **the most
significant bit position**."

BIP-158 doesn't textually mandate MSB-first, but its reference
implementation is Core, and Core's bit-stream-writer header was
defined for BIP-158 in PR #12254.  Every conforming impl (haskoin,
btcd, neutrino, rust-bitcoin's `bip158` crate, lnd's `cfilters`)
follows the MSB-first convention.

## Downstream surfaces affected

Grepped from `src/`:

- `src/storage/indexes/gcs.nim`
  - `golombRiceEncode` / `golombRiceDecode` (the codec itself)
  - `newGCSFilter(elements)` — produces `encoded` field
  - `newGCSFilter(encodedFilter)` — parses `encoded` field
- `src/storage/indexes/blockfilterindex.nim`
  - `writeFilter` / `readFilter` (on-disk `fltrNNNNN.dat` format)
- `src/rpc/rest.nim`
  - `encodeBlockFilterRecord`, `parseBlockFilterType` —
    `getEncodedFilter(filter)` returned to REST callers
- `src/network/messages.nim`
  - `CFilterMsg.filter: seq[byte]` (BIP-157 wire) is fed by
    `getEncodedFilter` directly
- `src/network/peer.nim`
  - `mkGetCFilters` / `mkCFilter` dispatch — these consume / emit
    the broken codec output

## Repro / regression tests

`tests/test_w122_codec_stress.nim` contains 12 tests organized in three
suites:

1. **Self-consistent round-trip** (3 tests) — exercises the haskoin
   BUG-16 stress regime (q = 0..1000).  Demonstrates the codec is
   internally consistent (writer matches reader) even though it
   doesn't match Core.  These PASS today and should keep passing
   after the fix.
2. **BUG FOUND** (7 tests) — concrete xfail-style assertions that
   nimrod's output **differs** from Core's expected bytes at each
   tested quotient (1, 5, 63, 65, 100) and at the testnet3 genesis
   fixture.  These tests PASS today (their `!=` assertions hold) and
   will FLIP when the fix lands — they need to be rewritten to use
   `==` against Core's expected bytes once the codec is fixed.
3. **Downstream impact** (3 tests) — concretely shows that
   `computeFilterHeader`, `cfilter` wire payloads, and silent
   garbage-decode of Core bytes all diverge.

All 12 currently pass against `master` HEAD `da93574`.

```
[Suite] W122 GR codec self-consistent round-trip across quotient regimes
  [OK] round-trip q=0,1,5,63,64,65,100,200,1000 (zero remainder)
  [OK] round-trip mixed sequence with nonzero remainder
  [OK] encoded byte length matches ceil((q+1+P)/8) for x = q << P

[Suite] W122 BUG FOUND: nimrod GR codec bit-order differs from Core
  [OK] genesis filter byte equality FAILS today (xfail)
  [OK] genesis filter hash byte equality FAILS today (xfail)
  [OK] GR-encoded q=1, r=0 (single bit 1 then 19 zeros)
  [OK] GR-encoded q=5, r=0 (five 1s then 0 then 19 zeros)
  [OK] GR-encoded q=63 (boundary just below 64-bit run)
  [OK] GR-encoded q=65 (boundary just above 64-bit run — split unary write)
  [OK] GR-encoded q=100 (well into haskoin BUG-16 stress regime)

[Suite] W122 downstream impact of bit-order bug
  [OK] filter header chain diverges at genesis (G7/G8 wire-incompat)
  [OK] cfilter wire payload (encoded bytes) is unreadable by Core peer
  [OK] round-trip survives self-decode but cross-decode of Core bytes fails
```

## Suggested fix shape (out-of-scope for this audit)

Switch `BitWriter` / `BitReader` to MSB-first within bytes.  Two
approaches:

**Option A — minimal change to writer/reader pair.**  In
`writeBits` change line 79 to place bits at the top of the byte:

```nim
# byte index in the buffer is the byte currently being filled top→down
# bitPos tracks bits already in current byte from the top (MSB side)
let shiftFromTop = 8 - w.bitPos - toWrite
w.data[^1] = w.data[^1] or byte(bitsToWrite shl shiftFromTop)
```

…and rewrite `readBit` / `readBits` symmetrically (top-down within
each byte).  Then `writeBits(val, n)` must also consume the *top*
n bits of `val`, not the bottom n, because each GR call writes
unary-then-remainder and the next write should continue from the top
of the new byte position.  See Core's `Write` for the precise
formula.

**Option B — port Core's BitStream verbatim** with the same
`m_offset` semantics.  More invasive but byte-for-byte identical
to Core.

Either way, the fix must also:
- Re-derive the test vectors in `test_gcs.nim` line 288 / 306 / 329
  — those expected hex strings are valid only against Core's encoding
  and were previously satisfied only because `getFilterHash` was
  computed over `019dfca8` (which was already provided as input),
  not over nimrod's own encode.  Specifically:
  - `expectedHex = "4c8af7fa..."` at line 288 will then equal
    `toHexStr(getFilterHash(nimrod-built-filter))`, closing the
    round-trip Core ↔ nimrod equivalence.
  - The G10 MISSING assertion in `test_w121_compact_filters.nim:81`
    can be closed (add a concrete `coreBIP158TestVectors` symbol
    behind the regression suite).
- Re-build all `fltr*.dat` files on existing nodes: every
  `blockfilterindex.nim` on-disk file written under the old codec
  is now invalid.  Either an explicit migration step (re-scan and
  re-emit) or a format-version bump that forces a backfill.
- Update `tests/test_w122_codec_stress.nim`: flip the `!=` assertions
  in the "BUG FOUND" suite to `==`, and the "downstream impact"
  inequality checks similarly.

## Notes for future audit waves

- The W121 audit marked nimrod's BIP-158 codec as PRESENT and
  "solid" because every test exercised it as an **internal**
  round-trip.  The hidden invariant was bit-order, which is invisible
  in a self-consistent ecosystem.
- The W121 G10 "MISSING: BIP-158 Core test-vector regression battery"
  was the exact pre-flag for this category of failure — the audit
  correctly identified the absence, this wave confirms it would have
  flushed out a real bug.
- This is another instance of the recurring "well-engineered codec,
  gaps at system edges" pattern observed fleet-wide in W121.  Here
  the codec is internally complete but cross-impl gap is total at
  the bit-pack layer.
- Recommend a **fleet-wide W122 re-sweep**: every BIP-158 impl
  should be byte-checked against Core's `blockfilters.json[0..N]`,
  not just SHA256d-checked, to catch any other LSB/MSB bit-order
  mismatches that round-trip locally but break the wire.
