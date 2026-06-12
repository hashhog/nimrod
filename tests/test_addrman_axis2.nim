## AXIS #2 — Core-bucketed addrman proof suite (nimrod).
##
## Mirrors the rustoshi 361d81b w104_addrman axis2 suite shape:
##   1. placement determinism + golden-stable bucket + nKey-matters +
##      source-group spread (anti-Sybil) + falsification (it really buckets).
##   2. Add -> NEW, Good -> TRIED, tried-collision evicts back to NEW, Select.
##   3. restart persistence preserves placement verbatim + corrupt cold-start.
##   4. bounded (one source group <= 64 new buckets; global ceiling).
##
## Reference: bitcoin-core/src/addrman.{cpp,h}, addrman_impl.h.

import unittest2
import std/[sets, tables, options, os]
import ../src/network/addrman
import ../src/network/netgroup

const TestNkey: array[32, byte] = [
  0xa1'u8, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
  0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
  0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
  0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]

proc ip4(a, b, c, d: byte): array[16, byte] =
  ## IPv4 in 16-byte ::ffff:a.b.c.d form.
  result[10] = 0xFF; result[11] = 0xFF
  result[12] = a; result[13] = b; result[14] = c; result[15] = d

proc src4(a, b, c, d: byte): array[16, byte] = ip4(a, b, c, d)

let ng = newNetGroupManager()

# ─── G-constants ─────────────────────────────────────────────────────────────
suite "axis2 bucket constants match Core":
  test "1024 / 256 / 64 / 64 / 8 + ceiling 81920":
    check AddrmanNewBucketCount == 1024
    check AddrmanTriedBucketCount == 256
    check AddrmanBucketSize == 64
    check AddrmanNewBucketsPerSourceGroup == 64
    check AddrmanTriedBucketsPerGroup == 8
    check AddrmanNewBucketsPerAddress == 8
    check AddrmanCeiling == 1024 * 64 + 256 * 64
    check AddrmanCeiling == 81920

# ─── 1. PLACEMENT DETERMINISM + GOLDEN + ANTI-SYBIL SPREAD ───────────────────
suite "axis2 placement determinism, golden, nkey, spread, falsification":

  test "same a16+nKey => identical new (bucket,pos) (recompute==stored)":
    let a16 = ip4(8, 8, 8, 8)
    let src = src4(8, 8, 8, 8)
    let t1 = newAddrManTableWithKey(TestNkey)
    let t2 = newAddrManTableWithKey(TestNkey)
    check t1.add(a16, 8333, src, 1, 1_700_000_000, ng)
    check t2.add(a16, 8333, src, 1, 1_700_000_000, ng)
    let s1 = t1.newSlotOf(a16, 8333, ng)
    let s2 = t2.newSlotOf(a16, 8333, ng)
    check s1.isSome
    check s2.isSome
    check s1.get() == s2.get()

  test "golden: stable bucket/pos for fixed nKey+a16, in-range":
    let a16 = ip4(8, 8, 8, 8)
    let src = src4(1, 1, 1, 1)
    let t = newAddrManTableWithKey(TestNkey)
    check t.add(a16, 8333, src, 1, 1_700_000_000, ng)
    let s = t.newSlotOf(a16, 8333, ng)
    check s.isSome
    let (b, p) = s.get()
    let t2 = newAddrManTableWithKey(TestNkey)
    check t2.add(a16, 8333, src, 1, 1_700_000_000, ng)
    let s2 = t2.newSlotOf(a16, 8333, ng)
    check s2.isSome
    check (b, p) == s2.get()
    check b < AddrmanNewBucketCount
    check p < AddrmanBucketSize

  test "different nKey remaps the same a16 (salt keys placement)":
    let a16 = ip4(9, 9, 9, 9)
    let src = src4(9, 9, 9, 9)
    var k1, k2: array[32, byte]
    for i in 0..<32: k1[i] = 0x01'u8
    for i in 0..<32: k2[i] = 0x02'u8
    let a = newAddrManTableWithKey(k1)
    let b = newAddrManTableWithKey(k2)
    discard a.add(a16, 8333, src, 1, 1_700_000_000, ng)
    discard b.add(a16, 8333, src, 1, 1_700_000_000, ng)
    let sa = a.newSlotOf(a16, 8333, ng)
    let sb = b.newSlotOf(a16, 8333, ng)
    check sa.isSome and sb.isSome
    check sa.get() != sb.get()

  test "distinct source groups spread one a16 across many new buckets":
    let a16 = ip4(8, 8, 1, 1)
    var buckets = initHashSet[int]()
    for i in 0'u8 ..< 40'u8:
      let t = newAddrManTableWithKey(TestNkey)
      let src = src4(11 + i, 200, 0, 1)
      discard t.add(a16, 8333, src, 1, 1_700_000_000, ng)
      let s = t.newSlotOf(a16, 8333, ng)
      if s.isSome:
        buckets.incl(s.get()[0])
    check buckets.len > 5

  test "single source group reaches <= NEW_BUCKETS_PER_SOURCE_GROUP (64)":
    let src = src4(172, 99, 0, 1)  # one /16 source group
    let t = newAddrManTableWithKey(TestNkey)
    var buckets = initHashSet[int]()
    for a in 1'u8 ..< 60'u8:
      for b in 1'u8 ..< 40'u8:
        let a16 = ip4(a, b, 7, 7)
        discard t.add(a16, 8333, src, 1, 1_700_000_000, ng)
        let s = t.newSlotOf(a16, 8333, ng)
        if s.isSome:
          buckets.incl(s.get()[0])
    check buckets.len <= AddrmanNewBucketsPerSourceGroup

  test "falsification: distinct addrs occupy many distinct (bucket,pos) slots":
    let t = newAddrManTableWithKey(TestNkey)
    var occupied = initHashSet[(int, int)]()
    for a in 1'u8 ..< 50'u8:
      let a16 = ip4(a, byte((int(a) * 3 + 1) and 0xFF), 4, 2)
      let src = src4(a, 50, 0, 1)
      discard t.add(a16, 8333, src, 1, 1_700_000_000, ng)
      let s = t.newSlotOf(a16, 8333, ng)
      if s.isSome:
        occupied.incl(s.get())
    check occupied.len > 20

# ─── 2. ADD / GOOD / SELECT + COLLISION EVICTION ─────────────────────────────
suite "axis2 add / good / select / tried-collision evict":

  test "Add places one a16 in NEW (not TRIED)":
    let t = newAddrManTableWithKey(TestNkey)
    let a16 = ip4(11, 22, 33, 44)
    check t.add(a16, 8333, src4(5, 5, 5, 5), 1, 1_700_000_000, ng)
    check t.newCount == 1
    check t.triedCount == 0
    check t.newSlotOf(a16, 8333, ng).isSome
    check not t.isInTried(a16, 8333)

  test "Good promotes NEW -> TRIED, removes from NEW":
    let t = newAddrManTableWithKey(TestNkey)
    let a16 = ip4(11, 22, 33, 44)
    discard t.add(a16, 8333, src4(5, 5, 5, 5), 1, 1_700_000_000, ng)
    check t.good(a16, 8333, 1_700_000_100, ng)
    check t.isInTried(a16, 8333)
    check t.triedCount == 1
    check t.newCount == 0
    check t.triedSlotOf(a16, 8333, ng).isSome
    # Good on an unknown a16 is a no-op.
    check not t.good(ip4(1, 2, 3, 4), 8333, 1_700_000_200, ng)

  test "tried-collision: promoting the collider evicts the first back to NEW":
    let t = newAddrManTableWithKey(TestNkey)
    let src = src4(5, 5, 5, 5)
    let a = ip4(50, 60, 70, 80)
    discard t.add(a, 8333, src, 1, 1_700_000_000, ng)
    discard t.good(a, 8333, 1_700_000_100, ng)
    let slotAOpt = t.triedSlotOf(a, 8333, ng)
    check slotAOpt.isSome
    let slotA = slotAOpt.get()

    # Find a second a16 that maps to the same tried slot (probe table).
    var collider: array[16, byte]
    var found = false
    block search:
      for x in 1'u8 ..< 255'u8:
        for y in 1'u8 ..< 255'u8:
          let cand = ip4(x, y, 200, 201)
          if cand == a: continue
          let probe = newAddrManTableWithKey(TestNkey)
          discard probe.add(cand, 8333, src, 1, 1_700_000_000, ng)
          discard probe.good(cand, 8333, 1_700_000_100, ng)
          let ps = probe.triedSlotOf(cand, 8333, ng)
          if ps.isSome and ps.get() == slotA:
            collider = cand
            found = true
            break search
    check found

    discard t.add(collider, 8333, src, 1, 1_700_000_000, ng)
    discard t.good(collider, 8333, 1_700_000_200, ng)
    check t.isInTried(collider, 8333)
    check not t.isInTried(a, 8333)
    check t.newSlotOf(a, 8333, ng).isSome

  test "Select returns only previously-added addrs; new_only excludes tried-only":
    let t = newAddrManTableWithKey(TestNkey)
    var added = initHashSet[AddrKey]()
    for i in 1'u8 ..< 30'u8:
      let a16 = ip4(120, i, 3, 3)
      discard t.add(a16, 8333, src4(120, i, 0, 1), 1, 1_700_000_000, ng)
      added.incl((a16, 8333'u16))
    # Empty table returns none.
    check newAddrManTableWithKey(TestNkey).select(false).isNone
    for _ in 0 ..< 200:
      let s = t.select(false)
      if s.isSome:
        check added.contains(s.get())
    # new_only must not return a tried-only a16.
    let only = ip4(200, 1, 1, 1)
    let t2 = newAddrManTableWithKey(TestNkey)
    discard t2.add(only, 8333, src4(200, 1, 0, 1), 1, 1_700_000_000, ng)
    discard t2.good(only, 8333, 1_700_000_100, ng)
    check t2.select(true).isNone
    let s2 = t2.select(false)
    check s2.isSome
    check s2.get() == (only, 8333'u16)

# ─── 3. RESTART PERSISTENCE (placement verbatim) ─────────────────────────────
suite "axis2 restart persistence":

  test "save -> load preserves nKey + NEW/TRIED placement verbatim":
    let dir = getTempDir() / ("nimrod-addrman-" & $getCurrentProcessId())
    createDir(dir)
    let t = newAddrManTableWithKey(TestNkey)
    var newAddrs: seq[array[16, byte]] = @[]
    for i in 1'u8 ..< 15'u8:
      let a = ip4(130, i, 9, 9)
      newAddrs.add(a)
      discard t.add(a, 8333, src4(130, i, 0, 1), 1, 1_700_000_000, ng)
    var triedAddrs: seq[array[16, byte]] = @[]
    for i in 1'u8 ..< 6'u8:
      let a = ip4(140, i, 9, 9)
      triedAddrs.add(a)
      discard t.add(a, 8333, src4(140, 50, 0, 1), 1, 1_700_000_000, ng)
      discard t.good(a, 8333, 1_700_000_100, ng)

    let preNkey = t.nkey
    var preNew = initTable[array[16, byte], (int, int)]()
    for a in newAddrs:
      let s = t.newSlotOf(a, 8333, ng)
      if s.isSome: preNew[a] = s.get()
    var preTried = initTable[array[16, byte], (int, int)]()
    for a in triedAddrs:
      let s = t.triedSlotOf(a, 8333, ng)
      if s.isSome: preTried[a] = s.get()

    t.save(dir)
    let loaded = addrman.load(dir, ng)

    check loaded.nkey == preNkey
    for a, s in preNew:
      let ls = loaded.newSlotOf(a, 8333, ng)
      check ls.isSome
      check ls.get() == s
    for a, s in preTried:
      check loaded.isInTried(a, 8333)
      let ls = loaded.triedSlotOf(a, 8333, ng)
      check ls.isSome
      check ls.get() == s
    removeDir(dir)

  test "corrupt / wrong-version / truncated / missing => empty cold start":
    let dir = getTempDir() / ("nimrod-addrman-corrupt-" & $getCurrentProcessId())
    createDir(dir)
    let path = dir / "peers.dat"
    for bad in ["@@@not a header@@@", "ADDRMAN 999 deadbeef\n", "ADDRMAN", ""]:
      writeFile(path, bad)
      let t = addrman.load(dir, ng)
      check t.totalCount == 0
    removeFile(path)
    let t = addrman.load(dir, ng)
    check t.totalCount == 0
    removeDir(dir)

# ─── 4. BOUNDEDNESS ──────────────────────────────────────────────────────────
suite "axis2 boundedness":

  test "thousands of addrs from one source group stay within per-source reach":
    let t = newAddrManTableWithKey(TestNkey)
    let src = src4(203, 113, 0, 1)  # one routable /16 source group
    var newBuckets = initHashSet[int]()
    for a in 1'u8 ..< 200'u8:
      for b in 1'u8 ..< 200'u8:
        let a16 = ip4(a, b, 1, 9)
        discard t.add(a16, 8333, src, 1, 1_700_000_000, ng)
        let s = t.newSlotOf(a16, 8333, ng)
        if s.isSome:
          newBuckets.incl(s.get()[0])
    check newBuckets.len <= AddrmanNewBucketsPerSourceGroup
    check t.totalCount <= AddrmanCeiling
    check t.totalCount <= AddrmanNewBucketsPerSourceGroup * AddrmanBucketSize

  test "re-adding the same a16 caps refcount, never grows the id set":
    let t = newAddrManTableWithKey(TestNkey)
    let a16 = ip4(150, 150, 150, 150)
    for i in 0'u8 ..< 200'u8:
      let src = src4(30 + (i mod 200'u8), 1, 0, 1)
      discard t.add(a16, 8333, src, 1, 1_700_000_000, ng)
    check t.totalCount == 1
    check uint32(t.newCount) <= uint32(AddrmanNewBucketsPerAddress)
