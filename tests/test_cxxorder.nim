## nimrod's port of libstdc++ std::sort / std heap algorithms
## (src/mempool/cxxorder.nim) must produce the same permutation of EQUAL keys
## as libstdc++ itself: Core's TxGraph::Trim keeps whichever of several
## equal-feerate transactions those algorithms happen to leave in place
## (KB-192). Expected orders were printed by g++ 14.2 / libstdc++ running
## std::sort / std::make_heap / std::push_heap / std::pop_heap on (key, id)
## pairs compared by key only (staged-patches/kb192/stl_ref.cpp in the
## meta-repo; a 12,000-case random differential found no mismatch).
##
## Command:  nim c -r tests/test_cxxorder.nim

import unittest2
import ../src/mempool/cxxorder

type P = tuple[k, id: int]

let byKey: CxxLess[P] = proc(a, b: P): bool = a.k < b.k

proc keyed(keys: openArray[int]): seq[P] =
  for i, k in keys: result.add((k, i))

proc sortedIds(keys: openArray[int]): seq[int] =
  var v = keyed(keys)
  cxxSort(v, byKey)
  for p in v: result.add(p.id)

proc heapIds(keys: openArray[int], ops: openArray[int]): seq[int] =
  ## make_heap, then each op pops (-1) or pushes a new key, then pop the rest.
  var v = keyed(keys)
  cxxMakeHeap(v, 0, v.len, byKey)
  var next = keys.len
  for op in ops:
    if op < 0:
      if v.len > 0: result.add(cxxPopHeap(v, byKey).id)
    else:
      v.add((op, next))
      inc next
      cxxPushHeap(v, byKey)
  while v.len > 0: result.add(cxxPopHeap(v, byKey).id)

proc rep(k, n: int): seq[int] =
  for _ in 0 ..< n: result.add(k)

suite "cxxorder matches libstdc++ on equal keys (KB-192)":

  test "std::sort, 20 equal keys (introsort + final insertion sort)":
    check sortedIds(rep(0, 20)) == @[10, 19, 18, 17, 16, 15, 14, 13, 12, 11, 0, 9, 8, 7, 6, 5, 4, 3, 2, 1]

  test "std::sort, 64 equal keys":
    check sortedIds(rep(7, 64)) == @[48, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 32, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]

  test "std::sort, 40 keys i mod 3":
    var ks: seq[int]
    for i in 0 ..< 40: ks.add(i mod 3)
    check sortedIds(ks) == @[0, 21, 18, 24, 15, 27, 12, 30, 9, 33, 6, 36, 3, 39, 31, 34, 28, 37, 25, 22, 1, 19, 16, 4, 13, 7, 10, 2, 20, 38, 5, 35, 8, 32, 11, 29, 14, 26, 17, 23]

  test "std::sort, 33 keys 7i mod 5":
    var ks: seq[int]
    for i in 0 ..< 33: ks.add((i * 7) mod 5)
    check sortedIds(ks) == @[0, 15, 20, 30, 5, 10, 25, 18, 13, 23, 8, 28, 3, 26, 21, 31, 1, 16, 11, 6, 19, 14, 24, 9, 29, 4, 17, 12, 22, 7, 27, 2, 32]

  test "make_heap + pop_heap, 10 equal keys":
    check heapIds(rep(1, 10), []) == @[6, 2, 0, 1, 3, 5, 7, 4, 9, 8]

  test "make_heap, interleaved push_heap / pop_heap":
    check heapIds([3, 1, 3, 2, 3, 1], [-1, 3, -1, 3, -1, -1, 2, -1]) == @[2, 0, 6, 7, 4, 3, 8, 1, 5]

  test "make_heap + pop_heap, 64 equal keys":
    check heapIds(rep(5, 64), []) == @[62, 30, 14, 6, 2, 0, 61, 31, 29, 59, 13, 57, 27, 55, 5, 53, 25, 51, 11, 49, 23, 47, 1, 45, 21, 43, 9, 41, 19, 39, 3, 37, 17, 35, 7, 33, 15, 60, 63, 28, 56, 12, 52, 24, 48, 4, 44, 20, 40, 8, 36, 16, 58, 32, 26, 50, 10, 42, 18, 54, 34, 22, 46, 38]
