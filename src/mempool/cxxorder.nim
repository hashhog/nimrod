## libstdc++ std::sort and heap algorithms, ported line for line
## (bits/stl_algo.h: __introsort_loop, __move_median_to_first,
## __unguarded_partition, __final_insertion_sort; bits/stl_heap.h:
## __adjust_heap, __push_heap, make_heap, push_heap, pop_heap).
##
## Bitcoin Core's TxGraph::Trim (txgraph.cpp:3285-) and GroupClusters
## (txgraph.cpp:1856-) order transactions with std::sort over keys that are
## often equal and with a std heap over chunk feerates that are often equal.
## Neither is stable, so which of several equal transactions Core keeps is
## whatever permutation these exact algorithms produce. Matching Core on a tie
## therefore means running the same algorithms, not a stable sort or a
## "first come" rule. Core's release builds use libstdc++, whose versions of
## these algorithms have been unchanged for many GCC releases.
##
## `lt(a, b)` plays the role of the C++ comparator (a strict "a < b").

type CxxLess*[T] = proc(a, b: T): bool {.closure.}

proc cxxLg(n: int): int =
  var x = n
  while x > 1:
    x = x shr 1
    inc result

proc pushHeapHole[T](a: var seq[T], first, hole0, top: int, value: T,
                     lt: CxxLess[T]) =
  var hole = hole0
  var parent = (hole - 1) div 2
  while hole > top and lt(a[first + parent], value):
    a[first + hole] = a[first + parent]
    hole = parent
    parent = (hole - 1) div 2
  a[first + hole] = value

proc adjustHeap[T](a: var seq[T], first, hole0, len: int, value: T,
                   lt: CxxLess[T]) =
  var hole = hole0
  let top = hole
  var second = hole
  while second < (len - 1) div 2:
    second = 2 * (second + 1)
    if lt(a[first + second], a[first + second - 1]):
      dec second
    a[first + hole] = a[first + second]
    hole = second
  if (len and 1) == 0 and second == (len - 2) div 2:
    second = 2 * (second + 1)
    a[first + hole] = a[first + second - 1]
    hole = second - 1
  pushHeapHole(a, first, hole, top, value, lt)

proc cxxMakeHeap*[T](a: var seq[T], first, last: int, lt: CxxLess[T]) =
  let len = last - first
  if len < 2:
    return
  var parent = (len - 2) div 2
  while true:
    let value = a[first + parent]
    adjustHeap(a, first, parent, len, value, lt)
    if parent == 0:
      return
    dec parent

proc cxxPushHeap*[T](a: var seq[T], lt: CxxLess[T]) =
  ## std::push_heap(a.begin(), a.end()) after a.push_back(x).
  let value = a[^1]
  pushHeapHole(a, 0, a.len - 1, 0, value, lt)

proc popHeapInto[T](a: var seq[T], first, last, res: int, lt: CxxLess[T]) =
  let value = a[res]
  a[res] = a[first]
  adjustHeap(a, first, 0, last - first, value, lt)

proc cxxPopHeap*[T](a: var seq[T], lt: CxxLess[T]): T =
  ## std::pop_heap(a.begin(), a.end()); x = a.back(); a.pop_back().
  if a.len > 1:
    popHeapInto(a, 0, a.len - 1, a.len - 1, lt)
  a.pop()

proc moveMedianToFirst[T](a: var seq[T], res, x, y, z: int, lt: CxxLess[T]) =
  if lt(a[x], a[y]):
    if lt(a[y], a[z]): swap(a[res], a[y])
    elif lt(a[x], a[z]): swap(a[res], a[z])
    else: swap(a[res], a[x])
  elif lt(a[x], a[z]): swap(a[res], a[x])
  elif lt(a[y], a[z]): swap(a[res], a[z])
  else: swap(a[res], a[y])

proc unguardedPartition[T](a: var seq[T], first0, last0, pivot: int,
                           lt: CxxLess[T]): int =
  var first = first0
  var last = last0
  while true:
    while lt(a[first], a[pivot]): inc first
    dec last
    while lt(a[pivot], a[last]): dec last
    if not (first < last):
      return first
    swap(a[first], a[last])
    inc first

proc introsortLoop[T](a: var seq[T], first, last0, depth0: int,
                      lt: CxxLess[T]) =
  const Threshold = 16
  var last = last0
  var depth = depth0
  while last - first > Threshold:
    if depth == 0:
      # std::__partial_sort(first, last, last): heap_select + sort_heap.
      cxxMakeHeap(a, first, last, lt)
      var l = last
      while l - first > 1:
        dec l
        popHeapInto(a, first, l, l, lt)
      return
    dec depth
    let mid = first + (last - first) div 2
    moveMedianToFirst(a, first, first + 1, mid, last - 1, lt)
    let cut = unguardedPartition(a, first + 1, last, first, lt)
    introsortLoop(a, cut, last, depth, lt)
    last = cut

proc unguardedLinearInsert[T](a: var seq[T], last0: int, lt: CxxLess[T]) =
  var last = last0
  let val = a[last]
  var next = last - 1
  while lt(val, a[next]):
    a[last] = a[next]
    last = next
    dec next
  a[last] = val

proc insertionSort[T](a: var seq[T], first, last: int, lt: CxxLess[T]) =
  if first == last:
    return
  for i in first + 1 ..< last:
    if lt(a[i], a[first]):
      let val = a[i]
      var j = i
      while j > first:
        a[j] = a[j - 1]
        dec j
      a[first] = val
    else:
      unguardedLinearInsert(a, i, lt)

proc cxxSort*[T](a: var seq[T], lt: CxxLess[T]) =
  ## std::sort(a.begin(), a.end(), lt).
  let n = a.len
  if n <= 1:
    return
  introsortLoop(a, 0, n, 2 * cxxLg(n), lt)
  if n > 16:
    insertionSort(a, 0, 16, lt)
    for i in 16 ..< n:
      unguardedLinearInsert(a, i, lt)
  else:
    insertionSort(a, 0, n, lt)
