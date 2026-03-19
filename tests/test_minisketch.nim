## Tests for Minisketch FFI bindings
## Tests sketch creation, serialization, merging, and decoding
##
## Note: These tests require libminisketch to be installed
## Compile with -d:useSystemMinisketch to enable actual minisketch bindings

import std/[random, sequtils, algorithm]
import unittest2
import ../src/crypto/minisketch

suite "minisketch availability":
  test "check 32-bit field support":
    # This test checks if minisketch supports 32-bit fields
    # When compiled without -d:useSystemMinisketch, this returns false
    let supported = bitsSupported(32)
    when defined(useSystemMinisketch):
      check supported == true
    else:
      check supported == false

  test "find best implementation":
    when defined(useSystemMinisketch):
      let impl = findBestImplementation(32)
      # Implementation should be found (at least 0)
      check impl >= 0
    else:
      check findBestImplementation(32) == 0

suite "sketch creation":
  when defined(useSystemMinisketch):
    test "create 32-bit sketch":
      var sketch = newMinisketch32(capacity = 10)
      check sketch.isValid()
      check sketch.getBits() == 32
      check sketch.getCapacity() == 10
      sketch.destroy()

    test "create sketch with false positive calculation":
      var sketch = newMinisketch32FP(maxElements = 10, fpbits = 16)
      check sketch.isValid()
      check sketch.getBits() == 32
      # Capacity should be >= maxElements
      check sketch.getCapacity() >= 10
      sketch.destroy()

    test "clone sketch":
      var sketch1 = newMinisketch32(capacity = 10)
      sketch1.add(12345)
      sketch1.add(67890)

      var sketch2 = sketch1.clone()
      check sketch2.isValid()
      check sketch2.getBits() == sketch1.getBits()
      check sketch2.getCapacity() == sketch1.getCapacity()

      sketch1.destroy()
      sketch2.destroy()

    test "destroy sketch":
      var sketch = newMinisketch32(capacity = 10)
      check sketch.isValid()
      sketch.destroy()
      check not sketch.isValid()

suite "sketch operations":
  when defined(useSystemMinisketch):
    test "add single element":
      var sketch = newMinisketch32(capacity = 10)
      sketch.add(12345)

      # Decode should return the element
      let (elements, success) = sketch.decode()
      check success
      check elements.len == 1
      check elements[0] == 12345

      sketch.destroy()

    test "add multiple elements":
      var sketch = newMinisketch32(capacity = 10)
      sketch.add(111)
      sketch.add(222)
      sketch.add(333)

      let (elements, success) = sketch.decode()
      check success
      check elements.len == 3

      var sortedElements = elements
      sortedElements.sort()
      check sortedElements == @[111'u64, 222, 333]

      sketch.destroy()

    test "adding same element twice removes it":
      var sketch = newMinisketch32(capacity = 10)
      sketch.add(12345)
      sketch.add(12345)  # XOR property: adding again removes

      let (elements, success) = sketch.decode()
      check success
      check elements.len == 0

      sketch.destroy()

    test "adding zero is no-op":
      var sketch = newMinisketch32(capacity = 10)
      sketch.add(0)  # Should be ignored
      sketch.add(12345)

      let (elements, success) = sketch.decode()
      check success
      check elements.len == 1
      check elements[0] == 12345

      sketch.destroy()

suite "sketch serialization":
  when defined(useSystemMinisketch):
    test "serialized size":
      var sketch = newMinisketch32(capacity = 10)
      let size = sketch.serializedSize()
      # 32-bit field, capacity 10 -> 10 * 4 = 40 bytes
      check size == 40
      sketch.destroy()

    test "serialize and deserialize":
      var sketch1 = newMinisketch32(capacity = 10)
      sketch1.add(111)
      sketch1.add(222)
      sketch1.add(333)

      let data = sketch1.serialize()
      check data.len == 40

      var sketch2 = newMinisketch32(capacity = 10)
      sketch2.deserialize(data)

      let (elements, success) = sketch2.decode()
      check success
      check elements.len == 3

      sketch1.destroy()
      sketch2.destroy()

    test "serialization is deterministic":
      var sketch1 = newMinisketch32(capacity = 10)
      sketch1.setSeed(0xFFFFFFFFFFFFFFFF'u64)  # Fixed seed
      sketch1.add(111)
      sketch1.add(222)

      var sketch2 = newMinisketch32(capacity = 10)
      sketch2.setSeed(0xFFFFFFFFFFFFFFFF'u64)
      sketch2.add(111)
      sketch2.add(222)

      check sketch1.serialize() == sketch2.serialize()

      sketch1.destroy()
      sketch2.destroy()

suite "sketch merging":
  when defined(useSystemMinisketch):
    test "merge identical sketches yields empty":
      var sketch1 = newMinisketch32(capacity = 10)
      sketch1.add(111)
      sketch1.add(222)

      var sketch2 = sketch1.clone()

      let newCap = sketch1.merge(sketch2)
      check newCap > 0

      let (elements, success) = sketch1.decode()
      check success
      check elements.len == 0  # XOR of identical = empty

      sketch1.destroy()
      sketch2.destroy()

    test "merge finds symmetric difference":
      var sketch1 = newMinisketch32(capacity = 10)
      sketch1.add(111)
      sketch1.add(222)
      sketch1.add(333)

      var sketch2 = newMinisketch32(capacity = 10)
      sketch2.add(111)  # Common
      sketch2.add(444)
      sketch2.add(555)

      let newCap = sketch1.merge(sketch2)
      check newCap > 0

      let (elements, success) = sketch1.decode()
      check success
      # Difference: 222, 333 (only in sketch1), 444, 555 (only in sketch2)
      check elements.len == 4

      var sortedElements = elements
      sortedElements.sort()
      check sortedElements == @[222'u64, 333, 444, 555]

      sketch1.destroy()
      sketch2.destroy()

suite "set reconciliation scenario":
  when defined(useSystemMinisketch):
    test "basic reconciliation":
      # Simulate reconciliation between two peers
      # Peer A has: 100, 200, 300, 400
      # Peer B has: 100, 200, 500, 600
      # Difference: 300, 400 (A only), 500, 600 (B only)

      var sketchA = newMinisketch32(capacity = 10)
      sketchA.add(100)
      sketchA.add(200)
      sketchA.add(300)
      sketchA.add(400)

      var sketchB = newMinisketch32(capacity = 10)
      sketchB.add(100)
      sketchB.add(200)
      sketchB.add(500)
      sketchB.add(600)

      # A sends sketch to B
      let sketchDataA = sketchA.serialize()

      # B deserializes and merges
      var receivedSketch = newMinisketch32(capacity = 10)
      receivedSketch.deserialize(sketchDataA)

      discard sketchB.merge(receivedSketch)

      # B decodes to find difference
      let (diff, success) = sketchB.decode()
      check success
      check diff.len == 4

      var sortedDiff = diff
      sortedDiff.sort()
      check sortedDiff == @[300'u64, 400, 500, 600]

      sketchA.destroy()
      sketchB.destroy()
      receivedSketch.destroy()

    test "reconciliation with capacity limit":
      # Test that decoding fails when difference exceeds capacity
      var sketchA = newMinisketch32(capacity = 5)  # Small capacity
      var sketchB = newMinisketch32(capacity = 5)

      # Create difference larger than capacity
      for i in 1..10:
        sketchA.add(uint64(i))

      for i in 11..20:
        sketchB.add(uint64(i))

      discard sketchA.merge(sketchB)

      let (diff, success) = sketchA.decode()
      # Should fail because difference (20) > capacity (5)
      check not success

      sketchA.destroy()
      sketchB.destroy()

    test "reconciliation with sufficient capacity":
      # Test successful decoding with proper capacity
      var sketchA = newMinisketch32(capacity = 20)
      var sketchB = newMinisketch32(capacity = 20)

      # Create moderate difference
      for i in 1..5:
        sketchA.add(uint64(i))
        sketchB.add(uint64(i + 10))

      discard sketchA.merge(sketchB)

      let (diff, success) = sketchA.decode()
      check success
      check diff.len == 10  # 5 from A + 5 from B

      sketchA.destroy()
      sketchB.destroy()

suite "capacity calculation":
  test "compute capacity":
    let cap = computeCapacity(bits = 32, maxElements = 10, fpbits = 16)
    when defined(useSystemMinisketch):
      # Should return something >= maxElements
      check cap >= 10
    else:
      check cap == 0

  test "compute max elements":
    let maxElems = computeMaxElements(bits = 32, capacity = 15, fpbits = 16)
    when defined(useSystemMinisketch):
      check maxElems > 0
    else:
      check maxElems == 0
