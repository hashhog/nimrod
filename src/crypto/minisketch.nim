## Minisketch FFI bindings for BIP330 Erlay set reconciliation
## Reference: https://github.com/sipa/minisketch
## Reference: Bitcoin Core /src/minisketch/include/minisketch.h
##
## Minisketch is a BCH-based set reconciliation library that allows
## two parties to efficiently determine the symmetric difference
## between their sets without transmitting the full sets.

type
  MinisketchPtr = distinct pointer

  Minisketch* = object
    ## Nim wrapper around a minisketch object
    handle*: MinisketchPtr  # 'ptr' is a Nim keyword
    bits: uint32
    capacity: uint

  MinisketchError* = object of CatchableError

const
  ## Default field size for Erlay (32-bit short IDs)
  ErlayFieldSize* = 32'u32

  ## Default false positive bits for capacity calculation
  DefaultFpBits* = 16'u32

# FFI bindings to libminisketch
when defined(useSystemMinisketch):
  {.passL: "-lminisketch".}

  proc minisketch_bits_supported(bits: cuint): cint
    {.importc, cdecl.}

  proc minisketch_implementation_max(): cuint
    {.importc, cdecl.}

  proc minisketch_implementation_supported(bits, impl: cuint): cint
    {.importc, cdecl.}

  proc minisketch_create(bits, impl: cuint, capacity: csize_t): MinisketchPtr
    {.importc, cdecl.}

  proc minisketch_clone(sketch: MinisketchPtr): MinisketchPtr
    {.importc, cdecl.}

  proc minisketch_destroy(sketch: MinisketchPtr)
    {.importc, cdecl.}

  proc minisketch_bits(sketch: MinisketchPtr): cuint
    {.importc, cdecl.}

  proc minisketch_capacity(sketch: MinisketchPtr): csize_t
    {.importc, cdecl.}

  proc minisketch_implementation(sketch: MinisketchPtr): cuint
    {.importc, cdecl.}

  proc minisketch_set_seed(sketch: MinisketchPtr, seed: uint64)
    {.importc, cdecl.}

  proc minisketch_serialized_size(sketch: MinisketchPtr): csize_t
    {.importc, cdecl.}

  proc minisketch_serialize(sketch: MinisketchPtr, output: ptr byte)
    {.importc, cdecl.}

  proc minisketch_deserialize(sketch: MinisketchPtr, input: ptr byte)
    {.importc, cdecl.}

  proc minisketch_add_uint64(sketch: MinisketchPtr, element: uint64)
    {.importc, cdecl.}

  proc minisketch_merge(sketch, other: MinisketchPtr): csize_t
    {.importc, cdecl.}

  proc minisketch_decode(sketch: MinisketchPtr, maxElements: csize_t,
                         output: ptr uint64): int64
    {.importc, cdecl.}

  proc minisketch_compute_capacity(bits: cuint, maxElements: csize_t,
                                    fpbits: cuint): csize_t
    {.importc, cdecl.}

  proc minisketch_compute_max_elements(bits: cuint, capacity: csize_t,
                                        fpbits: cuint): csize_t
    {.importc, cdecl.}

  proc bitsSupported*(bits: uint32): bool =
    ## Check if the library supports a given field size
    minisketch_bits_supported(cuint(bits)) != 0

  proc implementationMax*(): uint32 =
    ## Get the maximum implementation number
    uint32(minisketch_implementation_max())

  proc implementationSupported*(bits, impl: uint32): bool =
    ## Check if a specific implementation is supported for given bits
    minisketch_implementation_supported(cuint(bits), cuint(impl)) != 0

  proc computeCapacity*(bits: uint32, maxElements: uint, fpbits: uint32): uint =
    ## Compute capacity needed for given max elements with false positive probability
    uint(minisketch_compute_capacity(cuint(bits), csize_t(maxElements), cuint(fpbits)))

  proc computeMaxElements*(bits: uint32, capacity: uint, fpbits: uint32): uint =
    ## Compute max elements that can be decoded from given capacity
    uint(minisketch_compute_max_elements(cuint(bits), csize_t(capacity), cuint(fpbits)))

  proc findBestImplementation*(bits: uint32): uint32 =
    ## Find the best (fastest) supported implementation for given field size
    ## Implementation 0 is always the fallback
    result = 0
    let maxImpl = implementationMax()
    for impl in countdown(maxImpl, 0'u32):
      if implementationSupported(bits, impl):
        return impl

  proc newMinisketch*(bits: uint32, capacity: uint, impl: uint32 = 0): Minisketch =
    ## Create a new Minisketch with given parameters
    ## Uses the best available implementation if impl = 0
    let actualImpl = if impl == 0: findBestImplementation(bits) else: impl

    if not bitsSupported(bits):
      raise newException(MinisketchError, "unsupported field size: " & $bits)

    if not implementationSupported(bits, actualImpl):
      raise newException(MinisketchError, "unsupported implementation: " & $actualImpl)

    let sketchPtr = minisketch_create(cuint(bits), cuint(actualImpl), csize_t(capacity))
    if pointer(sketchPtr) == nil:
      raise newException(MinisketchError, "failed to create minisketch")

    result.handle = sketchPtr
    result.bits = bits
    result.capacity = capacity

  proc newMinisketchFP*(bits: uint32, maxElements: uint,
                         fpbits: uint32 = DefaultFpBits): Minisketch =
    ## Create a Minisketch with capacity computed from false positive probability
    let capacity = computeCapacity(bits, maxElements, fpbits)
    newMinisketch(bits, capacity)

  proc newMinisketch32*(capacity: uint): Minisketch =
    ## Create a 32-bit field minisketch (Erlay default)
    newMinisketch(ErlayFieldSize, capacity)

  proc newMinisketch32FP*(maxElements: uint,
                           fpbits: uint32 = DefaultFpBits): Minisketch =
    ## Create a 32-bit field minisketch with computed capacity
    newMinisketchFP(ErlayFieldSize, maxElements, fpbits)

  proc isValid*(m: Minisketch): bool =
    ## Check if the minisketch is valid
    pointer(m.handle) != nil

  proc clone*(m: Minisketch): Minisketch =
    ## Create a deep copy of a minisketch
    if not m.isValid():
      raise newException(MinisketchError, "cannot clone invalid minisketch")

    let sketchPtr = minisketch_clone(m.handle)
    if pointer(sketchPtr) == nil:
      raise newException(MinisketchError, "failed to clone minisketch")

    result.handle = sketchPtr
    result.bits = m.bits
    result.capacity = m.capacity

  proc destroy*(m: var Minisketch) =
    ## Destroy a minisketch and free resources
    if m.isValid():
      minisketch_destroy(m.handle)
      m.handle = MinisketchPtr(nil)

  proc getBits*(m: Minisketch): uint32 =
    ## Get the field size in bits
    if not m.isValid():
      return 0
    uint32(minisketch_bits(m.handle))

  proc getCapacity*(m: Minisketch): uint =
    ## Get the capacity of the sketch
    if not m.isValid():
      return 0
    uint(minisketch_capacity(m.handle))

  proc getImplementation*(m: Minisketch): uint32 =
    ## Get the implementation number
    if not m.isValid():
      return 0
    uint32(minisketch_implementation(m.handle))

  proc setSeed*(m: var Minisketch, seed: uint64) =
    ## Set the seed for randomizing algorithm choices
    ## Use -1 (max uint64) for deterministic behavior in tests
    if m.isValid():
      minisketch_set_seed(m.handle, seed)

  proc add*(m: var Minisketch, element: uint64) =
    ## Add an element to the sketch (or remove if already present)
    ## Note: element 0 is a no-op
    if m.isValid():
      minisketch_add_uint64(m.handle, element)

  proc serializedSize*(m: Minisketch): uint =
    ## Get the size in bytes of the serialized sketch
    if not m.isValid():
      return 0
    uint(minisketch_serialized_size(m.handle))

  proc serialize*(m: Minisketch): seq[byte] =
    ## Serialize the sketch to bytes
    if not m.isValid():
      return @[]

    let size = m.serializedSize()
    result = newSeq[byte](size)
    if size > 0:
      minisketch_serialize(m.handle, addr result[0])

  proc deserialize*(m: var Minisketch, data: openArray[byte]) =
    ## Deserialize bytes into the sketch
    ## Data must match the serialized size exactly
    if not m.isValid():
      raise newException(MinisketchError, "cannot deserialize into invalid minisketch")

    let expectedSize = m.serializedSize()
    if uint(data.len) != expectedSize:
      raise newException(MinisketchError,
        "data size mismatch: expected " & $expectedSize & ", got " & $data.len)

    if data.len > 0:
      var dataCopy = @data  # Need mutable copy
      minisketch_deserialize(m.handle, addr dataCopy[0])

  proc merge*(m: var Minisketch, other: Minisketch): uint =
    ## Merge another sketch into this one (XOR operation)
    ## Returns the new capacity, or 0 if merge failed
    if not m.isValid() or not other.isValid():
      return 0

    result = uint(minisketch_merge(m.handle, other.handle))

  proc decode*(m: Minisketch, maxElements: uint): (seq[uint64], bool) =
    ## Decode the sketch to recover the set difference
    ## Returns (elements, success)
    ## If success is false, decoding failed (too many elements)
    if not m.isValid():
      return (@[], false)

    var output = newSeq[uint64](maxElements)
    let count = minisketch_decode(m.handle, csize_t(maxElements), addr output[0])

    if count < 0:
      return (@[], false)

    output.setLen(count)
    (output, true)

  proc decode*(m: Minisketch): (seq[uint64], bool) =
    ## Decode using the sketch's capacity as max elements
    m.decode(m.getCapacity())

else:
  # Stub implementations when libminisketch not available
  proc bitsSupported*(bits: uint32): bool = false
  proc implementationMax*(): uint32 = 0
  proc implementationSupported*(bits, impl: uint32): bool = false
  proc computeCapacity*(bits: uint32, maxElements: uint, fpbits: uint32): uint = 0
  proc computeMaxElements*(bits: uint32, capacity: uint, fpbits: uint32): uint = 0
  proc findBestImplementation*(bits: uint32): uint32 = 0

  proc newMinisketch*(bits: uint32, capacity: uint, impl: uint32 = 0): Minisketch =
    raise newException(MinisketchError,
      "minisketch not available - compile with -d:useSystemMinisketch")

  proc newMinisketchFP*(bits: uint32, maxElements: uint,
                         fpbits: uint32 = DefaultFpBits): Minisketch =
    raise newException(MinisketchError,
      "minisketch not available - compile with -d:useSystemMinisketch")

  proc newMinisketch32*(capacity: uint): Minisketch =
    raise newException(MinisketchError,
      "minisketch not available - compile with -d:useSystemMinisketch")

  proc newMinisketch32FP*(maxElements: uint,
                           fpbits: uint32 = DefaultFpBits): Minisketch =
    raise newException(MinisketchError,
      "minisketch not available - compile with -d:useSystemMinisketch")

  proc isValid*(m: Minisketch): bool = false
  proc clone*(m: Minisketch): Minisketch =
    raise newException(MinisketchError, "minisketch not available")
  proc destroy*(m: var Minisketch) = discard
  proc getBits*(m: Minisketch): uint32 = 0
  proc getCapacity*(m: Minisketch): uint = 0
  proc getImplementation*(m: Minisketch): uint32 = 0
  proc setSeed*(m: var Minisketch, seed: uint64) = discard
  proc add*(m: var Minisketch, element: uint64) = discard
  proc serializedSize*(m: Minisketch): uint = 0
  proc serialize*(m: Minisketch): seq[byte] = @[]
  proc deserialize*(m: var Minisketch, data: openArray[byte]) = discard
  proc merge*(m: var Minisketch, other: Minisketch): uint = 0
  proc decode*(m: Minisketch, maxElements: uint): (seq[uint64], bool) = (@[], false)
  proc decode*(m: Minisketch): (seq[uint64], bool) = (@[], false)
