## secp256k1 elliptic curve operations
## FFI bindings to libsecp256k1 via importc
##
## Hardware Acceleration:
## libsecp256k1 should be built with assembly optimizations enabled.
## On x86_64, this uses optimized field/scalar arithmetic.
## Configure with: ./configure --enable-module-recovery --enable-module-schnorrsig
## Build with: make CFLAGS="-O3 -march=native"
##
## Verify optimizations are enabled:
##   strings /usr/lib/libsecp256k1.so | grep -i "asm\|simd"
##
## Performance targets:
## - ECDSA verify: ~50,000 ops/sec on modern x86_64
## - Schnorr verify: ~45,000 ops/sec on modern x86_64

import std/[os]

# Constants - must match libsecp256k1 headers
const
  SECP256K1_CONTEXT_NONE* = 0x0001'u32
  SECP256K1_CONTEXT_VERIFY* = 0x0101'u32
  SECP256K1_CONTEXT_SIGN* = 0x0201'u32
  SECP256K1_FLAGS_TYPE_CONTEXT* = 1'u32 shl 0
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN* = 1'u32 shl 9
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY* = 1'u32 shl 8
  SECP256K1_EC_COMPRESSED* = 258'u32

type
  Secp256k1Context* = distinct pointer
  Secp256k1Pubkey* = object
    data*: array[64, byte]
  Secp256k1Signature* = object
    data*: array[64, byte]
  Secp256k1EcdsaSignature* = object
    data*: array[64, byte]
  Secp256k1XonlyPubkey* = object
    ## X-only public key for Schnorr signatures (BIP340)
    data*: array[64, byte]

  Secp256k1Error* = object of CatchableError

  # ElligatorSwift types for BIP-324
  EllSwiftPubKey* = array[64, byte]

  # Function pointer type for ECDH hash function
  Secp256k1EllswiftXdhHashFunction* = proc(
    output: ptr byte,
    x32: ptr byte,
    ellA64: ptr byte,
    ellB64: ptr byte,
    data: pointer
  ): cint {.cdecl.}
  PrivateKey* = array[32, byte]
  PublicKey* = array[33, byte]  # Compressed
  UncompressedPublicKey* = array[65, byte]
  Signature* = array[64, byte]
  SchnorrSignature* = array[64, byte]
  XonlyPubkey* = array[32, byte]

# FFI bindings to libsecp256k1
when defined(useSystemSecp256k1):
  {.passL: "-lsecp256k1".}

  proc secp256k1_context_create(flags: cuint): Secp256k1Context
    {.importc, cdecl.}

  proc secp256k1_context_destroy(ctx: Secp256k1Context)
    {.importc, cdecl.}

  proc secp256k1_ec_pubkey_create(
    ctx: Secp256k1Context,
    pubkey: ptr Secp256k1Pubkey,
    seckey: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_ec_pubkey_serialize(
    ctx: Secp256k1Context,
    output: ptr byte,
    outputLen: ptr csize_t,
    pubkey: ptr Secp256k1Pubkey,
    flags: cuint
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_sign(
    ctx: Secp256k1Context,
    sig: ptr Secp256k1EcdsaSignature,
    msg32: ptr byte,
    seckey: ptr byte,
    noncefp: pointer,
    ndata: pointer
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_verify(
    ctx: Secp256k1Context,
    sig: ptr Secp256k1EcdsaSignature,
    msg32: ptr byte,
    pubkey: ptr Secp256k1Pubkey
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_signature_serialize_compact(
    ctx: Secp256k1Context,
    output64: ptr byte,
    sig: ptr Secp256k1EcdsaSignature
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_signature_parse_compact(
    ctx: Secp256k1Context,
    sig: ptr Secp256k1EcdsaSignature,
    input64: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_ec_pubkey_parse(
    ctx: Secp256k1Context,
    pubkey: ptr Secp256k1Pubkey,
    input: ptr byte,
    inputLen: csize_t
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_signature_parse_der(
    ctx: Secp256k1Context,
    sig: ptr Secp256k1EcdsaSignature,
    input: ptr byte,
    inputLen: csize_t
  ): cint {.importc, cdecl.}

  proc secp256k1_ecdsa_signature_normalize(
    ctx: Secp256k1Context,
    sigout: ptr Secp256k1EcdsaSignature,
    sigin: ptr Secp256k1EcdsaSignature
  ): cint {.importc, cdecl.}

  proc secp256k1_xonly_pubkey_parse(
    ctx: Secp256k1Context,
    pubkey: ptr Secp256k1XonlyPubkey,
    input32: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_xonly_pubkey_serialize(
    ctx: Secp256k1Context,
    output32: ptr byte,
    pubkey: ptr Secp256k1XonlyPubkey
  ): cint {.importc, cdecl.}

  proc secp256k1_xonly_pubkey_tweak_add(
    ctx: Secp256k1Context,
    output_pubkey: ptr Secp256k1Pubkey,
    internal_pubkey: ptr Secp256k1XonlyPubkey,
    tweak32: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_xonly_pubkey_from_pubkey(
    ctx: Secp256k1Context,
    xonly_pubkey: ptr Secp256k1XonlyPubkey,
    pk_parity: ptr cint,
    pubkey: ptr Secp256k1Pubkey
  ): cint {.importc, cdecl.}

  proc secp256k1_schnorrsig_verify(
    ctx: Secp256k1Context,
    sig64: ptr byte,
    msg: ptr byte,
    msgLen: csize_t,
    pubkey: ptr Secp256k1XonlyPubkey
  ): cint {.importc, cdecl.}

  # ElligatorSwift FFI bindings (BIP-324)
  # The hash function for BIP-324 compatible ECDH
  var secp256k1_ellswift_xdh_hash_function_bip324* {.importc.}: Secp256k1EllswiftXdhHashFunction

  proc secp256k1_ellswift_create(
    ctx: Secp256k1Context,
    ell64: ptr byte,
    seckey32: ptr byte,
    auxrnd32: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_ellswift_xdh(
    ctx: Secp256k1Context,
    output: ptr byte,
    ellA64: ptr byte,
    ellB64: ptr byte,
    seckey32: ptr byte,
    party: cint,
    hashfp: Secp256k1EllswiftXdhHashFunction,
    data: pointer
  ): cint {.importc, cdecl.}

  var globalContext: Secp256k1Context

  proc initSecp256k1*() =
    if pointer(globalContext) == nil:
      globalContext = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
      )

  proc getContext(): Secp256k1Context =
    if pointer(globalContext) == nil:
      initSecp256k1()
    globalContext

  proc derivePublicKey*(privateKey: PrivateKey): PublicKey =
    var pubkey: Secp256k1Pubkey
    var pk = privateKey
    if secp256k1_ec_pubkey_create(getContext(), addr pubkey, addr pk[0]) != 1:
      raise newException(Secp256k1Error, "failed to derive public key")

    var outputLen: csize_t = 33
    const SECP256K1_EC_COMPRESSED = 258'u32
    if secp256k1_ec_pubkey_serialize(
      getContext(), addr result[0], addr outputLen,
      addr pubkey, SECP256K1_EC_COMPRESSED
    ) != 1:
      raise newException(Secp256k1Error, "failed to serialize public key")

  proc sign*(privateKey: PrivateKey, msgHash: array[32, byte]): Signature =
    var sig: Secp256k1EcdsaSignature
    var pk = privateKey
    var msg = msgHash
    if secp256k1_ecdsa_sign(
      getContext(), addr sig, addr msg[0], addr pk[0], nil, nil
    ) != 1:
      raise newException(Secp256k1Error, "failed to sign")

    if secp256k1_ecdsa_signature_serialize_compact(
      getContext(), addr result[0], addr sig
    ) != 1:
      raise newException(Secp256k1Error, "failed to serialize signature")

  proc verify*(
    publicKey: PublicKey,
    msgHash: array[32, byte],
    signature: Signature
  ): bool =
    var pubkey: Secp256k1Pubkey
    var pk = publicKey
    if secp256k1_ec_pubkey_parse(
      getContext(), addr pubkey, addr pk[0], 33
    ) != 1:
      return false

    var sig: Secp256k1EcdsaSignature
    var sigData = signature
    if secp256k1_ecdsa_signature_parse_compact(
      getContext(), addr sig, addr sigData[0]
    ) != 1:
      return false

    var msg = msgHash
    result = secp256k1_ecdsa_verify(getContext(), addr sig, addr msg[0], addr pubkey) == 1

  proc verifyDer*(
    publicKey: openArray[byte],
    msgHash: array[32, byte],
    derSignature: openArray[byte]
  ): bool =
    ## Verify ECDSA signature with DER-encoded signature
    if publicKey.len == 0 or derSignature.len == 0:
      return false

    var pubkey: Secp256k1Pubkey
    var pk = newSeq[byte](publicKey.len)
    for i, b in publicKey:
      pk[i] = b
    if secp256k1_ec_pubkey_parse(
      getContext(), addr pubkey, addr pk[0], csize_t(publicKey.len)
    ) != 1:
      return false

    var sig: Secp256k1EcdsaSignature
    var sigData = newSeq[byte](derSignature.len)
    for i, b in derSignature:
      sigData[i] = b
    if secp256k1_ecdsa_signature_parse_der(
      getContext(), addr sig, addr sigData[0], csize_t(derSignature.len)
    ) != 1:
      return false

    var msg = msgHash
    result = secp256k1_ecdsa_verify(getContext(), addr sig, addr msg[0], addr pubkey) == 1

  proc ecdsaSignatureParseDerLax*(
    sig: var Secp256k1EcdsaSignature,
    input: openArray[byte]
  ): bool =
    ## Lax DER signature parser matching Bitcoin Core's ecdsa_signature_parse_der_lax.
    ## Accepts non-standard DER encodings that strict parsing would reject.
    ## This is used for consensus-compatible signature verification.
    if input.len == 0:
      return false

    var pos = 0
    let inputLen = input.len

    # Initialize sig with a correctly-parsed but invalid signature
    var tmpsig: array[64, byte]
    discard secp256k1_ecdsa_signature_parse_compact(getContext(), addr sig, addr tmpsig[0])

    # Sequence tag byte
    if pos == inputLen or input[pos] != 0x30:
      return false
    inc pos

    # Sequence length bytes
    if pos == inputLen:
      return false
    var lenbyte = int(input[pos])
    inc pos
    if (lenbyte and 0x80) != 0:
      lenbyte -= 0x80
      if lenbyte > inputLen - pos:
        return false
      pos += lenbyte

    # Integer tag byte for R
    if pos == inputLen or input[pos] != 0x02:
      return false
    inc pos

    # Integer length for R
    if pos == inputLen:
      return false
    lenbyte = int(input[pos])
    inc pos
    var rlen: int
    if (lenbyte and 0x80) != 0:
      lenbyte -= 0x80
      if lenbyte > inputLen - pos:
        return false
      while lenbyte > 0 and input[pos] == 0:
        inc pos
        dec lenbyte
      if lenbyte >= 4:
        return false
      rlen = 0
      while lenbyte > 0:
        rlen = (rlen shl 8) + int(input[pos])
        inc pos
        dec lenbyte
    else:
      rlen = lenbyte

    if rlen > inputLen - pos:
      return false
    var rpos = pos
    pos += rlen

    # Integer tag byte for S
    if pos == inputLen or input[pos] != 0x02:
      return false
    inc pos

    # Integer length for S
    if pos == inputLen:
      return false
    lenbyte = int(input[pos])
    inc pos
    var slen: int
    if (lenbyte and 0x80) != 0:
      lenbyte -= 0x80
      if lenbyte > inputLen - pos:
        return false
      while lenbyte > 0 and input[pos] == 0:
        inc pos
        dec lenbyte
      if lenbyte >= 4:
        return false
      slen = 0
      while lenbyte > 0:
        slen = (slen shl 8) + int(input[pos])
        inc pos
        dec lenbyte
    else:
      slen = lenbyte

    if slen > inputLen - pos:
      return false
    var spos = pos

    # Reset tmpsig
    for i in 0 ..< 64:
      tmpsig[i] = 0

    # Ignore leading zeroes in R
    while rlen > 0 and input[rpos] == 0:
      dec rlen
      inc rpos
    # Copy R value
    var overflow = false
    if rlen > 32:
      overflow = true
    else:
      for i in 0 ..< rlen:
        tmpsig[32 - rlen + i] = input[rpos + i]

    # Ignore leading zeroes in S
    while slen > 0 and input[spos] == 0:
      dec slen
      inc spos
    # Copy S value
    if slen > 32:
      overflow = true
    else:
      for i in 0 ..< slen:
        tmpsig[64 - slen + i] = input[spos + i]

    if not overflow:
      overflow = secp256k1_ecdsa_signature_parse_compact(
        getContext(), addr sig, addr tmpsig[0]
      ) != 1
    if overflow:
      for i in 0 ..< 64:
        tmpsig[i] = 0
      discard secp256k1_ecdsa_signature_parse_compact(
        getContext(), addr sig, addr tmpsig[0]
      )

    true

  proc verifyDerLax*(
    publicKey: openArray[byte],
    msgHash: array[32, byte],
    derSignature: openArray[byte]
  ): bool =
    ## Verify ECDSA signature with lax DER parsing and S normalization.
    ## This matches Bitcoin Core's CPubKey::Verify behavior:
    ## 1. Parse with lax DER parser (accepts non-standard encodings)
    ## 2. Normalize S to lower half of curve order
    ## 3. Verify with libsecp256k1
    if publicKey.len == 0 or derSignature.len == 0:
      return false

    var pubkey: Secp256k1Pubkey
    var pk = newSeq[byte](publicKey.len)
    for i, b in publicKey:
      pk[i] = b
    if secp256k1_ec_pubkey_parse(
      getContext(), addr pubkey, addr pk[0], csize_t(publicKey.len)
    ) != 1:
      return false

    var sig: Secp256k1EcdsaSignature
    var sigData = newSeq[byte](derSignature.len)
    for i, b in derSignature:
      sigData[i] = b
    if not ecdsaSignatureParseDerLax(sig, sigData):
      return false

    # Normalize S to lower half (Bitcoin Core does this unconditionally)
    discard secp256k1_ecdsa_signature_normalize(getContext(), addr sig, addr sig)

    var msg = msgHash
    result = secp256k1_ecdsa_verify(getContext(), addr sig, addr msg[0], addr pubkey) == 1

  proc isLowS*(derSignature: openArray[byte]): bool =
    ## Check if the S value in a DER signature is in the lower half of the curve order.
    ## Used for LOW_S flag enforcement.
    if derSignature.len == 0:
      return false
    var sig: Secp256k1EcdsaSignature
    var sigData = newSeq[byte](derSignature.len)
    for i, b in derSignature:
      sigData[i] = b
    if secp256k1_ecdsa_signature_parse_der(
      getContext(), addr sig, addr sigData[0], csize_t(derSignature.len)
    ) != 1:
      return false
    # normalize returns 1 if sig was NOT normalized (i.e. S was high)
    result = secp256k1_ecdsa_signature_normalize(getContext(), nil, addr sig) != 1

  proc verifySchnorr*(
    pubkey: XonlyPubkey,
    msg: openArray[byte],
    signature: SchnorrSignature
  ): bool =
    ## Verify BIP340 Schnorr signature
    var xonlyPk: Secp256k1XonlyPubkey
    var pk = pubkey
    if secp256k1_xonly_pubkey_parse(
      getContext(), addr xonlyPk, addr pk[0]
    ) != 1:
      return false

    var sig = signature
    if msg.len == 0:
      return false

    var msgData = newSeq[byte](msg.len)
    for i, b in msg:
      msgData[i] = b

    result = secp256k1_schnorrsig_verify(
      getContext(), addr sig[0], addr msgData[0], csize_t(msg.len), addr xonlyPk
    ) == 1

  proc tweakXonlyPubkey*(
    internalPk: array[32, byte],
    tweak: array[32, byte]
  ): (array[32, byte], int) =
    ## Tweak an x-only pubkey: output_key = internal_key + tweak * G
    ## Returns (output_x_only_key, parity).
    ## Raises on failure.
    var xonlyPk: Secp256k1XonlyPubkey
    var pk = internalPk
    if secp256k1_xonly_pubkey_parse(getContext(), addr xonlyPk, addr pk[0]) != 1:
      raise newException(Secp256k1Error, "failed to parse x-only pubkey for tweak")

    var tweakBytes = tweak
    var outPubkey: Secp256k1Pubkey
    if secp256k1_xonly_pubkey_tweak_add(
      getContext(), addr outPubkey, addr xonlyPk, addr tweakBytes[0]
    ) != 1:
      raise newException(Secp256k1Error, "failed to tweak x-only pubkey")

    var outXonly: Secp256k1XonlyPubkey
    var parity: cint = 0
    if secp256k1_xonly_pubkey_from_pubkey(
      getContext(), addr outXonly, addr parity, addr outPubkey
    ) != 1:
      raise newException(Secp256k1Error, "failed to extract x-only from tweaked pubkey")

    var outputKey: array[32, byte]
    if secp256k1_xonly_pubkey_serialize(
      getContext(), addr outputKey[0], addr outXonly
    ) != 1:
      raise newException(Secp256k1Error, "failed to serialize tweaked x-only pubkey")

    result = (outputKey, int(parity))

  # ==========================================================================
  # ElligatorSwift (BIP-324)
  # ==========================================================================

  proc ellswiftCreate*(privateKey: PrivateKey, auxRand: openArray[byte] = []): EllSwiftPubKey =
    ## Create a 64-byte ElligatorSwift public key from a private key
    ## auxRand is optional 32 bytes of randomness for encoding variety
    var pk = privateKey
    var auxPtr: ptr byte = nil
    var auxData: array[32, byte]

    if auxRand.len >= 32:
      for i in 0..<32:
        auxData[i] = auxRand[i]
      auxPtr = addr auxData[0]

    if secp256k1_ellswift_create(
      getContext(), addr result[0], addr pk[0], auxPtr
    ) != 1:
      raise newException(Secp256k1Error, "failed to create ElligatorSwift public key")

  proc computeBIP324ECDHSecret*(
    privateKey: PrivateKey,
    ourPubKey: EllSwiftPubKey,
    theirPubKey: EllSwiftPubKey,
    initiator: bool
  ): array[32, byte] =
    ## Compute BIP-324 ECDH shared secret
    ## initiator is true if we initiated the connection (we are party A)
    var pk = privateKey
    var ourPk = ourPubKey
    var theirPk = theirPubKey

    # Determine party order: initiator is party A, responder is party B
    # ell_a64 is always initiator's key, ell_b64 is responder's key
    var ellA: ptr byte
    var ellB: ptr byte
    var party: cint

    if initiator:
      ellA = addr ourPk[0]
      ellB = addr theirPk[0]
      party = 0  # We are party A
    else:
      ellA = addr theirPk[0]
      ellB = addr ourPk[0]
      party = 1  # We are party B

    if secp256k1_ellswift_xdh(
      getContext(), addr result[0],
      ellA, ellB,
      addr pk[0], party,
      secp256k1_ellswift_xdh_hash_function_bip324, nil
    ) != 1:
      raise newException(Secp256k1Error, "failed to compute BIP-324 ECDH secret")

  # High-level CryptoEngine wrapper
  type
    CryptoEngine* = object
      ## High-level wrapper for secp256k1 crypto operations
      ctx: Secp256k1Context

  proc newCryptoEngine*(): CryptoEngine =
    ## Create a new crypto engine with its own context
    result.ctx = secp256k1_context_create(
      SECP256K1_CONTEXT_SIGN or SECP256K1_CONTEXT_VERIFY
    )

  proc close*(e: var CryptoEngine) =
    ## Close and cleanup the crypto engine
    if pointer(e.ctx) != nil:
      secp256k1_context_destroy(e.ctx)
      e.ctx = Secp256k1Context(nil)

  proc verifyEcdsa*(e: CryptoEngine, sig, pubkey: openArray[byte], msgHash: array[32, byte]): bool =
    ## Verify ECDSA signature using the engine's context
    ## Supports both DER and compact signature formats
    if sig.len == 0 or pubkey.len == 0:
      return false

    var pk: Secp256k1Pubkey
    var pubkeyData = newSeq[byte](pubkey.len)
    for i, b in pubkey:
      pubkeyData[i] = b
    if secp256k1_ec_pubkey_parse(
      e.ctx, addr pk, addr pubkeyData[0], csize_t(pubkey.len)
    ) != 1:
      return false

    var ecdsaSig: Secp256k1EcdsaSignature
    var sigData = newSeq[byte](sig.len)
    for i, b in sig:
      sigData[i] = b

    # Try DER first, then compact
    if sig.len != 64:
      if secp256k1_ecdsa_signature_parse_der(
        e.ctx, addr ecdsaSig, addr sigData[0], csize_t(sig.len)
      ) != 1:
        return false
    else:
      if secp256k1_ecdsa_signature_parse_compact(
        e.ctx, addr ecdsaSig, addr sigData[0]
      ) != 1:
        return false

    var msg = msgHash
    result = secp256k1_ecdsa_verify(e.ctx, addr ecdsaSig, addr msg[0], addr pk) == 1

  proc verifySchnorr*(e: CryptoEngine, sig: array[64, byte], msg, pubkey: array[32, byte]): bool =
    ## Verify BIP340 Schnorr signature using the engine's context
    var xonlyPk: Secp256k1XonlyPubkey
    var pk = pubkey
    if secp256k1_xonly_pubkey_parse(
      e.ctx, addr xonlyPk, addr pk[0]
    ) != 1:
      return false

    var signature = sig
    var msgData = msg

    result = secp256k1_schnorrsig_verify(
      e.ctx, addr signature[0], addr msgData[0], csize_t(32), addr xonlyPk
    ) == 1

  # ==========================================================================
  # Benchmarking
  # ==========================================================================

  import std/[monotimes, times]

  proc benchEcdsaVerify*(iterations: int): float64 =
    ## Benchmark ECDSA verification throughput in ops/sec
    ## Uses pre-generated test vectors for consistent timing

    # Test vector: known good signature
    let privkey: PrivateKey = [
      0x01'u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
      0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
      0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    ]

    let msgHash: array[32, byte] = [
      0xaa'u8, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
      0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
    ]

    let pubkey = derivePublicKey(privkey)
    let signature = sign(privkey, msgHash)

    let start = getMonoTime()

    var verified = 0
    for _ in 0..<iterations:
      if verify(pubkey, msgHash, signature):
        inc verified

    let elapsed = (getMonoTime() - start).inMicroseconds
    let seconds = float64(elapsed) / 1_000_000.0

    # Ensure all verified (sanity check)
    assert verified == iterations, "Verification failed unexpectedly"

    result = float64(iterations) / seconds

else:
  # Stub implementations when libsecp256k1 not available
  proc initSecp256k1*() =
    discard

  proc derivePublicKey*(privateKey: PrivateKey): PublicKey =
    # Stub - requires actual crypto library
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc sign*(privateKey: PrivateKey, msgHash: array[32, byte]): Signature =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc verify*(
    publicKey: PublicKey,
    msgHash: array[32, byte],
    signature: Signature
  ): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc verifyDer*(
    publicKey: openArray[byte],
    msgHash: array[32, byte],
    derSignature: openArray[byte]
  ): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc verifyDerLax*(
    publicKey: openArray[byte],
    msgHash: array[32, byte],
    derSignature: openArray[byte]
  ): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc isLowS*(derSignature: openArray[byte]): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc verifySchnorr*(
    pubkey: XonlyPubkey,
    msg: openArray[byte],
    signature: SchnorrSignature
  ): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  # Stub CryptoEngine
  type
    CryptoEngine* = object
      discard

  proc newCryptoEngine*(): CryptoEngine =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc close*(e: var CryptoEngine) =
    discard

  proc verifyEcdsa*(e: CryptoEngine, sig, pubkey: openArray[byte], msgHash: array[32, byte]): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc verifySchnorr*(e: CryptoEngine, sig: array[64, byte], msg, pubkey: array[32, byte]): bool =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  # ElligatorSwift stubs
  proc ellswiftCreate*(privateKey: PrivateKey, auxRand: openArray[byte] = []): EllSwiftPubKey =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")

  proc computeBIP324ECDHSecret*(
    privateKey: PrivateKey,
    ourPubKey: EllSwiftPubKey,
    theirPubKey: EllSwiftPubKey,
    initiator: bool
  ): array[32, byte] =
    raise newException(Secp256k1Error, "secp256k1 not available - compile with -d:useSystemSecp256k1")
