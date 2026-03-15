## secp256k1 elliptic curve operations
## FFI bindings to libsecp256k1 via importc

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

  proc secp256k1_xonly_pubkey_parse(
    ctx: Secp256k1Context,
    pubkey: ptr Secp256k1XonlyPubkey,
    input32: ptr byte
  ): cint {.importc, cdecl.}

  proc secp256k1_schnorrsig_verify(
    ctx: Secp256k1Context,
    sig64: ptr byte,
    msg: ptr byte,
    msgLen: csize_t,
    pubkey: ptr Secp256k1XonlyPubkey
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
