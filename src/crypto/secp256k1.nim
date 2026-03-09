## secp256k1 elliptic curve operations
## FFI bindings to libsecp256k1 via importc

import std/[os]

# Constants
const
  SECP256K1_CONTEXT_SIGN* = 1'u32
  SECP256K1_CONTEXT_VERIFY* = 2'u32
  SECP256K1_FLAGS_TYPE_CONTEXT* = 1'u32 shl 0
  SECP256K1_FLAGS_BIT_CONTEXT_SIGN* = 1'u32 shl 9
  SECP256K1_FLAGS_BIT_CONTEXT_VERIFY* = 1'u32 shl 8

type
  Secp256k1Context* = distinct pointer
  Secp256k1Pubkey* = object
    data*: array[64, byte]
  Secp256k1Signature* = object
    data*: array[64, byte]
  Secp256k1EcdsaSignature* = object
    data*: array[64, byte]

  Secp256k1Error* = object of CatchableError
  PrivateKey* = array[32, byte]
  PublicKey* = array[33, byte]  # Compressed
  UncompressedPublicKey* = array[65, byte]
  Signature* = array[64, byte]

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
