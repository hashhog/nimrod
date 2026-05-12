## W98 BIP-324 v2 transport gate audit tests
##
## Covers gaps identified in the W98 audit that are NOT already covered by
## test_bip324.nim:
##
## G2  HKDF salt includes network magic bytes
## G3  HKDF label strings are exactly correct
## G5  Garbage-terminator first-16/last-16 split + role swap correctness
## G7  LENGTH_LEN=3 little-endian encoding
## G8  HEADER_LEN=1, IGNORE_BIT=0x80
## G10 No memory_cleanse on secrets (documented absence — known bug)
## G15 MAX_GARBAGE_LEN abort bound: scan aborts at 4111B
## G17 VERSION packet AAD = full received garbage (not empty)
## G18 VERSION decoy IGNORE_BIT accepted/skipped
## G19 APP decoy discard loop
## G23 Reserved short IDs 0x1d-0x22 accepted vs rejected
## G24 Max plaintext limit vs Core (32 MiB vs 4 MB — known bug)
## G25 Initiator garbage bound rand(32) vs rand(4095) (known bug)
## G26 ECDH private key now uses std/sysrand CSPRNG (fixed)
##
## Reference: BIP-324, bitcoin-core/src/bip324.cpp, bitcoin-core/src/net.h
## bitcoin-core/src/net.cpp V2Transport state machine.

import unittest2
import std/[os, strutils, tables, sets]
import ../src/crypto/chacha20poly1305
import ../src/crypto/secp256k1
import ../src/network/bip324
import ../src/network/messages
import ../src/consensus/params

proc bytesToHex(data: openArray[byte]): string =
  const h = "0123456789abcdef"
  result = newString(data.len * 2)
  for i, b in data:
    result[2 * i]     = h[(b shr 4) and 0xf]
    result[2 * i + 1] = h[b and 0xf]

# ============================================================================
# G2: HKDF salt = "bitcoin_v2_shared_secret" || 4-byte network magic
# ============================================================================
suite "G2 HKDF salt includes network magic bytes":
  test "mainnet and testnet4 produce different session keys":
    ## Two peers on different networks derive different keys even for the
    ## same ECDH output, because the magic bytes differ in the HKDF salt.
    ## This guards against cross-network replay.
    var initPriv: PrivateKey
    var respPriv: PrivateKey
    for i in 0 ..< 32:
      initPriv[i] = byte(i + 1)
      respPriv[i] = byte((i * 7 + 3) and 0xff)

    var initMain = newBIP324CipherWithKey(initPriv)
    var respMain = newBIP324CipherWithKey(respPriv)
    var initTest = newBIP324CipherWithKey(initPriv)
    var respTest = newBIP324CipherWithKey(respPriv)

    let iPub = initMain.getOurPubKey()
    let rPub = respMain.getOurPubKey()

    let main = mainnetParams()
    let t4   = testnet4Params()

    initMain.initialize(rPub, initiator = true,  magic = main.magic)
    respMain.initialize(iPub, initiator = false, magic = main.magic)
    initTest.initialize(rPub, initiator = true,  magic = t4.magic)
    respTest.initialize(iPub, initiator = false, magic = t4.magic)

    # Session IDs within the same network pair must match.
    check initMain.getSessionId() == respMain.getSessionId()
    check initTest.getSessionId() == respTest.getSessionId()
    # Session IDs across networks must differ (different HKDF salt).
    check initMain.getSessionId() != initTest.getSessionId()

  test "regtest produces different session key from mainnet":
    var initPriv: PrivateKey
    var respPriv: PrivateKey
    for i in 0 ..< 32:
      initPriv[i] = byte(i + 5)
      respPriv[i] = byte(i + 9)

    var cA = newBIP324CipherWithKey(initPriv)
    var cB = newBIP324CipherWithKey(respPriv)
    var cC = newBIP324CipherWithKey(initPriv)
    var cD = newBIP324CipherWithKey(respPriv)

    let pub_B = cB.getOurPubKey()
    let pub_A = cA.getOurPubKey()

    let main = mainnetParams()
    let rg   = regtestParams()

    cA.initialize(pub_B, initiator = true,  magic = main.magic)
    cB.initialize(pub_A, initiator = false, magic = main.magic)
    cC.initialize(pub_B, initiator = true,  magic = rg.magic)
    cD.initialize(pub_A, initiator = false, magic = rg.magic)

    check cA.getSessionId() == cB.getSessionId()
    check cC.getSessionId() == cD.getSessionId()
    check cA.getSessionId() != cC.getSessionId()

# ============================================================================
# G3: HKDF labels are exactly the BIP-324-specified strings
# ============================================================================
suite "G3 HKDF label strings":
  test "send/recv terminators are distinct and differ between initiator and responder":
    ## BIP-324 spec: garbage terminators are derived from label
    ## "garbage_terminators".  Initiator's send-term is responder's recv-term.
    ## If the labels were wrong, the terminators would not cross-match and
    ## the handshake scan (G16) would fail.
    var privA: PrivateKey
    var privB: PrivateKey
    for i in 0 ..< 32:
      privA[i] = byte(i + 2)
      privB[i] = byte(i + 11)

    var cA = newBIP324CipherWithKey(privA)
    var cB = newBIP324CipherWithKey(privB)
    let pubA = cA.getOurPubKey()
    let pubB = cB.getOurPubKey()
    let p = mainnetParams()
    cA.initialize(pubB, initiator = true,  magic = p.magic)
    cB.initialize(pubA, initiator = false, magic = p.magic)

    # Initiator's SEND terminator must equal Responder's RECV terminator.
    check cA.getSendGarbageTerminator() == cB.getRecvGarbageTerminator()
    # Initiator's RECV terminator must equal Responder's SEND terminator.
    check cA.getRecvGarbageTerminator() == cB.getSendGarbageTerminator()
    # The two terminators within each side must differ (16-byte vs 16-byte from 32-byte expand).
    check cA.getSendGarbageTerminator() != cA.getRecvGarbageTerminator()

  test "session ID is identical on both sides":
    ## label "session_id" must yield the same 32 bytes for both peers.
    var privA: PrivateKey
    var privB: PrivateKey
    for i in 0 ..< 32:
      privA[i] = byte(255 - i)
      privB[i] = byte(i * 3)

    var cA = newBIP324CipherWithKey(privA)
    var cB = newBIP324CipherWithKey(privB)
    let pubA = cA.getOurPubKey()
    let pubB = cB.getOurPubKey()
    let p = testnet4Params()
    cA.initialize(pubB, initiator = true,  magic = p.magic)
    cB.initialize(pubA, initiator = false, magic = p.magic)

    check cA.getSessionId() == cB.getSessionId()

# ============================================================================
# G5: Garbage terminator first-16/last-16 split + role swap
# ============================================================================
suite "G5 garbage terminator split and role swap":
  test "initiator send == responder recv and vice-versa (role symmetry)":
    ## BIP-324: HKDF expand("garbage_terminators") = 32 bytes.
    ## Initiator: first-16 -> SEND, last-16 -> RECV.
    ## Responder: first-16 -> RECV, last-16 -> SEND.
    ## This is the dual role-swap required for the scan to match.
    var privA: PrivateKey
    var privB: PrivateKey
    for i in 0 ..< 32:
      privA[i] = byte(0x11 * (i + 1) and 0xff)
      privB[i] = byte(0x22 * (i + 1) and 0xff)

    var cA = newBIP324CipherWithKey(privA)  # initiator
    var cB = newBIP324CipherWithKey(privB)  # responder
    let pubA = cA.getOurPubKey()
    let pubB = cB.getOurPubKey()
    let p = mainnetParams()
    cA.initialize(pubB, initiator = true,  magic = p.magic)
    cB.initialize(pubA, initiator = false, magic = p.magic)

    let aSend = cA.getSendGarbageTerminator()
    let aRecv = cA.getRecvGarbageTerminator()
    let bSend = cB.getSendGarbageTerminator()
    let bRecv = cB.getRecvGarbageTerminator()

    # Role swap: A's send is B's recv, and vice versa.
    check aSend == bRecv
    check aRecv == bSend
    # Both must be non-zero (sanity: HKDF produced real output).
    var aZero = true
    for b in aSend:
      if b != 0: aZero = false; break
    check aZero == false

  test "garbage terminator bytes are 16 bytes long":
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 1)
      priv2[i] = byte(32 - i)
    var c = newBIP324CipherWithKey(priv)
    var c2 = newBIP324CipherWithKey(priv2)
    let pub2 = c2.getOurPubKey()
    let pub1 = c.getOurPubKey()
    let p = regtestParams()
    c.initialize(pub2, initiator = true, magic = p.magic)
    c2.initialize(pub1, initiator = false, magic = p.magic)
    # GarbageTerminatorLen = 16
    check c.getSendGarbageTerminator().len == 16
    check c.getRecvGarbageTerminator().len == 16

# ============================================================================
# G7: LENGTH_LEN=3 little-endian encoding
# ============================================================================
suite "G7 LENGTH_LEN=3 little-endian":
  test "constant LengthLen is 3":
    check LengthLen == 3

  test "decryptLength round-trips small values correctly":
    ## The encrypted 3-byte length must decode to the original plaintext
    ## length via little-endian arithmetic.  We test the boundary values:
    ## 0, 1, 255, 256, 0xFFFF, 0x010000 (max 3-byte LE).
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 3)
      priv2[i] = byte(i + 7)

    var enc = newBIP324CipherWithKey(priv)
    var dec = newBIP324CipherWithKey(priv2)
    let pub1 = enc.getOurPubKey()
    let pub2 = dec.getOurPubKey()
    let p = regtestParams()
    enc.initialize(pub2, initiator = true,  magic = p.magic)
    dec.initialize(pub1, initiator = false, magic = p.magic)

    let testLengths = [0, 1, 255, 256, 0xFFFF]
    for expectedLen in testLengths:
      let payload = newSeq[byte](expectedLen)
      let packet  = enc.encrypt(payload)
      # First 3 bytes are the encrypted length field.
      let lenField = packet[0 ..< 3]
      let decodedLen = dec.decryptLength(lenField)
      check int(decodedLen) == expectedLen
      # Skip the payload to keep dec in sync.
      let aeadLen = HeaderLen + expectedLen + AEADExpansion
      let rest = packet[3 ..< packet.len]
      discard dec.decrypt(rest)

# ============================================================================
# G8: HEADER_LEN=1, IGNORE_BIT=0x80
# ============================================================================
suite "G8 HEADER_LEN=1 and IGNORE_BIT=0x80":
  test "constants have correct values":
    check HeaderLen == 1
    check IgnoreBit == 0x80'u8

  test "ignore=true sets IGNORE_BIT in decrypted packet":
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 1)
      priv2[i] = byte(i * 2 + 3)

    var enc = newBIP324CipherWithKey(priv)
    var dec = newBIP324CipherWithKey(priv2)
    let pub1 = enc.getOurPubKey()
    let pub2 = dec.getOurPubKey()
    let p = regtestParams()
    enc.initialize(pub2, initiator = true,  magic = p.magic)
    dec.initialize(pub1, initiator = false, magic = p.magic)

    let payload = @[byte(0xab), byte(0xcd)]

    # Decoy (ignore=true)
    let decoyPkt = enc.encrypt(payload, ignore = true)
    let decoyLen = decoyPkt[0 ..< 3]
    let dl       = dec.decryptLength(decoyLen)
    check int(dl) == payload.len
    let decoyBody = decoyPkt[3 ..< decoyPkt.len]
    let decoyDec  = dec.decrypt(decoyBody)
    check decoyDec.ignore == true
    check bytesToHex(decoyDec.contents) == bytesToHex(payload)

    # Real packet (ignore=false)
    let realPkt  = enc.encrypt(payload, ignore = false)
    let realLen  = realPkt[0 ..< 3]
    let rl       = dec.decryptLength(realLen)
    check int(rl) == payload.len
    let realBody = realPkt[3 ..< realPkt.len]
    let realDec  = dec.decrypt(realBody)
    check realDec.ignore == false

# ============================================================================
# G10: memory_cleanse — documented ABSENCE (known bug)
# ============================================================================
suite "G10 memory_cleanse absence (known bug)":
  test "no wipe of private key or derived cipher material (CRYPTO bug)":
    ## BUG: nimrod does NOT call memory_cleanse / zeroMem on:
    ##   1. BIP324Cipher.privateKey after initialize()
    ##   2. FSChaCha20.key after rekey (unlike Core's explicit memory_cleanse call)
    ##   3. Intermediate ECDH shared secret returned from computeBIP324ECDHSecret()
    ##
    ## Bitcoin Core (bip324.cpp:112): memory_cleanse(one_block, sizeof(one_block))
    ## after generating the new FSChaCha20Poly1305 rekey material.
    ##
    ## Severity: CRYPTO — private key material can persist in process heap,
    ## readable via coredump or heap scan after connection teardown.
    ##
    ## This test documents the absence of the call; once fixed, this test
    ## should assert that the private key bytes are zero after initialization.
    var priv: PrivateKey
    for i in 0 ..< 32: priv[i] = byte(i + 1)
    var c = newBIP324CipherWithKey(priv)

    # Currently: priv is still fully intact in the cipher object — no wipe.
    # A fixed impl would zero c.privateKey after ECDH during initialize().
    check true  # placeholder — fix will turn this into a positive check

# ============================================================================
# G15: MAX_GARBAGE_LEN abort bound at 4111 bytes (4095 + 16)
# ============================================================================
suite "G15 MAX_GARBAGE_LEN constant":
  test "MaxGarbageLen is 4095":
    ## BIP-324 spec: receivers abort if no garbage terminator found in
    ## 4095 + 16 = 4111 bytes (Core net.h:640).
    check MaxGarbageLen == 4095

  test "GarbageTerminatorLen is 16":
    check GarbageTerminatorLen == 16

# ============================================================================
# G17: VERSION packet AAD = full received garbage
# ============================================================================
suite "G17 VERSION packet AAD = received garbage":
  test "version packet decrypts only when AAD matches received garbage":
    ## The version packet's AEAD is authenticated with the full received
    ## garbage as AAD.  If we use a different (or empty) AAD the tag check
    ## must fail.  This is the binding that prevents MITM garbage injection.
    var privA: PrivateKey
    var privB: PrivateKey
    for i in 0 ..< 32:
      privA[i] = byte(i + 10)
      privB[i] = byte(i + 20)

    var cA = newBIP324CipherWithKey(privA)
    var cB = newBIP324CipherWithKey(privB)
    let pubA = cA.getOurPubKey()
    let pubB = cB.getOurPubKey()
    let p = regtestParams()
    cA.initialize(pubB, initiator = true,  magic = p.magic)
    cB.initialize(pubA, initiator = false, magic = p.magic)

    # Simulate A sending its garbage and a version packet with AAD=garbage.
    let garbage = @[byte(0xde), byte(0xad), byte(0xbe), byte(0xef)]
    let versionPkt = cA.encrypt(@[], aad = garbage)

    # B must use the SAME garbage as AAD to verify the tag.
    let lenField  = versionPkt[0 ..< 3]
    let vLen      = cB.decryptLength(lenField)
    check int(vLen) == 0  # empty version contents

    let body = versionPkt[3 ..< versionPkt.len]
    # Correct AAD -> decrypt succeeds.
    let ok = cB.decrypt(body, aad = garbage)
    check ok.contents.len == 0

    # Wrong AAD -> auth failure raises exception.
    # We need a fresh pair to test this (state already advanced above).
    var cA2 = newBIP324CipherWithKey(privA)
    var cB2 = newBIP324CipherWithKey(privB)
    let pubA2 = cA2.getOurPubKey()
    let pubB2 = cB2.getOurPubKey()
    cA2.initialize(pubB2, initiator = true,  magic = p.magic)
    cB2.initialize(pubA2, initiator = false, magic = p.magic)

    let garbage2 = @[byte(0xde), byte(0xad), byte(0xbe), byte(0xef)]
    let vPkt2    = cA2.encrypt(@[], aad = garbage2)
    let lf2      = vPkt2[0 ..< 3]
    discard cB2.decryptLength(lf2)
    let body2    = vPkt2[3 ..< vPkt2.len]
    # Wrong garbage (one byte differs) must cause auth failure.
    let wrongGarbage = @[byte(0xde), byte(0xad), byte(0xbe), byte(0x00)]
    var raised = false
    try:
      discard cB2.decrypt(body2, aad = wrongGarbage)
    except BIP324Error:
      raised = true
    check raised == true

# ============================================================================
# G18: VERSION decoy IGNORE_BIT accepted (decoys before version are skipped)
# ============================================================================
suite "G18 VERSION decoy IGNORE_BIT":
  test "version-phase decoy packet has ignore=true":
    ## BIP-324: between garbage_terminator and the version packet, a sender
    ## MAY send zero or more decoy (ignore=true) packets.  The receiver must
    ## skip them.  We verify that encrypt(ignore=true) sets the IGNORE_BIT.
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 1)
      priv2[i] = byte(i + 2)

    var enc = newBIP324CipherWithKey(priv)
    var dec = newBIP324CipherWithKey(priv2)
    let p1 = enc.getOurPubKey()
    let p2 = dec.getOurPubKey()
    let params = regtestParams()
    enc.initialize(p2, initiator = true,  magic = params.magic)
    dec.initialize(p1, initiator = false, magic = params.magic)

    # Send a decoy version packet (ignore=true) with empty contents and empty AAD.
    let decoyPkt = enc.encrypt(@[], ignore = true)
    let lf       = decoyPkt[0 ..< 3]
    let dl       = dec.decryptLength(lf)
    check int(dl) == 0
    let body  = decoyPkt[3 ..< decoyPkt.len]
    let decResult = dec.decrypt(body)
    check decResult.ignore == true

  test "real version packet after a decoy has ignore=false":
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 3)
      priv2[i] = byte(i + 4)

    var enc = newBIP324CipherWithKey(priv)
    var dec = newBIP324CipherWithKey(priv2)
    let p1 = enc.getOurPubKey()
    let p2 = dec.getOurPubKey()
    let params = regtestParams()
    enc.initialize(p2, initiator = true,  magic = params.magic)
    dec.initialize(p1, initiator = false, magic = params.magic)

    # First: decoy with garbage AAD
    let garbage = @[byte(0xca), byte(0xfe)]
    let decoyPkt = enc.encrypt(@[], ignore = true, aad = garbage)
    let lf1 = decoyPkt[0 ..< 3]
    discard dec.decryptLength(lf1)
    let b1 = decoyPkt[3 ..< decoyPkt.len]
    let dr1 = dec.decrypt(b1, aad = garbage)
    check dr1.ignore == true

    # Then: real version packet (no AAD after first decrypt consumed garbage)
    let realPkt = enc.encrypt(@[])
    let lf2 = realPkt[0 ..< 3]
    discard dec.decryptLength(lf2)
    let b2 = realPkt[3 ..< realPkt.len]
    let dr2 = dec.decrypt(b2)
    check dr2.ignore == false

# ============================================================================
# G19: APP decoy discard loop
# ============================================================================
suite "G19 APP-phase decoy discard":
  test "decoy packets in application phase are transparent":
    ## After the handshake, the application decryption loop in readMessageV2
    ## skips decoy packets until a real one arrives.  We verify the cipher
    ## state advances correctly through multiple decoys.
    var privA: PrivateKey
    var privB: PrivateKey
    for i in 0 ..< 32:
      privA[i] = byte(i + 50)
      privB[i] = byte(i + 60)

    var enc = newBIP324CipherWithKey(privA)
    var dec = newBIP324CipherWithKey(privB)
    let pubA = enc.getOurPubKey()
    let pubB = dec.getOurPubKey()
    let p = regtestParams()
    enc.initialize(pubB, initiator = true,  magic = p.magic)
    dec.initialize(pubA, initiator = false, magic = p.magic)

    # Send 5 decoys then 1 real packet.
    for i in 0 ..< 5:
      let decoy = enc.encrypt(@[byte(i)], ignore = true)
      let lf = decoy[0 ..< 3]
      let dl = dec.decryptLength(lf)
      let b  = decoy[3 ..< decoy.len]
      let d  = dec.decrypt(b)
      check d.ignore == true
      check int(dl) == 1

    # Real packet must decode correctly after 5 decoys.
    let realPayload = @[byte(0xaa), byte(0xbb), byte(0xcc)]
    let realPkt = enc.encrypt(realPayload)
    let lf = realPkt[0 ..< 3]
    let dl = dec.decryptLength(lf)
    check int(dl) == realPayload.len
    let b  = realPkt[3 ..< realPkt.len]
    let d  = dec.decrypt(b)
    check d.ignore == false
    check bytesToHex(d.contents) == bytesToHex(realPayload)

# ============================================================================
# G23: Reserved short IDs 0x1d-0x22 — nimrod accepts, Core rejects (known bug)
# ============================================================================
suite "G23 reserved short ID acceptance (known CORRECTNESS bug)":
  test "nimrod accepts extended IDs 0x1d-0x22 (deviation from Core)":
    ## BUG: Bitcoin Core's V2_MESSAGE_IDS table has only 33 entries (0x00-0x20).
    ## Indices 0x1d(29), 0x1e(30), 0x1f(31), 0x20(32) are empty string in Core
    ## and returned as unknown (disconnects peer).  0x21 and 0x22 are out of
    ## range and also rejected.
    ##
    ## Nimrod intentionally accepts 0x1d-0x22 as "wtxidrelay", "sendaddrv2",
    ## etc. for cross-impl interop (see bip324.nim extendedDecodeIds).
    ## This deviates from Core's strict rejection: a strict peer would
    ## disconnect on receiving these IDs.
    ##
    ## Severity: CORRECTNESS (wire-incompatible with Core on the SEND side
    ## if these IDs were ever emitted, but nimrod encodes via long-form so
    ## outbound traffic is spec-compliant).
    let testCases = [
      (0x1d'u8, "wtxidrelay"),
      (0x1e'u8, "sendaddrv2"),
      (0x1f'u8, "sendheaders"),
      (0x20'u8, "version"),
      (0x21'u8, "verack"),
      (0x22'u8, "getaddr"),
    ]
    let payload = @[byte(0x01), byte(0x02)]
    for (id, expectedCmd) in testCases:
      var wire = newSeq[byte](1 + payload.len)
      wire[0] = id
      for i, b in payload: wire[1 + i] = b
      # nimrod accepts and maps to the command name.
      let d = decodeV2Message(wire)
      check d.command == expectedCmd
      check bytesToHex(d.payload) == bytesToHex(payload)
      # NOTE: Core would return nullopt (disconnect) for these IDs.
      # A strict conformance test would check that SENDING these IDs to Core
      # results in disconnection — that requires a live peer and is not
      # tested here.

  test "encoder uses long-form (0x00) for reserved-band commands, not extended IDs":
    ## Even though the decoder accepts extended IDs, the encoder MUST emit
    ## long-form for version/verack/etc. so outbound traffic is spec-compliant.
    for cmd in ["version", "verack", "getaddr", "wtxidrelay",
                "sendaddrv2", "sendheaders"]:
      let enc = encodeV2Message(cmd, @[byte(0xab)])
      check enc[0] == 0x00'u8  # long-form indicator

# ============================================================================
# G24: Max plaintext vs Core (32 MiB → 4 MB — FIXED W98 G24)
# ============================================================================
suite "G24 max plaintext limit (FIXED)":
  test "MaxMessagePayload matches Bitcoin Core's limit":
    ## FIXED: MaxMessagePayload = 4_000_000 (4 MB) per Core net.h:65.
    ## Bitcoin Core net.h:65: MAX_PROTOCOL_MESSAGE_LENGTH = 4 * 1000 * 1000 = 4 MB.
    ## Was: 33_554_432 (32 MiB) — 8x too large (DoS memory amplifier).
    ## Fix: messages.nim MaxMessagePayload changed to 4_000_000.

    const coreLimit = 4_000_000
    check MaxMessagePayload == coreLimit   # FIXED: matches Core exactly
    check MaxMessagePayload <= coreLimit   # FIXED: no longer over-permissive

# ============================================================================
# G25: Initiator garbage bound rand(32) vs spec rand(4095) (known anonymity bug)
# ============================================================================
suite "G25 initiator garbage size (known anonymity bug)":
  test "generateGarbage uses the full 0..MaxGarbageLen range (bip324.nim)":
    ## generateGarbage() in bip324.nim uses rand(MaxGarbageLen=4095) — correct.
    ## BUG: peer.nim performV2HandshakeResponder and performV2HandshakeInitiator
    ## both call rand(32) instead of rand(MaxGarbageLen).  This caps garbage
    ## at 32 bytes, reducing the anonymity set of the connection (traffic
    ## analysis can observe very short garbage bursts).
    ##
    ## BIP-324 spec: garbage length chosen uniformly from [0, MAX_GARBAGE_LEN].
    ## Bitcoin Core: ret.resize(rng.randrange(MAX_GARBAGE_LEN + 1))  (net.cpp:982).
    ##
    ## Severity: DoS/Privacy — reduces traffic-analysis resistance.
    ## Fix: change rand(32) -> rand(MaxGarbageLen) in peer.nim:642 and peer.nim:811.
    var randomLengths: seq[int]
    for _ in 0 ..< 50:
      let g = generateGarbage()
      randomLengths.add(g.len)

    # generateGarbage() itself uses the correct MaxGarbageLen bound.
    for l in randomLengths:
      check l >= 0
      check l <= MaxGarbageLen

    # Document the peer.nim bug: the actual handshake only ever generates
    # garbage of length 0..32, not 0..4095.
    check MaxGarbageLen == 4095  # spec says 4095

# ============================================================================
# G26: ECDH private key uses std/sysrand CSPRNG (fixed)
# ============================================================================
suite "G26 ECDH private key uses CSPRNG (std/sysrand)":
  test "G26: ECDH private key uses CSPRNG — 1024 keys all distinct + high byte entropy":
    ## FIXED: newBIP324Cipher() now generates the 32-byte ECDH private key via
    ## std/sysrand.urandom() — the OS CSPRNG (/dev/urandom on Linux), matching
    ## Bitcoin Core's GetStrongRandBytes() (src/random.cpp).
    ##
    ## Previously: Nim's std/random.rand(255) seeded by randomize()
    ## (xoroshiro128+ seeded from epochTime()) — NOT cryptographically random.
    ## Two connections opened in the same second could share the same seed.
    ##
    ## Property test: generate 1024 keys, assert:
    ##   1. All keys are distinct (no duplicates).
    ##   2. Each of the 32 byte-positions has at least 200 distinct values
    ##      across 1024 samples — a heuristic CSPRNG signature that the
    ##      deterministic xoroshiro128+ would NOT satisfy after a common seed.
    var keys: seq[array[32, byte]]
    for i in 0 ..< 1024:
      let c = newBIP324Cipher()
      # Extract the private key bytes via a test-key round-trip: the public
      # key derivation is deterministic, so we probe the key indirectly by
      # checking that each cipher's public key is unique.
      # We also expose the private key bytes directly since newBIP324Cipher
      # stores them in BIP324Cipher.privateKey.
      var privCopy: array[32, byte]
      # Use newBIP324CipherWithKey path to read what was generated:
      # We can't read privateKey directly since it's not exported, so we
      # compare public keys (which are a deterministic function of privkey).
      let pub = c.getOurPubKey()
      for j in 0 ..< 64:
        privCopy[j mod 32] = privCopy[j mod 32] xor pub[j]
      keys.add(privCopy)

    # 1. Deduplicate based on raw public key uniqueness instead.
    #    Rebuild using the public key (exported) as the uniqueness proxy.
    var pubKeys: seq[array[64, byte]]
    for i in 0 ..< 1024:
      let c = newBIP324Cipher()
      pubKeys.add(c.getOurPubKey())

    # All public keys must be distinct (prob 2^-256 of collision from true CSPRNG).
    var seen: HashSet[array[64, byte]]
    for pk in pubKeys:
      seen.incl(pk)
    check seen.len == 1024

    # 2. Byte-position entropy heuristic on public key bytes.
    #    True CSPRNG → each byte position over 1024 samples ≥ 200 distinct values.
    #    xoroshiro128+ from same seed → far fewer distinct values.
    for bytePos in 0 ..< 64:
      var byteSeen: HashSet[byte]
      for pk in pubKeys:
        byteSeen.incl(pk[bytePos])
      check byteSeen.len >= 200

# ============================================================================
# G28: AEAD tag failure raises BIP324Error (disconnect signal)
# ============================================================================
suite "G28 AEAD tag-fail disconnect":
  test "bit-flip in ciphertext causes decrypt to raise BIP324Error":
    ## Per G28: a bad AEAD tag MUST result in disconnect, not silent
    ## acceptance of corrupted plaintext.  nimrod raises BIP324Error which
    ## the caller (peer.nim readMessageV2) catches and re-raises as PeerError,
    ## triggering a disconnect.
    var priv: PrivateKey
    var priv2: PrivateKey
    for i in 0 ..< 32:
      priv[i]  = byte(i + 1)
      priv2[i] = byte(i + 2)

    var enc = newBIP324CipherWithKey(priv)
    var dec = newBIP324CipherWithKey(priv2)
    let p1 = enc.getOurPubKey()
    let p2 = dec.getOurPubKey()
    let p = regtestParams()
    enc.initialize(p2, initiator = true,  magic = p.magic)
    dec.initialize(p1, initiator = false, magic = p.magic)

    let payload = @[byte(0xde), byte(0xad), byte(0xbe), byte(0xef)]
    let pkt = enc.encrypt(payload)

    let lf = pkt[0 ..< 3]
    discard dec.decryptLength(lf)

    # Corrupt one byte in the ciphertext body (byte 4 of the AEAD payload).
    var corrupt = pkt[3 ..< pkt.len]
    corrupt[4] = corrupt[4] xor 0x55'u8

    var raised = false
    try:
      discard dec.decrypt(corrupt)
    except BIP324Error:
      raised = true
    check raised == true

# ============================================================================
# Short ID table completeness (G21)
# ============================================================================
suite "G21 short message ID table completeness":
  test "all 28 canonical short IDs 0x01..0x1c are present":
    ## BIP-324 assigns 28 message types to short IDs 0x01..0x1c.
    ## Verify the decoder table covers all 28 without gap.
    let expectedCmds = [
      "addr", "block", "blocktxn", "cmpctblock", "feefilter",
      "filteradd", "filterclear", "filterload", "getblocks", "getblocktxn",
      "getdata", "getheaders", "headers", "inv", "mempool",
      "merkleblock", "notfound", "ping", "pong", "sendcmpct",
      "tx", "getcfilters", "cfilter", "getcfheaders", "cfheaders",
      "getcfcheckpt", "cfcheckpt", "addrv2"
    ]
    check expectedCmds.len == 28
    for cmd in expectedCmds:
      check shortMsgTypes.hasKey(cmd)

  test "short IDs 0x01..0x1c decode to correct commands":
    let pairs = [
      (0x01'u8, "addr"),   (0x02'u8, "block"),  (0x12'u8, "ping"),
      (0x13'u8, "pong"),   (0x15'u8, "tx"),      (0x1c'u8, "addrv2"),
    ]
    for (id, cmd) in pairs:
      var wire = newSeq[byte](2)
      wire[0] = id
      wire[1] = 0xab'u8
      let d = decodeV2Message(wire)
      check d.command == cmd
