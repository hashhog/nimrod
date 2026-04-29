## BIP-324 v2 transport tests
##
## Covers:
## 1. FSChaCha20 length-cipher correctness, anchored to vectors generated
##    from Bitcoin Core's reference implementation
##    (`bitcoin-core/test/functional/test_framework/crypto/chacha20.py
##    ::FSChaCha20`).  These pin the cipher to the spec — the previous
##    nimrod code reset the ChaCha20 block counter on every crypt() call,
##    silently diverging from Core/ouroboros after packet 1 (the same
##    bug clearbit fixed in cb04a1f).
## 2. Inbound v1/v2 classification (`classifyInboundV2`).
## 3. Cross-cipher AEAD roundtrip with the BIP324Cipher session.
##
## Reference: BIP-324, bitcoin-core/src/crypto/chacha20.cpp::FSChaCha20,
## clearbit/src/v2_transport.zig::FSChaCha20 (post-cb04a1f), nimrod
## CLAUDE.md "P2P parity Category B".

import unittest2
import ../src/crypto/chacha20poly1305
import ../src/crypto/secp256k1
import ../src/network/peer
import ../src/network/bip324
import ../src/consensus/params

proc bytesToHex(data: openArray[byte]): string =
  const hex = "0123456789abcdef"
  result = newString(data.len * 2)
  for i, b in data:
    result[2 * i] = hex[(b shr 4) and 0xf]
    result[2 * i + 1] = hex[b and 0xf]

suite "FSChaCha20 continuous keystream (BIP-324)":
  test "two consecutive 3-byte chunks form a continuous keystream":
    # Anchored to Bitcoin Core test_framework/crypto/chacha20.py:
    #   key=0x42*32, REKEY_INTERVAL=224, two crypt(b"\x00"*3) calls
    # Expected: a4ddf31f7f32
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 0x42'u8
    var c = initFSChaCha20(key, 224'u32)

    var out1: array[3, byte]
    var out2: array[3, byte]
    let zeros: array[3, byte] = [0'u8, 0'u8, 0'u8]
    c.crypt(zeros, out1)
    c.crypt(zeros, out2)
    var combined: array[6, byte]
    for i in 0 ..< 3: combined[i] = out1[i]
    for i in 0 ..< 3: combined[3 + i] = out2[i]
    check bytesToHex(combined) == "a4ddf31f7f32"

  test "single 64-byte crypt matches concatenated 3+61 split":
    # Same key as above; the 64-byte output of one crypt() call MUST
    # equal the concatenation of two crypt() calls totalling 64 bytes —
    # this is the "continuous keystream within an epoch" invariant.
    # Expected: a4ddf31f7f32ba696f14ce50ecf3f21e3e100e83bdf47966e7b07468e9500b6ee106b40d369f5c94f5dd2a13d9131585121002ed9e313d2dc9e49ff534c50bd1
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 0x42'u8

    var cFull = initFSChaCha20(key, 224'u32)
    var fullOut = newSeq[byte](64)
    let zeros64 = newSeq[byte](64)
    cFull.crypt(zeros64, fullOut)

    var cSplit = initFSChaCha20(key, 224'u32)
    var part1 = newSeq[byte](3)
    var part2 = newSeq[byte](61)
    let zeros3 = newSeq[byte](3)
    let zeros61 = newSeq[byte](61)
    cSplit.crypt(zeros3, part1)
    cSplit.crypt(zeros61, part2)

    var splitConcat = newSeq[byte](64)
    for i in 0 ..< 3: splitConcat[i] = part1[i]
    for i in 0 ..< 61: splitConcat[3 + i] = part2[i]

    check bytesToHex(fullOut) == bytesToHex(splitConcat)
    check bytesToHex(fullOut) ==
      "a4ddf31f7f32ba696f14ce50ecf3f21e3e100e83bdf47966e7b07468e9500b6ee106b40d369f5c94f5dd2a13d9131585121002ed9e313d2dc9e49ff534c50bd1"

  test "rekey at interval=2 produces three distinct epochs":
    # Anchored to Bitcoin Core reference: key=0xff*32, rekey_interval=2,
    # 5 consecutive crypt(b"\x00"*3) calls.
    # Expected: f6b898412f4aaa8d40c4196a39c624
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 0xff'u8
    var c = initFSChaCha20(key, 2'u32)
    var combined = newSeq[byte](15)
    let zeros3: array[3, byte] = [0'u8, 0'u8, 0'u8]
    for i in 0 ..< 5:
      var part: array[3, byte]
      c.crypt(zeros3, part)
      for j in 0 ..< 3: combined[3 * i + j] = part[j]
    check bytesToHex(combined) == "f6b898412f4aaa8d40c4196a39c624"

  test "single 64-byte chunk matches Core reference vector":
    # Anchored: key=0xa1*32, REKEY_INTERVAL=224, crypt(64 zero bytes).
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 0xa1'u8
    var c = initFSChaCha20(key, 224'u32)
    var output = newSeq[byte](64)
    let zeros = newSeq[byte](64)
    c.crypt(zeros, output)
    check bytesToHex(output) ==
      "7921b6ed8fa8cff2baf61a43f3a66a9f591d569c4ffe6c9f26b4feddb0a80d2b806f09308412341c4e16299bcdaec47823a8476c755f51055efeccf7a8f1f189"

  test "encrypt-then-decrypt roundtrip via two parallel ciphers":
    # Both sides initialised with the same key advance through the same
    # epochs in lock-step.  Models the wire: the sender's crypt() output
    # XOR'd back through the receiver's crypt() recovers the plaintext.
    var key: array[32, byte]
    for i in 0 ..< 32: key[i] = 0x37'u8
    var enc = initFSChaCha20(key, 224'u32)
    var dec = initFSChaCha20(key, 224'u32)

    let plaintexts = @[
      @[byte(0x01), byte(0x02), byte(0x03)],
      @[byte(0xff), byte(0x00), byte(0x55)],
      @[byte(0xab), byte(0xcd), byte(0xef)],
      @[byte(0x12), byte(0x34), byte(0x56)],
    ]
    for pt in plaintexts:
      var ct = newSeq[byte](pt.len)
      enc.crypt(pt, ct)
      var rt = newSeq[byte](pt.len)
      dec.crypt(ct, rt)
      check bytesToHex(rt) == bytesToHex(pt)

suite "BIP-324 inbound classification":
  test "v1 prefix on mainnet is detected as v1":
    let p = mainnetParams()
    var prefix: array[16, byte]
    prefix[0] = p.magic[0]
    prefix[1] = p.magic[1]
    prefix[2] = p.magic[2]
    prefix[3] = p.magic[3]
    let cmd = "version"
    for i in 0 ..< cmd.len:
      prefix[4 + i] = byte(cmd[i])
    # Bytes 11..15 left as 0 = "version\0\0\0\0\0"
    check classifyInboundV2(prefix, p.magic) == true

  test "random first 16 bytes are not v1 (would take the v2 path)":
    # ElligatorSwift pubkeys are uniformly random; a random 16-byte
    # window has 2^-128 chance of matching the v1 header.  Use a
    # deterministic non-matching pattern so the test is reproducible.
    let p = mainnetParams()
    var prefix: array[16, byte]
    for i in 0 ..< 16: prefix[i] = byte(0xa5)
    check classifyInboundV2(prefix, p.magic) == false

  test "wrong magic on testnet4 is not v1":
    # Mainnet magic in the prefix should not match testnet4's magic.
    let m = mainnetParams()
    let t = testnet4Params()
    var prefix: array[16, byte]
    prefix[0] = m.magic[0]
    prefix[1] = m.magic[1]
    prefix[2] = m.magic[2]
    prefix[3] = m.magic[3]
    let cmd = "version"
    for i in 0 ..< cmd.len:
      prefix[4 + i] = byte(cmd[i])
    check classifyInboundV2(prefix, t.magic) == false

  test "magic match but command not 'version' is not v1":
    let p = mainnetParams()
    var prefix: array[16, byte]
    prefix[0] = p.magic[0]
    prefix[1] = p.magic[1]
    prefix[2] = p.magic[2]
    prefix[3] = p.magic[3]
    let cmd = "ping"
    for i in 0 ..< cmd.len:
      prefix[4 + i] = byte(cmd[i])
    # Remaining bytes not zero — wrong command stem.
    check classifyInboundV2(prefix, p.magic) == false

suite "BIP-324 cipher session roundtrip":
  test "initiator+responder pair encrypt+decrypt application packets":
    # Build an initiator+responder cipher pair from a shared key
    # exchange.  Encrypt several packets through the initiator, decrypt
    # them through the responder, verify the contents and the IGNORE
    # flag on a decoy packet.  This indirectly tests the FSChaCha20
    # length-cipher fix because BIP324Cipher.encrypt/decrypt advances
    # both the length and AEAD ciphers together — if the length cipher
    # diverges, decryption fails on packet 2+.
    var initPriv: PrivateKey
    var respPriv: PrivateKey
    for i in 0 ..< 32:
      initPriv[i] = byte(i + 1)
      respPriv[i] = byte((i * 7 + 3) and 0xff)

    var initiator = newBIP324CipherWithKey(initPriv)
    var responder = newBIP324CipherWithKey(respPriv)
    let initPub = initiator.getOurPubKey()
    let respPub = responder.getOurPubKey()

    let p = mainnetParams()
    initiator.initialize(respPub, initiator = true, magic = p.magic)
    responder.initialize(initPub, initiator = false, magic = p.magic)

    # Session IDs must match across both sides.
    check initiator.getSessionId() == responder.getSessionId()

    # Packet 1: real message.
    let pt1 = @[byte(0xde), byte(0xad), byte(0xbe), byte(0xef)]
    let ct1 = initiator.encrypt(pt1)
    let lenField1 = ct1[0 ..< 3]
    let payload1 = ct1[3 ..< ct1.len]
    let decLen1 = responder.decryptLength(lenField1)
    check int(decLen1) == pt1.len
    let dec1 = responder.decrypt(payload1)
    check bytesToHex(dec1.contents) == bytesToHex(pt1)
    check dec1.ignore == false

    # Packet 2: decoy (ignore=true).  This exercises the second
    # length-cipher chunk; with the old bug, decryptLength would return
    # garbage here.
    let pt2 = @[byte(0xaa)]
    let ct2 = initiator.encrypt(pt2, ignore = true)
    let lenField2 = ct2[0 ..< 3]
    let payload2 = ct2[3 ..< ct2.len]
    let decLen2 = responder.decryptLength(lenField2)
    check int(decLen2) == pt2.len
    let dec2 = responder.decrypt(payload2)
    check dec2.ignore == true
    check bytesToHex(dec2.contents) == bytesToHex(pt2)

    # Packet 3: real, larger.  Continued forward progress through the
    # cipher epoch.
    var pt3 = newSeq[byte](128)
    for i in 0 ..< 128: pt3[i] = byte((i * 13 + 7) and 0xff)
    let ct3 = initiator.encrypt(pt3)
    let lenField3 = ct3[0 ..< 3]
    let payload3 = ct3[3 ..< ct3.len]
    let decLen3 = responder.decryptLength(lenField3)
    check int(decLen3) == pt3.len
    let dec3 = responder.decrypt(payload3)
    check bytesToHex(dec3.contents) == bytesToHex(pt3)
    check dec3.ignore == false

  test "v2 message envelope short ID encode/decode roundtrip":
    let payload = @[byte(0xc0), byte(0xff), byte(0xee)]
    let encoded = encodeV2Message("ping", payload)
    # short-form: 1 byte (id=0x12 for "ping") + payload
    check encoded.len == 1 + payload.len
    check encoded[0] == 0x12'u8

    let decoded = decodeV2Message(encoded)
    check decoded.command == "ping"
    check bytesToHex(decoded.payload) == bytesToHex(payload)

  test "v2 message envelope long-form for unknown command":
    # An unknown command takes the long-form path: 0x00 || cmd[12] || payload.
    let payload = @[byte(0x01), byte(0x02)]
    let encoded = encodeV2Message("xenophobia", payload)
    check encoded.len == 1 + 12 + payload.len
    check encoded[0] == 0x00'u8

    let decoded = decodeV2Message(encoded)
    check decoded.command == "xenophobia"
    check bytesToHex(decoded.payload) == bytesToHex(payload)
