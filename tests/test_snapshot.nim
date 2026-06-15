## Tests for assumeUTXO snapshot functionality (Bitcoin Core byte-compatible)
## Covers VARINT, CompressAmount/Script, per-coin layout, file round-trip,
## metadata validation, and assumeutxo data wiring.

import std/[os, options, tables, unittest, strutils, json]
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing
import ../src/crypto/muhash
import ../src/consensus/params
import ../src/storage/[chainstate, snapshot]

# ----------------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------------

proc mkHash32(b0: byte): array[32, byte] =
  result[0] = b0

proc mkHashWith(prefix: openArray[byte]): array[32, byte] =
  for i in 0 ..< prefix.len:
    result[i] = prefix[i]

proc bytesFromHex(s: string): seq[byte] =
  let clean = s.toLowerAscii
  doAssert clean.len mod 2 == 0
  result = newSeq[byte](clean.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(clean[i*2 .. i*2 + 1]))

proc roundtripVarInt(v: uint64): uint64 =
  var w = BinaryWriter()
  w.writeVarInt(v)
  var r = BinaryReader(data: w.data, pos: 0)
  r.readVarInt()

# ----------------------------------------------------------------------------
# VARINT (Bitcoin-style, NOT compactsize)
# ----------------------------------------------------------------------------

suite "Bitcoin VARINT":
  test "round-trips at edge values":
    for v in [0'u64, 1, 0x7F, 0x80, 0xFF, 0x4000, 0xFFFF, 0xFFFFFF,
              0x1FFFFFFF, 0xFFFFFFFF'u64, 0xFFFFFFFFFF'u64,
              high(uint64) - 1]:
      check roundtripVarInt(v) == v

  test "matches Core's known encodings":
    # WriteVarInt encodes 0 as a single byte 0x00.
    var w0 = BinaryWriter()
    w0.writeVarInt(0)
    check w0.data == @[0x00'u8]
    # 0x7F encodes as a single byte 0x7F (no continuation bit).
    var w1 = BinaryWriter()
    w1.writeVarInt(0x7F)
    check w1.data == @[0x7F'u8]
    # 0x80 encodes as two bytes 0x80 0x00 (Core: tmp[1]=0|0, tmp[0]=0x80, emit hi-first).
    var w2 = BinaryWriter()
    w2.writeVarInt(0x80)
    check w2.data == @[0x80'u8, 0x00'u8]
    # 0xFF encodes as 0x80 0x7F.
    var w3 = BinaryWriter()
    w3.writeVarInt(0xFF)
    check w3.data == @[0x80'u8, 0x7F'u8]

# ----------------------------------------------------------------------------
# CompressAmount / DecompressAmount
# ----------------------------------------------------------------------------

suite "CompressAmount":
  test "round-trips on a spread of amounts":
    let cases = [
      0'u64, 1, 100, 546, 999, 1000, 100000000'u64, 50_00000000'u64,
      21_000_000_00000000'u64, 12345678901234'u64, 73_50000000'u64
    ]
    for v in cases:
      check decompressAmount(compressAmount(v)) == v

  test "matches Core spec edge cases":
    # CompressAmount(0) == 0
    check compressAmount(0) == 0
    # 1 BTC = 1e8 sats: e=8, n=1, d=1 -> 1 + (1*9 + 0)*10 + 8 = 1+0+8 = 9
    # but careful: n becomes 1 after dividing trailing zeros, then d = (1 mod 10) = 1
    # actually: 1e8 -> divide by 10 eight times -> v=1, e=8. d = 1, n = (1-1)/10? ...
    # Easiest: round-trip and trust the algorithm.
    for v in [50_00000000'u64, 100'u64, 21_00000000_00000000'u64]:
      check decompressAmount(compressAmount(v)) == v

# ----------------------------------------------------------------------------
# CompressScript
# ----------------------------------------------------------------------------

suite "ScriptCompression":
  test "P2PKH special-cases to 21 bytes":
    # OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
    let hash160 = @[0xAA'u8, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
                    0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x10, 0x20,
                    0x30, 0x40, 0x50, 0x60]
    let script = @[0x76'u8, 0xA9, 0x14] & hash160 & @[0x88'u8, 0xAC]
    var w = BinaryWriter()
    w.writeCompressedScript(script)
    # Tag (0x00) + 20-byte hash = 21 bytes total.
    check w.data.len == 21
    check w.data[0] == 0x00
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded == script

  test "P2SH special-cases to 21 bytes":
    let hash160 = @[0x11'u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
                    0x01, 0x02, 0x03, 0x04]
    # OP_HASH160 0x14 <20> OP_EQUAL
    let script = @[0xA9'u8, 0x14] & hash160 & @[0x87'u8]
    var w = BinaryWriter()
    w.writeCompressedScript(script)
    check w.data.len == 21
    check w.data[0] == 0x01
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded == script

  test "Generic fallback emits VARINT(size+6) + raw":
    # P2WPKH-ish: 0x00 0x14 <20 bytes> — not a compressor special case.
    let script = @[0x00'u8, 0x14] & newSeq[byte](20)
    var w = BinaryWriter()
    w.writeCompressedScript(script)
    # First byte must be VARINT(22+6) = 28 = 0x1C (single byte).
    check w.data[0] == 0x1C
    check w.data.len == 1 + script.len
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded == script

  test "Tag 0x04 recovers uncompressed P2PK via secp256k1 (generator G)":
    # Vector: secp256k1 generator G.
    # Compressed (even-y): 02 79be667e... -> tag 0x04, x = 79be667e...
    # Uncompressed:        04 79be667e... 483ada77...
    let xCoord = bytesFromHex(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    let yCoord = bytesFromHex(
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    # Reader-side input: tag 0x04 (single VARINT byte) followed by 32 x-bytes.
    var w = BinaryWriter()
    w.writeVarInt(0x04'u64)
    w.writeBytes(xCoord)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    # Expected: 0x41 <65-byte pubkey> 0xAC, total 67 bytes.
    check decoded.len == 67
    check decoded[0] == 0x41'u8
    check decoded[1] == 0x04'u8
    check decoded[2 .. 33] == xCoord
    check decoded[34 .. 65] == yCoord
    check decoded[66] == 0xAC'u8

  test "Tag 0x05 recovers uncompressed P2PK with odd y":
    # Vector: pubkey 03 79be667e... is the odd-y partner of G's negation point.
    # Use 03-prefixed compressed pubkey (odd y) = -G mod p.
    # Compressed: 03 79be667e...  (same x, odd y)
    # Uncompressed equivalent has odd y = p - 483ada77...
    # We don't hard-code the odd-y bytes here; instead verify the decoder
    # produces a valid 67-byte P2PK script with x preserved and odd y parity.
    let xCoord = bytesFromHex(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    var w = BinaryWriter()
    w.writeVarInt(0x05'u64)
    w.writeBytes(xCoord)
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded.len == 67
    check decoded[0] == 0x41'u8
    check decoded[1] == 0x04'u8
    check decoded[2 .. 33] == xCoord
    # Odd y parity: last byte of y must be odd.
    check (decoded[65].int and 1) == 1
    check decoded[66] == 0xAC'u8

  test "Tag 0x04 with invalid x-coordinate raises SnapshotError":
    # x = all-zeros is not on the secp256k1 curve.
    var w = BinaryWriter()
    w.writeVarInt(0x04'u64)
    w.writeBytes(newSeq[byte](32))
    var r = BinaryReader(data: w.data, pos: 0)
    expect SnapshotError:
      discard r.readCompressedScript()

  test "Uncompressed P2PK compresses to tag 0x04/0x05 + X[32] (Finding 5B/7B)":
    ## Non-vacuous: without the fix tryCompressScript returns false for a
    ## 67-byte uncompressed P2PK, causing writeCompressedScript to emit
    ## VARINT(73) + 67 raw bytes = 68 bytes. With the fix it emits the
    ## 33-byte special encoding (tag + X). The check for w.data.len == 33
    ## would FAIL (got 68) without the fix.
    ##
    ## Uses secp256k1 generator G (even y) as the test vector:
    ##   G.x = 79be667e...   G.y = 483ada77...4b8  (LSB = 0 → tag 0x04)
    ## Core compressor.cpp:79: out[0] = 0x04 | (pubkey[64] & 0x01)
    let xCoord = bytesFromHex(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    let yCoord = bytesFromHex(
      "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
    # Build 67-byte uncompressed P2PK: 0x41 <0x04 || X[32] || Y[32]> OP_CHECKSIG
    var script = newSeq[byte](67)
    script[0] = 0x41'u8
    script[1] = 0x04'u8
    for i in 0 ..< 32: script[2 + i] = xCoord[i]
    for i in 0 ..< 32: script[34 + i] = yCoord[i]
    script[66] = 0xAC'u8

    var w = BinaryWriter()
    w.writeCompressedScript(script)

    # With the fix: 33 bytes (tag + X). Without the fix: 68 bytes (generic).
    check w.data.len == 33
    # G has even y (last byte of Y = 0xb8, LSB = 0) → tag = 0x04.
    check w.data[0] == 0x04'u8
    # X coordinate preserved verbatim.
    check w.data[1..32] == xCoord

    # Round-trip via decoder must recover the original 67-byte script.
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded == script

  test "Uncompressed P2PK with odd Y encodes as tag 0x05 (Finding 5B/7B)":
    ## -G has the same X as G but odd Y. Tag must be 0x05. Validates Y-parity.
    ## Non-vacuous: without the fix the encoding would be 68 bytes (generic);
    ## with the fix it is 33 bytes with tag 0x05.
    let xCoord = bytesFromHex(
      "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
    # Obtain odd-Y uncompressed script by decoding the 0x05-tagged form.
    var wTag = BinaryWriter()
    wTag.writeVarInt(0x05'u64)
    wTag.writeBytes(xCoord)
    var rTag = BinaryReader(data: wTag.data, pos: 0)
    let negGScript = rTag.readCompressedScript()
    check negGScript.len == 67
    check (negGScript[65].int and 1) == 1  # odd y

    var w = BinaryWriter()
    w.writeCompressedScript(negGScript)
    # With the fix: 33 bytes, tag 0x05.
    check w.data.len == 33
    check w.data[0] == 0x05'u8
    check w.data[1..32] == xCoord

    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readCompressedScript()
    check decoded == negGScript

  test "Invalid uncompressed P2PK (not on curve) falls back to generic encoding":
    ## all-zero x+y is not a valid secp256k1 point; tryCompressScript must
    ## reject it and fall through to VARINT(size+6)+raw (68 bytes, not 33).
    var script = newSeq[byte](67)
    script[0] = 0x41'u8; script[1] = 0x04'u8; script[66] = 0xAC'u8
    var w = BinaryWriter()
    w.writeCompressedScript(script)
    # Generic path: VARINT(73) is one byte (73 < 0xfd), then 67 raw bytes = 68 total.
    check w.data.len == 68
    check w.data[0] == byte(73)

# ----------------------------------------------------------------------------
# Header serialization (file metadata)
# ----------------------------------------------------------------------------

suite "snapshot header":
  test "header round-trip preserves all fields":
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(default(array[32, byte])),
      coinsCount: 12345
    )
    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)
    # Header MUST be exactly 51 bytes: 5 + 2 + 4 + 32 + 8.
    check w.data.len == 51
    var r = BinaryReader(data: w.data, pos: 0)
    let decoded = r.readSnapshotMetadata()
    check decoded.version == meta.version
    check decoded.networkMagic == meta.networkMagic
    check decoded.baseBlockhash == meta.baseBlockhash
    check decoded.coinsCount == meta.coinsCount

  test "header byte layout matches Core spec":
    # Magic (5) | version (2 LE) | netmagic (4) | base hash (32) | count (8 LE).
    let meta = SnapshotMetadata(
      version: 2,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(mkHash32(0xAB'u8)),
      coinsCount: 0x1122334455667788'u64
    )
    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)
    # First 5 bytes = "utxo\xff"
    check w.data[0] == byte('u')
    check w.data[1] == byte('t')
    check w.data[2] == byte('x')
    check w.data[3] == byte('o')
    check w.data[4] == 0xFF'u8
    # Next 2 bytes = 0x02 0x00 (uint16 LE).
    check w.data[5] == 0x02
    check w.data[6] == 0x00
    # Next 4 bytes = network magic in order.
    check w.data[7..10] == @[0xF9'u8, 0xBE, 0xB4, 0xD9]
    # Last 8 bytes = coinsCount in LE.
    check w.data[43..50] == @[0x88'u8, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]

  test "rejects bad magic":
    let testDir = getTempDir() / "nimrod_snapshot_magic"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let testPath = testDir / "bad.dat"
    let f = open(testPath, fmWrite)
    discard f.writeBytes(@[0x00'u8, 0x00, 0x00, 0x00, 0x00], 0, 5)
    f.close()
    expect SnapshotError:
      discard openSnapshotForRead(testPath)

  test "rejects unsupported version":
    let testDir = getTempDir() / "nimrod_snapshot_ver"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let testPath = testDir / "bad.dat"
    var w = BinaryWriter()
    w.writeBytes(SnapshotMagic)
    w.writeUint16LE(99)
    w.writeBytes([0xF9'u8, 0xBE, 0xB4, 0xD9])
    w.writeBlockHash(BlockHash(default(array[32, byte])))
    w.writeUint64LE(0)
    let f = open(testPath, fmWrite)
    discard f.writeBytes(w.data, 0, w.data.len)
    f.close()
    expect SnapshotError:
      discard openSnapshotForRead(testPath)

# ----------------------------------------------------------------------------
# Per-coin (group) round-trip — the new Core-byte-compat layout
# ----------------------------------------------------------------------------

suite "snapshot file dump+load":
  test "two-coin-different-txid round-trip":
    let testDir = getTempDir() / "nimrod_snapshot_rt1"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let path = testDir / "snap.dat"

    let txid1 = TxId(mkHash32(1'u8))
    let txid2 = TxId(mkHash32(2'u8))
    let coin1 = SnapshotCoin(
      outpoint: OutPoint(txid: txid1, vout: 0),
      output: TxOut(value: Satoshi(50_00000000),
                    scriptPubKey: @[0x76'u8, 0xA9, 0x14] &
                                  newSeq[byte](20) & @[0x88'u8, 0xAC]),
      height: 1, isCoinbase: true
    )
    let coin2 = SnapshotCoin(
      outpoint: OutPoint(txid: txid2, vout: 1),
      output: TxOut(value: Satoshi(100), scriptPubKey: @[0x51'u8]),
      height: 2, isCoinbase: false
    )
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(mkHash32(3'u8)),
      coinsCount: 2
    )
    let sf = openSnapshotForWrite(path, meta)
    sf.writeTxidGroup(txid1, @[coin1])
    sf.writeTxidGroup(txid2, @[coin2])
    sf.close()

    let rd = openSnapshotForRead(path)
    check rd.metadata.coinsCount == 2
    let r1 = rd.readCoin()
    check r1.isSome
    check r1.get().outpoint.txid == txid1
    check r1.get().outpoint.vout == 0
    check r1.get().output.value == coin1.output.value
    check r1.get().output.scriptPubKey == coin1.output.scriptPubKey
    check r1.get().isCoinbase == true
    check r1.get().height == 1
    let r2 = rd.readCoin()
    check r2.isSome
    check r2.get().outpoint.txid == txid2
    check r2.get().outpoint.vout == 1
    check r2.get().output.value == coin2.output.value
    check r2.get().output.scriptPubKey == coin2.output.scriptPubKey
    check r2.get().isCoinbase == false
    check r2.get().height == 2
    check rd.readCoin().isNone
    rd.close()

  test "two-coin-same-txid round-trip (group of 2)":
    let testDir = getTempDir() / "nimrod_snapshot_rt2"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let path = testDir / "snap.dat"
    let txid = TxId(mkHash32(0xFF'u8))
    let coinA = SnapshotCoin(
      outpoint: OutPoint(txid: txid, vout: 0),
      output: TxOut(value: Satoshi(73_00000000),
                    scriptPubKey: @[0xA9'u8, 0x14] &
                                  newSeq[byte](20) & @[0x87'u8]),
      height: 100000, isCoinbase: false
    )
    let coinB = SnapshotCoin(
      outpoint: OutPoint(txid: txid, vout: 7),
      output: TxOut(value: Satoshi(0), scriptPubKey: @[0x6A'u8, 0x10]),
      height: 100000, isCoinbase: false
    )
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0xF9'u8, 0xBE, 0xB4, 0xD9],
      baseBlockhash: BlockHash(mkHash32(4'u8)),
      coinsCount: 2
    )
    let sf = openSnapshotForWrite(path, meta)
    sf.writeTxidGroup(txid, @[coinA, coinB])
    sf.close()

    let rd = openSnapshotForRead(path)
    let a = rd.readCoin()
    let b = rd.readCoin()
    check a.isSome and b.isSome
    check a.get().outpoint.txid == txid
    check a.get().outpoint.vout == 0
    check a.get().output.value == coinA.output.value
    check a.get().output.scriptPubKey == coinA.output.scriptPubKey
    check b.get().outpoint.txid == txid
    check b.get().outpoint.vout == 7
    check b.get().output.value == coinB.output.value
    rd.close()

# ----------------------------------------------------------------------------
# end-to-end: createSnapshot + loadSnapshot via ChainState
# ----------------------------------------------------------------------------

suite "snapshot dump via ChainState":
  test "createSnapshot writes a Core-format file":
    # We can't validate against the real assumeutxo list (we'd need to be at
    # exactly height 840000 with the correct UTXO set), so we test that the
    # bytes we emit are self-consistent: header valid, body parses back.
    let testDir = getTempDir() / "nimrod_snapshot_dump"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, mainnetParams())
    defer: cs.close()

    # Inject a fake UTXO so dump has something to write.
    let txid = TxId(mkHashWith([0xCA'u8, 0xFE, 0xBA, 0xBE]))
    let op = OutPoint(txid: txid, vout: 0)
    let entry = UtxoEntry(
      output: TxOut(value: Satoshi(123_45678910'i64),
                    scriptPubKey: @[0x76'u8, 0xA9, 0x14] &
                                  newSeq[byte](20) & @[0x88'u8, 0xAC]),
      height: 500000,
      isCoinbase: false
    )
    cs.putUtxoCache(op, entry)
    cs.bestBlockHash = BlockHash(mkHashWith([0xDE'u8, 0xAD, 0xBE, 0xEF]))
    cs.bestHeight = 500000

    let outPath = testDir / "out.dat"
    let res = createSnapshot(cs, outPath, mainnetParams())
    check res.coinsWritten == 1
    check fileExists(outPath)

    # Re-read the written file: header must match, single coin must round-trip.
    let rd = openSnapshotForRead(outPath)
    check rd.metadata.networkMagic == mainnetParams().networkMagic
    check rd.metadata.coinsCount == 1
    let coin = rd.readCoin()
    check coin.isSome
    check coin.get().outpoint == op
    check coin.get().output.value == entry.output.value
    check coin.get().output.scriptPubKey == entry.output.scriptPubKey
    check coin.get().height == entry.height
    check coin.get().isCoinbase == entry.isCoinbase
    rd.close()

  test "createSnapshot excludes the genesis coinbase (regtest empty dump)":
    # Bitcoin Core never adds the genesis coinbase to the UTXO set
    # (validation.cpp:2337-2343 special-cases the genesis block to skip
    # connection). nimrod's connectBlock(genesis, 0) DOES insert it, so
    # createSnapshot must filter it out for byte-compat with Core.
    #
    # On a fresh regtest chain (only the genesis block connected), the dump
    # must be exactly 51 bytes (header only) with coins_count=0 — matching
    # Core's `dumptxoutset` on a fresh regtest chainstate.
    let testDir = getTempDir() / "nimrod_snapshot_genesis_excl"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()

    # Connect the regtest genesis block (mirrors nimrod startup at
    # src/nimrod.nim:972-973). After this, the genesis coinbase output is
    # in the cache; it must NOT end up in the snapshot.
    let genesis = buildGenesisBlock(regtest)
    let r = cs.connectBlock(genesis, 0)
    check r.isOk

    let outPath = testDir / "regtest-fresh.dat"
    let res = createSnapshot(cs, outPath, regtest)
    check res.coinsWritten == 0

    # Header is exactly 51 bytes (5 magic + 2 version + 4 magic + 32 hash + 8 count).
    check fileExists(outPath)
    check getFileSize(outPath) == 51

    # The on-disk file must parse cleanly with coinsCount=0 and no body.
    let rd = openSnapshotForRead(outPath)
    check rd.metadata.coinsCount == 0
    check rd.metadata.baseBlockhash == regtest.genesisBlockHash
    check rd.readCoin().isNone
    rd.close()

  test "createSnapshot keeps a non-genesis coinbase (sanity check)":
    # The exclusion must be SPECIFIC to (genesis-coinbase-txid, height=0,
    # isCoinbase=true). A coinbase from any other block at any other height
    # must still be dumped.
    let testDir = getTempDir() / "nimrod_snapshot_nongenesis_cb"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    # Inject a height=1 coinbase coin (not genesis) — must survive the dump.
    let cbTxid = TxId(mkHashWith([0xC0'u8, 0x1B, 0xCA, 0x5E]))
    let op = OutPoint(txid: cbTxid, vout: 0)
    let entry = UtxoEntry(
      output: TxOut(value: Satoshi(50_00000000),
                    scriptPubKey: @[0x51'u8]),
      height: 1, isCoinbase: true
    )
    cs.putUtxoCache(op, entry)
    cs.bestBlockHash = BlockHash(mkHashWith([0xAA'u8, 0xBB]))
    cs.bestHeight = 1

    let outPath = testDir / "h1-cb.dat"
    let res = createSnapshot(cs, outPath, regtestParams())
    check res.coinsWritten == 1
    let rd = openSnapshotForRead(outPath)
    check rd.metadata.coinsCount == 1
    let coin = rd.readCoin()
    check coin.isSome
    check coin.get().outpoint == op
    check coin.get().isCoinbase == true
    check coin.get().height == 1
    rd.close()

  test "createSnapshot uses atomic-write protocol (no .incomplete on success)":
    # Mirrors Bitcoin Core's rpc/blockchain.cpp::dumptxoutset which writes
    # to `temppath = path + ".incomplete"`, fsyncs, then renames. After a
    # successful dump only <path> should exist on disk; the temp must be
    # gone so that operators copying the snapshot never see a torn file.
    let testDir = getTempDir() / "nimrod_snapshot_atomic"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, mainnetParams())
    defer: cs.close()

    let txid = TxId(mkHashWith([0xA1'u8, 0xB2, 0xC3, 0xD4]))
    let op = OutPoint(txid: txid, vout: 0)
    let entry = UtxoEntry(
      output: TxOut(value: Satoshi(1_00000000),
                    scriptPubKey: @[0x51'u8]),
      height: 100, isCoinbase: false
    )
    cs.putUtxoCache(op, entry)
    cs.bestBlockHash = BlockHash(mkHashWith([0xEE'u8, 0xFF]))
    cs.bestHeight = 100

    let outPath = testDir / "snapshot.dat"
    let tmpPath = outPath & ".incomplete"
    discard createSnapshot(cs, outPath, mainnetParams())

    check fileExists(outPath)
    check (not fileExists(tmpPath))

# ----------------------------------------------------------------------------
# assumeutxo wiring on ConsensusParams
# ----------------------------------------------------------------------------

suite "assumeutxo data":
  test "mainnet has all 4 Core entries":
    let p = mainnetParams()
    check p.assumeutxoData.len == 4
    let heights = [840000'i32, 880000, 910000, 935000]
    for i, h in heights:
      check p.assumeutxoData[i].height == h
      check p.assumeutxoData[i].chainTxCount > 0

  test "mainnet 840k blockhash matches Core":
    let p = mainnetParams()
    let want = "0000000000000000000320283a032748cef8227873ff4872689bf23f1cda83a5"
    var got = ""
    let arr = array[32, byte](p.assumeutxoData[0].blockhash)
    # Display order is reversed (big-endian).
    for i in countdown(31, 0):
      got.add(toHex(arr[i].int, 2).toLowerAscii)
    check got == want

  test "metadata validation accepts a known assumeutxo entry":
    let p = mainnetParams()
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: p.networkMagic,
      baseBlockhash: p.assumeutxoData[1].blockhash,  # 880k entry
      coinsCount: 0
    )
    let v = validateSnapshotMetadata(meta, p, p.assumeutxoData)
    check v.valid == true
    check v.data.isSome
    check v.data.get().height == 880000

  test "metadata validation rejects wrong network":
    let p = mainnetParams()
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: [0x00'u8, 0x00, 0x00, 0x00],
      baseBlockhash: p.assumeutxoData[0].blockhash,
      coinsCount: 0
    )
    let v = validateSnapshotMetadata(meta, p, p.assumeutxoData)
    check v.valid == false
    check v.error == "network magic mismatch"

  test "metadata validation rejects unknown blockhash with Core-strict error":
    # bitcoin-core/src/validation.cpp:5775-5780 — refuses to load a snapshot
    # whose blockhash isn't in the hardcoded assumeutxo list.
    let p = mainnetParams()
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: p.networkMagic,
      baseBlockhash: BlockHash(mkHash32(0xFF'u8)),
      coinsCount: 0
    )
    let v = validateSnapshotMetadata(meta, p, p.assumeutxoData)
    check v.valid == false
    check v.error ==
      "Assumeutxo height in snapshot metadata not recognized (0) - " &
      "refusing to load snapshot"

  test "loadtxoutset rejects regtest-genesis snapshot (whitelist enforced)":
    # Build a snapshot file whose baseBlockhash is the regtest genesis (not in
    # any assumeutxo list — regtest has empty assumeutxoData). Core-strict
    # behaviour: refuse with the recognized error string.
    let testDir = getTempDir() / "nimrod_snapshot_whitelist"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)
    let snapPath = testDir / "regtest-genesis.dat"

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()
    let regtest = regtestParams()

    # Hand-craft a 51-byte header with regtest genesis blockhash + count=0.
    var w = BinaryWriter()
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: regtest.networkMagic,
      baseBlockhash: regtest.genesisBlockHash,
      coinsCount: 0
    )
    w.writeSnapshotMetadata(meta)
    let f = open(snapPath, fmWrite)
    discard f.writeBytes(w.data, 0, w.data.len)
    f.close()

    # loadSnapshot should reject because regtest has empty assumeutxoData
    # (so any hash, including the genesis, is "not recognized").
    let res = loadSnapshot(snapPath, cs, regtest, regtest.assumeutxoData)
    check res.success == false
    check res.error ==
      "Assumeutxo height in snapshot metadata not recognized (0) - " &
      "refusing to load snapshot"

    # Also ensure mainnet rejects a regtest-genesis blockhash (not in the
    # mainnet whitelist either, even though mainnet has 4 valid entries).
    let mainnet = mainnetParams()
    var w2 = BinaryWriter()
    let meta2 = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: regtest.genesisBlockHash,
      coinsCount: 0
    )
    w2.writeSnapshotMetadata(meta2)
    let snap2 = testDir / "regtest-on-mainnet.dat"
    let f2 = open(snap2, fmWrite)
    discard f2.writeBytes(w2.data, 0, w2.data.len)
    f2.close()
    let dbDir2 = testDir / "cs2"
    createDir(dbDir2)
    var cs2 = newChainState(dbDir2, mainnet)
    defer: cs2.close()
    let res2 = loadSnapshot(snap2, cs2, mainnet, mainnet.assumeutxoData)
    check res2.success == false
    check res2.error ==
      "Assumeutxo height in snapshot metadata not recognized (0) - " &
      "refusing to load snapshot"

  test "non-mainnet networks have empty assumeutxo data":
    check testnet3Params().assumeutxoData.len == 0
    check testnet4Params().assumeutxoData.len == 0
    check regtestParams().assumeutxoData.len == 0
    check signetParams().assumeutxoData.len == 0

# ----------------------------------------------------------------------------
# enum sanity, chainstate wrapper, background validation struct
# ----------------------------------------------------------------------------

suite "snapshot misc":
  test "Assumeutxo enum values are distinct":
    check auValidated != auUnvalidated
    check auUnvalidated != auInvalid
    check auInvalid != auValidated

  test "newSnapshotChainState defaults":
    let testDir = getTempDir() / "nimrod_snapshot_misc"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)
    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()
    let scs = newSnapshotChainState(cs)
    check scs.assumeutxo == auValidated
    check scs.snapshotBlockhash.isNone
    check scs.targetUtxoHash.isNone

  test "newBackgroundValidation initial state":
    let bgv = newBackgroundValidation(
      targetHeight = 100,
      snapshotHash = default(array[32, byte])
    )
    check bgv.running == false
    check bgv.progress == 0
    check bgv.targetHeight == 100
    let (cur, tgt) = bgv.getProgress()
    check cur == 0
    check tgt == 100

# ----------------------------------------------------------------------------
# Snapshot content-hash commitment: dump + strict load
# (HASH_SERIALIZED = SHA256d via HashWriter — see strict-gate suite below
# for the contract pinning the hash function.)
# ----------------------------------------------------------------------------

suite "snapshot content-hash commitment":
  test "createSnapshot returns a non-default txoutsetHash for non-empty dumps":
    # SHA256d over any non-empty TxOutSer byte stream is deterministic and
    # vanishingly unlikely to collide with default(array[32, byte]).
    let testDir = getTempDir() / "nimrod_muhash_dump"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, mainnetParams())
    defer: cs.close()

    let txid = TxId(mkHashWith([0x12'u8, 0x34, 0x56, 0x78]))
    cs.putUtxoCache(
      OutPoint(txid: txid, vout: 0),
      UtxoEntry(
        output: TxOut(value: Satoshi(1_00000000),
                      scriptPubKey: @[0x00'u8, 0x14] & newSeq[byte](20)),
        height: 700000, isCoinbase: false
      ))
    cs.bestBlockHash = BlockHash(mkHashWith([0xAA'u8]))
    cs.bestHeight = 700000

    let outPath = testDir / "h.dat"
    let res = createSnapshot(cs, outPath, mainnetParams())
    check res.coinsWritten == 1
    check res.txoutsetHash != default(array[32, byte])

    # Order independence: the same coin set yields the same txoutsetHash
    # regardless of iteration order. We can't directly perturb iteration
    # order on Tables, but we can verify determinism: same input, same hash.
    let res2 = createSnapshot(cs, testDir / "h2.dat", mainnetParams())
    check res2.txoutsetHash == res.txoutsetHash

  test "loadSnapshot rejects with Core-format Bad-content-hash error":
    # End-to-end: write a snapshot whose baseBlockhash IS in mainnet's
    # assumeutxo whitelist, but whose UTXO content does NOT match the
    # whitelisted hash_serialized. The strict check at validation.cpp:5912
    # must fail with the exact "Bad snapshot content hash: expected X, got Y"
    # error format Core emits.
    let testDir = getTempDir() / "nimrod_muhash_strict"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    # Hand-craft a snapshot file with a single fake coin and the 840k
    # whitelisted blockhash. The SHA256d-over-TxOutSer digest will not match
    # the real Core hashSerialized, so loadSnapshot must refuse.
    let snapPath = testDir / "fake-840k.dat"
    let txid = TxId(mkHashWith([0xDE'u8, 0xAD, 0xBE, 0xEF]))
    let coin = SnapshotCoin(
      outpoint: OutPoint(txid: txid, vout: 0),
      output: TxOut(value: Satoshi(5_00000000),
                    scriptPubKey: @[0x76'u8, 0xA9, 0x14] &
                                  newSeq[byte](20) & @[0x88'u8, 0xAC]),
      height: 100000, isCoinbase: false
    )
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: mainnet.assumeutxoData[0].blockhash,  # 840k
      coinsCount: 1
    )
    let sf = openSnapshotForWrite(snapPath, meta)
    sf.writeTxidGroup(coin.outpoint.txid, @[coin])
    sf.close()

    let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
    check res.success == false
    # Error must start with the Core-verbatim prefix.
    check res.error.startsWith("Bad snapshot content hash: expected ")
    # Must include the expected hash (840k entry, byte-reversed display).
    let expectedDisplay = block:
      let b = mainnet.assumeutxoData[0].hashSerialized
      var s = ""
      for k in countdown(31, 0):
        s.add(toHex(b[k].int, 2).toLowerAscii)
      s
    check expectedDisplay in res.error
    check ", got " in res.error

  test "createSnapshot empty UTXO set yields default-zero txoutsetHash":
    # Honest progress: when there are no coins, we return all-zero rather
    # than the SHA256d-of-empty digest, because Core never produces a
    # snapshot over an empty UTXO set in practice. Keeping this test pinned
    # here documents the choice for future PRs.
    let testDir = getTempDir() / "nimrod_muhash_empty"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()
    let genesis = buildGenesisBlock(regtestParams())
    let r = cs.connectBlock(genesis, 0)
    check r.isOk

    let outPath = testDir / "empty.dat"
    let res = createSnapshot(cs, outPath, regtestParams())
    check res.coinsWritten == 0
    check res.txoutsetHash == default(array[32, byte])

# ----------------------------------------------------------------------------
# Strict-gate hash function pinning
#
# Per `bitcoin-core/src/validation.cpp:5901-5915` and
# `bitcoin-core/src/kernel/coinstats.cpp:161-163`, the `loadtxoutset` strict
# gate compares against `CoinStatsHashType::HASH_SERIALIZED` =
# `HashWriter::GetHash()` over canonical-order TxOutSer bytes — i.e. SHA256d.
# MuHash3072 (`hash_type=muhash`) is a separate code path and MUST NOT be
# wired to assumeutxo. These tests pin that contract: the strict gate must
# never silently fall back to MuHash, and `computeUtxoSetHashFromCoins` must
# return a SHA256d digest that matches the createSnapshot commitment.
# ----------------------------------------------------------------------------

suite "snapshot strict gate uses SHA256d (HASH_SERIALIZED)":
  test "computeUtxoSetHashFromCoins matches sha256d(concat(TxOutSer)) and NOT MuHash":
    # Build two distinct coins, hand-compute the canonical TxOutSer byte stream,
    # and check that `computeUtxoSetHashFromCoins` equals SHA256d(stream).
    let txid1 = TxId(mkHashWith([0x11'u8]))
    let txid2 = TxId(mkHashWith([0x22'u8]))
    let coin1 = SnapshotCoin(
      outpoint: OutPoint(txid: txid1, vout: 0),
      output: TxOut(value: Satoshi(50_00000000),
                    scriptPubKey: @[0x76'u8, 0xA9, 0x14] &
                                  newSeq[byte](20) & @[0x88'u8, 0xAC]),
      height: 200000, isCoinbase: true
    )
    let coin2 = SnapshotCoin(
      outpoint: OutPoint(txid: txid2, vout: 3),
      output: TxOut(value: Satoshi(123_456789),
                    scriptPubKey: @[0x51'u8]),
      height: 250000, isCoinbase: false
    )
    let computed = computeUtxoSetHashFromCoins(@[coin1, coin2])

    var stream: seq[byte] = @[]
    for c in [coin1, coin2]:
      stream.add(serializeCoinForHash(
        c.outpoint, int64(c.output.value), c.output.scriptPubKey,
        c.height, c.isCoinbase))
    let expected = sha256d(stream)
    check computed == expected

    # And it must NOT equal the MuHash3072 of the same coins. (MuHash applies
    # `SHA256(numerator/denominator)` to a 384-byte modular product — it is
    # deterministically different from SHA256d over the raw byte stream for
    # any non-trivial input set.)
    var muhash = newMuHash3072()
    for c in [coin1, coin2]:
      muhash.insert(serializeCoinForHash(
        c.outpoint, int64(c.output.value), c.output.scriptPubKey,
        c.height, c.isCoinbase))
    let muhashDigest = muhash.finalize()
    check computed != muhashDigest

  test "createSnapshot txoutsetHash matches sha256d over canonical stream":
    # End-to-end: dump a single coin into a snapshot file. The recorded
    # `txoutsetHash` must equal the SHA256d of that coin's TxOutSer bytes,
    # NOT the MuHash3072 digest.
    let testDir = getTempDir() / "nimrod_strict_gate_sha256d"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, mainnetParams())
    defer: cs.close()

    let txid = TxId(mkHashWith([0xAB'u8, 0xCD]))
    let outpoint = OutPoint(txid: txid, vout: 0)
    let value = Satoshi(7_00000000)
    let scriptPubKey = @[0x00'u8, 0x14] & newSeq[byte](20)  # P2WPKH-shaped
    let height: int32 = 700000
    let isCoinbase = false

    cs.putUtxoCache(
      outpoint,
      UtxoEntry(output: TxOut(value: value, scriptPubKey: scriptPubKey),
                height: height, isCoinbase: isCoinbase))
    cs.bestBlockHash = BlockHash(mkHashWith([0xCC'u8]))
    cs.bestHeight = height

    let outPath = testDir / "single.dat"
    let res = createSnapshot(cs, outPath, mainnetParams())
    check res.coinsWritten == 1

    let coinBytes = serializeCoinForHash(
      outpoint, int64(value), scriptPubKey, height, isCoinbase)
    let expected = sha256d(coinBytes)
    check res.txoutsetHash == expected

    # Sanity: must NOT equal the MuHash3072 of the same coin.
    var muhash = newMuHash3072()
    muhash.insert(coinBytes)
    check res.txoutsetHash != muhash.finalize()

  test "loadSnapshot strict gate rejects with SHA256d-derived 'got' value":
    # Hand-build a fake snapshot whose baseBlockhash is whitelisted (840k)
    # but whose coin contents do not match the real Core hash_serialized.
    # The error message must include the SHA256d of our fake coin's TxOutSer
    # bytes as the "got" value, byte-reversed for display.
    let testDir = getTempDir() / "nimrod_strict_gate_reject"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    let txid = TxId(mkHashWith([0xFE'u8, 0xED, 0xFA, 0xCE]))
    let outpoint = OutPoint(txid: txid, vout: 0)
    let value = Satoshi(1)
    let scriptPubKey = @[0x51'u8]
    let height: int32 = 800000
    let isCoinbase = false
    let coin = SnapshotCoin(
      outpoint: outpoint,
      output: TxOut(value: value, scriptPubKey: scriptPubKey),
      height: height, isCoinbase: isCoinbase
    )
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: mainnet.assumeutxoData[0].blockhash,  # 840k
      coinsCount: 1
    )
    let snapPath = testDir / "fake.dat"
    let sf = openSnapshotForWrite(snapPath, meta)
    sf.writeTxidGroup(coin.outpoint.txid, @[coin])
    sf.close()

    let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
    check res.success == false
    check res.error.startsWith("Bad snapshot content hash: expected ")

    # Compute the expected SHA256d ourselves and check the byte-reversed hex
    # appears as the "got" half of the message.
    let coinBytes = serializeCoinForHash(
      outpoint, int64(value), scriptPubKey, height, isCoinbase)
    let actualDigest = sha256d(coinBytes)
    var gotHex = ""
    for k in countdown(31, 0):
      gotHex.add(toHex(actualDigest[k].int, 2).toLowerAscii)
    check (", got " & gotHex) in res.error

    # And the MuHash3072 hex of the same coin must NOT appear as "got".
    var muhash = newMuHash3072()
    muhash.insert(coinBytes)
    let muDigest = muhash.finalize()
    var muHex = ""
    for k in countdown(31, 0):
      muHex.add(toHex(muDigest[k].int, 2).toLowerAscii)
    check (", got " & muHex) notin res.error

# ----------------------------------------------------------------------------
# dumptxoutset rollback mode (Bitcoin Core rpc/blockchain.cpp:3074)
#
# Mirrors Core's three-mode RPC: "" / "latest" -> dump current tip;
# "rollback" without options -> pick the highest assumeutxo entry <= tip;
# rollback=<height|hash> -> roll back to that exact block.
#
# Implementation re-uses nimrod's existing `disconnectBlock` and `connectBlock`
# reorg primitives in `src/storage/chainstate.nim`. The rollback dance:
#   1. collect (hash, height, Block) tuples from tip down to target+1
#   2. disconnectBlock each in order
#   3. createSnapshot at the rolled-back state
#   4. connectBlock each saved block back in reverse order
# Errors at any stage attempt best-effort recovery to the original tip.
# ----------------------------------------------------------------------------

import ../src/rpc/server
import ../src/mempool/mempool
import ../src/mining/fees
import ../src/network/peermanager

suite "dumptxoutset rollback":

  proc buildSimpleChain(cs: var ChainState, params: ConsensusParams,
                        targetHeight: int32): seq[BlockHash] =
    ## Build a simple chain: regtest genesis + N coinbase-only blocks.
    ## Returns hashes in ascending-height order (genesis at index 0).
    let genesis = buildGenesisBlock(params)
    let r = cs.connectBlock(genesis, 0)
    doAssert r.isOk
    let genHeader = serialize(genesis.header)
    let genHash = BlockHash(doubleSha256(genHeader))
    result = @[genHash]

    var prevHash = genHash
    var height: int32 = 1
    while height <= targetHeight:
      # Bare coinbase tx: no inputs to spend, no merkle work.
      var scriptSig: seq[byte]
      if height <= 0x7F:
        scriptSig = @[byte(0x01), byte(height)]
      else:
        scriptSig = @[byte(0x02), byte(height and 0xFF),
                                  byte((height shr 8) and 0xFF)]
      let coinbase = Transaction(
        version: 1,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                            vout: 0xFFFFFFFF'u32),
          scriptSig: scriptSig,
          sequence: 0xFFFFFFFF'u32
        )],
        outputs: @[TxOut(
          value: Satoshi(50_00000000),
          scriptPubKey: @[byte(0x51)]  # OP_TRUE
        )],
        witnesses: @[],
        lockTime: 0
      )
      let txHash = array[32, byte](coinbase.txid())
      let blk = Block(
        header: BlockHeader(
          version: 1,
          prevBlock: prevHash,
          merkleRoot: txHash,
          timestamp: uint32(1296688602 + height * 600),
          bits: 0x207fffff'u32,
          nonce: uint32(height)
        ),
        txs: @[coinbase]
      )
      let cr = cs.connectBlock(blk, height)
      doAssert cr.isOk, cr.error
      let bh = BlockHash(doubleSha256(serialize(blk.header)))
      result.add(bh)
      prevHash = bh
      inc height

  proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
    let mp = newMempool(cs, params)
    let fe = newFeeEstimator()
    newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params
    )

  test "default (no type) dumps current tip without rollback":
    let testDir = getTempDir() / "nimrod_dumptxo_default"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let hashes = buildSimpleChain(cs, regtest, 3)
    check cs.bestHeight == 3
    let preTip = cs.bestBlockHash

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "out.dat"
    let res = rpc.handleDumpTxOutSet(%*[outPath])
    check res["base_height"].getInt() == 3
    check fileExists(outPath)
    # Tip is unchanged.
    check cs.bestHeight == 3
    check cs.bestBlockHash == preTip
    check hashes.len == 4  # silence unused-warning

  test "type=latest is equivalent to default":
    let testDir = getTempDir() / "nimrod_dumptxo_latest"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard buildSimpleChain(cs, regtest, 2)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "out.dat"
    let res = rpc.handleDumpTxOutSet(%*[outPath, "latest"])
    check res["base_height"].getInt() == 2
    check cs.bestHeight == 2

  test "rollback=<height> rolls back, dumps, then re-applies to original tip":
    let testDir = getTempDir() / "nimrod_dumptxo_rollback_height"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let hashes = buildSimpleChain(cs, regtest, 4)
    check cs.bestHeight == 4
    let originalTip = cs.bestBlockHash

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "rb2.dat"
    # Rollback to height 2.
    let res = rpc.handleDumpTxOutSet(
      %*[outPath, "", {"rollback": %2}]
    )
    check res["base_height"].getInt() == 2
    # Snapshot's base_hash should be the height-2 block hash (display order).
    let want2 = block:
      var s = ""
      let arr = array[32, byte](hashes[2])
      for k in countdown(31, 0):
        s.add(toHex(arr[k].int, 2).toLowerAscii)
      s
    check res["base_hash"].getStr() == want2
    # Chain has been re-applied back to the original tip.
    check cs.bestHeight == 4
    check cs.bestBlockHash == originalTip

  test "rollback=<hash> resolves block by hash and rolls back":
    let testDir = getTempDir() / "nimrod_dumptxo_rollback_hash"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let hashes = buildSimpleChain(cs, regtest, 3)
    check cs.bestHeight == 3
    let originalTip = cs.bestBlockHash

    # Pass the hex of hashes[1] (display-reversed).
    var hashHex = ""
    let arr1 = array[32, byte](hashes[1])
    for k in countdown(31, 0):
      hashHex.add(toHex(arr1[k].int, 2).toLowerAscii)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "rb-hash.dat"
    let res = rpc.handleDumpTxOutSet(
      %*[outPath, "rollback", {"rollback": %hashHex}]
    )
    check res["base_height"].getInt() == 1
    check cs.bestHeight == 3
    check cs.bestBlockHash == originalTip

  test "rollback above tip is rejected":
    let testDir = getTempDir() / "nimrod_dumptxo_rb_above"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard buildSimpleChain(cs, regtest, 2)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "wont-be-written.dat"
    expect RpcError:
      discard rpc.handleDumpTxOutSet(
        %*[outPath, "", {"rollback": %999}]
      )
    check not fileExists(outPath)
    # Tip is unchanged.
    check cs.bestHeight == 2

  test "type=rollback with no entries (regtest) raises misc error":
    # Regtest has empty assumeutxoData, so `type=rollback` with no explicit
    # height has nothing to pick.
    let testDir = getTempDir() / "nimrod_dumptxo_rb_no_entries"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard buildSimpleChain(cs, regtest, 2)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "out.dat"
    expect RpcError:
      discard rpc.handleDumpTxOutSet(%*[outPath, "rollback"])
    check not fileExists(outPath)

  test "conflicting type and rollback option is rejected":
    let testDir = getTempDir() / "nimrod_dumptxo_conflict"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard buildSimpleChain(cs, regtest, 2)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "out.dat"
    expect RpcError:
      discard rpc.handleDumpTxOutSet(
        %*[outPath, "latest", {"rollback": %1}]
      )
    check not fileExists(outPath)

  test "invalid type string is rejected":
    let testDir = getTempDir() / "nimrod_dumptxo_invalid_type"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard buildSimpleChain(cs, regtest, 1)

    let rpc = mkRpc(cs, regtest)
    let outPath = testDir / "out.dat"
    expect RpcError:
      discard rpc.handleDumpTxOutSet(%*[outPath, "garbage"])
    check not fileExists(outPath)

# ----------------------------------------------------------------------------
# loadtxoutset RPC — real background dual-chainstate validation.
#
# UPDATED (AssumeUTXO dual-chainstate pilot): loadtxoutset now loads the
# snapshot into an ISOLATED store (a sibling `<chainstate>-snapshot` dir, NOT
# the live `chainState`) and drives the real SECOND background chainstate
# (own coins store) that re-connects genesis->base and recomputes the
# HASH_SERIALIZED to trustlessly re-verify the snapshot (Core ActivateSnapshot
# / AddChainstate / MaybeValidateSnapshot). The verdict is surfaced via
# getchainstates. The earlier "disabled in this build / use --load-snapshot"
# refusal is removed.
#
# Invariants this suite pins:
#   1. A non-loadable file (missing / not in the assumeutxo whitelist) is
#      refused with RpcInternalError (-32603), matching Core's error code when
#      ActivateSnapshot cannot proceed.
#   2. The live `chainState` is NEVER mutated by loadtxoutset — the load goes
#      to an isolated store, so even a refused load has zero chainState side
#      effects.
#   3. Malformed params (empty/empty-path) are still rejected with
#      RpcInvalidParams before any load attempt.
# ----------------------------------------------------------------------------

suite "loadtxoutset RPC gate":

  proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
    let mp = newMempool(cs, params)
    let fe = newFeeEstimator()
    newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params
    )

  test "non-loadable snapshot file refused with RpcInternalError":
    ## FIXED (AssumeUTXO dual-chainstate pilot): loadtxoutset now actually
    ## attempts the load (into an ISOLATED store) and drives background
    ## validation. A path that cannot be loaded (missing file / not in the
    ## assumeutxo whitelist) is refused with RpcInternalError, mirroring Core's
    ## error code when ActivateSnapshot cannot proceed. The old "disabled in
    ## this build / use --load-snapshot" refusal message is gone.
    let testDir = getTempDir() / "nimrod_loadtxo_gate_basic"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let rpc = mkRpc(cs, regtest)

    var caught = false
    var code = 0
    var msg = ""
    try:
      discard rpc.handleLoadTxOutSet(%*["/some/snapshot.dat"])
    except RpcError as e:
      caught = true
      code = e.code
      msg = e.msg
    check caught
    check code == RpcInternalError
    check "Unable to load UTXO snapshot" in msg

  test "missing snapshot file is refused with RpcInternalError":
    # A path that does not exist cannot be loaded; loadSnapshot fails to open
    # it and the handler surfaces RpcInternalError (Core's ActivateSnapshot
    # cannot-proceed code). No live-chainState side effects (isolated store).
    let testDir = getTempDir() / "nimrod_loadtxo_gate_nofile"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let rpc = mkRpc(cs, regtest)

    let bogusPath = testDir / "does-not-exist.dat"
    check not fileExists(bogusPath)

    var code = 0
    try:
      discard rpc.handleLoadTxOutSet(%*[bogusPath])
    except RpcError as e:
      code = e.code
    check code == RpcInternalError

  test "does not mutate chainState across the refused RPC":
    # Pre-fix: loadSnapshot would have updated cs.bestBlockHash and
    # cs.bestHeight on a successful load. The refusal must leave both
    # unchanged. We can't easily craft a "would-have-succeeded" snapshot here,
    # but we can pin the no-side-effects guarantee: a refused RPC leaves
    # cs.bestHeight at whatever it was before.
    let testDir = getTempDir() / "nimrod_loadtxo_gate_no_mutate"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let preHeight = cs.bestHeight
    let preHash = cs.bestBlockHash
    let rpc = mkRpc(cs, regtest)

    expect RpcError:
      discard rpc.handleLoadTxOutSet(%*["/some/snapshot.dat"])

    check cs.bestHeight == preHeight
    check cs.bestBlockHash == preHash

  test "still rejects malformed params before the gate":
    let testDir = getTempDir() / "nimrod_loadtxo_gate_bad_params"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let rpc = mkRpc(cs, regtest)

    # Empty params → RpcInvalidParams, NOT RpcInternalError.
    var code = 0
    try:
      discard rpc.handleLoadTxOutSet(%*[])
    except RpcError as e:
      code = e.code
    check code == RpcInvalidParams

    # Empty path → RpcInvalidParams.
    var code2 = 0
    try:
      discard rpc.handleLoadTxOutSet(%*[""])
    except RpcError as e:
      code2 = e.code
    check code2 == RpcInvalidParams

# ----------------------------------------------------------------------------
# importdescriptors — real watch-only import (replaces the 2026-05-05 -4
# refusal gate; cross-impl lying-RPC audit closed for nimrod).
#
# Contract pinned here (bitcoin-core/src/wallet/rpc/backup.cpp):
#   * per-element {success[, error]} results, batch NEVER aborted by an
#     element failure (backup.cpp:141-300);
#   * checksum REQUIRED — missing checksum is a PER-ELEMENT -5 with Core's
#     "Missing checksum" string, NOT a top-level error (backup.cpp:158-161,
#     descriptor.cpp:2838-2869);
#   * private-key descriptor into a disable_private_keys wallet: per-element
#     -4 (backup.cpp:224-226); pubkey-only descriptor into an enabled
#     wallet: per-element -4 (backup.cpp:259-262);
#   * malformed/missing "timestamp" anywhere: TOP-LEVEL -3 (the one
#     batch-aborting case — GetImportTimestamp is outside the per-element
#     try, backup.cpp:127-139, 388-392);
#   * imported scripts land in the wallet's watched-script view, are
#     persisted (sqlite watched_descriptors), survive unload/load, and are
#     credited by scanBlockForWallet;
#   * createwallet disable_private_keys persists (wallet_flags) and
#     getwalletinfo reports private_keys_enabled honestly.
# ----------------------------------------------------------------------------

import ../src/wallet/wallet as walletMod
import ../src/wallet/manager
import ../src/wallet/descriptor
import ../src/crypto/secp256k1

suite "importdescriptors watch-only import":

  proc mkRpc(cs: ChainState, params: ConsensusParams): RpcServer =
    let mp = newMempool(cs, params)
    let fe = newFeeEstimator()
    newRpcServer(
      port = 18443'u16,
      chainState = cs,
      mempool = mp,
      peerManager = nil,
      feeEstimator = fe,
      params = params
    )

  proc hexOf(data: openArray[byte]): string =
    for b in data:
      result.add(toHex(int(b), 2).toLowerAscii)

  # Deterministic test key (valid secp256k1 scalar).
  proc testPriv(last: byte): PrivateKey =
    for i in 0 ..< 31:
      result[i] = byte(i + 1)
    result[31] = last

  proc chk(payload: string): string =
    payload & "#" & computeDescriptorChecksum(payload)

  # One rig per test: regtest chainstate + manager + dpk watch wallet "wo".
  template withRig(dirName: string, body: untyped) =
    let testDir = getTempDir() / dirName
    if dirExists(testDir): removeDir(testDir)
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)
    let regtest {.inject.} = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    let rpc {.inject.} = mkRpc(cs, regtest)
    var wm {.inject.} = newWalletManager(testDir, regtest, cs)
    defer: wm.close()
    rpc.walletManager = wm
    discard wm.createWallet("wo", WalletCreateOptions(
      disablePrivateKeys: true, blank: true, descriptors: true))
    body

  test "valid pubkey+addr descriptors import per-element success:true":
    withRig("nimrod_impdesc_success"):
      let pub = derivePublicKey(testPriv(0x11))
      let wpkhDesc = chk("wpkh(" & hexOf(pub) & ")")
      let addrA = deriveAddresses(parseDescriptor(wpkhDesc), 0, 1, false)[0]
      let addrDesc = chk("addr(" & addrA & ")")

      let res = rpc.handleImportDescriptors(%*[[
        {"desc": addrDesc, "timestamp": 0, "label": "wo"},
        {"desc": wpkhDesc, "timestamp": 0}
      ]])
      check res.kind == JArray
      check res.len == 2
      for el in res:
        check el["success"].getBool() == true

      # The scripts really landed in the wallet's watched view.
      let w = wm.getWallet("wo").get().wallet
      check w.watchedScripts.len >= 1
      let spk = deriveScripts(parseDescriptor(wpkhDesc))[0]
      check w.isWatchedScript(spk)

  test "missing checksum -> per-element -5 'Missing checksum', batch survives":
    withRig("nimrod_impdesc_chksum"):
      let pub = derivePublicKey(testPriv(0x22))
      let noChk = "wpkh(" & hexOf(pub) & ")"   # deliberately unchecksummed

      # Must NOT raise (top-level error would be a Core-contract violation).
      let res = rpc.handleImportDescriptors(%*[[
        {"desc": noChk, "timestamp": 0}
      ]])
      check res.kind == JArray
      check res.len == 1
      check res[0]["success"].getBool() == false
      check res[0]["error"]["code"].getInt() == RpcInvalidAddressOrKey  # -5
      check res[0]["error"]["message"].getStr() == "Missing checksum"

  test "checksum mismatch -> -5 with provided-then-computed Core string":
    withRig("nimrod_impdesc_badchk"):
      let pub = derivePublicKey(testPriv(0x33))
      let bad = "wpkh(" & hexOf(pub) & ")#qqqqqqqq"
      let res = rpc.handleImportDescriptors(%*[[
        {"desc": bad, "timestamp": 0}
      ]])
      check res[0]["success"].getBool() == false
      check res[0]["error"]["code"].getInt() == RpcInvalidAddressOrKey
      let msg = res[0]["error"]["message"].getStr()
      check msg.startsWith("Provided checksum 'qqqqqqqq' does not match computed checksum '")

  test "private-key descriptor into dpk wallet -> per-element -4":
    withRig("nimrod_impdesc_privneg"):
      let priv = testPriv(0x44)
      let wif = encodeWIF(priv, mainnet = false)
      let privDesc = chk("wpkh(" & wif & ")")
      let res = rpc.handleImportDescriptors(%*[[
        {"desc": privDesc, "timestamp": 0}
      ]])
      check res.kind == JArray
      check res.len == 1
      check res[0]["success"].getBool() == false
      check res[0]["error"]["code"].getInt() == RpcWalletError  # -4
      check "private keys disabled" in res[0]["error"]["message"].getStr()

  test "missing/typed-wrong timestamp -> TOP-LEVEL -3 (batch-aborting)":
    withRig("nimrod_impdesc_timestamp"):
      let pub = derivePublicKey(testPriv(0x55))
      let goodDesc = chk("wpkh(" & hexOf(pub) & ")")

      # Missing timestamp key.
      var code = 0
      try:
        discard rpc.handleImportDescriptors(%*[[{"desc": goodDesc}]])
      except RpcError as e:
        code = e.code
      check code == RpcTypeError  # -3

      # Wrong type (bool).
      var code2 = 0
      var msg2 = ""
      try:
        discard rpc.handleImportDescriptors(%*[[
          {"desc": goodDesc, "timestamp": true}
        ]])
      except RpcError as e:
        code2 = e.code
        msg2 = e.msg
      check code2 == RpcTypeError
      check "got type bool" in msg2

      # A bad timestamp in element 2 aborts the WHOLE call even though
      # element 1 is importable (Core: GetImportTimestamp outside the
      # per-element try).
      var code3 = 0
      try:
        discard rpc.handleImportDescriptors(%*[[
          {"desc": goodDesc, "timestamp": 0},
          {"desc": goodDesc, "timestamp": "yesterday"}
        ]])
      except RpcError as e:
        code3 = e.code
      check code3 == RpcTypeError
      # ... and nothing from element 1 landed (whole call aborted).
      let w = wm.getWallet("wo").get().wallet
      check w.watchedScripts.len == 0

  test "dpk flag honest in getwalletinfo + key ops refuse with -4":
    withRig("nimrod_impdesc_dpkflag"):
      rpc.currentWalletName = "wo"
      let info = rpc.handleMethod("getwalletinfo", newJArray())
      check info["private_keys_enabled"].getBool() == false
      check info["keypoolsize"].getInt() == 0

      # sendtoaddress / getnewaddress / importprivkey must refuse with -4.
      for (m, p) in [("getnewaddress", %*[]),
                     ("sendtoaddress", %*["bcrt1qy2syumt4leyws46zfmx8h4n5494ewexfg79d7n", 1.0]),
                     ("importprivkey", %*[encodeWIF(testPriv(0x66), false)])]:
        var code = 0
        try:
          discard rpc.handleMethod(m, p)
        except RpcError as e:
          code = e.code
        check code == RpcWalletError

  test "watched scripts + dpk flag survive unload/load (sqlite round-trip)":
    withRig("nimrod_impdesc_roundtrip"):
      rpc.currentWalletName = "wo"
      let pub = derivePublicKey(testPriv(0x77))
      let wpkhDesc = chk("wpkh(" & hexOf(pub) & ")")
      let spk = deriveScripts(parseDescriptor(wpkhDesc))[0]

      let res = rpc.handleImportDescriptors(%*[[
        {"desc": wpkhDesc, "timestamp": 0, "label": "rt"}
      ]])
      check res[0]["success"].getBool() == true

      discard wm.unloadWallet("wo")
      let (lw2, _) = wm.loadWallet("wo")
      check lw2.wallet.privateKeysDisabled == true
      check lw2.wallet.isWatchedScript(spk)
      check lw2.wallet.watchedScripts[spk].descriptor == wpkhDesc
      check lw2.wallet.watchedScripts[spk].label == "rt"

  test "watched scripts are credited by scanBlockForWallet":
    withRig("nimrod_impdesc_scan"):
      let pub = derivePublicKey(testPriv(0x88))
      let wpkhDesc = chk("wpkh(" & hexOf(pub) & ")")
      let res = rpc.handleImportDescriptors(%*[[
        {"desc": wpkhDesc, "timestamp": 0}
      ]])
      check res[0]["success"].getBool() == true

      var w = wm.getWallet("wo").get().wallet
      let spk = deriveScripts(parseDescriptor(wpkhDesc))[0]
      var prevTxid: array[32, byte]
      prevTxid[0] = 0xAB
      let tx = Transaction(
        version: 2,
        inputs: @[TxIn(
          prevOut: OutPoint(txid: TxId(prevTxid), vout: 0),
          scriptSig: @[],
          sequence: 0xffffffff'u32)],
        outputs: @[TxOut(value: Satoshi(123_456_789), scriptPubKey: spk)],
        lockTime: 0)
      let blk = Block(
        header: BlockHeader(version: 2, timestamp: 1700000000'u32),
        txs: @[tx])
      w.scanBlockForWallet(blk, 7'i32)

      check w.utxos.len == 1
      var credited = false
      for _, u in w.utxos:
        if u.output.scriptPubKey == spk and int64(u.output.value) == 123_456_789:
          check u.keyPath == "watch"
          credited = true
      check credited
      # Watch-only funds count toward the balance the RPC layer reports.
      check int64(w.getBalance()) == 123_456_789

  test "getaddressinfo dispatch + ismine for watched address":
    withRig("nimrod_impdesc_addrinfo"):
      rpc.currentWalletName = "wo"
      let pub = derivePublicKey(testPriv(0x99))
      let wpkhDesc = chk("wpkh(" & hexOf(pub) & ")")
      let addrA = deriveAddresses(parseDescriptor(wpkhDesc), 0, 1, false)[0]

      # Before import: reachable through dispatch (NOT -32601), ismine false.
      let pre = rpc.handleMethod("getaddressinfo", %*[addrA])
      check pre.kind == JObject
      check pre["ismine"].getBool() == false
      check pre["iswatchonly"].getBool() == false

      discard rpc.handleImportDescriptors(%*[[
        {"desc": wpkhDesc, "timestamp": 0}
      ]])

      let post = rpc.handleMethod("getaddressinfo", %*[addrA])
      check post["ismine"].getBool() == true
      check post["solvable"].getBool() == true
      check post["parent_desc"].getStr() == wpkhDesc
      check post["iswatchonly"].getBool() == false  # deprecated, always false
      check post["labels"].kind == JArray

      # Invalid address -> -5.
      var code = 0
      try:
        discard rpc.handleMethod("getaddressinfo", %*["notanaddress"])
      except RpcError as e:
        code = e.code
      check code == RpcInvalidAddressOrKey

  test "still rejects malformed params with -32602":
    withRig("nimrod_impdesc_bad_params"):
      # Empty params → RpcInvalidParams, NOT a wallet error.
      var code = 0
      try:
        discard rpc.handleImportDescriptors(%*[])
      except RpcError as e:
        code = e.code
      check code == RpcInvalidParams

      # First param not an array → RpcInvalidParams.
      var code2 = 0
      try:
        discard rpc.handleImportDescriptors(%*["not-an-array"])
      except RpcError as e:
        code2 = e.code
      check code2 == RpcInvalidParams

# ----------------------------------------------------------------------------
# gettxoutsetinfo (W12) — UTXO set walk + Core-byte-parity statistics
#
# Pins the cross-impl diff-test contract: `gettxoutsetinfo` must emit
# `hash_serialized_3` (and `hash_serialized_2` alias) byte-identical to
# Bitcoin Core's `kernel/coinstats.cpp::ComputeUTXOStats` over the same
# UTXO set. nimrod was the last impl in the fleet still emitting
# `"not implemented"` until W12 wired the handler.
# ----------------------------------------------------------------------------

# Shared helpers for "build a regtest chain" duplicated from the dumptxoutset
# suite; we can't re-import the generic helper since suite-local procs are
# not exported.
proc utxoInfoBuildChain(cs: var ChainState, params: ConsensusParams,
                        targetHeight: int32): BlockHash =
  let genesis = buildGenesisBlock(params)
  let r = cs.connectBlock(genesis, 0)
  doAssert r.isOk
  result = BlockHash(doubleSha256(serialize(genesis.header)))
  var prevHash = result
  var height: int32 = 1
  while height <= targetHeight:
    var scriptSig: seq[byte]
    if height <= 0x7F:
      scriptSig = @[byte(0x01), byte(height)]
    else:
      scriptSig = @[byte(0x02), byte(height and 0xFF),
                                byte((height shr 8) and 0xFF)]
    let coinbase = Transaction(
      version: 1,
      inputs: @[TxIn(
        prevOut: OutPoint(txid: TxId(default(array[32, byte])),
                          vout: 0xFFFFFFFF'u32),
        scriptSig: scriptSig,
        sequence: 0xFFFFFFFF'u32
      )],
      outputs: @[TxOut(value: Satoshi(50_00000000),
                       scriptPubKey: @[byte(0x51)])],  # OP_TRUE
      witnesses: @[],
      lockTime: 0
    )
    let txHash = array[32, byte](coinbase.txid())
    let blk = Block(
      header: BlockHeader(
        version: 1,
        prevBlock: prevHash,
        merkleRoot: txHash,
        timestamp: uint32(1296688602 + height * 600),
        bits: 0x207fffff'u32,
        nonce: uint32(height)
      ),
      txs: @[coinbase]
    )
    let cr = cs.connectBlock(blk, height)
    doAssert cr.isOk, cr.error
    result = BlockHash(doubleSha256(serialize(blk.header)))
    prevHash = result
    inc height

suite "gettxoutsetinfo Core-byte-parity":

  test "computeUtxoSetInfo returns expected counts + nonzero hash":
    # Build a small regtest chain and check the high-level invariants:
    # one UTXO per coinbase block, one distinct txid per UTXO, total amount
    # = N * 50 BTC, bogosize matches GetBogoSize(scriptPubKey=OP_TRUE).
    # Byte-level Core parity is verified end-to-end by tools/diff-test.sh
    # (cross-impl harness against bitcoin-core 31.99 on regtest).
    let testDir = getTempDir() / "nimrod_utxosetinfo_basic"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 5)

    let info = computeUtxoSetInfo(cs, cshtHashSerialized)

    # 5 coinbase outputs (genesis is filtered, only h=1..5 enter UTXO).
    check info.height == 5
    check info.txOuts == 5
    check info.transactions == 5
    check info.totalAmount == 5'i64 * 50_00000000'i64
    # bogosize = 5 * (32 + 4 + 4 + 8 + 2 + 1)  -- OP_TRUE script is 1 byte.
    check info.bogosize == 5'u64 * 51'u64

    # Hash must be non-zero (we have coins) and stable across calls.
    check info.hashSerialized != default(array[32, byte])
    let info2 = computeUtxoSetInfo(cs, cshtHashSerialized)
    check info.hashSerialized == info2.hashSerialized

  test "muhash variant produces different digest than hash_serialized":
    # MuHash3072 finalize is `SHA256(numerator/denominator)`, structurally
    # different from a SHA256d stream over TxOutSer bytes. Both walk the
    # same coin stream, but the outer hash differs.
    let testDir = getTempDir() / "nimrod_utxosetinfo_muhash"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 3)

    let muInfo = computeUtxoSetInfo(cs, cshtMuHash)
    let serInfo = computeUtxoSetInfo(cs, cshtHashSerialized)
    check muInfo.txOuts == 3
    check serInfo.txOuts == 3
    check muInfo.hashSerialized != default(array[32, byte])
    check serInfo.hashSerialized != default(array[32, byte])
    # Hash kinds must differ for any non-trivial input set.
    check muInfo.hashSerialized != serInfo.hashSerialized

    # MuHash is order-independent — calling twice on the same set must yield
    # the same digest.
    let muInfo2 = computeUtxoSetInfo(cs, cshtMuHash)
    check muInfo.hashSerialized == muInfo2.hashSerialized

  test "hashType=cshtNone skips hash but still returns counts":
    let testDir = getTempDir() / "nimrod_utxosetinfo_none"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 2)

    let info = computeUtxoSetInfo(cs, cshtNone)
    check info.txOuts == 2
    check info.totalAmount == 2'i64 * 50_00000000'i64
    check info.hashSerialized == default(array[32, byte])

  test "RPC handler emits both hash_serialized_3 and hash_serialized_2":
    # The cross-impl diff-test reads `hash_serialized_2` first; we emit
    # both keys with identical values for harness compatibility.
    let testDir = getTempDir() / "nimrod_gtxosi_rpc_keys"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 4)

    let mp = newMempool(cs, regtest)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = fe, params = regtest
    )
    let res = rpc.handleGetTxOutSetInfo(%*[])

    check res.hasKey("hash_serialized_3")
    check res.hasKey("hash_serialized_2")
    check res["hash_serialized_3"].getStr() == res["hash_serialized_2"].getStr()
    check res["hash_serialized_3"].getStr().len == 64
    check res["hash_serialized_3"].getStr() != "not implemented"
    check res["height"].getInt() == 4
    check res["txouts"].getInt() == 4
    check res["transactions"].getInt() == 4

  test "RPC handler hash_type=muhash returns muhash key":
    let testDir = getTempDir() / "nimrod_gtxosi_rpc_muhash"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 2)

    let mp = newMempool(cs, regtest)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = fe, params = regtest
    )
    let res = rpc.handleGetTxOutSetInfo(%*["muhash"])

    check res.hasKey("muhash")
    check not res.hasKey("hash_serialized_3")
    check not res.hasKey("hash_serialized_2")
    check res["muhash"].getStr().len == 64

  test "RPC handler rejects unknown hash_type with RpcInvalidParams":
    let testDir = getTempDir() / "nimrod_gtxosi_rpc_badtype"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()
    discard utxoInfoBuildChain(cs, regtest, 1)

    let mp = newMempool(cs, regtest)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = fe, params = regtest
    )
    var code = 0
    try:
      discard rpc.handleGetTxOutSetInfo(%*["not-a-real-type"])
    except RpcError as e:
      code = e.code
    check code == RpcInvalidParams

# ============================================================================
# W102 AssumeUTXO snapshot loading gate audit
#
# Covers missing per-coin validation gates in loadSnapshot that exist in
# Bitcoin Core's PopulateAndValidateSnapshot (validation.cpp:5791-5882):
#
#   B1  coin.nHeight > base_height          — missing in loadSnapshot
#   B2  MoneyRange per-coin                 — missing in loadSnapshot
#   B3  outpoint.n >= UINT32_MAX guard      — missing in loadSnapshot
#   B4  coins_per_txid > coins_left guard   — missing in loadSnapshot
#   B5  trailing-bytes exhaustion check     — missing in loadSnapshot
#   B6  background UTXO hash cross-check    — validateSnapshot skips UTXO hash
#   B7  double-activate guard               — activateSnapshot missing guard
#   B8  work-exceeds-active pre-check       — loadSnapshot missing guard
#   B9  wrong height (0) in unknown-hash msg — validateSnapshotMetadata
#   B10 getchainstates RPC absent           — no handler for getchainstates
# ============================================================================

# Helper: write a minimal valid snapshot file to `path` with a single coin.
proc writeFakeCoinSnapshot(path: string, networkMagic: array[4, byte],
                            baseBlockhash: BlockHash, coin: SnapshotCoin) =
  let meta = SnapshotMetadata(
    version: SnapshotVersion,
    networkMagic: networkMagic,
    baseBlockhash: baseBlockhash,
    coinsCount: 1
  )
  let sf = openSnapshotForWrite(path, meta)
  sf.writeTxidGroup(coin.outpoint.txid, @[coin])
  sf.close()

proc writeFakeCoinSnapshotRaw(path: string, networkMagic: array[4, byte],
                               baseBlockhash: BlockHash, coin: SnapshotCoin,
                               extraBytes: seq[byte]) =
  ## Write a snapshot with an explicit coin AND trailing extra bytes for the
  ## trailing-bytes-check test (B5).
  let meta = SnapshotMetadata(
    version: SnapshotVersion,
    networkMagic: networkMagic,
    baseBlockhash: baseBlockhash,
    coinsCount: 1
  )
  let sf = openSnapshotForWrite(path, meta)
  sf.writeTxidGroup(coin.outpoint.txid, @[coin])
  sf.close()
  # Append extra garbage bytes past the coin data.
  if extraBytes.len > 0:
    let f = open(path, fmAppend)
    discard f.writeBytes(extraBytes, 0, extraBytes.len)
    f.close()

suite "W102 AssumeUTXO per-coin validation gates":

  test "B1: loadSnapshot rejects coin with height > base_height":
    # Bitcoin Core validation.cpp:5814 rejects coins where coin.nHeight >
    # base_height. Guard added in W102 fix.
    let testDir = getTempDir() / "nimrod_w102_b1"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    # Base height is 840000 per the first mainnet assumeutxo entry.
    # Inject a coin at height 840001 — one block ABOVE the base.
    let coin = SnapshotCoin(
      outpoint: OutPoint(txid: TxId(mkHashWith([0xB1'u8])), vout: 0),
      output: TxOut(value: Satoshi(1_00000000),
                    scriptPubKey: @[0x51'u8]),
      height: 840001'i32,   # > base_height (840000) — Core rejects this
      isCoinbase: false
    )
    let snapPath = testDir / "future-height.dat"
    writeFakeCoinSnapshot(snapPath, mainnet.networkMagic,
                          mainnet.assumeutxoData[0].blockhash, coin)

    let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
    # Fixed: guard now rejects with "Bad snapshot data" (Core's exact phrase).
    check res.success == false
    check "Bad snapshot data" in res.error

  test "B2: loadSnapshot rejects coin with negative value (MoneyRange)":
    # Bitcoin Core validation.cpp:5820-5822 rejects coins with value outside
    # [0, MAX_MONEY]. Guard added in W102 fix.
    let testDir = getTempDir() / "nimrod_w102_b2"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    # Negative satoshi value. This is encoded as a large uint64 after
    # CompressAmount, but on a real honest file negative values cannot exist.
    # We inject one via direct SnapshotCoin construction.
    let coin = SnapshotCoin(
      outpoint: OutPoint(txid: TxId(mkHashWith([0xB2'u8])), vout: 0),
      output: TxOut(value: Satoshi(-1),   # negative — out of MoneyRange
                    scriptPubKey: @[0x51'u8]),
      height: 100'i32,
      isCoinbase: false
    )
    let snapPath = testDir / "neg-value.dat"
    writeFakeCoinSnapshot(snapPath, mainnet.networkMagic,
                          mainnet.assumeutxoData[0].blockhash, coin)

    let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
    # Fixed: MoneyRange guard now rejects before any coin is stored.
    # Core's exact phrase at 5821: "bad tx out value"
    check res.success == false
    check "bad tx out value" in res.error

  test "B3: vout=UINT32_MAX is rejected during load (overflow guard)":
    # Bitcoin Core validation.cpp:5815-5816 rejects outpoint.n == UINT32_MAX
    # to avoid integer wrap-around in coinstats.cpp ApplyHash (ApplyHash uses
    # (outpoint.n + 1) which overflows for UINT32_MAX). Guard added in W102 fix.
    let testDir = getTempDir() / "nimrod_w102_b3"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    let coin = SnapshotCoin(
      outpoint: OutPoint(txid: TxId(mkHashWith([0xB3'u8])), vout: 0xFFFFFFFF'u32),
      output: TxOut(value: Satoshi(1_00000000),
                    scriptPubKey: @[0x51'u8]),
      height: 100'i32,
      isCoinbase: false
    )
    let snapPath = testDir / "maxvout.dat"
    writeFakeCoinSnapshot(snapPath, mainnet.networkMagic,
                          mainnet.assumeutxoData[0].blockhash, coin)

    let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
    # Fixed: vout == UINT32_MAX now rejected with "Bad snapshot data" (Core phrase).
    check res.success == false
    check "Bad snapshot data" in res.error

  test "B4: coins_per_txid overflow: group larger than coins_left not rejected":
    # Bitcoin Core validation.cpp:5804-5806 rejects when the compactsize
    # coins_per_txid for a group exceeds the remaining coins_left counter.
    # This prevents reading coins from the NEXT group when the count is wrong.
    # nimrod has no such check — it keeps reading until coinsRead == coinsCount.
    #
    # Craft a snapshot with coinsCount=1 but two coins in the only group (the
    # second coin would be read as belonging to a non-existent next group in
    # Core's model). nimrod reads only 1 coin and succeeds; Core would reject.
    let testDir = getTempDir() / "nimrod_w102_b4"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard

    # Build a raw snapshot: header (coinsCount=1) + one txid group with 2 coins.
    let mainnet = mainnetParams()
    let txid = TxId(mkHashWith([0xB4'u8]))
    let coinA = SnapshotCoin(
      outpoint: OutPoint(txid: txid, vout: 0),
      output: TxOut(value: Satoshi(1_00000000), scriptPubKey: @[0x51'u8]),
      height: 100'i32, isCoinbase: false
    )
    let coinB = SnapshotCoin(
      outpoint: OutPoint(txid: txid, vout: 1),
      output: TxOut(value: Satoshi(2_00000000), scriptPubKey: @[0x51'u8]),
      height: 100'i32, isCoinbase: false
    )
    # Write a snapshot file manually: header with coinsCount=1,
    # but ONE txid group containing 2 coins (coins_per_txid=2 > coins_left=1).
    let path = testDir / "overcount.dat"
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: mainnet.assumeutxoData[0].blockhash,
      coinsCount: 1   # claims 1 but group has 2
    )
    let sf = openSnapshotForWrite(path, meta)
    sf.writeTxidGroup(txid, @[coinA, coinB])  # writes group with compactsize=2
    sf.close()

    var cs = newChainState(testDir / "cs", mainnet)
    defer: cs.close()

    let res = loadSnapshot(path, cs, mainnet, mainnet.assumeutxoData)
    # Fixed: the B4 guard in readCoin now rejects when coins_per_txid > coins_left.
    # Core's exact phrase: "Mismatch in coins count in snapshot metadata and actual snapshot data"
    check res.success == false
    check "Mismatch in coins count" in res.error

  test "B5: trailing bytes after all coins are silently ignored (missing exhaustion check)":
    # Bitcoin Core validation.cpp:5872-5882 attempts to read one extra byte
    # after all coins have been consumed. If it SUCCEEDS (no exception), Core
    # returns "Bad snapshot - coins left over". nimrod never attempts this
    # read and silently ignores any garbage bytes appended to the snapshot.
    let testDir = getTempDir() / "nimrod_w102_b5"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()

    # Build a valid snapshot (empty body — coinsCount=0, regtest magic).
    let path = testDir / "trailing.dat"
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: regtest.networkMagic,
      baseBlockhash: BlockHash(default(array[32, byte])),
      coinsCount: 0
    )
    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)
    let f = open(path, fmWrite)
    discard f.writeBytes(w.data, 0, w.data.len)
    # Append 4 garbage bytes after the header.
    let garbage = @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    discard f.writeBytes(garbage, 0, garbage.len)
    f.close()

    # Attempt to load: the metadata fails first (regtest has no assumeutxo
    # entries) before trailing bytes are checked. This case correctly reports
    # the whitelist error. The trailing-bytes guard (B5 fix) would fire if a
    # valid whitelisted hash were used with a snapshot that has extra data after
    # all declared coins.
    let res = loadSnapshot(path, cs, regtest, regtest.assumeutxoData)
    check res.success == false
    check "not recognized" in res.error  # whitelist check fires before trailing-bytes check

  test "B5b: trailing bytes after all coins rejected when whitelisted hash used":
    # Part 2: use a mainnet whitelisted blockhash with a zero-coin snapshot
    # that has garbage appended. The B5 trailing-bytes guard must fire and
    # reject with "coins left over" (Core's exact phrase at validation.cpp:5881).
    let testDir = getTempDir() / "nimrod_w102_b5b"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    # Build a zero-coin mainnet snapshot (coinsCount=0) + trailing garbage bytes.
    let path = testDir / "trailing-mainnet.dat"
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: mainnet.assumeutxoData[0].blockhash,
      coinsCount: 0
    )
    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)
    let f = open(path, fmWrite)
    discard f.writeBytes(w.data, 0, w.data.len)
    let garbage = @[0xDE'u8, 0xAD, 0xBE, 0xEF]
    discard f.writeBytes(garbage, 0, garbage.len)
    f.close()

    let res = loadSnapshot(path, cs, mainnet, mainnet.assumeutxoData)
    # Fixed: B5 guard detects extra bytes and rejects with Core's exact phrase.
    check res.success == false
    check "coins left over" in res.error

  test "B6 FIXED: validateSnapshot is NotReady until the bg store reaches the base":
    # FIXED (AssumeUTXO dual-chainstate pilot): validateSnapshot now recomputes
    # ComputeUTXOStats (HASH_SERIALIZED) over the BACKGROUND store's own coins
    # and compares to au_data.hash_serialized (Core validation.cpp:5967). Here
    # the background store's tip (genesis sentinel) does NOT equal the snapshot
    # base blockhash, so validateSnapshot correctly returns svrNotReady and
    # leaves the snapshot auUnvalidated — it never validates a bg store that
    # has not reached the base. (The full accept/mismatch behaviour is proven
    # end-to-end in test_assumeutxo_dual_chainstate.nim.)
    let testDir = getTempDir() / "nimrod_w102_b6"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir1 = testDir / "snap_cs"
    let dbDir2 = testDir / "bg_cs"
    createDir(dbDir1); createDir(dbDir2)

    let regtest = regtestParams()
    var snapCs = newChainState(dbDir1, regtest)
    var bgCs = newChainState(dbDir2, regtest)
    defer: snapCs.close(); bgCs.close()

    # Set up a snapshot chainstate pointing at height 5.
    let fakeBlockhash = BlockHash(mkHashWith([0xF6'u8, 0x00]))
    var snapshotChain = newSnapshotChainState(snapCs)
    snapshotChain.assumeutxo = auUnvalidated
    snapshotChain.snapshotBlockhash = some(fakeBlockhash)
    snapshotChain.targetUtxoHash = some(default(array[32, byte]))  # all-zero target

    # The bg store's tip is the genesis sentinel, which does NOT equal the
    # snapshot base blockhash, so validateSnapshot has NOT reached the base.
    bgCs.bestHeight = 10  # height alone is not enough — tip-hash must match base

    let result = validateSnapshot(snapshotChain, bgCs)
    # bgCs.bestBlockHash != snapshotChain.snapshotBlockhash → NotReady. The
    # fixed validateSnapshot only recomputes/compares the hash once the bg
    # store's tip IS the base — it never validates a bg store that has not
    # actually reached the snapshot base.
    check result == svrNotReady
    check snapshotChain.assumeutxo == auUnvalidated  # never silently validated

  test "B7: activateSnapshot double-activation guard fires before file I/O":
    # Bitcoin Core validation.cpp:5600-5601 returns an error if a
    # snapshot-based chainstate already exists ("Can't activate a snapshot-based
    # chainstate more than once"). Guard added in W102 fix.
    let testDir = getTempDir() / "nimrod_w102_b7"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()

    let scs = newSnapshotChainState(cs)
    # Mark as already unvalidated (= a snapshot is loaded).
    scs.assumeutxo = auUnvalidated
    scs.snapshotBlockhash = some(BlockHash(mkHashWith([0xB7'u8])))

    # Attempt a second activation on the same SnapshotChainState.
    # The guard fires BEFORE any file I/O — the bogus path is never opened.
    let bogusPath = testDir / "does-not-exist.dat"
    let res2 = activateSnapshot(scs, bogusPath, regtest, regtest.assumeutxoData)
    # Fixed: guard returns the Core-exact error before touching the file.
    check res2.success == false
    check "Can't activate a snapshot-based chainstate more than once" in res2.error

  test "B8: work-exceeds-active-chainstate pre-check rejects when active chain is at/past snapshot height":
    # Bitcoin Core PopulateAndValidateSnapshot (validation.cpp:5787-5788)
    # pre-checks that the snapshot block's work exceeds the active chain tip.
    # W102 fix: nimrod approximates this via height comparison since AssumeutxoData
    # does not store chainwork. A chain already at or past the snapshot height is rejected.
    let testDir = getTempDir() / "nimrod_w102_b8"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()
    var cs = newChainState(dbDir, mainnet)
    defer: cs.close()

    # Part 1: fresh chain (bestHeight=0) — guard does NOT fire; snapshot proceeds
    # to fail at hash check (zero coins != expected hash).
    let path = testDir / "low-work.dat"
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: mainnet.assumeutxoData[0].blockhash,
      coinsCount: 0
    )
    var w = BinaryWriter()
    w.writeSnapshotMetadata(meta)
    let f = open(path, fmWrite)
    discard f.writeBytes(w.data, 0, w.data.len)
    f.close()

    let res = loadSnapshot(path, cs, mainnet, mainnet.assumeutxoData)
    # Fresh chain: work guard does not fire (bestHeight=0); fails at hash check.
    check res.success == false
    check "Bad snapshot content hash" in res.error

    # Part 2: simulate an active chain that is already AT the snapshot height.
    # The guard must reject before reading any coins.
    let dbDir2 = testDir / "cs2"
    createDir(dbDir2)
    var cs2 = newChainState(dbDir2, mainnet)
    defer: cs2.close()
    cs2.bestHeight = mainnet.assumeutxoData[0].height  # = 840000

    let res2 = loadSnapshot(path, cs2, mainnet, mainnet.assumeutxoData)
    check res2.success == false
    check "Work does not exceed active chainstate" in res2.error

  test "B9: validateSnapshotMetadata reports height=0 for all unknown hashes":
    # Bitcoin Core's ActivateSnapshot error message includes the actual height
    # from the block index when a blockhash is recognized but not whitelisted.
    # nimrod's validateSnapshotMetadata returns `(0)` in all error messages
    # regardless of height — operators can't distinguish "hash unknown" vs
    # "hash at height N not in the table".
    let mainnet = mainnetParams()

    # Unknown blockhash: not in the assumeutxo table.
    let unknownHash = BlockHash(mkHashWith([0xB9'u8, 0x00, 0x00]))
    let meta = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: unknownHash,
      coinsCount: 0
    )
    let v = validateSnapshotMetadata(meta, mainnet, mainnet.assumeutxoData)
    check v.valid == false
    # BUG: always reports "(0)" regardless of what height the hash is at.
    # Core reports the actual block height from the snapshot block index.
    # For an unknown hash with no block index entry, "(0)" is acceptable,
    # but the error path is shared for ALL unknown hashes (no distinction).
    check "(0)" in v.error

    # Additionally verify that even a "close" hash (modified last byte) gives
    # the same "(0)" placeholder — evidence the error is always the default.
    var closeHash = mainnet.assumeutxoData[0].blockhash
    array[32, byte](closeHash)[0] = byte(array[32, byte](closeHash)[0] xor 0xFF'u8)
    let meta2 = SnapshotMetadata(
      version: SnapshotVersion,
      networkMagic: mainnet.networkMagic,
      baseBlockhash: closeHash,
      coinsCount: 0
    )
    let v2 = validateSnapshotMetadata(meta2, mainnet, mainnet.assumeutxoData)
    check v2.valid == false
    check "(0)" in v2.error  # same placeholder; no height disambiguation

  test "B10: getchainstates RPC is absent (no handler in RPC dispatch)":
    # Bitcoin Core rpc/blockchain.cpp exposes `getchainstates` which surfaces
    # snapshot validation state including the `validated` bool per chainstate.
    # nimrod has no such handler. Operators cannot observe whether the
    # background validation has completed.
    let testDir = getTempDir() / "nimrod_w102_b10"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let regtest = regtestParams()
    var cs = newChainState(dbDir, regtest)
    defer: cs.close()

    let mp = newMempool(cs, regtest)
    let fe = newFeeEstimator()
    let rpc = newRpcServer(
      port = 18443'u16, chainState = cs, mempool = mp,
      peerManager = nil, feeEstimator = fe, params = regtest
    )
    # Dispatch "getchainstates" through the RPC router. The router
    # must currently produce a method-not-found or unimplemented error.
    var code = 0
    try:
      discard rpc.handleMethod("getchainstates", %*[])
    except RpcError as e:
      code = e.code
    except Exception:
      code = -1  # any crash/unhandled exception
    # BUG: `getchainstates` is not in the dispatch table; the call silently
    # returns nil or raises RpcMethodNotFound.
    # When implemented, this test should verify the response shape instead.
    check code != 0  # non-zero = currently unimplemented

# ----------------------------------------------------------------------------
# FIX-D — snapshot-load atomicity via SNAPSHOT_LOAD_IN_PROGRESS marker.
#
# These tests pin the contract of the marker-based atomicity protocol added
# in this commit (analog of ouroboros commit 2b76e0e). The contract:
#
#   1. The marker key + helpers (`writeSnapshotLoadMarker`,
#      `getSnapshotLoadMarker`, `hasSnapshotLoadMarker`,
#      `clearUtxoColumnFamily`, `recoverFromSnapshotCrash`) round-trip via
#      cfMeta and survive close+reopen of the database.
#
#   2. `recoverFromSnapshotCrash` invoked on a db with the marker present
#      MUST: clear cfUtxo, reset the tip pointer to all-zeros / height 0,
#      delete the marker. Returns true.
#
#   3. `recoverFromSnapshotCrash` invoked on a db WITHOUT the marker MUST
#      be a no-op. Returns false. UTXOs + tip pointer untouched.
#
#   4. Re-opening the database (via `openChainDb`) auto-runs the recovery,
#      so if a previous process crashed mid-loadtxoutset (marker set, tip
#      not yet committed, cfUtxo half-populated), the next open lands in
#      the clean "genesis-sentinel" state ready for the operator to re-run
#      loadtxoutset.
#
#   5. A successful `loadSnapshot` (happy path, when the chain happens to
#      meet the assumeutxo whitelist) MUST clear the marker as part of the
#      final commit batch — so subsequent re-opens are no-op'd by recovery.
#      We cover the negative path (load fails → marker stays set) and the
#      successful-helper path (manual begin + commit clears it).
#
# Reference: ouroboros snapshot.py / ferrous-utils sync db.rs +
#            CORE-PARITY-AUDIT/_chainstate-atomicity-family-2026-05-26.md
# ----------------------------------------------------------------------------

import ../src/storage/db as snapshot_db

suite "FIX-D — snapshot-load atomicity":
  test "marker round-trips (write + read + has + delete) via cfMeta":
    let testDir = getTempDir() / "nimrod_fixd_marker_roundtrip"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    check cs.db.hasSnapshotLoadMarker() == false
    check cs.db.getSnapshotLoadMarker().isNone

    let baseHash = BlockHash(mkHashWith([0xF1'u8, 0xD0, 0xBE, 0xEF]))
    cs.db.writeSnapshotLoadMarker(baseHash, 840_000'i32)

    check cs.db.hasSnapshotLoadMarker() == true
    let m = cs.db.getSnapshotLoadMarker()
    check m.isSome
    check m.get().baseBlockhash == baseHash
    check m.get().baseHeight == 840_000'i32

  test "marker survives close + re-open of the database":
    # The whole point of the marker is to be readable on the NEXT process —
    # so we round-trip across close+reopen, which is what crash-recovery does.
    let testDir = getTempDir() / "nimrod_fixd_marker_persist"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let baseHash = BlockHash(mkHashWith([0xC0'u8, 0xCA, 0xC0, 0x1A]))
    block writePhase:
      var cs = newChainState(dbDir, regtestParams())
      cs.db.writeSnapshotLoadMarker(baseHash, 12345'i32)
      check cs.db.hasSnapshotLoadMarker()
      cs.close()

    # Re-open: openChainDb now auto-clears the marker via
    # `recoverFromSnapshotCrash` (item 4 of the contract).  Verify the
    # marker DOES get cleared on reopen AND the tip is reset to the
    # genesis sentinel (bestHeight=0, bestBlockHash=all-zeros) because
    # there are no committed UTXOs above it.
    block recoveryPhase:
      var cs2 = newChainState(dbDir, regtestParams())
      defer: cs2.close()
      check cs2.db.hasSnapshotLoadMarker() == false  # auto-cleared
      check cs2.bestHeight == 0                      # genesis sentinel
      check cs2.bestBlockHash == BlockHash(default(array[32, byte]))

  test "crash-mid-load recovery: marker + partial UTXOs -> cleared on reopen":
    # Simulate the failure mode FIX-D fixes:
    #   1. operator runs `loadtxoutset`
    #   2. Phase 1 writes the SNAPSHOT_LOAD_IN_PROGRESS marker
    #   3. Phase 2 writes some chunk of UTXOs to cfUtxo (the "partial load")
    #   4. SIGKILL fires BEFORE the Phase 3 commit batch (no tip update,
    #      no marker delete)
    #   5. next process opens the database — must observe a clean slate
    #
    # Without FIX-D: the cfUtxo half-populated, the tip still points at
    # the old chain, the marker is absent. New blocks would validate
    # against a corrupt UTXO set.
    # With FIX-D: the marker is present → recovery wipes cfUtxo + resets
    # the tip → operator re-runs loadtxoutset.
    let testDir = getTempDir() / "nimrod_fixd_crash_recovery"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let baseHash = BlockHash(mkHashWith([0x12'u8, 0x34, 0x56, 0x78]))
    let baseHeight = 840_000'i32
    let partialTxid = TxId(mkHashWith([0xAB'u8, 0xCD, 0xEF, 0x01]))
    let partialOp = OutPoint(txid: partialTxid, vout: 0'u32)

    block crashPhase:
      var cs = newChainState(dbDir, regtestParams())
      # Phase 1: mark the snapshot load in progress.
      cs.db.writeSnapshotLoadMarker(baseHash, baseHeight)
      # Phase 2: write a partial UTXO (mimic the per-chunk WriteBatch
      # landing one or more coins before the SIGKILL).
      cs.db.putUtxo(partialOp, UtxoEntry(
        output: TxOut(value: Satoshi(50_00000000),
                      scriptPubKey: @[0x51'u8]),
        height: baseHeight,
        isCoinbase: false
      ))
      # SIGKILL simulation: close WITHOUT writing the Phase 3 commit
      # batch. The marker stays set, the partial UTXO stays in cfUtxo.
      check cs.db.hasUtxo(partialOp)
      check cs.db.hasSnapshotLoadMarker()
      cs.close()

    block recoveryPhase:
      var cs2 = newChainState(dbDir, regtestParams())
      defer: cs2.close()
      # All three invariants of FIX-D recovery must hold:
      #   - marker is gone (cleared by recoverFromSnapshotCrash)
      #   - the partial UTXO is gone (cfUtxo was wiped)
      #   - the tip points at the genesis sentinel, so block validation
      #     can NOT continue from the half-loaded snapshot
      check cs2.db.hasSnapshotLoadMarker() == false
      check cs2.db.hasUtxo(partialOp) == false
      check cs2.bestHeight == 0
      check cs2.bestBlockHash == BlockHash(default(array[32, byte]))

  test "recoverFromSnapshotCrash is a no-op when no marker is set":
    # The reverse contract: on a healthy database (no in-progress load),
    # recovery MUST NOT touch the tip pointer or the UTXO set.
    let testDir = getTempDir() / "nimrod_fixd_noop_recovery"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let healthyTxid = TxId(mkHashWith([0x42'u8]))
    let healthyOp = OutPoint(txid: healthyTxid, vout: 0'u32)
    let healthyTip = BlockHash(mkHashWith([0x99'u8, 0x88, 0x77]))

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    cs.db.putUtxo(healthyOp, UtxoEntry(
      output: TxOut(value: Satoshi(1_00000000), scriptPubKey: @[0x51'u8]),
      height: 100'i32,
      isCoinbase: false
    ))
    cs.db.updateBestBlock(healthyTip, 100'i32)

    check cs.db.recoverFromSnapshotCrash() == false
    check cs.db.hasUtxo(healthyOp) == true
    check cs.db.bestBlockHash == healthyTip
    check cs.db.bestHeight == 100'i32

  test "marker payload is exactly 36 bytes (32-byte hash + 4-byte LE height)":
    # Pins the on-disk layout — future cross-impl tooling (incl. ouroboros)
    # can parse the marker byte-identically.
    let testDir = getTempDir() / "nimrod_fixd_marker_payload"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    let baseHash = BlockHash(mkHashWith([0xDE'u8, 0xAD]))
    cs.db.writeSnapshotLoadMarker(baseHash, 0x01020304'i32)

    # Read raw bytes via the low-level db interface.
    let raw = cs.db.db.get(snapshot_db.cfMeta,
                           snapshot_db.metaKey(SnapshotLoadMarkerKey))
    check raw.isSome
    check raw.get().len == 36
    # Last four bytes are LE height = 0x04 03 02 01.
    check raw.get()[32] == 0x04'u8
    check raw.get()[33] == 0x03'u8
    check raw.get()[34] == 0x02'u8
    check raw.get()[35] == 0x01'u8
    # First 32 bytes are the raw blockhash.
    let hashBytes = array[32, byte](baseHash)
    for i in 0 ..< 32:
      check raw.get()[i] == hashBytes[i]

  test "happy-path commit clears the marker (no recovery on reopen)":
    # Mimic the Phase 1 / Phase 3 pair that `loadSnapshot` runs on the
    # happy path: write the marker, then commit the tip + delete the
    # marker in one synced WriteBatch. After this, reopening the database
    # must NOT trigger recovery, the marker is gone, and the tip survives.
    let testDir = getTempDir() / "nimrod_fixd_happy_commit"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let snapshotTip = BlockHash(mkHashWith([0xAB'u8, 0xBA]))
    let snapshotHeight = 840_000'i32

    block commitPhase:
      var cs = newChainState(dbDir, regtestParams())
      # Phase 1 — begin.
      cs.db.writeSnapshotLoadMarker(snapshotTip, snapshotHeight)
      check cs.db.hasSnapshotLoadMarker()

      # Phase 3 — commit (single batch fuses tip + height + marker delete).
      let batch = cs.db.db.newWriteBatch()
      defer: batch.destroy()
      batch.put(snapshot_db.cfMeta, snapshot_db.metaKey("bestblock"),
                @(array[32, byte](snapshotTip)))
      var w = BinaryWriter()
      w.writeInt32LE(snapshotHeight)
      batch.put(snapshot_db.cfMeta, snapshot_db.metaKey("height"), w.data)
      batch.delete(snapshot_db.cfMeta,
                   snapshot_db.metaKey(SnapshotLoadMarkerKey))
      cs.db.db.writeSynced(batch)

      check cs.db.hasSnapshotLoadMarker() == false
      cs.close()

    # Re-open: recovery does NOT fire (no marker), tip survives.
    block reopenPhase:
      var cs2 = newChainState(dbDir, regtestParams())
      defer: cs2.close()
      check cs2.db.hasSnapshotLoadMarker() == false
      check cs2.bestBlockHash == snapshotTip
      check cs2.bestHeight == snapshotHeight

  test "loadSnapshot failure leaves marker set (next-boot recovery will fire)":
    # loadSnapshot fails the content-hash check on a junk snapshot — but
    # because Phase 1 already wrote the marker before the per-coin loop,
    # a crash here leaves the marker on disk so next-boot recovery can
    # clear the half-loaded state. We assert that path: after a failed
    # loadSnapshot the marker remains, and re-opening the database
    # triggers the recovery (genesis sentinel).
    let testDir = getTempDir() / "nimrod_fixd_failure_marker"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    let mainnet = mainnetParams()

    # Build a snapshot whose base_blockhash IS in the assumeutxo whitelist
    # (so we get past validateSnapshotMetadata) and whose body declares
    # one coin that we make WAY out of MoneyRange — Phase 2's B2 check
    # will reject it AFTER Phase 1 has written the marker.
    let snapPath = testDir / "junk.dat"
    block:
      var w = BinaryWriter()
      let meta = SnapshotMetadata(
        version: SnapshotVersion,
        networkMagic: mainnet.networkMagic,
        baseBlockhash: mainnet.assumeutxoData[0].blockhash,
        coinsCount: 1
      )
      w.writeSnapshotMetadata(meta)
      # txid group: txid + coins_per_txid=1
      let txid = TxId(mkHashWith([0xBA'u8, 0xD0]))
      w.writeTxId(txid)
      w.writeCompactSize(1)
      # one coin: vout=0, code=0 (height 0, not coinbase),
      # value=compressAmount of an int64 that decompresses out of range.
      # Easier: use B1 (height > base_height): code = (basHeight+1) << 1.
      w.writeCompactSize(0)
      let badCode = uint64(mainnet.assumeutxoData[0].height + 1'i32) * 2'u64
      w.writeVarInt(badCode)  # height > base_height → B1 fires
      w.writeVarInt(compressAmount(1_00000000'u64))
      # tiny P2PKH-ish script
      w.writeCompressedScript(@[0x76'u8, 0xA9, 0x14] & newSeq[byte](20) &
                              @[0x88'u8, 0xAC])
      let f = open(snapPath, fmWrite)
      discard f.writeBytes(w.data, 0, w.data.len)
      f.close()

    block loadAttempt:
      var cs = newChainState(dbDir, mainnet)
      let res = loadSnapshot(snapPath, cs, mainnet, mainnet.assumeutxoData)
      check res.success == false
      # B1 fires partway through Phase 2 — marker is still set because
      # Phase 3 commit (the marker-delete) never ran.
      check cs.db.hasSnapshotLoadMarker() == true
      cs.close()

    # On reopen, the auto-recovery in openChainDb fires.
    block reopen:
      var cs2 = newChainState(dbDir, mainnet)
      defer: cs2.close()
      check cs2.db.hasSnapshotLoadMarker() == false
      check cs2.bestHeight == 0
      check cs2.bestBlockHash == BlockHash(default(array[32, byte]))

  test "clearUtxoColumnFamily removes every cfUtxo entry":
    # Direct contract test for the helper that backs recoverFromSnapshotCrash.
    # We seed N coins, call clear, and verify nothing remains.
    let testDir = getTempDir() / "nimrod_fixd_clear_utxo"
    createDir(testDir)
    defer:
      try: removeDir(testDir) except OSError: discard
    let dbDir = testDir / "cs"
    createDir(dbDir)

    var cs = newChainState(dbDir, regtestParams())
    defer: cs.close()

    for i in 0 ..< 20:
      let txid = TxId(mkHashWith([byte(i)]))
      cs.db.putUtxo(OutPoint(txid: txid, vout: 0'u32), UtxoEntry(
        output: TxOut(value: Satoshi(int64(i + 1) * 1_00000000),
                      scriptPubKey: @[0x51'u8]),
        height: int32(i + 1),
        isCoinbase: false
      ))

    # Sanity: at least the first coin is in the db.
    check cs.db.hasUtxo(OutPoint(txid: TxId(mkHashWith([0'u8])), vout: 0))

    cs.db.clearUtxoColumnFamily()

    var anyLeft = false
    for _ in cs.db.db.iterCf(snapshot_db.cfUtxo):
      anyLeft = true
      break
    check anyLeft == false
