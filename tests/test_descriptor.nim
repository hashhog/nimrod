## Tests for output descriptors (BIP380-386)
## Tests checksum computation, parsing, and address derivation

import std/[unittest, strutils, options]
import ../src/wallet/descriptor
import ../src/wallet/wallet
import ../src/crypto/[secp256k1, address, hashing]

# Initialize secp256k1
when defined(useSystemSecp256k1):
  initSecp256k1()

suite "Descriptor Checksum":
  test "compute checksum for simple pkh descriptor":
    let desc = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let checksum = computeDescriptorChecksum(desc)
    check checksum.len == 8
    check checksum != ""

  test "checksum is deterministic":
    let desc = "wpkh(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)"
    let c1 = computeDescriptorChecksum(desc)
    let c2 = computeDescriptorChecksum(desc)
    check c1 == c2

  test "different descriptors have different checksums":
    let desc1 = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let desc2 = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let c1 = computeDescriptorChecksum(desc1)
    let c2 = computeDescriptorChecksum(desc2)
    check c1 != c2

  test "verify checksum":
    let desc = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let checksum = computeDescriptorChecksum(desc)
    let full = desc & "#" & checksum
    let (valid, payload) = verifyDescriptorChecksum(full)
    check valid
    check payload == desc

  test "reject invalid checksum":
    let full = "pkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)#xxxxxxxx"
    let (valid, _) = verifyDescriptorChecksum(full)
    check not valid

  test "add checksum":
    let desc = "wpkh(0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798)"
    let full = addDescriptorChecksum(desc)
    check "#" in full
    check full.len == desc.len + 9  # +1 for # and +8 for checksum

  test "empty descriptor returns empty checksum":
    let checksum = computeDescriptorChecksum("")
    check checksum.len == 8  # Still produces a checksum

  test "reject invalid characters":
    # Tab character is not in the charset
    let checksum = computeDescriptorChecksum("pkh(\t)")
    check checksum == ""

suite "Key Path Parsing":
  test "parse simple path":
    let (path, _) = parseKeyPath("44/0/0")
    check path.len == 3
    check path[0] == 44
    check path[1] == 0
    check path[2] == 0

  test "parse hardened path with apostrophe":
    let (path, apostrophe) = parseKeyPath("44'/0'/0'")
    check path.len == 3
    check (path[0] and 0x80000000'u32) != 0
    check (path[1] and 0x80000000'u32) != 0
    check (path[2] and 0x80000000'u32) != 0
    check apostrophe == true

  test "parse hardened path with h notation":
    let (path, apostrophe) = parseKeyPath("44h/0h/0h")
    check path.len == 3
    check (path[0] and 0x80000000'u32) != 0
    check apostrophe == false

  test "parse mixed path":
    let (path, _) = parseKeyPath("84'/0'/0'/0/0")
    check path.len == 5
    check (path[0] and 0x80000000'u32) != 0  # 84'
    check (path[1] and 0x80000000'u32) != 0  # 0'
    check (path[2] and 0x80000000'u32) != 0  # 0'
    check (path[3] and 0x80000000'u32) == 0  # 0
    check (path[4] and 0x80000000'u32) == 0  # 0

  test "path to string":
    let path = @[84'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32, 0'u32]
    let str = pathToString(path, true)
    check str == "84'/0'/0"

  test "path to string h notation":
    let path = @[84'u32 or 0x80000000'u32, 0'u32 or 0x80000000'u32]
    let str = pathToString(path, false)
    check str == "84h/0h"

suite "Descriptor Parsing":
  test "parse addr descriptor":
    let desc = parseDescriptor("addr(bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq)")
    check desc.node.kind == DKAddr
    check desc.node.address.kind == P2WPKH

  test "parse raw descriptor":
    let desc = parseDescriptor("raw(76a914000000000000000000000000000000000000000088ac)")
    check desc.node.kind == DKRaw
    check desc.node.rawScript.len > 0

  test "parse pk descriptor with hex pubkey":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("pk(" & pubkeyHex & ")")
    check desc.node.kind == DKPk
    check desc.node.key.kind == KPConstHex

  test "parse pkh descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("pkh(" & pubkeyHex & ")")
    check desc.node.kind == DKPkh

  test "parse wpkh descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("wpkh(" & pubkeyHex & ")")
    check desc.node.kind == DKWpkh

  test "parse sh(wpkh()) nested descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("sh(wpkh(" & pubkeyHex & "))")
    check desc.node.kind == DKSh
    check desc.node.sub.kind == DKWpkh

  test "parse wsh(multi()) descriptor":
    let pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    let desc = parseDescriptor("wsh(multi(2," & pk1 & "," & pk2 & "))")
    check desc.node.kind == DKWsh
    check desc.node.sub.kind == DKMulti
    check desc.node.sub.threshold == 2
    check desc.node.sub.keys.len == 2

  test "parse sortedmulti descriptor":
    let pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    let desc = parseDescriptor("sh(sortedmulti(1," & pk1 & "," & pk2 & "))")
    check desc.node.kind == DKSh
    check desc.node.sub.kind == DKSortedMulti
    check desc.node.sub.threshold == 1

  test "parse combo descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("combo(" & pubkeyHex & ")")
    check desc.node.kind == DKCombo

  test "parse tr descriptor":
    # 32-byte x-only pubkey for Taproot
    let xonlyHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("tr(" & xonlyHex & ")")
    check desc.node.kind == DKTr

  test "parse descriptor with checksum":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let descStr = "pkh(" & pubkeyHex & ")"
    let checksum = computeDescriptorChecksum(descStr)
    let full = descStr & "#" & checksum
    let desc = parseDescriptor(full)
    check desc.node.kind == DKPkh
    check desc.checksum == checksum

  test "reject invalid checksum":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let full = "pkh(" & pubkeyHex & ")#xxxxxxxx"
    var caught = false
    try:
      discard parseDescriptor(full)
    except DescriptorError:
      caught = true
    check caught

  test "reject invalid descriptor function":
    var caught = false
    try:
      discard parseDescriptor("invalid()")
    except DescriptorError:
      caught = true
    check caught

suite "Descriptor with Extended Keys":
  test "parse xpub descriptor":
    # Standard BIP84 xpub for "abandon" mnemonic
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let desc = parseDescriptor("wpkh(" & xpub & ")")
    check desc.node.kind == DKWpkh
    check desc.node.key.kind == KPBIP32

  test "parse xpub with derivation path":
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let desc = parseDescriptor("wpkh(" & xpub & "/0/0)")
    check desc.node.kind == DKWpkh
    check desc.node.key.derivePath.len == 2
    check desc.node.key.deriveType == NonRanged

  test "parse xpub with wildcard":
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let desc = parseDescriptor("wpkh(" & xpub & "/0/*)")
    check desc.node.kind == DKWpkh
    check desc.node.key.derivePath.len == 1
    check desc.node.key.deriveType == UnhardenedRanged
    check desc.node.isRange == true

  test "parse xpub with hardened wildcard":
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let desc = parseDescriptor("wpkh(" & xpub & "/0/*')")
    check desc.node.key.deriveType == HardenedRanged
    check desc.node.key.apostrophe == true

  test "parse xpub with origin info":
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let desc = parseDescriptor("wpkh([d34db33f/84'/0'/0']" & xpub & "/0/*)")
    check desc.node.key.origin.isSome
    let origin = desc.node.key.origin.get
    check origin.fingerprint == [0xd3'u8, 0x4d, 0xb3, 0x3f]
    check origin.path.len == 3

suite "Descriptor Expansion":
  test "expand pk descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("pk(" & pubkeyHex & ")")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    # Script should be <pubkey> OP_CHECKSIG
    let script = expanded.scripts[0]
    check script[0] == 33  # Push 33 bytes
    check script[^1] == 0xAC  # OP_CHECKSIG

  test "expand pkh descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("pkh(" & pubkeyHex & ")")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2PKH
    # Script: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    let script = expanded.scripts[0]
    check script.len == 25
    check script[0] == 0x76  # OP_DUP
    check script[1] == 0xA9  # OP_HASH160

  test "expand wpkh descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("wpkh(" & pubkeyHex & ")")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2WPKH
    # Script: OP_0 <20 bytes>
    let script = expanded.scripts[0]
    check script.len == 22
    check script[0] == 0x00
    check script[1] == 0x14

  test "expand sh(wpkh()) descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("sh(wpkh(" & pubkeyHex & "))")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2SH
    # Script: OP_HASH160 <20 bytes> OP_EQUAL
    let script = expanded.scripts[0]
    check script.len == 23
    check script[0] == 0xA9  # OP_HASH160
    check script[^1] == 0x87  # OP_EQUAL

  test "expand wsh(multi()) descriptor":
    let pk1 = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let pk2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    let desc = parseDescriptor("wsh(multi(2," & pk1 & "," & pk2 & "))")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2WSH
    # Script: OP_0 <32 bytes>
    let script = expanded.scripts[0]
    check script.len == 34
    check script[0] == 0x00
    check script[1] == 0x20

  test "expand combo descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("combo(" & pubkeyHex & ")")
    let expanded = expandNode(desc.node, 0)
    # combo generates: P2PK, P2PKH, P2WPKH, P2SH-P2WPKH (4 scripts for compressed key)
    check expanded.scripts.len == 4
    # P2PKH, P2WPKH, P2SH-P2WPKH addresses
    check expanded.addresses.len == 3

  test "expand tr descriptor":
    let xonlyHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("tr(" & xonlyHex & ")")
    let expanded = expandNode(desc.node, 0)
    check expanded.scripts.len == 1
    check expanded.addresses.len == 1
    check expanded.addresses[0].kind == P2TR
    # Script: OP_1 <32 bytes>
    let script = expanded.scripts[0]
    check script.len == 34
    check script[0] == 0x51  # OP_1
    check script[1] == 0x20

suite "Address Derivation":
  test "derive addresses from wpkh":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("wpkh(" & pubkeyHex & ")")
    let addresses = deriveAddresses(desc, 0, 1, true)
    check addresses.len == 1
    check addresses[0].startsWith("bc1q")

  test "derive addresses from pkh (legacy)":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("pkh(" & pubkeyHex & ")")
    let addresses = deriveAddresses(desc, 0, 1, true)
    check addresses.len == 1
    check addresses[0][0] == '1'  # Mainnet P2PKH starts with 1

  test "derive testnet addresses":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("wpkh(" & pubkeyHex & ")")
    let addresses = deriveAddresses(desc, 0, 1, false)
    check addresses.len == 1
    check addresses[0].startsWith("tb1q")

  test "derive taproot address":
    let xonlyHex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let desc = parseDescriptor("tr(" & xonlyHex & ")")
    let addresses = deriveAddresses(desc, 0, 1, true)
    check addresses.len == 1
    check addresses[0].startsWith("bc1p")

suite "Descriptor Info":
  test "get info for non-ranged descriptor":
    let pubkeyHex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    let info = getDescriptorInfo("wpkh(" & pubkeyHex & ")")
    check info.isRange == false
    check info.isSolvable == true
    check info.hasPrivateKeys == false
    check info.checksum.len == 8

  test "get info for ranged descriptor":
    let xpub = "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"
    let info = getDescriptorInfo("wpkh(" & xpub & "/0/*)")
    check info.isRange == true
    check info.isSolvable == true

  test "addr descriptor is not solvable":
    let info = getDescriptorInfo("addr(bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq)")
    check info.isRange == false
    check info.isSolvable == false

  test "raw descriptor is not solvable":
    let info = getDescriptorInfo("raw(76a914000000000000000000000000000000000000000088ac)")
    check info.isRange == false
    check info.isSolvable == false

suite "BIP380 Test Vectors":
  # Test vectors from BIP380 for checksum validation
  test "BIP380 test vector 1":
    let desc = "pkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)"
    let checksum = computeDescriptorChecksum(desc)
    check checksum.len == 8
    # The descriptor should parse without error
    discard parseDescriptor(desc)

  test "BIP380 test vector - addr descriptor":
    let desc = "addr(bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4)"
    let checksum = computeDescriptorChecksum(desc)
    let full = addDescriptorChecksum(desc)
    let parsed = parseDescriptor(full)
    check parsed.node.kind == DKAddr
    check parsed.checksum == checksum

  test "BIP380 test vector - raw descriptor":
    # P2PKH script for null pubkey hash
    let desc = "raw(76a914000000000000000000000000000000000000000088ac)"
    let parsed = parseDescriptor(desc)
    check parsed.node.kind == DKRaw
    check parsed.node.rawScript == parseHexBytes("76a914000000000000000000000000000000000000000088ac")

when isMainModule:
  echo "Running descriptor tests..."
