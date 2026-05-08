## Tests for BIP-32 (HD key derivation) and BIP-86 (single-key Taproot)
## using the canonical test vectors from the BIPs.
##
## These vectors directly exercise the W20 wallet correctness fixes:
##   P0-1 (BIP-32 CKD_priv mod-n via libsecp tweak_add)
##   P0-2 (BIP-86 TapTweak applied at purpose-86 derive)
##
## Reference:
##   BIP-32: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
##   BIP-86: https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki

import std/[unittest, strutils]
import ../src/wallet/wallet
import ../src/crypto/[secp256k1, address]

proc hexToBytes(hex: string): seq[byte] =
  result = newSeq[byte](hex.len div 2)
  for i in 0 ..< result.len:
    result[i] = byte(parseHexInt(hex[i*2 ..< i*2+2]))

proc hexToArr32(hex: string): array[32, byte] =
  doAssert hex.len == 64
  for i in 0 ..< 32:
    result[i] = byte(parseHexInt(hex[i*2 ..< i*2+2]))

proc bytesToHex(b: openArray[byte]): string =
  result = newStringOfCap(b.len * 2)
  for c in b:
    result.add(toHex(int(c), 2).toLowerAscii)

# Tests that require secp256k1 (HD derivation calls libsecp directly)
when defined(useSystemSecp256k1):
  initSecp256k1()

  suite "BIP-32 official test vectors (vector 1)":
    # Seed: 000102030405060708090a0b0c0d0e0f
    # Reference values from BIP-32 spec table.
    const seedHex = "000102030405060708090a0b0c0d0e0f"

    # Master m
    const expectMasterXprv =
      "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    const expectMasterXpub =
      "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

    # m/0'
    const expectM0hPriv =
      "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    const expectM0hPub =
      "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"

    # m/0'/1
    const expectM0h1Priv =
      "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs"
    const expectM0h1Pub =
      "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"

    # m/0'/1/2'
    const expectM0h12hPriv =
      "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM"
    const expectM0h12hPub =
      "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"

    test "BIP-32 official m/0'/1/2' vector via masterKeyFromSeedRaw":
      # This drives the BIP-32 vector verbatim (16-byte seed input) and walks
      # m -> m/0' (hardened) -> m/0'/1 (normal CKD_priv) -> m/0'/1/2' (hardened).
      # It validates:
      #   - the HMAC chain-code split
      #   - hardened derivation (parent_key prefix path)
      #   - non-hardened derivation (parent_pubkey prefix path), which is the
      #     code-path that exercises libsecp's seckey_tweak_add (P0-1).
      let seedBytes = hexToBytes(seedHex)
      let master = masterKeyFromSeedRaw(seedBytes)

      check serializeExtendedKey(master, mainnet=true) == expectMasterXprv
      check serializeExtendedKey(neuter(master), mainnet=true) == expectMasterXpub

      let m0h = deriveChild(master, HARDENED + 0'u32)
      check serializeExtendedKey(m0h, mainnet=true) == expectM0hPriv
      check serializeExtendedKey(neuter(m0h), mainnet=true) == expectM0hPub

      let m0h1 = deriveChild(m0h, 1'u32)
      check serializeExtendedKey(m0h1, mainnet=true) == expectM0h1Priv
      check serializeExtendedKey(neuter(m0h1), mainnet=true) == expectM0h1Pub

      let m0h12h = deriveChild(m0h1, HARDENED + 2'u32)
      check serializeExtendedKey(m0h12h, mainnet=true) == expectM0h12hPriv
      check serializeExtendedKey(neuter(m0h12h), mainnet=true) == expectM0h12hPub

  suite "BIP-86 official test vector (single-key Taproot)":
    # Mnemonic: 12 abandons + about
    # m/86'/0'/0'/0/0:
    #   internal_key (x-only):
    #     cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115
    #   output_key (tweaked, x-only):
    #     a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c
    #   address (mainnet, bech32m):
    #     bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr
    const mnemonic =
      "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    const expectInternalKey =
      "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115"
    const expectOutputKey =
      "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
    const expectAddress =
      "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"

    test "m/86'/0'/0'/0/0 internal key matches BIP-86":
      var wallet = newWallet(mnemonic)
      let extKey = derivePathStr(wallet.masterKey, "m/86'/0'/0'/0/0")
      # internal key is the x-only of the compressed pubkey (drop parity byte)
      var internalKey: array[32, byte]
      for i in 0 ..< 32:
        internalKey[i] = extKey.publicKey[1 + i]
      check bytesToHex(internalKey) == expectInternalKey

    test "m/86'/0'/0'/0/0 output key is the BIP-86 tweaked key":
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 86, accountIndex = 0, gap = 1)
      let derived = wallet.accounts[0].externalKeys[0]
      check derived.address.kind == P2TR
      check bytesToHex(derived.address.taprootKey) == expectOutputKey

    test "m/86'/0'/0'/0/0 mainnet bech32m address matches BIP-86":
      var wallet = newWallet(mnemonic)
      wallet.addAccount(purpose = 86, accountIndex = 0, gap = 1)
      let derived = wallet.accounts[0].externalKeys[0]
      check derived.addressStr == expectAddress

  suite "BIP-32 CKD_priv overflow handling":
    # Synthesize a pathological case: parent_key very close to n, IL = 1.
    # (parent_key + 1) mod n should wrap and produce a valid (but specific)
    # child. This exercises the modular reduction path, which the old naive
    # byte-add-with-carry got silently wrong whenever sum >= 2^256.
    test "tweakSeckeyAdd wraps mod n correctly":
      # parent_key = n - 1
      const nMinus1Hex =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
      # tweak = 1
      const oneHex =
        "0000000000000000000000000000000000000000000000000000000000000001"
      # Expected child = (n - 1 + 1) mod n = 0 -> libsecp REJECTS (zero seckey).
      # Per BIP-32 the caller must bump the index. We assert the rejection.
      let parent = hexToArr32(nMinus1Hex)
      let tweak = hexToArr32(oneHex)
      let r = tweakSeckeyAdd(parent, tweak)
      check r.isNone

    test "tweakSeckeyAdd rejects tweak == n (overflow)":
      # parent_key = 1 (valid)
      var parent: array[32, byte]
      parent[31] = 1
      # tweak = n itself -> overflow; libsecp rejects.
      const nHex =
        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
      let tweak = hexToArr32(nHex)
      let r = tweakSeckeyAdd(parent, tweak)
      check r.isNone

    test "tweakSeckeyAdd accepts a normal in-range tweak":
      var parent: array[32, byte]
      parent[31] = 1
      var tweak: array[32, byte]
      tweak[31] = 2
      let r = tweakSeckeyAdd(parent, tweak)
      check r.isSome
      # 1 + 2 = 3, no reduction needed
      var expected: array[32, byte]
      expected[31] = 3
      check r.get() == expected
