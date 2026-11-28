## cffix-nimrod-netgroup-random-key: the keyed netgroup used by inbound
## eviction must be keyed with a per-process random secret.
##
## Finding (fingerprint nimrod-eviction-hardcoded-netgroup-key):
## PeerManager.netgroupKey was the constant NetgroupKey = 0x6c0edd8036ef4036
## (SHA256("netgroup")[0:8]), fed to an unkeyed FNV-style mix in
## getKeyedNetGroup.  selectNodeToEvict protects the 4 candidates with the
## highest keyed netgroup, so the protected netgroups were the same, and
## computable, on every nimrod node: an attacker could pick source /16s that
## are always protected, or always evictable.
##
## Core (bitcoin-core/src/net.cpp):
##   :110   RANDOMIZER_ID_NETGROUP = 0x6c0edd8036ef4036 -- a domain separator
##   :4139  GetDeterministicRandomizer(id) = CSipHasher(nSeed0, nSeed1).Write(id)
##   :4148  CalculateKeyedNetGroup = ...(RANDOMIZER_ID_NETGROUP)
##                                    .Write(vchNetGroup).Finalize()
##   nSeed0/nSeed1 are GetRand<uint64_t>() per CConnman (init.cpp).
##
## Run:
##   nim c -r tests/test_cffix_netgroup_random_key.nim

import std/[tempfiles, os]
import unittest2

import ../src/consensus/params
import ../src/crypto/siphash
import ../src/network/netgroup
import ../src/network/peermanager

proc freshManager(): PeerManager =
  let dir = createTempDir("nimrod-netgroup-key-", "")
  result = newPeerManager(regtestParams(), dataDir = dir)
  removeDir(dir)

suite "cffix-nimrod-netgroup-random-key":

  test "two PeerManager instances get different netgroupKey values":
    # Master: both are the public constant 0x6c0edd8036ef4036.
    let a = freshManager()
    let b = freshManager()
    check a.netgroupKey != b.netgroupKey

  test "the same IP gets a different keyed netgroup on two nodes":
    # The key must actually reach the hash.  Four /16s so that one chance
    # collision of a 64-bit hash cannot make the test pass on master.
    let a = freshManager()
    let b = freshManager()
    var differing = 0
    for s in ["8.8.8.8", "1.2.3.4", "203.0.113.7", "2001:db8::1"]:
      let ip = parseIpAddr(s)
      if getKeyedNetGroup(ip, a.netgroupKey) != getKeyedNetGroup(ip, b.netgroupKey):
        inc differing
    check differing == 4

  test "keyed netgroup is Core's SipHash(seed).Write(id).Write(group)":
    # Pins the construction, not just "differs": the expected value is
    # computed through the byte-oriented sipHash with the id serialized
    # little-endian, as CSipHasher::Write(uint64_t) does.
    when compiles(getKeyedNetGroup(parseIpAddr("8.8.8.8"),
                                   (k0: 1'u64, k1: 2'u64))):
      let seed = (k0: 0x0706050403020100'u64, k1: 0x0f0e0d0c0b0a0908'u64)
      for s in ["8.8.8.8", "192.168.1.1", "2001:db8::1"]:
        let ip = parseIpAddr(s)
        var msg: seq[byte]
        for i in 0 ..< 8:
          msg.add byte((RandomizerIdNetgroup shr (i * 8)) and 0xff)
        msg.add getNetGroup(ip).data
        check getKeyedNetGroup(ip, seed) == sipHash(seed.k0, seed.k1, msg)
    else:
      checkpoint "getKeyedNetGroup has no 128-bit (NetgroupSeed) form"
      fail()

  test "control: one node's keyed netgroup is stable across calls":
    # Eviction sorts by this value; it must be deterministic within a process.
    let a = freshManager()
    let ip = parseIpAddr("8.8.8.8")
    check getKeyedNetGroup(ip, a.netgroupKey) == getKeyedNetGroup(ip, a.netgroupKey)

  test "control: same /16 shares a keyed netgroup, different /16 does not":
    let a = freshManager()
    let k = a.netgroupKey
    check getKeyedNetGroup(parseIpAddr("8.8.1.1"), k) ==
          getKeyedNetGroup(parseIpAddr("8.8.200.3"), k)
    check getKeyedNetGroup(parseIpAddr("8.8.1.1"), k) !=
          getKeyedNetGroup(parseIpAddr("8.9.1.1"), k)
