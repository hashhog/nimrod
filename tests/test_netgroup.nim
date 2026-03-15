## Tests for network group computation (eclipse protection)
## Reference: Bitcoin Core netgroup.cpp GetGroup()

import unittest
import std/strutils
import ../src/network/netgroup

suite "network group computation":
  test "IPv4 /16 grouping":
    # Same /16 subnet should have same group
    let ip1 = parseIpAddr("192.168.1.1")
    let ip2 = parseIpAddr("192.168.2.1")
    let ip3 = parseIpAddr("192.169.1.1")

    let ng1 = getNetGroup(ip1)
    let ng2 = getNetGroup(ip2)
    let ng3 = getNetGroup(ip3)

    # 192.168.x.x should be in same group
    check ng1 == ng2
    # 192.169.x.x should be different
    check ng1 != ng3

  test "IPv4 different /16 subnets":
    let ip1 = parseIpAddr("10.0.0.1")
    let ip2 = parseIpAddr("10.1.0.1")
    let ip3 = parseIpAddr("172.16.0.1")

    let ng1 = getNetGroup(ip1)
    let ng2 = getNetGroup(ip2)
    let ng3 = getNetGroup(ip3)

    # Different /16 should have different groups
    check ng1 != ng2
    check ng1 != ng3
    check ng2 != ng3

  test "IPv6 /32 grouping":
    # Same /32 prefix should have same group
    let ip1 = parseIpAddr("2001:0db8:0000:0000:0000:0000:0000:0001")
    let ip2 = parseIpAddr("2001:0db8:1234:5678:0000:0000:0000:0001")
    let ip3 = parseIpAddr("2001:0db9:0000:0000:0000:0000:0000:0001")

    let ng1 = getNetGroup(ip1)
    let ng2 = getNetGroup(ip2)
    let ng3 = getNetGroup(ip3)

    # Same /32 (2001:0db8::) should be same group
    check ng1 == ng2
    # Different /32 should be different
    check ng1 != ng3

  test "IPv4-mapped IPv6 uses IPv4 rules":
    # Pure IPv4 address
    let ipv4 = parseIpAddr("192.168.1.1")
    check ipv4.isV6 == false

    let ng4 = getNetGroup(ipv4)
    # Check that IPv4 group uses NetIPv4 type and has /16 data
    check ng4.data.len == 3
    check ng4.data[0] == NetIPv4
    check ng4.data[1] == 192
    check ng4.data[2] == 168

    # IPv4-mapped IPv6 should also use IPv4 rules
    var ipv6mapped: IpAddr
    ipv6mapped = IpAddr(isV6: true, v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1])
    check ipv6mapped.isIPv4Mapped() == true

    let ng6 = getNetGroup(ipv6mapped)
    check ng6.data.len == 3
    check ng6.data[0] == NetIPv4
    check ng6 == ng4  # Should match the IPv4 version

  test "localhost grouping":
    let ip1 = parseIpAddr("127.0.0.1")
    let ip2 = parseIpAddr("127.0.0.2")
    let ip3 = parseIpAddr("127.1.2.3")

    let ng1 = getNetGroup(ip1)
    let ng2 = getNetGroup(ip2)
    let ng3 = getNetGroup(ip3)

    # All localhost should be in same group
    check ng1 == ng2
    check ng1 == ng3

  test "IPv6 loopback":
    let ip = parseIpAddr("::1")
    let ng = getNetGroup(ip)

    # Should be in local group
    check ip.isLocal()
    check ng.data.len >= 1
    check ng.data[0] == NetLocal

  test "unroutable addresses":
    # 0.0.0.0 is truly unroutable
    let ip1 = parseIpAddr("0.0.0.0")
    check ip1.isRoutable() == false

    # Multicast is not routable
    let ip2 = parseIpAddr("224.0.0.1")
    check ip2.isRoutable() == false

    # Private addresses ARE routable for netgroup purposes
    # (they route within their private networks)
    let ip3 = parseIpAddr("10.0.0.1")
    check ip3.isRoutable() == true

    let ip4 = parseIpAddr("192.168.1.1")
    check ip4.isRoutable() == true

  test "routable addresses":
    let ip1 = parseIpAddr("8.8.8.8")
    let ip2 = parseIpAddr("1.1.1.1")

    check ip1.isRoutable() == true
    check ip2.isRoutable() == true

  test "same netgroup check":
    check sameNetGroup("192.168.1.1", "192.168.2.2") == true
    check sameNetGroup("192.168.1.1", "192.169.1.1") == false
    check sameNetGroup("10.0.1.1", "10.0.2.2") == true
    check sameNetGroup("10.0.1.1", "10.1.1.1") == false

  test "netgroup from string with port":
    # Should strip port correctly
    let ng1 = getNetGroup("192.168.1.1:8333")
    let ng2 = getNetGroup("192.168.1.1")

    check ng1 == ng2

  test "keyed netgroup is deterministic":
    let ip = parseIpAddr("192.168.1.1")
    let key = 0x1234567890abcdef'u64

    let kg1 = getKeyedNetGroup(ip, key)
    let kg2 = getKeyedNetGroup(ip, key)

    check kg1 == kg2

  test "keyed netgroup different for different netgroups":
    # Different /16 subnets should have different keyed netgroups
    let ip1 = parseIpAddr("192.168.1.1")
    let ip2 = parseIpAddr("10.0.0.1")
    let key = 0x1234567890abcdef'u64

    let kg1 = getKeyedNetGroup(ip1, key)
    let kg2 = getKeyedNetGroup(ip2, key)

    check kg1 != kg2

  test "keyed netgroup same for same netgroup":
    # Same /16 subnet should have same keyed netgroup
    let ip1 = parseIpAddr("192.168.1.1")
    let ip2 = parseIpAddr("192.168.2.2")
    let key = 0x1234567890abcdef'u64

    let kg1 = getKeyedNetGroup(ip1, key)
    let kg2 = getKeyedNetGroup(ip2, key)

    check kg1 == kg2  # Same netgroup, same keyed value

  test "keyed netgroup different for different keys":
    let ip = parseIpAddr("192.168.1.1")
    let key1 = 0x1234567890abcdef'u64
    let key2 = 0xfedcba0987654321'u64

    let kg1 = getKeyedNetGroup(ip, key1)
    let kg2 = getKeyedNetGroup(ip, key2)

    check kg1 != kg2

  test "CJDNS addresses":
    # CJDNS uses fc00::/8 - need a valid IPv6 address in that range
    # The issue is the full IPv6 needs to be parsed correctly
    var ip: IpAddr
    ip = IpAddr(isV6: true, v6: [0xFC'u8, 0x12, 0x34, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    check ip.isCJDNS() == true

    let ng = getNetGroup(ip)
    check ng.data.len >= 2
    check ng.data[0] == NetCJDNS

  test "netgroup string representation":
    let ng = getNetGroup("192.168.1.1")
    let s = $ng
    check s.startsWith("NetGroup(")
    check s.endsWith(")")

  test "parse various IPv4 formats":
    let ip1 = parseIpAddr("1.2.3.4")
    check ip1.isV6 == false
    check ip1.v4 == [1'u8, 2, 3, 4]

    let ip2 = parseIpAddr("255.255.255.255")
    check ip2.v4 == [255'u8, 255, 255, 255]

    let ip3 = parseIpAddr("0.0.0.0")
    check ip3.v4 == [0'u8, 0, 0, 0]

  test "parse IPv6 with double colon":
    let ip1 = parseIpAddr("::1")
    check ip1.isV6 == true
    check ip1.v6[15] == 1

    let ip2 = parseIpAddr("2001:db8::1")
    check ip2.isV6 == true
    check ip2.v6[0] == 0x20
    check ip2.v6[1] == 0x01
    check ip2.v6[15] == 1

  test "isIPv4Mapped detection":
    var mapped: IpAddr
    mapped = IpAddr(isV6: true, v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1])
    check mapped.isIPv4Mapped() == true

    let notMapped = parseIpAddr("2001:db8::1")
    check notMapped.isIPv4Mapped() == false

  test "extractIPv4 from mapped":
    var mapped: IpAddr
    mapped = IpAddr(isV6: true, v6: [0'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1])
    let v4 = mapped.extractIPv4()
    check v4 == [192'u8, 168, 1, 1]
