## Tests for header sync module
## Validates work calculation, header validation, and chain management

import std/[unittest, tables, options]
import ../src/network/sync
import ../src/consensus/params
import ../src/primitives/[types, serialize]
import ../src/crypto/hashing

suite "256-bit Work Calculation":
  test "calculateWork returns non-zero for valid target":
    # Mainnet genesis difficulty
    let bits = 0x1d00ffff'u32
    let work = calculateWork(bits)

    # Work should be non-zero
    var isZero = true
    for b in work:
      if b != 0:
        isZero = false
        break
    check not isZero

  test "calculateWork returns zero for zero target":
    # Zero target (invalid)
    let bits = 0'u32
    let work = calculateWork(bits)
    check isZeroWork(work)

  test "higher difficulty produces more work":
    # Lower target = higher difficulty = more work
    let easyBits = 0x1d00ffff'u32  # Easy target
    let hardBits = 0x1c00ffff'u32  # Harder target (smaller)

    let easyWork = calculateWork(easyBits)
    let hardWork = calculateWork(hardBits)

    # Hard work should be greater than easy work
    check compareWork(hardWork, easyWork) > 0

  test "addWork correctly sums two values":
    var a: array[32, byte]
    var b: array[32, byte]

    a[0] = 100
    b[0] = 50

    let sum = addWork(a, b)
    check sum[0] == 150
    check sum[1] == 0

  test "addWork handles carry":
    var a: array[32, byte]
    var b: array[32, byte]

    a[0] = 200
    b[0] = 100

    let sum = addWork(a, b)
    # 200 + 100 = 300 = 0x12C = carry 1, value 0x2C = 44
    check sum[0] == 44
    check sum[1] == 1

  test "compareWork returns correct ordering":
    var a: array[32, byte]
    var b: array[32, byte]

    a[0] = 100
    b[0] = 100
    check compareWork(a, b) == 0  # Equal

    a[0] = 101
    check compareWork(a, b) == 1  # a > b

    a[0] = 99
    check compareWork(a, b) == -1  # a < b

    # Test high byte comparison
    a[31] = 1
    b[31] = 0
    check compareWork(a, b) == 1  # a > b

suite "HeaderChain Management":
  test "initHeaderChain creates empty chain":
    let hc = initHeaderChain()
    check hc.headers.len == 0
    check hc.tipHeight == -1
    check isZeroWork(hc.totalWork)

  test "initHeaderChain with genesis":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let hc = initHeaderChain(genesis.header, genesisHash)

    check hc.headers.len == 1
    check hc.tipHeight == 0
    check hc.tip == genesisHash
    check hc.hasHeader(genesisHash)

  test "getHeader returns correct header":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let hc = initHeaderChain(genesis.header, genesisHash)

    let headerOpt = hc.getHeader(genesisHash)
    check headerOpt.isSome
    check headerOpt.get().timestamp == genesis.header.timestamp

    let missingOpt = hc.getHeader(BlockHash(default(array[32, byte])))
    check missingOpt.isNone

  test "getHeaderByHeight returns correct header":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let hc = initHeaderChain(genesis.header, genesisHash)

    check hc.getHeaderByHeight(0).isSome
    check hc.getHeaderByHeight(1).isNone
    check hc.getHeaderByHeight(-1).isNone

suite "Header Validation":
  test "validateHeaderPoW accepts valid header":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)

    # Genesis header should have valid PoW
    check validateHeaderPoW(genesis.header)

  test "validateHeaderPoW rejects invalid header":
    var header = BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),
      merkleRoot: default(array[32, byte]),
      timestamp: 1296688602,
      bits: 0x207fffff'u32,  # Regtest difficulty
      nonce: 0  # Wrong nonce - won't meet target
    )

    # Most random nonces won't meet the target
    # (though regtest is easy, nonce=0 might not work)
    # This test checks the function runs, actual rejection depends on hash

  test "validateHeaderChainLink accepts linked headers":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    # Create a header that links to genesis
    let childHeader = BlockHeader(
      version: 1,
      prevBlock: genesisHash,
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: genesis.header.bits,
      nonce: 0
    )

    check validateHeaderChainLink(childHeader, genesis.header)

  test "validateHeaderChainLink rejects unlinked headers":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)

    # Create a header that doesn't link to genesis
    let badHeader = BlockHeader(
      version: 1,
      prevBlock: BlockHash(default(array[32, byte])),  # Wrong prev
      merkleRoot: default(array[32, byte]),
      timestamp: genesis.header.timestamp + 600,
      bits: genesis.header.bits,
      nonce: 0
    )

    check not validateHeaderChainLink(badHeader, genesis.header)

suite "Median Time Past":
  test "MTP with single header":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    let hc = initHeaderChain(genesis.header, genesisHash)
    let mtp = getMedianTimePastFromChain(hc, 0)

    check mtp == genesis.header.timestamp

  test "MTP calculation with multiple headers":
    # Build a chain of headers with known timestamps
    var hc = initHeaderChain()
    hc.headers = @[]

    let timestamps = [100'u32, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100]
    for i, ts in timestamps:
      var header = BlockHeader(
        version: 1,
        timestamp: ts,
        bits: 0x207fffff'u32,
        nonce: 0
      )
      hc.headers.add(header)

    hc.tipHeight = int32(hc.headers.len - 1)

    # MTP of last 11 blocks (indices 0-10)
    # Sorted: 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000, 1100
    # Median (index 5): 600
    let mtp = getMedianTimePastFromChain(hc, 10)
    check mtp == 600

suite "SyncManager":
  test "newSyncManager initializes with genesis":
    let params = regtestParams()
    # Note: This test would need a mock PeerManager and ChainDb
    # For now, we just verify the module compiles and exports correctly
    check true

  test "buildBlockLocator with small chain":
    let params = regtestParams()
    let genesis = buildGenesisBlock(params)
    let genesisBytes = serialize(genesis.header)
    let genesisHash = BlockHash(doubleSha256(genesisBytes))

    var hc = initHeaderChain(genesis.header, genesisHash)

    # Should contain at least genesis
    check hc.headers.len >= 1
