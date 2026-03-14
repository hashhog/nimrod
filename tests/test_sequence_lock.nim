## Tests for BIP68 sequence lock validation
## Tests calculateSequenceLocks, checkSequenceLocks, and block validation integration

import std/[options, tables]
import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]
import ../src/storage/chainstate
import ../src/crypto/hashing

suite "BIP68 sequence lock constants":
  test "sequence lock disable flag":
    check SequenceLockDisableFlag == 0x80000000'u32
    check (1'u32 shl 31) == 0x80000000'u32

  test "sequence lock type flag":
    check SequenceLockTypeFlag == 0x00400000'u32
    check (1'u32 shl 22) == 0x00400000'u32

  test "sequence lock mask":
    check SequenceLockMask == 0x0000ffff'u32

  test "sequence lock granularity":
    check SequenceLockGranularity == 9
    # 2^9 = 512 seconds per unit
    check (1 shl SequenceLockGranularity) == 512

suite "sequence lock calculation":
  test "tx version 1 bypasses BIP68":
    let params = regtestParams()

    # Create a v1 transaction with sequence locks that would fail
    let tx = Transaction(
      version: 1,  # Version 1 - BIP68 doesn't apply
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 10  # Relative lock of 10 blocks, but v1 tx ignores this
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]  # UTXO mined at height 100

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)  # Simple MTP approximation

    let lock = calculateSequenceLocks(tx, prevHeights, 105, getMtp, params)

    # Version 1 should have no constraints
    check lock.minHeight == -1
    check lock.minTime == -1

  test "disabled sequence lock input":
    let params = regtestParams()

    # Create a v2 transaction with disable flag set
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: SequenceLockDisableFlag or 100  # Disable flag set
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 105, getMtp, params)

    # Disable flag means no constraints
    check lock.minHeight == -1
    check lock.minTime == -1
    # prevHeights should be set to 0 for disabled inputs
    check prevHeights[0] == 0

  test "height-based relative lock":
    let params = regtestParams()

    # Create a v2 transaction with height-based lock of 10 blocks
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 10  # Relative lock of 10 blocks (type flag not set = height-based)
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]  # UTXO mined at height 100

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 115, getMtp, params)

    # minHeight = coinHeight + lockValue - 1 = 100 + 10 - 1 = 109
    check lock.minHeight == 109
    check lock.minTime == -1

  test "time-based relative lock":
    let params = regtestParams()

    # Create a v2 transaction with time-based lock of 2 units (1024 seconds)
    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: SequenceLockTypeFlag or 2  # Time-based lock of 2 units
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]  # UTXO mined at height 100

    # MTP at height 99 (height - 1) is 60000
    proc getMtp(h: int32): uint32 =
      if h == 99:
        return 60000
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 105, getMtp, params)

    # minTime = coinMtp + (2 * 512) - 1 = 60000 + 1024 - 1 = 61023
    check lock.minHeight == -1
    check lock.minTime == 61023

  test "multiple inputs take maximum constraint":
    let params = regtestParams()

    # Create a v2 transaction with multiple inputs having different locks
    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(
          prevOut: OutPoint(
            txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            vout: 0
          ),
          scriptSig: @[],
          sequence: 5  # Height-based: 5 blocks
        ),
        TxIn(
          prevOut: OutPoint(
            txid: TxId([2'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            vout: 0
          ),
          scriptSig: @[],
          sequence: 15  # Height-based: 15 blocks
        )
      ],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100), int32(90)]  # UTXOs mined at heights 100 and 90

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 120, getMtp, params)

    # Input 0: minHeight = 100 + 5 - 1 = 104
    # Input 1: minHeight = 90 + 15 - 1 = 104
    # Both equal, so max is 104
    check lock.minHeight == 104
    check lock.minTime == -1

  test "mixed height and time locks":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[
        TxIn(
          prevOut: OutPoint(
            txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            vout: 0
          ),
          scriptSig: @[],
          sequence: 10  # Height-based: 10 blocks
        ),
        TxIn(
          prevOut: OutPoint(
            txid: TxId([2'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            vout: 0
          ),
          scriptSig: @[],
          sequence: SequenceLockTypeFlag or 3  # Time-based: 3 units
        )
      ],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100), int32(95)]

    proc getMtp(h: int32): uint32 =
      if h == 94:  # height - 1 for input 1
        return 50000
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 120, getMtp, params)

    # Input 0: minHeight = 100 + 10 - 1 = 109
    # Input 1: minTime = 50000 + (3 * 512) - 1 = 50000 + 1536 - 1 = 51535
    check lock.minHeight == 109
    check lock.minTime == 51535

suite "sequence lock evaluation":
  test "satisfied height lock":
    let lock = SequenceLock(minHeight: 100, minTime: -1)
    # Block at height 101 should satisfy lock (101 > 100)
    check checkSequenceLocks(lock, 101, 0) == true

  test "unsatisfied height lock":
    let lock = SequenceLock(minHeight: 100, minTime: -1)
    # Block at height 100 should not satisfy lock (100 not > 100)
    check checkSequenceLocks(lock, 100, 0) == false

  test "boundary height lock":
    let lock = SequenceLock(minHeight: 100, minTime: -1)
    # Block at height 99 should not satisfy lock
    check checkSequenceLocks(lock, 99, 0) == false

  test "satisfied time lock":
    let lock = SequenceLock(minHeight: -1, minTime: 60000)
    # Block with MTP 60001 should satisfy lock
    check checkSequenceLocks(lock, 100, 60001) == true

  test "unsatisfied time lock":
    let lock = SequenceLock(minHeight: -1, minTime: 60000)
    # Block with MTP 60000 should not satisfy lock (60000 not > 60000)
    check checkSequenceLocks(lock, 100, 60000) == false

  test "both locks must be satisfied":
    let lock = SequenceLock(minHeight: 100, minTime: 60000)
    # Both must pass
    check checkSequenceLocks(lock, 101, 60001) == true
    # Only height passes
    check checkSequenceLocks(lock, 101, 60000) == false
    # Only time passes
    check checkSequenceLocks(lock, 100, 60001) == false
    # Neither passes
    check checkSequenceLocks(lock, 100, 60000) == false

  test "no constraints":
    let lock = SequenceLock(minHeight: -1, minTime: -1)
    # No constraints means always satisfied
    check checkSequenceLocks(lock, 0, 0) == true
    check checkSequenceLocks(lock, 1000000, 1000000000) == true

suite "BIP68 CSV activation":
  test "mainnet CSV activation height":
    let params = mainnetParams()
    check params.csvHeight == 419328

  test "regtest CSV active from genesis":
    let params = regtestParams()
    check params.csvHeight == 0

  test "testnet3 CSV activation":
    let params = testnet3Params()
    check params.csvHeight == 770112

suite "sequence lock validation error":
  test "validation error enum exists":
    check $veSequenceLockNotSatisfied == "BIP68 relative lock-time not satisfied"

suite "sequence lock integration":
  test "checkSequenceLocksForTx with v1 tx passes":
    let params = regtestParams()

    let tx = Transaction(
      version: 1,  # v1 bypasses BIP68
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 1000  # Would require 1000 block wait if v2
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    # Provide UTXO entry via closure
    var utxoTable = initTable[string, UtxoEntry]()
    let key = $[1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] & ":0"
    utxoTable[key] = UtxoEntry(
      output: TxOut(value: Satoshi(2000), scriptPubKey: @[]),
      height: 100,
      isCoinbase: false
    )

    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      let k = $array[32, byte](op.txid) & ":" & $op.vout
      if k in utxoTable:
        return some(utxoTable[k])
      none(UtxoEntry)

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    # Block at height 105 - v1 tx should pass regardless of sequence
    let result = checkSequenceLocksForTx(tx, lookupUtxo, 105, 60000, getMtp, params)
    check result.isOk == true

  test "checkSequenceLocksForTx with satisfied height lock passes":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 5  # 5 block relative lock
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var utxoTable = initTable[string, UtxoEntry]()
    let key = $[1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] & ":0"
    utxoTable[key] = UtxoEntry(
      output: TxOut(value: Satoshi(2000), scriptPubKey: @[]),
      height: 100,  # UTXO mined at height 100
      isCoinbase: false
    )

    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      let k = $array[32, byte](op.txid) & ":" & $op.vout
      if k in utxoTable:
        return some(utxoTable[k])
      none(UtxoEntry)

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    # minHeight = 100 + 5 - 1 = 104
    # Block at height 105 > 104, so should pass
    let result = checkSequenceLocksForTx(tx, lookupUtxo, 105, 60000, getMtp, params)
    check result.isOk == true

  test "checkSequenceLocksForTx with unsatisfied height lock fails":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 10  # 10 block relative lock
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var utxoTable = initTable[string, UtxoEntry]()
    let key = $[1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] & ":0"
    utxoTable[key] = UtxoEntry(
      output: TxOut(value: Satoshi(2000), scriptPubKey: @[]),
      height: 100,  # UTXO mined at height 100
      isCoinbase: false
    )

    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      let k = $array[32, byte](op.txid) & ":" & $op.vout
      if k in utxoTable:
        return some(utxoTable[k])
      none(UtxoEntry)

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    # minHeight = 100 + 10 - 1 = 109
    # Block at height 105 <= 109, so should fail
    let result = checkSequenceLocksForTx(tx, lookupUtxo, 105, 60000, getMtp, params)
    check result.isOk == false
    check result.error == veSequenceLockNotSatisfied

  test "coinbase tx bypasses sequence lock check":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId(default(array[32, byte])),  # Coinbase: null txid
          vout: 0xffffffff'u32                   # Coinbase: max vout
        ),
        scriptSig: @[0x03'u8, 0x01, 0x00, 0x00],
        sequence: 10  # Would fail if checked
      )],
      outputs: @[TxOut(
        value: Satoshi(50_00000000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    proc lookupUtxo(op: OutPoint): Option[UtxoEntry] =
      none(UtxoEntry)

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    # Coinbase should pass because it's skipped
    let result = checkSequenceLocksForTx(tx, lookupUtxo, 1, 0, getMtp, params)
    check result.isOk == true

suite "BIP68 edge cases":
  test "zero relative lock":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 0  # Zero relative lock (effectively immediately spendable)
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 100, getMtp, params)

    # minHeight = 100 + 0 - 1 = 99
    check lock.minHeight == 99
    # Block at height 100 > 99, so valid
    check checkSequenceLocks(lock, 100, 60000) == true

  test "maximum height lock":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: 0xffff  # Maximum height lock (65535 blocks)
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]

    proc getMtp(h: int32): uint32 =
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 100000, getMtp, params)

    # minHeight = 100 + 65535 - 1 = 65634
    check lock.minHeight == 65634

  test "maximum time lock":
    let params = regtestParams()

    let tx = Transaction(
      version: 2,
      inputs: @[TxIn(
        prevOut: OutPoint(
          txid: TxId([1'u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
          vout: 0
        ),
        scriptSig: @[],
        sequence: SequenceLockTypeFlag or 0xffff  # Maximum time lock
      )],
      outputs: @[TxOut(
        value: Satoshi(1000),
        scriptPubKey: @[]
      )],
      witnesses: @[],
      lockTime: 0
    )

    var prevHeights = @[int32(100)]

    proc getMtp(h: int32): uint32 =
      if h == 99:
        return 1000000
      uint32(h * 600)

    let lock = calculateSequenceLocks(tx, prevHeights, 200, getMtp, params)

    # minTime = 1000000 + (65535 * 512) - 1 = 1000000 + 33553920 - 1 = 34553919
    check lock.minTime == 34553919
