## BIP68 block validation integration tests
## Tests that sequence locks are properly enforced during block validation

import std/[options, tables]
import unittest2
import ../src/consensus/[params, validation]
import ../src/primitives/[types, serialize]
import ../src/script/interpreter
import ../src/crypto/hashing

suite "BIP68 block validation":
  test "CSV flag in script flags before activation":
    let params = mainnetParams()
    # Before CSV activation (419328), CHECKSEQUENCEVERIFY should not be in flags
    let flags = getBlockScriptFlags(419327, params)
    check sfCheckSequenceVerify notin flags

  test "CSV flag in script flags after activation":
    let params = mainnetParams()
    # At CSV activation height, CHECKSEQUENCEVERIFY should be in flags
    let flags = getBlockScriptFlags(419328, params)
    check sfCheckSequenceVerify in flags

  test "regtest has CSV from genesis":
    let params = regtestParams()
    let flags = getBlockScriptFlags(0, params)
    check sfCheckSequenceVerify in flags

    let flags1 = getBlockScriptFlags(1, params)
    check sfCheckSequenceVerify in flags1

suite "BIP68 constants verification":
  test "constants match Bitcoin Core values":
    # Verify our constants match Bitcoin Core's CTxIn values
    # SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31)
    check SequenceLockDisableFlag == (1'u32 shl 31)
    # SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22)
    check SequenceLockTypeFlag == (1'u32 shl 22)
    # SEQUENCE_LOCKTIME_MASK = 0x0000ffff
    check SequenceLockMask == 0x0000ffff'u32
    # SEQUENCE_LOCKTIME_GRANULARITY = 9
    check SequenceLockGranularity == 9

  test "time granularity is 512 seconds":
    # Each time unit is 512 seconds (2^9)
    let secondsPerUnit = 1 shl SequenceLockGranularity
    check secondsPerUnit == 512

  test "maximum relative height lock":
    # Maximum relative height lock is 65535 blocks (~1.25 years at 10 min/block)
    let maxBlocks = int(SequenceLockMask)
    check maxBlocks == 65535

  test "maximum relative time lock":
    # Maximum relative time lock is 65535 * 512 seconds (~388 days)
    let maxSeconds = int(SequenceLockMask) * (1 shl SequenceLockGranularity)
    check maxSeconds == 33553920  # About 388 days

suite "BIP68 semantic correctness":
  test "sequence value interpretation - height based":
    # A sequence of 0x0000000A means 10 blocks
    let sequence = 0x0000000A'u32
    check (sequence and SequenceLockDisableFlag) == 0  # Not disabled
    check (sequence and SequenceLockTypeFlag) == 0     # Height-based
    check (sequence and SequenceLockMask) == 10        # 10 blocks

  test "sequence value interpretation - time based":
    # A sequence of 0x00400005 means 5 time units (2560 seconds)
    let sequence = 0x00400005'u32
    check (sequence and SequenceLockDisableFlag) == 0         # Not disabled
    check (sequence and SequenceLockTypeFlag) != 0            # Time-based
    check (sequence and SequenceLockMask) == 5                # 5 units
    check int(sequence and SequenceLockMask) * 512 == 2560    # 2560 seconds

  test "sequence value interpretation - disabled":
    # A sequence of 0x80000000 means BIP68 disabled
    let sequence = 0x80000000'u32
    check (sequence and SequenceLockDisableFlag) != 0  # Disabled
    # When disabled, type flag and mask are irrelevant

  test "sequence value interpretation - max final":
    # Sequence 0xFFFFFFFF is SEQUENCE_FINAL and disables BIP68
    let sequence = 0xFFFFFFFF'u32
    check (sequence and SequenceLockDisableFlag) != 0  # Disabled

suite "BIP68 activation by network":
  test "mainnet CSV height":
    let params = mainnetParams()
    check params.csvHeight == 419328

  test "testnet3 CSV height":
    let params = testnet3Params()
    check params.csvHeight == 770112

  test "regtest CSV from genesis":
    let params = regtestParams()
    check params.csvHeight == 0

suite "BIP68 nLockTime semantics":
  test "lock value is last invalid value":
    # BIP68 uses nLockTime semantics: the lock value is the LAST invalid height/time
    # So if minHeight = 100, height 100 is invalid but 101 is valid
    let lock = SequenceLock(minHeight: 100, minTime: -1)

    check checkSequenceLocks(lock, 100, 0) == false  # 100 is invalid
    check checkSequenceLocks(lock, 101, 0) == true   # 101 is valid

  test "time lock semantics":
    let lock = SequenceLock(minHeight: -1, minTime: 1000)

    check checkSequenceLocks(lock, 100, 1000) == false  # MTP 1000 is invalid
    check checkSequenceLocks(lock, 100, 1001) == true   # MTP 1001 is valid
