## HASHHOG_CAMPAIGN_ASSUMEUTXO: a campaign entry IDENTICAL to a built-in
## assumeutxo row (height, blockhash, hash_serialized, m_chain_tx_count) is a
## confirmation, not a collision; a DIFFERENT entry at a built-in height is
## still refused. R4 slice 910000-920000 was BLOCKED because the soak-910000
## rung (dumped from a Core clone) equals Core's hardcoded 910,000 anchor.
##
##   nim c -r --nimcache:<scratch> tests/test_campaign_builtin_confirmation.nim

import unittest2
import std/[os, strutils, json]
import ../src/consensus/params
import ../src/primitives/types

const
  H910 = 910000
  BH910 = "0000000000000000000108970acb9522ffd516eae17acddcb1bd16469194a821"
  HS910 = "4daf8a17b4902498c5787966a2b51c613acdab5df5db73f196fa59a4da2f1568"
  TX910 = 1226586151
  # base_header / chainwork from tools/boundary-blocks/soak-910000/campaign-entry.json
  BaseHdr910 = "00a0572be06d4f01a2ed2228dec965539cc8b96512ccde7d2824010000000000000000006f28c30dc748f6b1430fb2b9a5a94b5b34a5df6e318c6cc5c310a1a35b432b59a3ab9d68b32c021719d103e9"
  CW910 = "0000000000000000000000000000000000000000da15bcbf68ad7fed795c504f"
  RealFixture = "/home/work/hashhog/tools/boundary-blocks/soak-910000/campaign-entry.json"

proc writeCampaign(name: string, entries: JsonNode): string =
  let dir = getTempDir() / "nimrod_campaign_builtin_confirm"
  createDir(dir)
  result = dir / name
  writeFile(result, $entries)

proc entry910(hs = HS910, tx = TX910, bh = BH910, withAncestry = true): JsonNode =
  result = %*{"height": H910, "blockhash": bh, "hash_serialized": hs,
              "m_chain_tx_count": tx}
  if withAncestry:
    result["base_header"] = %BaseHdr910
    result["chainwork"] = %CW910

proc row910(p: ConsensusParams): AssumeutxoData =
  for d in p.assumeutxoData:
    if d.height == H910: return d
  doAssert false, "mainnet has no built-in 910000 row"

proc isZero(a: array[32, byte]): bool =
  for b in a:
    if b != 0: return false
  true

suite "campaign assumeutxo: identical-to-built-in is a confirmation":
  teardown:
    try: removeDir(getTempDir() / "nimrod_campaign_builtin_confirm") except OSError: discard

  test "identical entry (real 910000 commitment) accepted; commitment kept, gaps filled":
    var p = mainnetParams()
    let before = p.assumeutxoData.len
    check isZero(row910(p).chainwork)
    check row910(p).baseTailHeaders.len == 0
    applyCampaignAssumeutxoFile(p, writeCampaign("ok.json", %*[entry910()]))
    check p.assumeutxoData.len == before           # no second row at 910000
    let r = row910(p)
    check r.hashSerialized == hexToBytes32(HS910)
    check r.chainTxCount == uint64(TX910)
    check r.blockhash == BlockHash(hexToBytes32(BH910))
    check r.chainwork == hexToBytes32(CW910)        # filled from the entry
    check r.baseTailHeaders.len == 1                # base_header grafted band

  test "identical entry with UPPERCASE hex accepted":
    var p = mainnetParams()
    applyCampaignAssumeutxoFile(p, writeCampaign("upper.json",
      %*[entry910(hs = HS910.toUpperAscii, bh = BH910.toUpperAscii, withAncestry = false)]))
    check row910(p).hashSerialized == hexToBytes32(HS910)

  test "different hash_serialized at the built-in height refused":
    var p = mainnetParams()
    let before = p.assumeutxoData
    var bad = HS910
    bad[^1] = '9'
    expect CampaignAssumeutxoError:
      applyCampaignAssumeutxoFile(p, writeCampaign("badhs.json", %*[entry910(hs = bad)]))
    check p.assumeutxoData == before                # refusal leaves table untouched

  test "different m_chain_tx_count at the built-in height refused":
    var p = mainnetParams()
    expect CampaignAssumeutxoError:
      applyCampaignAssumeutxoFile(p, writeCampaign("badtx.json", %*[entry910(tx = TX910 + 1)]))

  test "different blockhash at the built-in height refused":
    var p = mainnetParams()
    expect CampaignAssumeutxoError:
      applyCampaignAssumeutxoFile(p, writeCampaign("badbh.json",
        %*[entry910(bh = "11".repeat(32), withAncestry = false)]))

  test "built-in blockhash at a different height refused":
    var p = mainnetParams()
    var e = entry910(withAncestry = false)
    e["height"] = %(H910 + 1)
    expect CampaignAssumeutxoError:
      applyCampaignAssumeutxoFile(p, writeCampaign("otherh.json", %*[e]))

  test "duplicate of the confirmed entry within the file refused":
    var p = mainnetParams()
    expect CampaignAssumeutxoError:
      applyCampaignAssumeutxoFile(p, writeCampaign("dup.json",
        %*[entry910(withAncestry = false), entry910(withAncestry = false)]))

  test "real soak-910000 fixture accepted against the mainnet table":
    if not fileExists(RealFixture):
      skip()
    else:
      var p = mainnetParams()
      applyCampaignAssumeutxoFile(p, RealFixture)
      let r = row910(p)
      check r.hashSerialized == hexToBytes32(HS910)
      check r.chainwork == hexToBytes32(CW910)
      check r.baseTailHeaders.len > 1
