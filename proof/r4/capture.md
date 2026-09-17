# T2 capture — nimrod — MATCH

**nimrod reproduces C(958794).**

| field | value |
|---|---|
| captured (UTC) | 20260818T201537Z |
| height | 958794 |
| bestblockhash | `000000000000000000015eaadd989e4f09ff75b643a128dc7bdf6070431d7d0e` |
| hash_serialized | `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` |
| anchor | `29692050559b8f064a03af9cd605040e71d1d978fa22947c079cc7e5546e7af0` |
| utxo count | 166180925 |

Lineage: from-genesis, assumevalid=0, fed by the capped
blk-replay-server (--max-serve-height 958794) so the node
FROZE on the anchor. No rollback was performed at any point.

Captured automatically by tools/lineage-capture-watch.sh.

## Not yet ratified

This receipt is EVIDENCE, not a ledger entry. A human must still:
1. append the TRUST-ANCHOR row,
2. run the release wrapper + smoke gate,
3. GPG-sign the tag.
