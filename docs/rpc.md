# RPC reference

nimrod serves Bitcoin Core-style JSON-RPC over HTTP on the RPC port (see
[running.md](running.md)), bound to `127.0.0.1`. Method names, positional parameters and
result fields follow Core. Both JSON-RPC 1.0 and 2.0 request bodies work, and so do batch
requests (a JSON array of requests). Only `POST` is accepted.

## Calling it

Authentication is HTTP Basic auth, with either the cookie written at startup to
`<datadir>/<network>/.cookie` (user `__cookie__`) or `--rpcuser`/`--rpcpassword`:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" \
  -d '{"jsonrpc":"1.0","id":1,"method":"getblockchaininfo","params":[]}' http://127.0.0.1:18443/
```

Calls for a specific wallet go to `/wallet/<name>`, as in Core:

```bash
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"createwallet","params":["demo"]}' http://127.0.0.1:18443/
ADDR=$(curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getnewaddress","params":[]}' http://127.0.0.1:18443/wallet/demo | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])')
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d "{\"method\":\"generatetoaddress\",\"params\":[101,\"$ADDR\"]}" http://127.0.0.1:18443/ > /dev/null
curl -s --user "$(cat "$DATADIR/regtest/.cookie")" -d '{"method":"getbalance","params":[]}' http://127.0.0.1:18443/wallet/demo
```

`help` lists the methods it documents, grouped as below, and `help <method>` prints one
method's usage.

## REST

With `--rest`, unauthenticated read-only endpoints are served on `127.0.0.1` at
`--restport` (default: RPC port + 1000, so 19443 on regtest): `/rest/block/<hash>`,
`/rest/block/notxdetails/<hash>`, `/rest/headers/...`, `/rest/blockhashbyheight/<height>`,
`/rest/tx/<txid>`, `/rest/getutxos/...`, `/rest/mempool/info.json`,
`/rest/mempool/contents.json`, `/rest/blockfilter/...` and `/rest/blockfilterheaders/...`
(the last two need `--blockfilterindex`), with `.json`, `.hex` or `.bin` suffixes as in
Core. There is no `/rest/chaininfo` endpoint.

```bash
curl -s http://127.0.0.1:19443/rest/mempool/info.json
```

## ZMQ

`getzmqnotifications` answers, but no ZMQ publisher can be configured from the command
line; it returns an empty list.

## Methods

146 methods are dispatched (`handleMethodUnlocked` in `src/rpc/server.nim`). 117 of them
are listed by `help`; the other 29 work but are missing from `help` ("no" below).

### Blockchain

| Method | In `help` | Notes |
|---|---|---|
| `getbestblockhash` | yes |  |
| `getblock` | yes |  |
| `getblockchaininfo` | yes |  |
| `getblockcount` | yes |  |
| `getblockfilter` | yes |  |
| `getblockfrompeer` | yes |  |
| `getblockhash` | yes |  |
| `getblockheader` | yes |  |
| `getblockstats` | yes |  |
| `getbodyrepairinfo` | no | nimrod extension, not in Core. |
| `getchainstates` | yes |  |
| `getchaintips` | yes |  |
| `getchaintxstats` | yes |  |
| `getdeploymentinfo` | yes |  |
| `getdifficulty` | yes |  |
| `getsyncstate` | yes | nimrod extension, not in Core. |
| `gettxout` | yes |  |
| `gettxoutproof` | yes |  |
| `gettxoutsetinfo` | yes |  |
| `gettxspendingprevout` | yes |  |
| `invalidateblock` | yes |  |
| `preciousblock` | yes |  |
| `pruneblockchain` | yes |  |
| `reconsiderblock` | yes |  |
| `scanblocks` | yes |  |
| `scantxoutset` | yes |  |
| `verifychain` | yes |  |
| `verifytxoutproof` | yes |  |
| `waitforblock` | yes |  |
| `waitforblockheight` | yes |  |
| `waitfornewblock` | yes |  |

### Control

| Method | In `help` | Notes |
|---|---|---|
| `getmemoryinfo` | yes |  |
| `getrpcinfo` | yes |  |
| `help` | yes |  |
| `logging` | yes |  |
| `stop` | yes |  |
| `uptime` | yes |  |

### Generating

| Method | In `help` | Notes |
|---|---|---|
| `generate` | no | Removed from Core in v0.19; kept for old tooling (regtest only). |
| `generateblock` | no |  |
| `generatetoaddress` | no |  |
| `generatetodescriptor` | no |  |

### Mining

| Method | In `help` | Notes |
|---|---|---|
| `getblocktemplate` | yes |  |
| `getmininginfo` | yes |  |
| `getnetworkhashps` | yes |  |
| `getprioritisedtransactions` | yes |  |
| `prioritisetransaction` | yes |  |
| `submitblock` | yes |  |
| `submitheader` | yes |  |

### Mempool

| Method | In `help` | Notes |
|---|---|---|
| `dumpmempool` | yes |  |
| `getmempoolancestors` | yes |  |
| `getmempooldescendants` | yes |  |
| `getmempoolentry` | yes |  |
| `getmempoolinfo` | yes |  |
| `getorphantxs` | no |  |
| `getrawmempool` | yes |  |
| `importmempool` | yes |  |
| `loadmempool` | yes |  |
| `savemempool` | yes |  |
| `testmempoolaccept` | yes |  |

### Network

| Method | In `help` | Notes |
|---|---|---|
| `addnode` | yes |  |
| `addpeeraddress` | no |  |
| `clearbanned` | yes |  |
| `disconnectnode` | yes |  |
| `getaddednodeinfo` | yes |  |
| `getaddrmaninfo` | yes |  |
| `getconnectioncount` | yes |  |
| `getnettotals` | yes |  |
| `getnetworkinfo` | yes |  |
| `getnodeaddresses` | yes |  |
| `getpeerinfo` | yes |  |
| `getzmqnotifications` | yes |  |
| `listbanned` | yes |  |
| `ping` | yes |  |
| `setban` | yes |  |
| `setnetworkactive` | yes |  |

### Rawtransactions

| Method | In `help` | Notes |
|---|---|---|
| `analyzepsbt` | yes |  |
| `combinepsbt` | yes |  |
| `combinerawtransaction` | yes |  |
| `converttopsbt` | yes |  |
| `createpsbt` | yes |  |
| `createrawtransaction` | yes |  |
| `decodepsbt` | yes |  |
| `decoderawtransaction` | yes |  |
| `decodescript` | yes |  |
| `descriptorprocesspsbt` | yes |  |
| `finalizepsbt` | yes |  |
| `getrawtransaction` | yes |  |
| `joinpsbts` | yes |  |
| `sendrawtransaction` | yes |  |
| `signrawtransactionwithkey` | yes |  |
| `submitpackage` | yes |  |
| `utxoupdatepsbt` | yes |  |

### Util

| Method | In `help` | Notes |
|---|---|---|
| `createmultisig` | yes |  |
| `deriveaddresses` | yes |  |
| `estimaterawfee` | yes |  |
| `estimatesmartfee` | yes |  |
| `getdescriptorinfo` | yes |  |
| `getindexinfo` | yes |  |
| `signmessage` | yes |  |
| `signmessagewithprivkey` | yes |  |
| `validateaddress` | yes |  |
| `verifymessage` | yes |  |

### Wallet

| Method | In `help` | Notes |
|---|---|---|
| `backupwallet` | yes |  |
| `bumpfee` | no |  |
| `createwallet` | yes |  |
| `dumpprivkey` | no | Legacy-wallet call; Core v30+ descriptor wallets no longer have it. |
| `encryptwallet` | no |  |
| `fundrawtransaction` | yes |  |
| `getaddressesbylabel` | no |  |
| `getaddressinfo` | yes |  |
| `getbalance` | yes |  |
| `getbalances` | yes |  |
| `getnewaddress` | yes |  |
| `getpayjoinrequest` | no | nimrod extension (BIP-78 PayJoin). |
| `getrawchangeaddress` | no |  |
| `gettransaction` | no |  |
| `getwalletinfo` | yes |  |
| `importdescriptors` | no |  |
| `importprivkey` | no | Legacy-wallet call; Core v30+ descriptor wallets no longer have it. |
| `listdescriptors` | no |  |
| `listlabels` | no |  |
| `listtransactions` | yes |  |
| `listunspent` | yes |  |
| `listwalletdir` | no |  |
| `listwallets` | yes |  |
| `loadwallet` | yes |  |
| `newpayjoinrequest` | no | nimrod extension (BIP-78 PayJoin). |
| `psbtbumpfee` | no |  |
| `rescanblockchain` | no |  |
| `restorewallet` | yes |  |
| `send` | yes |  |
| `sendpayjoinrequest` | no | nimrod extension (BIP-78 PayJoin). |
| `sendtoaddress` | yes |  |
| `sethdseed` | no | Legacy-wallet call; Core v30+ descriptor wallets no longer have it. |
| `setlabel` | no |  |
| `signrawtransactionwithwallet` | yes |  |
| `startpayjoin` | no | nimrod extension (BIP-78 PayJoin). |
| `unloadwallet` | yes |  |
| `walletcreatefundedpsbt` | yes |  |
| `walletlock` | no |  |
| `walletpassphrase` | no |  |
| `walletpassphrasechange` | no |  |
| `walletprocesspsbt` | yes |  |

### AssumeUTXO

| Method | In `help` | Notes |
|---|---|---|
| `dumptxoutset` | yes |  |
| `loadtxoutset` | yes |  |
| `scrubunspendable` | yes | nimrod extension, not in Core. |
## Known differences from Core

- Named parameters (a JSON object as `params`) are accepted only by `createwallet`,
  `loadwallet`, `unloadwallet`, `importdescriptors`, `listdescriptors`,
  `getaddressinfo`, `getwalletinfo`, `listwallets`, `listwalletdir`, `getbalances`,
  `getnewaddress`, `backupwallet`, `restorewallet` and `send`. Other methods return
  error -32602 for object params. Use positional arrays.
- No `-rpcauth`, no `-rpcallowip`, no `-rpcbind`: the server listens on `127.0.0.1` only.
- 29 working methods are missing from `help` (table above).
- `generate` is still present, though Core removed it.
- Some wallet calls (`importprivkey`, `dumpprivkey`, `sethdseed`) are legacy-wallet calls
  that Core's descriptor-only wallets no longer offer.
- The wallet has not been audited. Do not hold real funds in it.
