# Hardening notes

Known weaknesses that are not bugs in a code path today but make one easier to
write. Each entry says what is weak, what guards it now, and what would close it.

## Wallet private keys stay in memory while the wallet is locked

`encryptWallet` (src/wallet/wallet.nim) zeroes the plaintext seed and the
cached encryption key, but not `masterKey` and not the derived account keys
(`accounts[*].externalKeys` / `internalKeys`, each holding its `extKey.key`).
`lockWallet` zeroes the seed, the cached encryption key and `masterKey.key`,
but not the derived account keys. Imported private keys are not scrubbed by
either.

So `Wallet.signTransaction` can still sign while `isLocked` is true. Core
cannot: a locked descriptor wallet holds only encrypted keys, and FillPSBT
gets no private keys from it.

**What guards it now.** Each signing RPC checked so far tests
`isEncrypted and isLocked` itself before it signs (list not proven
exhaustive): `signmessage`, `sendtoaddress`, `send` (returns
`{"psbt", "complete": false}` like Core's FinishTransaction, added for
fingerprint nimrod/rpc/send/missing-wallet-lock-check), `walletprocesspsbt`
with `sign=true`, `signrawtransactionwithwallet`, `bumpfee` and the payjoin
sender. A new signing RPC that forgets the check signs from a locked wallet;
`send` did exactly that until tests/test_cffix_send_lock_check.nim.

**What would close it.** Scrub the derived and imported private keys on
encrypt and on lock (keep public keys, addresses and paths), and re-derive or
decrypt them on unlock, so `signTransaction` fails on its own while locked.
Two things to handle first:

- `lockWallet` already zeroes `masterKey.key`, and `deriveChild` from a zero
  private key never terminates: libsecp rejects every tweak, and the BIP-32
  "try the next index" loop walks the whole index range. After `walletlock`,
  anything that derives a fresh key spins: seen for a `send` that needs a
  change address (`createTransaction` -> `getNewAddress` -> `ensureGap`,
  stuck in `deriveChild` for 10+ minutes before it was stopped);
  `getnewaddress` and `getrawchangeaddress` take the same `ensureGap` path
  (not run). Derivation must refuse a zero or cleared key (`canDeriveKeys`)
  before scrubbing goes further.
- Receive and change addresses past the pre-derived gap need a public-only
  derivation path (account xpubs) to keep working while locked, as Core's
  descriptor wallets do.
