#!/usr/bin/env python3
"""NI-4 reproducer: SIGTERM delivered while the main thread is inside a block
connect must not write spent coins back to disk.

Needs a nimrod binary built with -d:nimrodRaceHooks (the park hook in
src/util/test_park_hook.nim) and a wallet-enabled bitcoind as the oracle.

  1. Core regtest mines 101 blocks; nimrod syncs them over P2P (--connect).
  2. tx1 (Core wallet) is mined in block 102 -> nimrod connects 102 on its
     MAIN thread (P2P), so tx1's outputs sit in nimrod's UTXO cache.
  3. tx2 spends tx1's output; the park hook is armed; Core mines block 103.
     nimrod parks inside connectBlock's cache-apply loop (point
     connect.midcache: the batch is committed, the cache still holds the coin
     103 spends) and writes a marker file.
  4. The harness sends SIGTERM to nimrod and waits for it to exit.
  5. nimrod is restarted with no peers; its tip, chainwork, gettxoutsetinfo
     hash_serialized_3 and gettxout(tx1 spent output, include_mempool=false)
     are compared with Core at the SAME height (recorded as the chain grew).

Verdict CORRUPT if the coin set or chainwork differ from Core's at nimrod's
tip, or the spent coin is present; CLEAN otherwise. Exit 0 clean, 1 corrupt,
2 harness error.

Negative control: --point connect.precommit parks BEFORE the batch commit;
there the cache and disk agree, so even a flush from the signal handler cannot
resurrect anything (expected CLEAN on any build).
"""
import argparse, base64, json, os, shutil, signal, subprocess, sys, time
import urllib.request

def rpc(port, auth, method, params=None, timeout=60):
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body,
                                 headers={"Content-Type": "application/json"})
    tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            out = json.loads(r.read())
    except urllib.error.HTTPError as e:
        out = json.loads(e.read())
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]

def wait_for(pred, timeout, what, step=0.2):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            v = pred()
            if v:
                return v
        except Exception:
            pass
        time.sleep(step)
    raise TimeoutError(what)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nimrod", required=True)
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--point", default="connect.midcache")
    ap.add_argument("--base-port", type=int, default=27100)
    ap.add_argument("--work", required=True)
    ap.add_argument("--park-ms", type=int, default=4000)
    ap.add_argument("--no-signal", action="store_true",
                    help="control: let the park finish, then stop via RPC")
    ap.add_argument("--label", default="")
    a = ap.parse_args()

    B = a.base_port
    core_rpc, core_p2p, nim_rpc, nim_p2p = B, B + 1, B + 2, B + 3
    auth = ("test", "test")
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(a.work)
    arm, marker = f"{a.work}/park.arm", f"{a.work}/park.marker"
    procs = []
    res = {"label": a.label, "point": a.point, "nimrod": a.nimrod}

    def start_nimrod(tag, park, connect):
        env = dict(os.environ)
        env.pop("NIMROD_TEST_PARK_POINT", None)
        if park:
            env.update(NIMROD_TEST_PARK_POINT=a.point, NIMROD_TEST_PARK_ARM=arm,
                       NIMROD_TEST_PARK_MARKER=marker,
                       NIMROD_TEST_PARK_MS=str(a.park_ms))
        logf = open(f"{a.work}/nimrod-{tag}.log", "w")
        p = subprocess.Popen(
            [a.nimrod, "--network=regtest", f"--datadir={a.work}/nim",
             f"--port={nim_p2p}", f"--rpcport={nim_rpc}", "--metricsport=0",
             "--rpcuser=test", "--rpcpassword=test", "--nodnsseed",
             f"--connect={connect}", "--nolisten", "start"],
            stdout=logf, stderr=subprocess.STDOUT, env=env,
            start_new_session=True)
        procs.append(p)
        wait_for(lambda: rpc(nim_rpc, auth, "getblockcount") is not None, 120,
                 "nimrod rpc")
        return p

    core = None
    try:
        os.makedirs(f"{a.work}/core")
        logf = open(f"{a.work}/core.log", "w")
        core = subprocess.Popen(
            [a.bitcoind, "-regtest", f"-datadir={a.work}/core",
             f"-rpcport={core_rpc}", f"-port={core_p2p}", "-listen=1",
             "-bind=127.0.0.1", "-server=1", "-rpcuser=test",
             "-rpcpassword=test", "-fallbackfee=0.0002", "-printtoconsole=0",
             "-dnsseed=0", "-fixedseeds=0", "-connect=0"],
            stdout=logf, stderr=logf, start_new_session=True)
        c = lambda m, *p: rpc(core_rpc, auth, m, list(p))
        wait_for(lambda: c("getblockcount") == 0, 60, "core rpc")
        c("createwallet", "w")
        addr = c("getnewaddress")
        c("generatetoaddress", 101, addr)
        core_at = {}
        def snap():
            h = c("getblockcount")
            core_at[h] = {"hash": c("getbestblockhash"),
                          "utxo": c("gettxoutsetinfo")["hash_serialized_3"],
                          "chainwork": c("getblockchaininfo")["chainwork"]}
        snap()

        nim = start_nimrod("run", park=True, connect=f"127.0.0.1:{core_p2p}")
        n = lambda m, *p: rpc(nim_rpc, auth, m, list(p))
        wait_for(lambda: n("getblockcount") == 101, 180, "nimrod sync 101")

        addr2 = c("getnewaddress")
        tx1 = c("sendtoaddress", addr2, 10)
        c("generatetoaddress", 1, addr)
        snap()
        wait_for(lambda: n("getblockcount") == 102, 60, "nimrod 102")
        vout = next(o["n"] for o in c("decoderawtransaction",
                                       c("gettransaction", tx1)["hex"])["vout"]
                    if o["scriptPubKey"].get("address") == addr2)
        raw = c("createrawtransaction", [{"txid": tx1, "vout": vout}],
                {addr: 9.999})
        signed = c("signrawtransactionwithwallet", raw)["hex"]
        tx2 = c("sendrawtransaction", signed)
        res.update(tx1=tx1, vout=vout, tx2=tx2)

        open(arm, "w").close()
        c("generatetoaddress", 1, addr)
        snap()
        if a.no_signal:
            wait_for(lambda: n("getblockcount") == 103, 60, "nimrod 103")
            res["parked"] = os.path.exists(marker)
            t0 = time.time()
            n("stop")
        else:
            wait_for(lambda: os.path.exists(marker) and
                     open(marker).read().strip(), 30, "park marker")
            mk = open(marker).read().split()
            res["parked"] = {"pid": int(mk[0]), "tid": int(mk[1]),
                             "main_thread": int(mk[0]) == int(mk[1]),
                             "point": mk[2], "block": mk[3]}
            t0 = time.time()
            os.kill(nim.pid, signal.SIGTERM)
        try:
            rc = nim.wait(timeout=90)
        except subprocess.TimeoutExpired:
            res["exit"] = "HUNG (SIGKILL)"
            nim.kill(); nim.wait()
        else:
            res["exit"] = rc
        res["exit_after_s"] = round(time.time() - t0, 2)

        # Restart with no reachable peer: the datadir is judged as SIGTERM left it.
        nim = start_nimrod("restart", park=False, connect=f"127.0.0.1:{nim_p2p + 50}")
        h = n("getblockcount")
        res["nimrod_tip"] = h
        res["nimrod_tiphash_ok"] = n("getbestblockhash") == core_at[h]["hash"]
        nu = n("gettxoutsetinfo")["hash_serialized_3"]
        res["utxo_equal_core"] = nu == core_at[h]["utxo"]
        res["nimrod_utxo"], res["core_utxo"] = nu, core_at[h]["utxo"]
        res["chainwork_equal_core"] = n("getblockchaininfo")["chainwork"] == core_at[h]["chainwork"]
        coin = n("gettxout", tx1, vout, False)
        res["spent_coin_present"] = coin is not None
        res["spent_coin_should_be_present"] = h < 103
        res["core_gettxout_at_103"] = c("gettxout", tx1, vout, False)
        bad = (not res["nimrod_tiphash_ok"] or not res["utxo_equal_core"] or
               not res["chainwork_equal_core"] or
               res["spent_coin_present"] != res["spent_coin_should_be_present"])
        res["verdict"] = "CORRUPT" if bad else "CLEAN"
        n("stop")
        try:
            nim.wait(timeout=60)
        except subprocess.TimeoutExpired:
            nim.kill(); nim.wait()
    except Exception as e:
        res["verdict"] = "ERROR"
        res["error"] = repr(e)
    finally:
        for p in procs:
            if p.poll() is None:
                p.send_signal(signal.SIGKILL); p.wait()
        if core is not None:
            try:
                rpc(core_rpc, auth, "stop")
                core.wait(timeout=60)
            except Exception:
                core.kill(); core.wait()
    print(json.dumps(res, indent=1))
    return {"CLEAN": 0, "CORRUPT": 1}.get(res["verdict"], 2)

if __name__ == "__main__":
    sys.exit(main())
