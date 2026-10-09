#!/usr/bin/env python3
"""NI-8: nimrod vs Bitcoin Core regtest, offline, plus a connect-during-walk.

Mines a short regtest chain on Core (a few spends), lets nimrod sync it over
P2P, and compares gettxoutsetinfo, dumptxoutset, the snapshot file, and the
tip. Then, with the utxo.walk park hook armed, connects one more block while
dumptxoutset and gettxoutsetinfo are inside the walk and checks that the
block lands before the park ends and that the RPC result is the pre-block
snapshot.

Needs a nimrod built with -d:nimrodRaceHooks (installTestParkHook) and a
bitcoind. No peers other than each other; neither dials the public network.

Exit 0 when every compared field matches and both forced connects land
inside --prompt-ms. Exit 1 on a mismatch or a late connect. Exit 2 on a
harness error.
"""
import argparse, base64, hashlib, json, os, shutil, subprocess, sys, threading, time
import urllib.error, urllib.request

def rpc(port, auth, method, params=None, timeout=120):
    body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method,
                       "params": params or []}).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}/", data=body,
                                 headers={"Content-Type": "application/json"})
    tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
    out = json.loads(raw)
    if out.get("error"):
        raise RuntimeError(f"{method}: {out['error']}")
    return out["result"]

def rest_blockhash(port, height, timeout=5):
    url = f"http://127.0.0.1:{port}/rest/blockhashbyheight/{height}.json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return json.loads(r.read()).get("blockhash")
    except urllib.error.HTTPError:
        return None

def wait_for(pred, timeout, what, step=0.05):
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

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def amt(v):
    return f"{float(v):.8f}"

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nimrod", required=True)
    ap.add_argument("--bitcoind", required=True)
    ap.add_argument("--bitcoin-cli", default="")
    ap.add_argument("--work", required=True)
    ap.add_argument("--base-port", type=int, default=27110)
    ap.add_argument("--park-ms", type=int, default=3000)
    ap.add_argument("--prompt-ms", type=int, default=1000,
                    help="a connect during the walk must finish under this")
    a = ap.parse_args()

    B = a.base_port
    core_rpc, core_p2p = B, B + 1
    nim_rpc, nim_p2p, nim_rest = B + 2, B + 3, B + 4
    auth = ("test", "test")
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(a.work)
    arm = os.path.join(a.work, "park.arm")
    marker = os.path.join(a.work, "park.marker")
    procs = []
    mismatches = []

    def differ(field, core_v, nim_v):
        if core_v != nim_v:
            mismatches.append((field, core_v, nim_v))
            print(f"MISMATCH {field}: core={core_v!r} nimrod={nim_v!r}",
                  flush=True)
        else:
            print(f"match {field}: {core_v!r}", flush=True)

    def start_core():
        os.makedirs(f"{a.work}/core")
        logf = open(f"{a.work}/core.log", "w")
        p = subprocess.Popen(
            [a.bitcoind, "-regtest", f"-datadir={a.work}/core",
             f"-rpcport={core_rpc}", f"-port={core_p2p}",
             "-listen=1", "-bind=127.0.0.1", "-server=1",
             "-rpcuser=test", "-rpcpassword=test", "-fallbackfee=0.0002",
             "-dnsseed=0", "-fixedseeds=0", "-connect=0",
             "-printtoconsole=0"],
            stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
        procs.append(p)
        return p

    def start_nimrod():
        os.makedirs(f"{a.work}/nim", exist_ok=True)
        env = dict(os.environ)
        env.update(NIMROD_TEST_PARK_POINT="utxo.walk",
                   NIMROD_TEST_PARK_ARM=arm,
                   NIMROD_TEST_PARK_MARKER=marker,
                   NIMROD_TEST_PARK_MS=str(a.park_ms))
        logf = open(f"{a.work}/nimrod.log", "w")
        p = subprocess.Popen(
            [a.nimrod, "--network=regtest", f"--datadir={a.work}/nim",
             f"--port={nim_p2p}", f"--rpcport={nim_rpc}",
             "--metricsport=0", "--rpcuser=test", "--rpcpassword=test",
             "--nodnsseed", f"--connect=127.0.0.1:{core_p2p}", "--nolisten",
             "--rest", f"--restport={nim_rest}", "start"],
            stdout=logf, stderr=subprocess.STDOUT, env=env,
            start_new_session=True)
        procs.append(p)
        return p

    def c(method, *params, timeout=120):
        return rpc(core_rpc, auth, method, list(params), timeout=timeout)

    def n(method, *params, timeout=180):
        return rpc(nim_rpc, auth, method, list(params), timeout=timeout)

    core = nim = None
    try:
        core = start_core()
        wait_for(lambda: c("getblockcount") == 0, 60, "core rpc")
        c("createwallet", "w")
        addr = c("getnewaddress")
        c("generatetoaddress", 101, addr)
        for i in range(3):
            c("sendtoaddress", addr, 0.1)
            c("generatetoaddress", 1, addr)
        c("generatetoaddress", 10, addr)
        height = c("getblockcount")
        if height < 110:
            raise RuntimeError(f"chain too short: {height}")
        print(f"core height {height}", flush=True)

        nim = start_nimrod()
        wait_for(lambda: n("getblockcount") == height, 180, "nimrod sync")
        print("nimrod synced", flush=True)

        # --- field comparison at the same tip ---
        cg = c("gettxoutsetinfo")
        ng = n("gettxoutsetinfo")
        for k in ("height", "bestblock", "txouts", "bogosize",
                  "hash_serialized_3", "transactions"):
            differ("gettxoutsetinfo." + k, cg[k], ng[k])
        differ("gettxoutsetinfo.total_amount", amt(cg["total_amount"]),
               amt(ng["total_amount"]))
        differ("gettxoutsetinfo.disk_size", cg.get("disk_size"),
               ng.get("disk_size"))
        cm = c("gettxoutsetinfo", "muhash")
        nm = n("gettxoutsetinfo", "muhash")
        differ("gettxoutsetinfo.muhash", cm.get("muhash"), nm.get("muhash"))
        differ("tip.count", c("getblockcount"), n("getblockcount"))
        differ("tip.hash", c("getbestblockhash"), n("getbestblockhash"))

        cpath = os.path.join(a.work, "core.dat")
        npath = os.path.join(a.work, "nim.dat")
        # Core v31 requires the type argument; "" is rejected with -8.
        cd = c("dumptxoutset", cpath, "latest")
        nd = n("dumptxoutset", npath, "latest")
        for k in ("coins_written", "base_hash", "base_height",
                  "txoutset_hash", "nchaintx"):
            differ("dumptxoutset." + k, cd[k], nd[k])
        differ("snapshot.sha256", sha256_file(cpath), sha256_file(npath))

        pre_dump = {k: nd[k] for k in
                    ("coins_written", "base_hash", "base_height",
                     "txoutset_hash", "nchaintx")}
        pre_height = int(ng["height"])

        # --- dumptxoutset walk vs a P2P connect ---
        # The RPC thread is inside the walk, so the new block is observed
        # on REST (its own thread), which takes the chain lock per request.
        if os.path.exists(marker):
            os.remove(marker)
        open(arm, "w").close()
        dump_box = {}

        def run_dump():
            t0 = time.perf_counter()
            try:
                dump_box["res"] = n("dumptxoutset",
                                    os.path.join(a.work, "nim-during.dat"),
                                    "latest")
            except Exception as e:
                dump_box["err"] = str(e)
            dump_box["ms"] = (time.perf_counter() - t0) * 1000.0

        th = threading.Thread(target=run_dump)
        th.start()
        wait_for(lambda: os.path.exists(marker), 30, "dumptxoutset park")
        t0 = time.perf_counter()
        c("generatetoaddress", 1, addr)
        got = wait_for(
            lambda: rest_blockhash(nim_rest, pre_height + 1),
            30, "REST saw the block connected during dumptxoutset")
        rest_ms = (time.perf_counter() - t0) * 1000.0
        print(f"dumptxoutset REST connect ms={rest_ms:.1f} hash={got}",
              flush=True)
        th.join(timeout=a.park_ms / 1000.0 + 60)
        if "err" in dump_box:
            raise RuntimeError(dump_box["err"])
        res = dump_box["res"]
        print(f"dumptxoutset rpc ms={dump_box['ms']:.1f}", flush=True)
        for k, v in pre_dump.items():
            differ("during-dump." + k, v, res[k])
        # Tip has moved; the dump must still describe the pre-block set.
        after = n("getblockcount")
        differ("during-dump.tip_is_next", pre_height + 1, after)
        if rest_ms >= a.prompt_ms:
            mismatches.append(("during-dump.rest_ms", f"<{a.prompt_ms}",
                               round(rest_ms, 1)))
            print(f"MISMATCH during-dump.rest_ms: limit<{a.prompt_ms} "
                  f"nimrod={rest_ms:.1f}", flush=True)

        # --- gettxoutsetinfo walk vs a P2P connect ---
        # Single-request gettxoutsetinfo walks off the RPC thread, so a
        # second RPC can observe the tip while the walk is parked.
        # Capture the pre-image BEFORE arming: that call itself walks.
        pre_h2 = n("getblockcount")
        pre_info2 = n("gettxoutsetinfo")
        if os.path.exists(marker):
            os.remove(marker)
        open(arm, "w").close()
        info_box = {}

        def run_info():
            t0 = time.perf_counter()
            try:
                info_box["res"] = n("gettxoutsetinfo")
            except Exception as e:
                info_box["err"] = str(e)
            info_box["ms"] = (time.perf_counter() - t0) * 1000.0

        th = threading.Thread(target=run_info)
        th.start()
        wait_for(lambda: os.path.exists(marker), 30, "gettxoutsetinfo park")
        if not th.is_alive():
            raise RuntimeError("gettxoutsetinfo returned before the park")
        t0 = time.perf_counter()
        probe = n("getblockcount")
        probe_ms = (time.perf_counter() - t0) * 1000.0
        print(f"gettxoutsetinfo probe getblockcount={probe} "
              f"ms={probe_ms:.1f}", flush=True)
        t1 = time.perf_counter()
        c("generatetoaddress", 1, addr)
        wait_for(lambda: n("getblockcount") == pre_h2 + 1, 30,
                 "getblockcount advanced during gettxoutsetinfo")
        conn_ms = (time.perf_counter() - t1) * 1000.0
        print(f"gettxoutsetinfo connect ms={conn_ms:.1f}", flush=True)
        th.join(timeout=a.park_ms / 1000.0 + 60)
        if "err" in info_box:
            raise RuntimeError(info_box["err"])
        ires = info_box["res"]
        print(f"gettxoutsetinfo rpc ms={info_box['ms']:.1f}", flush=True)
        if info_box["ms"] < a.park_ms * 0.5:
            raise RuntimeError(
                "gettxoutsetinfo finished before the park "
                f"({info_box['ms']:.0f} ms)")
        for k in ("height", "bestblock", "txouts", "hash_serialized_3"):
            differ("during-info." + k, pre_info2[k], ires[k])
        differ("during-info.total_amount", amt(pre_info2["total_amount"]),
               amt(ires["total_amount"]))
        differ("during-info.tip_is_next", pre_h2 + 1, n("getblockcount"))
        if probe_ms >= a.prompt_ms:
            mismatches.append(("during-info.probe_ms", f"<{a.prompt_ms}",
                               round(probe_ms, 1)))
        if conn_ms >= a.prompt_ms:
            mismatches.append(("during-info.connect_ms", f"<{a.prompt_ms}",
                               round(conn_ms, 1)))
            print(f"MISMATCH during-info.connect_ms: limit<{a.prompt_ms} "
                  f"nimrod={conn_ms:.1f}", flush=True)

        print("---", flush=True)
        if mismatches:
            print(f"{len(mismatches)} mismatch(es)", flush=True)
            return 1
        print("all compared fields match; connects landed during the walks",
              flush=True)
        return 0
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"HARNESS ERROR: {e}", file=sys.stderr)
        sys.exit(2)
