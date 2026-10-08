#!/usr/bin/env python3
"""NI-6 reproducer: an RPC that sends to a peer must not write that peer's
main-loop transport from the RPC thread.

The RPC server runs its own chronos loop on its own thread. `ping`,
`sendrawtransaction`, `submitblock`/`generate*`, `getblockfrompeer`,
`disconnectnode`, `addnode` and `setban` used to call transp.write /
closeWait on peer transports owned by the MAIN thread's loop. chronos
transports are single-loop objects: when the socket is full and the
transport's write queue is empty, write() queues the remainder and calls
resumeWrite -> addWriter2(fd) on the CALLING thread's selector, where the fd
is not registered -> error. The write future fails, but the vector stays
queued with WritePaused still set, so the transport never writes again:
every later message to that peer (from any thread) sits behind it. The peer
is silently wedged until the send-stall disconnect.

Deterministic recipe (no timing luck needed):
  1. nimrod regtest, listening; no outbound peers.
  2. A raw P2P client with a tiny SO_RCVBUF connects and handshakes, then
     STOPS READING. Nothing else writes to it (no other traffic).
  3. RPC `ping` in JSON-RPC batches: each ping is written to the client by
     the RPC thread. They complete synchronously until the kernel buffers
     fill; the first one that does not fit hits the empty-queue path above.
     Batches continue until the node's Send-Q stops growing.
  4. The client resumes reading, drains everything, then sends its own
     `ping` (nonce N) and waits for `pong` N.

Verdict WEDGED if pong N never arrives (or the stream is torn); OK if it
does. Exit 0 OK, 1 WEDGED, 2 harness error.

Run with NIMROD_SEND_STALL_TIMEOUT_MS large (set below) so the stall
disconnect does not masquerade as either verdict.
"""
import argparse, base64, hashlib, json, os, random, re, shutil, signal, socket
import struct, subprocess, sys, time, urllib.request

MAGIC = bytes.fromhex("fabfb5da")  # regtest

def sha256d(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def msg(cmd, payload=b""):
    return (MAGIC + cmd.encode().ljust(12, b"\0") +
            struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload)

def netaddr(port):
    return (struct.pack("<Q", 0) + b"\0" * 10 + b"\xff\xff" +
            socket.inet_aton("127.0.0.1") + struct.pack(">H", port))

def version_payload(port):
    ua = b"/ni6-repro:0.1/"
    return (struct.pack("<iQq", 70016, 0, int(time.time())) + netaddr(port) +
            netaddr(0) + struct.pack("<Q", random.getrandbits(64)) +
            bytes([len(ua)]) + ua + struct.pack("<i", 0) + b"\x00")

class Reader:
    def __init__(self, sock):
        self.s, self.buf, self.torn = sock, b"", False
    def fill(self, timeout):
        self.s.settimeout(timeout)
        try:
            d = self.s.recv(1 << 20)
        except socket.timeout:
            return 0
        if not d:
            raise EOFError("peer closed")
        self.buf += d
        return len(d)
    def next(self):
        if len(self.buf) < 24:
            return None
        if self.buf[:4] != MAGIC:
            self.torn = True
            raise ValueError("stream desync: bad magic at offset")
        n = struct.unpack("<I", self.buf[16:20])[0]
        if len(self.buf) < 24 + n:
            return None
        cmd = self.buf[4:16].rstrip(b"\0").decode()
        pl = self.buf[24:24 + n]
        if sha256d(pl)[:4] != self.buf[20:24]:
            self.torn = True
            raise ValueError("stream desync: bad checksum")
        self.buf = self.buf[24 + n:]
        return cmd, pl

def rpc(port, auth, payload, timeout=120):
    req = urllib.request.Request(f"http://127.0.0.1:{port}/",
                                 data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"})
    tok = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
    req.add_header("Authorization", "Basic " + tok)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())

def sendq(port, peer_port):
    out = subprocess.run(["ss", "-tnH", "state", "established",
                          f"( sport = :{port} and dport = :{peer_port} )"],
                         capture_output=True, text=True).stdout.split()
    return int(out[1]) if len(out) >= 2 else -1

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nimrod", required=True)
    ap.add_argument("--work", required=True)
    ap.add_argument("--base-port", type=int, default=27200)
    ap.add_argument("--batch", type=int, default=1000)
    ap.add_argument("--max-batches", type=int, default=400)
    ap.add_argument("--label", default="")
    a = ap.parse_args()
    rpcp, p2p = a.base_port, a.base_port + 1
    auth = ("test", "test")
    if os.path.exists(a.work):
        shutil.rmtree(a.work)
    os.makedirs(a.work)
    env = dict(os.environ, NIMROD_SEND_STALL_TIMEOUT_MS="600000")
    logf = open(f"{a.work}/nimrod.log", "w")
    node = subprocess.Popen(
        [a.nimrod, "--network=regtest", f"--datadir={a.work}/nim",
         f"--port={p2p}", f"--rpcport={rpcp}", "--metricsport=0",
         "--rpcuser=test", "--rpcpassword=test", "--nodnsseed",
         f"--connect=127.0.0.1:{p2p + 50}", "start"],
        stdout=logf, stderr=subprocess.STDOUT, env=env, start_new_session=True)
    res = {"label": a.label, "nimrod": a.nimrod}
    try:
        for _ in range(300):
            try:
                rpc(rpcp, auth, {"jsonrpc": "1.0", "id": 0,
                                 "method": "getblockcount", "params": []})
                break
            except Exception:
                time.sleep(0.2)
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        s.connect(("127.0.0.1", p2p))
        my_port = s.getsockname()[1]
        s.sendall(msg("version", version_payload(p2p)))
        r = Reader(s)
        got_verack = got_version = False
        t0 = time.time()
        while not (got_verack and got_version) and time.time() - t0 < 20:
            r.fill(1)
            while True:
                m = r.next()
                if m is None:
                    break
                if m[0] == "version":
                    got_version = True
                    s.sendall(msg("verack"))
                elif m[0] == "verack":
                    got_verack = True
        if not (got_verack and got_version):
            raise RuntimeError("handshake failed")
        # Let the post-handshake chatter (sendcmpct, getheaders, ping, ...)
        # arrive, answer nothing, and drain it.
        t0 = time.time()
        while time.time() - t0 < 2:
            r.fill(0.2)
        while r.next() is not None:
            pass
        res["peers_seen_by_node"] = len(rpc(rpcp, auth, {"jsonrpc": "1.0", "id": 0,
                                        "method": "getpeerinfo", "params": []})["result"])

        # STOP READING. Fill the pipe with RPC-thread writes.
        sent_rpc_pings, stagnant, last_q = 0, 0, -1
        for b in range(a.max_batches):
            batch = [{"jsonrpc": "1.0", "id": i, "method": "ping", "params": []}
                     for i in range(a.batch)]
            rpc(rpcp, auth, batch)
            sent_rpc_pings += a.batch
            q = sendq(p2p, my_port)
            stagnant = stagnant + 1 if q == last_q and q > 0 else 0
            last_q = q
            if stagnant >= 3:
                break
        res["rpc_pings_sent"] = sent_rpc_pings
        res["node_sendq_when_full"] = last_q

        # RESUME READING: drain everything the node has for us.
        pings_rx, other = 0, {}
        idle_since = time.time()
        try:
            while time.time() - idle_since < 5:
                if r.fill(0.5):
                    idle_since = time.time()
                while True:
                    m = r.next()
                    if m is None:
                        break
                    if m[0] == "ping":
                        pings_rx += 1
                    else:
                        other[m[0]] = other.get(m[0], 0) + 1
        except ValueError as e:
            res["stream_error"] = str(e)
        res["pings_received"] = pings_rx
        res["other_received"] = other
        res["trailing_partial_bytes"] = len(r.buf)

        # Liveness probe: our own ping must be answered.
        nonce = random.getrandbits(64)
        s.sendall(msg("ping", struct.pack("<Q", nonce)))
        pong = False
        t0 = time.time()
        try:
            while time.time() - t0 < 15 and not pong:
                r.fill(0.5)
                while True:
                    m = r.next()
                    if m is None:
                        break
                    if m[0] == "pong" and struct.unpack("<Q", m[1])[0] == nonce:
                        pong = True
        except (ValueError, EOFError) as e:
            res["probe_error"] = str(e)
        res["pong_after_s"] = round(time.time() - t0, 2) if pong else None
        res["verdict"] = "OK" if pong and not r.torn else "WEDGED"
        s.close()
    except Exception as e:
        res["verdict"] = "ERROR"
        res["error"] = repr(e)
    finally:
        if node.poll() is None:
            node.send_signal(signal.SIGTERM)
            try:
                node.wait(timeout=60)
            except subprocess.TimeoutExpired:
                node.kill(); node.wait()
        log = open(f"{a.work}/nimrod.log", errors="replace").read()
        res["log_offthread_sends"] = len(re.findall(r"P2P transport used off its loop", log))
    print(json.dumps(res, indent=1))
    return {"OK": 0, "WEDGED": 1}.get(res["verdict"], 2)

if __name__ == "__main__":
    sys.exit(main())
