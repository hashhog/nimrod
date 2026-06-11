#!/usr/bin/env python3
"""Differential driver for the nimrod `checkheader` op (Phase B header-level
reject bar). Pipes each vector in checkheader-vectors.json to the nimrod shim
and compares the decision + bip22 reason token against Core's expected verdict.

Usage:  python3 checkheader_prove_nimrod.py [path/to/checkheader-vectors.json] [shim_path]
"""
import json, os, subprocess, sys

SHIM = sys.argv[2] if len(sys.argv) > 2 else "/tmp/nimrod-shim"
CORPUS = sys.argv[1] if len(sys.argv) > 1 else "/tmp/checkheader-vectors.json"
corpus = json.load(open(CORPUS))

proc = subprocess.Popen([SHIM], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

def call(req):
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())

passed = failed = 0
rows = []
for v in corpus["vectors"]:
    resp = call(v["request"])
    exp = v["expected"]
    got_accept = resp.get("accept")
    got_reason = resp.get("reason", "")
    got_err = resp.get("error", "")
    ok_accept = (got_accept == exp["accept"])
    ok_reason = True
    if not exp["accept"]:
        ok_reason = (got_reason == exp["reason"])
    ok = ok_accept and ok_reason and not got_err
    rows.append((v["name"], v["class"], exp["accept"], got_accept, exp["reason"], got_reason or got_err, ok))
    if ok: passed += 1
    else: failed += 1

proc.stdin.close()
proc.wait()

w = max(len(r[0]) for r in rows)
print(f"{'VECTOR'.ljust(w)}  {'CLASS':<20} {'EXP':<6} {'GOT':<6} {'EXP_REASON':<26} {'GOT_REASON':<26} OK")
for name, klass, ea, ga, er, gr, ok in rows:
    ea_s = "accept" if ea else "reject"
    ga_s = "accept" if ga is True else ("reject" if ga is False else str(ga))
    print(f"{name.ljust(w)}  {klass:<20} {ea_s:<6} {ga_s:<6} {er:<26} {gr:<26} {'PASS' if ok else 'FAIL <<<'}")
print(f"\n{passed}/{passed+failed} PASS")
sys.exit(0 if failed==0 else 1)
