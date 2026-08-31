## Dispatcher arity check — Core rpc/util.cpp:644 / IsValidNumArgs (:733).
##
## Core validates argument COUNT centrally before any handler runs, and a
## violation is error -1. nimrod's handlers deliberately skip arity checks
## because they "rely on the dispatcher's arity check" (server.nim, ping) — and
## until 2026-08-31 the dispatcher had no such check, so extra arguments were
## silently ignored. savemempool failed this in 10 of 10 fleet implementations.
##
## These fail at the parent commit: without checkCoreArity the extra-argument
## calls simply succeed.

import unittest2
import std/[json, tables]
import ../src/rpc/server

suite "dispatcher arity (Core IsValidNumArgs parity)":

  test "the arity table is present and derived, not empty":
    ## Guards the whole suite against passing vacuously: every assertion below
    ## is meaningless if the embedded table failed to load.
    check CoreArity.len >= 80
    check CoreArity.hasKey("savemempool")
    check CoreArity.hasKey("clearbanned")

  test "zero-arg methods declare zero arguments (matches Core's help)":
    check CoreArity["savemempool"] == (required: 0, declared: 0)
    check CoreArity["clearbanned"] == (required: 0, declared: 0)

  test "an extra argument is REJECTED with Core's code -1":
    for m in ["savemempool", "clearbanned"]:
      var raised = false
      try:
        checkCoreArity(m, %*["r5-probe-extra-arg"])
      except RpcError as e:
        raised = true
        check e.code == -1          # RpcMiscError, Core's arity failure code
      check raised

  test "CONTROL: the correct zero-arg call is still accepted":
    ## Without this, a dispatcher that rejected everything would pass the test
    ## above. This is the assertion that makes the fix binding rather than
    ## merely loud.
    for m in ["savemempool", "clearbanned"]:
      checkCoreArity(m, %*[])       # must not raise

  test "CONTROL: methods with real arguments keep working at every legal count":
    ## getblockhash takes exactly 1; gettxout takes 2 required, 3 declared.
    checkCoreArity("getblockhash", %*[100000])
    checkCoreArity("gettxout", %*["ab", 0])
    checkCoreArity("gettxout", %*["ab", 0, true])
    var tooMany = false
    try: checkCoreArity("gettxout", %*["ab", 0, true, "x"])
    except RpcError: tooMany = true
    check tooMany
    var tooFew = false
    try: checkCoreArity("gettxout", %*["ab"])
    except RpcError: tooFew = true
    check tooFew

  test "a method ABSENT from the table is not checked (fails OPEN)":
    ## Coverage is 87 of 103. Treating an unknown method as zero-arg would
    ## reject calls Core accepts — worse than the gap being closed.
    check not CoreArity.hasKey("definitely-not-an-rpc-method")
    checkCoreArity("definitely-not-an-rpc-method", %*["a", "b", "c"])

  test "named (object) params are not subject to the positional check":
    checkCoreArity("savemempool", %*{"unexpected": 1})
