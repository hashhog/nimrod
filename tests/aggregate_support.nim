## Support machinery for `tests/test_all.nim`.  Not a test module: the name
## deliberately does NOT match `test_*.nim` so the coverage guard in
## test_all.nim does not demand that it list itself.
##
## test_all.nim MUST import this module FIRST.  Nim runs exit procs
## last-in-first-out, and `unittest2` registers its own exit proc (the one that
## actually runs the collected tests and then prints `[Summary]`) when the
## unittest2 module is initialised.  Registering `reportCoverage` before that
## happens is what puts the coverage lines AFTER the summary instead of before
## a single test has run.

import std/[exitprocs, macros, os, strutils]

type ExcludedTest* = tuple[module: string, reason: string]

var
  covOnDisk*: int              ## number of tests/test_*.nim found on disk
  covIncluded*: int            ## number compiled into this binary
  covExcluded*: seq[ExcludedTest]  ## the rest, with a reason each

proc discoverTestModules*(dir: string): seq[string] {.compileTime.} =
  ## Every `tests/test_*.nim` on disk, module name only, `test_all` excluded.
  ## Used only by the compile-time completeness guard -- the imports themselves
  ## come from the explicit list in test_all.nim so they stay greppable.
  result = @[]
  for line in staticExec("ls -1 -- " & dir).splitLines():
    let f = line.strip()
    if f.startsWith("test_") and f.endsWith(".nim") and f != "test_all.nim":
      result.add f[0 ..< f.len - 4]

macro importTestModules*(dir: static string,
                         names: static openArray[string]): untyped =
  ## Emit one `import "<dir>/<name>"` per entry.  Absolute paths: a relative
  ## path in a macro-generated import has no source file to resolve against.
  result = newStmtList()
  for n in names:
    result.add parseStmt("import \"" & (dir / n) & "\"")

proc reportCoverage() =
  ## Printed after unittest2's `[Summary]`.  The rule this enforces: no total
  ## printed by this binary may quietly exclude tests that ran, and anything
  ## NOT in the run has to be named here with a reason.
  echo ""
  echo "[Coverage] tests/test_*.nim on disk: ", covOnDisk,
       "  compiled in: ", covIncluded,
       "  excluded: ", covExcluded.len
  echo "[Coverage] the [Summary] line above is the complete count for all ",
       covIncluded, " included files -- one framework (unittest2), one counter."
  if covExcluded.len > 0:
    echo "[Coverage] NOT RUN by this binary (", covExcluded.len,
         " files, declared in tests/test_all.nim):"
    for e in covExcluded:
      echo "[Coverage]   ", alignLeft(e.module, 32), " ", e.reason

addExitProc(reportCoverage)
