# begin Nimble config (version 2)
--noNimblePath
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config

# Disable GC-safety warnings for async code
switch("warning", "GcUnsafe2:off")
