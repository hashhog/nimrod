# Test builds compile chainstate's named race points (no-ops unless a test
# installs chainstate.raceHook) so tests/test_chain_lock_race.nim can force a
# thread interleaving deterministically. Production builds never define it.
switch("define", "nimrodRaceHooks")
