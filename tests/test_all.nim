## Main test runner
## Imports all test modules

import unittest2

import ./test_serialize
import ./test_crypto
import ./test_script
import ./test_consensus

when isMainModule:
  echo "Running all tests..."
