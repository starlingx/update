"""
Copyright (c) 2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import sys
import unittest.mock

# fm_core is a C extension only available on the target system.
# Mock it so test modules can import patch_alarm_manager.
TESTING_MODULES = [
    'fm_core',
]

for _mod in TESTING_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = unittest.mock.MagicMock()
