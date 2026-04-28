"""
Copyright (c) 2023-2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import sys
import unittest


TESTING_MODULES = [
    'fm_core',
    'jwkest',
    'jwkest.jws',
    'oic',
    'oic.exception',
    'oic.oic',
    'oic.oic.message',
    'oic.utils',
    'oic.utils.jwt',
    'oic.utils.keyio',
]

for _mod in TESTING_MODULES:
    if _mod not in sys.modules:
        sys.modules[_mod] = unittest.mock.MagicMock()
