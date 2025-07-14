#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools

from software.authapi.policies import base


def list_rules():
    return itertools.chain(
        base.list_rules(),
    )
