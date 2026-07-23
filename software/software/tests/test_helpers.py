#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Shared test helpers for software controller tests."""

import threading
from unittest.mock import MagicMock
from software.software_controller import PatchController


def create_software_controller(**extra_attrs):
    """Create a MagicMock PatchController with common attrs.

    Args:
        **extra_attrs: Additional attributes to set on the
            mock controller instance.

    Returns:
        A MagicMock spec'd to PatchController.
    """
    controller = MagicMock(spec=PatchController)
    controller.interim_state = {}
    controller.pre_bootstrap = False
    controller.install_local = False
    controller.port = 5497
    controller.socket_lock = threading.RLock()
    controller.sock_out = MagicMock()
    controller.base_pkgdata = MagicMock()
    for attr, value in extra_attrs.items():
        setattr(controller, attr, value)
    return controller
