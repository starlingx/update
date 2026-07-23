#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for state decorators, utils edge cases, and ReleaseState init.
"""

import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base  # noqa: F401
from software.deploy_state import require_deploy_state
from software.deploy_state import DEPLOY_STATES
from software import utils
from software.release_state import ReleaseState


class TestDeployStateFalseBranches(unittest.TestCase):
    """Tests for require_deploy_state decorator."""

    def test_require_deploy_state_passes(self):
        """Decorator passes when current state matches required state.
so decorator passes.
"""

        @require_deploy_state([DEPLOY_STATES.START_DONE],
                              "bad state {state}")
        def dummy(_self_arg):
            return "ok"
        with patch('software.deploy_state.DeployState.get_deploy_state',
                   return_value=DEPLOY_STATES.START_DONE):
            self.assertEqual(dummy(None), "ok")


class TestUtilsFalseBranch(unittest.TestCase):
    """Tests for gethostbyname edge cases."""

    def test_gethostbyname_empty(self):
        """Empty hostname still resolves via getaddrinfo."""
        with patch('socket.getaddrinfo',
                   return_value=[(None, None, None, None, ('10.0.0.1',))]):
            result = utils.gethostbyname("")
            self.assertEqual(result, "10.0.0.1")


class TestReleaseStateFalseBranch(unittest.TestCase):
    """Tests for ReleaseState initialization."""

    def test_init_by_release_state(self):
        """Initializes using release_state parameter instead of release_ids."""
        with patch('software.release_state.'
                   'get_SWReleaseCollection') as mock_rc:
            mock_rc.return_value.iterate_releases_by_state.return_value = [
                MagicMock(id="P1", is_product_release=False)]
            mock_rc.return_value.__getitem__ = MagicMock(
                return_value=MagicMock(is_product_release=False))
            rs = ReleaseState(release_state="available")
            self.assertIn("P1", rs._release_ids)
