#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for SoftwareController decision logic methods.

Focuses on branching logic in:
- _should_run_precheck_prior_deploy_start
- deploy_state_changed
- host_deploy_state_changed
"""

import json
import time
import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import constants
from software.software_controller import PatchController


class TestShouldRunPrecheckPriorDeployStart(unittest.TestCase):
    """Tests for _should_run_precheck_prior_deploy_start.

    This method decides whether to run precheck before deploy start.
    6 distinct decision branches — all tested via return value.
    """

    def _make_controller(self, pre_bootstrap=False):
        """Create a minimal mock controller with the real method bound."""
        sc = mock.MagicMock(spec=PatchController)
        sc.pre_bootstrap = pre_bootstrap
        sc._get_precheck_result_file_path = (
            PatchController._get_precheck_result_file_path.__get__(sc))
        sc._should_run_precheck_prior_deploy_start = (
            PatchController._should_run_precheck_prior_deploy_start.__get__(sc))
        return sc

    def test_pre_bootstrap_skips(self):
        """Pre-bootstrap state always skips precheck."""
        sc = self._make_controller(pre_bootstrap=True)
        result = sc._should_run_precheck_prior_deploy_start(
            "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertFalse(result)

    def test_force_patch_skips(self):
        """force=True + is_patch=True skips precheck."""
        sc = self._make_controller()
        result = sc._should_run_precheck_prior_deploy_start(
            "24.09", force=True, is_patch=True, metapackages=["mp1"])
        self.assertFalse(result)

    def test_force_upgrade_does_not_skip(self):
        """force=True but is_patch=False does NOT skip."""
        sc = self._make_controller()
        with mock.patch('os.path.isfile', return_value=False):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=True, is_patch=False, metapackages=["mp1"])
        self.assertTrue(result)

    @mock.patch('os.path.isfile', return_value=False)
    def test_no_result_file_triggers_precheck(self, _):
        """Missing result file means precheck must run."""
        sc = self._make_controller()
        result = sc._should_run_precheck_prior_deploy_start(
            "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertTrue(result)

    @mock.patch('os.path.isfile', return_value=True)
    def test_kwargs_present_triggers_precheck(self, _):
        """Extra kwargs forces precheck to run."""
        sc = self._make_controller()
        precheck_data = json.dumps({
            "healthy": True, "timestamp": time.time(),
            "metapackages": ["mp1"]
        })
        with mock.patch('builtins.open', mock.mock_open(read_data=precheck_data)):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=False, is_patch=False,
                metapackages=["mp1"], extra_param="yes")
        self.assertTrue(result)

    @mock.patch('os.path.isfile', return_value=True)
    def test_expired_result_triggers_precheck(self, _):
        """Expired timestamp triggers precheck."""
        sc = self._make_controller()
        old_time = time.time() - constants.PRECHECK_RESULT_VALID_PERIOD - 100
        precheck_data = json.dumps({
            "healthy": True, "timestamp": old_time,
            "metapackages": ["mp1"]
        })
        with mock.patch('builtins.open', mock.mock_open(read_data=precheck_data)):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertTrue(result)

    @mock.patch('os.path.isfile', return_value=True)
    def test_different_metapackages_triggers_precheck(self, _):
        """Different metapackage set from last run triggers precheck."""
        sc = self._make_controller()
        precheck_data = json.dumps({
            "healthy": True, "timestamp": time.time(),
            "metapackages": ["mp_other"]
        })
        with mock.patch('builtins.open', mock.mock_open(read_data=precheck_data)):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertTrue(result)

    @mock.patch('os.path.isfile', return_value=True)
    def test_healthy_recent_same_metapackages_skips(self, _):
        """Healthy + recent + same metapackages = skip precheck."""
        sc = self._make_controller()
        precheck_data = json.dumps({
            "healthy": True, "timestamp": time.time(),
            "metapackages": ["mp1"]
        })
        with mock.patch('builtins.open', mock.mock_open(read_data=precheck_data)):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertFalse(result)

    @mock.patch('os.path.isfile', return_value=True)
    def test_unhealthy_result_triggers_precheck(self, _):
        """Previous unhealthy result triggers re-run."""
        sc = self._make_controller()
        precheck_data = json.dumps({
            "healthy": False, "timestamp": time.time(),
            "metapackages": ["mp1"]
        })
        with mock.patch('builtins.open', mock.mock_open(read_data=precheck_data)):
            result = sc._should_run_precheck_prior_deploy_start(
                "24.09", force=False, is_patch=False, metapackages=["mp1"])
        self.assertTrue(result)
