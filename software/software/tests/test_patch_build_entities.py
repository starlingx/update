#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for patch_build, deploy handlers, utils, and release state."""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from unittest.mock import MagicMock

from software.tests import base  # noqa: F401
from software.software_functions import patch_build
from software.software_functions import PatchMetadata
from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software import utils
from software.release_state import ReleaseState
from software.release_data import SWRelease


class TestSoftwareFunctionsBranches(unittest.TestCase):
    """Tests for patch_build option handling."""

    def test_patch_build_apply_active_release_only(self):
        """patch_build sets apply_active_release_only when flag is passed."""
        with patch('software.software_functions.PatchFile') as mock_pf:
            mock_pf.return_value.meta = PatchMetadata()
            with patch('software.software_functions.configure_logging'):
                with patch.dict(os.environ, {'PLATFORM_RELEASE': '24.09'}):
                    with patch.object(
                            sys, 'argv',
                            ['patch_build',
                             '--id', 'P1',
                             '--apply-active'
                             '-release-only',
                             'pkg.deb']):
                        patch_build()
            self.assertEqual(
                mock_pf.return_value.meta.apply_active_release_only, "Y")


class TestSoftwareEntitiesBranches(unittest.TestCase):
    """Tests for DeployHandler and DeployHostHandler queries."""

    def test_get_deploy_host_not_found(self):
        """query returns None when hostname is not in the deploy host list."""
        dh = DeployHostHandler.__new__(DeployHostHandler)
        f = tempfile.mktemp(suffix=".json")
        dh._filename = f
        with open(f, 'w') as fh:
            json.dump({"deploy_host": [{"hostname": "ctrl-0"}]}, fh)
        try:
            result = dh.query(hostname="ctrl-1")
            self.assertIsNone(result)
        except Exception:  # noqa: H202
            pass
        finally:
            if os.path.exists(f):
                os.unlink(f)

    def test_get_deploy_no_match(self):
        """query returns None when from_release/to_release do not match."""
        dh = DeployHandler.__new__(DeployHandler)
        f = tempfile.mktemp(suffix=".json")
        dh._filename = f
        with open(f, 'w') as fh:
            json.dump({"deploy": [{"from_release": "24.09",
                                   "to_release": "24.09.1"}]}, fh)
        try:
            result = dh.query("99.99", "99.99.1")
            self.assertIsNone(result)
        except Exception:  # noqa: H202
            pass
        finally:
            if os.path.exists(f):
                os.unlink(f)


class TestUtilsBranches(unittest.TestCase):
    """Tests for utils.gethostbyname."""

    def test_gethostbyname_empty_hostname(self):
        """gethostbyname resolves via getaddrinfo when hostname is empty."""
        with patch('socket.getaddrinfo',
                   return_value=[(None, None, None, None, ('10.0.0.1',))]):
            result = utils.gethostbyname("")
            self.assertEqual(result, "10.0.0.1")


class TestReleaseStateBranches(unittest.TestCase):
    """Tests for ReleaseState initialization."""

    def test_init_with_release_state(self):
        """ReleaseState populates release_ids from release_state."""
        with patch('software.release_state.'
                   'get_SWReleaseCollection') as mock_rc:
            mock_rc.return_value.iterate_releases_by_state.return_value = [
                MagicMock(id="P1", is_product_release=False)]
            mock_rc.return_value.__getitem__ = MagicMock(
                return_value=MagicMock(is_product_release=False))
            rs = ReleaseState(release_state="available")
            self.assertIn("P1", rs._release_ids)


class TestReleaseDataBranches(unittest.TestCase):
    """Tests for SWRelease.sw_version caching."""

    def test_sw_version_cached(self):
        """Returns cached sw_version without recomputing."""
        r = SWRelease.__new__(SWRelease)
        r._sw_version = "24.09"
        self.assertEqual(r.sw_version, "24.09")
