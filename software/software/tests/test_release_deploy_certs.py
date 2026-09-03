#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for release_state.py,
deploy_utils.py, certificates.py.
"""

import unittest
from unittest import mock

from software.tests import base  # noqa: F401
from software import states
from software.exceptions import ReleaseNotFound
from software.release_state import ReleaseState
from software.deploy_utils import get_etc_backup_path
from software.deploy_utils import backup_etc
from software.certificates import dev_certificate
from software.certificates import formal_certificate


class TestReleaseStateInit(unittest.TestCase):
    """Tests for ReleaseState.__init__."""

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_with_release_ids(self, mock_coll):
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(return_value=mock_rel)
        rs = ReleaseState(release_ids=["rel-1", "rel-2"])
        self.assertEqual(rs._release_ids, ["rel-1", "rel-2"])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_with_not_found(self, mock_coll):
        mock_coll.return_value.__getitem__ = mock.Mock(return_value=None)
        with self.assertRaises(ReleaseNotFound):
            ReleaseState(release_ids=["bad-rel"])

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_init_with_release_state(self, mock_coll):
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.id = "rel-1"
        mock_rel.is_product_release = False
        mock_coll.return_value.iterate_releases_by_state.return_value = [
            mock_rel]
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock.Mock(is_product_release=False))
        rs = ReleaseState(release_state=states.AVAILABLE)
        self.assertEqual(rs._release_ids, ["rel-1"])


class TestReleaseStateRegister(unittest.TestCase):
    """Tests for register_event_listener."""

    def setUp(self):
        ReleaseState._callbacks = []

    def test_register(self):

        def callback(_state):
            pass
        ReleaseState.register_event_listener(callback)
        self.assertIn(callback, ReleaseState._callbacks)

    def test_register_none(self):
        ReleaseState.register_event_listener(None)
        self.assertEqual(len(ReleaseState._callbacks), 0)

    def test_register_duplicate(self):

        def callback(_state):
            pass
        ReleaseState.register_event_listener(callback)
        ReleaseState.register_event_listener(callback)
        self.assertEqual(ReleaseState._callbacks.count(callback), 1)


class TestReleaseStateCheckTransition(unittest.TestCase):
    """Tests for check_transition."""

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_valid_transition(self, mock_coll):
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.state = states.AVAILABLE
        mock_coll.return_value.__getitem__ = mock.Mock(return_value=mock_rel)
        rs = ReleaseState(release_ids=["rel-1"])
        self.assertTrue(rs.check_transition(states.DEPLOYING))

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_invalid_transition(self, mock_coll):
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.state = states.AVAILABLE
        mock_coll.return_value.__getitem__ = mock.Mock(return_value=mock_rel)
        rs = ReleaseState(release_ids=["rel-1"])
        self.assertFalse(rs.check_transition(states.DEPLOYED))


class TestReleaseStateMajorRelease(unittest.TestCase):
    """Tests for is_major_release_deployment."""

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_ga_release(self, mock_coll):
        mock_rel_init = mock.Mock()
        mock_rel_init.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock_rel_init)
        rs = ReleaseState(release_ids=["rel-1"])
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = True
        mock_rel.prepatched_iso = False
        mock_coll.return_value.get_release_by_id.return_value = mock_rel
        self.assertTrue(rs.is_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_prepatched_iso(self, mock_coll):
        mock_rel_init = mock.Mock()
        mock_rel_init.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock_rel_init)
        rs = ReleaseState(release_ids=["rel-1"])
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = False
        mock_rel.prepatched_iso = True
        mock_coll.return_value.get_release_by_id.return_value = mock_rel
        self.assertTrue(rs.is_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_not_major(self, mock_coll):
        mock_rel_init = mock.Mock()
        mock_rel_init.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock_rel_init)
        rs = ReleaseState(release_ids=["rel-1"])
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.is_ga_release = False
        mock_rel.prepatched_iso = False
        mock_coll.return_value.get_release_by_id.return_value = mock_rel
        self.assertFalse(rs.is_major_release_deployment())


class TestReleaseStatePatchedMajor(unittest.TestCase):
    """Tests for is_patched_major_release_deployment."""

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_patched(self, mock_coll):
        mock_rel_init = mock.Mock()
        mock_rel_init.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock_rel_init)
        rs = ReleaseState(release_ids=["rel-1"])
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.prepatched_iso = True
        mock_coll.return_value.get_release_by_id.return_value = mock_rel
        self.assertTrue(rs.is_patched_major_release_deployment())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_not_patched(self, mock_coll):
        mock_rel_init = mock.Mock()
        mock_rel_init.is_product_release = False
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock_rel_init)
        rs = ReleaseState(release_ids=["rel-1"])
        mock_rel = mock.Mock()
        mock_rel.is_product_release = False
        mock_rel.prepatched_iso = False
        mock_coll.return_value.get_release_by_id.return_value = mock_rel
        self.assertFalse(rs.is_patched_major_release_deployment())


class TestReleaseStateHelpers(unittest.TestCase):
    """Tests for has_release_id, get_release_ids, event methods."""

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_has_release_id(self, mock_coll):
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock.Mock(is_product_release=False))
        rs = ReleaseState(release_ids=["rel-1"])
        self.assertTrue(rs.has_release_id())

    @mock.patch('software.release_state.get_SWReleaseCollection')
    def test_get_release_ids(self, mock_coll):
        mock_coll.return_value.__getitem__ = mock.Mock(
            return_value=mock.Mock(is_product_release=False))
        rs = ReleaseState(release_ids=["rel-1"])
        self.assertEqual(rs.get_release_ids(), ["rel-1"])


class TestDeployUtils(unittest.TestCase):
    """Tests for deploy_utils.py."""

    def test_get_etc_backup_path_with_commit(self):
        result = get_etc_backup_path("abc123")
        self.assertIn("abc123", result)

    def test_get_etc_backup_path_without_commit(self):
        result = get_etc_backup_path()
        self.assertIn("*", result)

    @mock.patch('software.deploy_utils.delete_etc_backup')
    @mock.patch('shutil.copytree', side_effect=Exception("copy failed"))
    @mock.patch('os.makedirs')
    @mock.patch('os.path.exists', return_value=False)
    def test_backup_etc_failure(
            self,
            _mock_exists,
            _mock_makedirs,
            _mock_copy,
            _mock_del):
        with self.assertRaises(Exception):  # noqa: H202
            backup_etc("commit1")


class TestCertificates(unittest.TestCase):
    """Tests for certificates.py."""

    def test_dev_certificate_exists(self):
        self.assertIsInstance(dev_certificate, bytes)
        self.assertIn(b"BEGIN CERTIFICATE", dev_certificate)

    def test_formal_certificate_exists(self):
        self.assertIsInstance(formal_certificate, bytes)
        self.assertIn(b"BEGIN CERTIFICATE", formal_certificate)
