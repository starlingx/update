#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import MagicMock
from unittest.mock import patch
import tempfile
import os
import unittest
from software.tests import base  # noqa: F401
from software.deploy_state import DeployState
from software.deploy_state import DEPLOY_STATES
from software.exceptions import InvalidOperation
from software.software_functions import PatchMetadata
from software.software_functions import ReleaseData
from software.software_functions import BasePackageData
from software.software_functions import deploy_host_validations
from software.exceptions import SoftwareServiceError
from software.software_functions import validate_host_deploy_order
from software.software_functions import get_metadata_files
from software.software_functions import create_deploy_hosts
from software.software_functions import mount_remote_directory


class TestDeployStateTransform(unittest.TestCase):
    @patch('software.deploy_state.get_instance')
    def test_check_transition_valid(self, mock_db):
        ds = DeployState()
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': DEPLOY_STATES.START_DONE.value}
        ]
        result = ds.check_transition(DEPLOY_STATES.HOST)
        self.assertTrue(result)

    @patch('software.deploy_state.get_instance')
    def test_check_transition_invalid(self, mock_db):
        ds = DeployState()
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': DEPLOY_STATES.START_DONE.value}
        ]
        result = ds.check_transition(DEPLOY_STATES.COMPLETED)
        self.assertFalse(result)

    @patch('software.deploy_state.get_instance')
    def test_transform_invalid_raises(self, mock_db):
        ds = DeployState()
        mock_db.return_value.get_deploy_all.return_value = [
            {'state': DEPLOY_STATES.START_DONE.value}
        ]
        with self.assertRaises(InvalidOperation):
            ds.transform(DEPLOY_STATES.COMPLETED)


class TestPatchMetadata(unittest.TestCase):
    def test_gen_xml(self):
        pm = PatchMetadata()
        pm.id = 'PATCH_001'
        pm.sw_version = '24.09'
        pm.summary = 'Test patch'
        pm.description = 'Desc'
        pm.status = 'REL'
        pm.reboot_required = 'Y'
        pm.requires = ['PATCH_000']
        pm.contents = {'pkg1.rpm': True}
        with tempfile.NamedTemporaryFile(suffix='.xml', delete=False) as f:
            fname = f.name
        try:
            pm.gen_xml(fname)
            self.assertTrue(os.path.exists(fname))
            with open(fname) as f:
                content = f.read()
            self.assertIn('PATCH_001', content)
        finally:
            os.unlink(fname)

    def test_add_rpm(self):
        pm = PatchMetadata()
        pm.add_rpm('/path/to/pkg.rpm')
        self.assertIn('pkg.rpm', pm.contents)


class TestReleaseDataQueryLine(unittest.TestCase):
    def test_query_none_index(self):
        rd = ReleaseData()
        self.assertIsNone(rd.query_line('r1', None))

    def test_query_contents(self):
        rd = ReleaseData()
        rd.contents = {'r1': {'pkg': True}}
        result = rd.query_line('r1', 'contents')
        self.assertEqual(result, {'pkg': True})

    def test_query_missing_key(self):
        rd = ReleaseData()
        rd.metadata = {'r1': {'summary': 'test'}}
        self.assertIsNone(rd.query_line('r1', 'missing'))

    def test_query_existing_key(self):
        rd = ReleaseData()
        rd.metadata = {'r1': {'summary': 'test'}}
        self.assertEqual(rd.query_line('r1', 'summary'), 'test')


class TestBasePackageData(unittest.TestCase):
    @patch('software.software_functions.os.path.exists', return_value=False)
    def test_loaddirs_no_base_dir(self, _mock_exists):
        bpd = BasePackageData()
        self.assertEqual(bpd.pkgs, {})

    def test_check_release(self):
        with patch(
                'software.software_functions'
                '.os.path.exists',
                return_value=False):
            bpd = BasePackageData()
        bpd.pkgs = {'24.09': {}}
        self.assertTrue(bpd.check_release('24.09'))
        self.assertFalse(bpd.check_release('25.03'))

    def test_find_version_missing(self):
        with patch(
                'software.software_functions'
                '.os.path.exists',
                return_value=False):
            bpd = BasePackageData()
        self.assertIsNone(bpd.find_version('24.09', 'pkg', 'x86'))


class TestDeployHostValidations(unittest.TestCase):

    @patch('software.software_functions.is_host_locked_and_online',
           return_value=False)
    @patch('software.software_functions.validate_host_deploy_order')
    @patch('software.software_functions.get_instance')
    @patch('software.software_functions.get_system_info',
           return_value=('sys', 'duplex'))
    def test_duplex_not_locked(
            self,
            _mock_sys,
            mock_db,
            _mock_order,
            _mock_locked):
        mock_db.return_value.get_current_deploy.return_value = {
            'reboot_required': True
        }
        with self.assertRaises(SoftwareServiceError):
            deploy_host_validations('worker-0', is_major_release=True)


class TestValidateHostDeployOrder(unittest.TestCase):

    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_wrong_order(self, mock_db, mock_hosts):
        mock_hosts.return_value = [
            MagicMock(personality='worker', hostname='worker-0'),
        ]
        mock_db.return_value.get_deploy_host.return_value = []
        with self.assertRaises(SoftwareServiceError):
            validate_host_deploy_order('controller-0', is_major_release=True)

    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_all_deployed(self, mock_db, mock_hosts):
        mock_hosts.return_value = []
        mock_db.return_value.get_deploy_host.return_value = [
            {'hostname': 'controller-1', 'state': 'deployed'},
            {'hostname': 'controller-0', 'state': 'deployed'},
        ]
        with self.assertRaises(SoftwareServiceError):
            validate_host_deploy_order('controller-0', is_major_release=True)


class TestGetMetadataFiles(unittest.TestCase):
    @patch('software.software_functions.os.listdir')
    def test_get_metadata_files(self, mock_listdir):
        mock_listdir.return_value = ['test-metadata.xml', 'other.txt']
        result = get_metadata_files('/dir')
        self.assertEqual(len(result), 1)


class TestCreateDeployHosts(unittest.TestCase):
    @patch('software.software_functions.get_ihost_list')
    @patch('software.software_functions.get_instance')
    def test_create_all(self, mock_db, mock_hosts):
        mock_hosts.return_value = [
            MagicMock(hostname='ctrl-0'),
            MagicMock(hostname='worker-0'),
        ]
        create_deploy_hosts()
        self.assertEqual(mock_db.return_value.create_deploy_host.call_count, 2)


class TestMountRemoteDirectory(unittest.TestCase):
    @patch('software.software_functions.subprocess.check_call')
    @patch('software.software_functions.os.mkdir')
    @patch('software.software_functions.os.path.isdir', return_value=False)
    def test_mount_and_unmount(self, _mock_isdir, _mock_mkdir, mock_call):
        with mount_remote_directory('host:/remote', '/tmp/test_local'):
            pass
        self.assertEqual(mock_call.call_count, 2)
