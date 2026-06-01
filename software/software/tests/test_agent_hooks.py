#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
import logging
from unittest import mock
from unittest import TestCase

# Patch basicConfig before importing agent_hooks to prevent it from
# trying to open /var/log/software.log at module load time.
with mock.patch.object(logging, 'basicConfig'):
    from software.agent_hooks import KubeletUpgradeHook


class TestAgentHooks(TestCase):

    def setUp(self):
        self.attrs = {
            "major_release": "FAKE_MAJOR_RELEASE",
            "from_release": "STX12",
            "to_release": "STX13",
            "hook_action": "FAKE_ACTION",
            "additional_data": {
                "from_commit_id": "FAKE_COMMIT_ID",
                "to_commit_id": "FAKE_COMMIT_ID"
            }
        }

    def tearDown(self):
        pass

    def test_kubelet_upgrade_hook_success(self):
        """Test successful execution of KubeletUpgradeHook"""
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        kubelet_upgrade_hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        mock_json_dump = mock.MagicMock()
        p = mock.patch('json.dump', mock_json_dump)
        p.start()
        self.addCleanup(p.stop)

        kubelet_upgrade_hook.run()

        mocked_open.assert_called()
        mock_json_dump.assert_called()

    def test_kubelet_upgrade_hook_success_version_absent(self):
        """Test successful execution of KubeletUpgradeHook when to_kubelet_version absent"""
        kubelet_upgrade_hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        mock_json_dump = mock.MagicMock()
        p = mock.patch('json.dump', mock_json_dump)
        p.start()
        self.addCleanup(p.stop)

        kubelet_upgrade_hook.run()

        mocked_open.assert_not_called()
        mock_json_dump.assert_not_called()

    def test_kubelet_upgrade_hook_failure(self):
        """Test failed execution of KubeletUpgradeHook"""
        self.attrs["additional_data"]["to_kubelet_version"] = "v1.34.1"
        kubelet_upgrade_hook = KubeletUpgradeHook(self.attrs)

        mocked_open = mock.mock_open()
        p = mock.patch('builtins.open', mocked_open)
        p.start()
        self.addCleanup(p.stop)

        mock_json_dump = mock.MagicMock()
        p = mock.patch('json.dump', mock_json_dump)
        p.start().side_effect = Exception("Some error!")
        self.addCleanup(p.stop)

        self.assertRaises(Exception, kubelet_upgrade_hook.run)  # noqa: H202

        mocked_open.assert_called()
        mock_json_dump.assert_called()
