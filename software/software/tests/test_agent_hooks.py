#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
import logging
import tempfile
from unittest import mock
from unittest import TestCase

# Patch basicConfig before importing agent_hooks to prevent it from
# trying to open /var/log/software.log at module load time.
with mock.patch.object(logging, 'basicConfig'):
    from software.agent_hooks import KubeletUpgradeHook
    from software.agent_hooks import HookManager
    from software.agent_hooks import UpdateSysinvHostSwVersionRollbackHook
    from software.agent_hooks import UsmInitHook


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

    KS_CONFIG = {
        "auth_url": "http://keystone:5000", "username": "usm",
        "password": "pw", "project_name": "services",
        "user_domain_name": "Default", "project_domain_name": "Default",
        "region_name": "RegionOne",
    }

    def _run_hook(self, nodetype="controller", token=("tok", "http://sysinv"),
                  config=None, update_exc=None, current="26.10"):
        """Run the hook with all external access mocked"""
        self.attrs["to_release"] = "26.03"
        hook = UpdateSysinvHostSwVersionRollbackHook(self.attrs)
        client = mock.MagicMock()
        client.ihost.update.side_effect = update_exc
        client.ihost.get.return_value.sw_version = current
        patches = [
            mock.patch('software.agent_hooks.BaseHook.get_platform_conf',
                       return_value=nodetype),
            mock.patch('software.agent_hooks.socket.gethostname',
                       return_value='controller-1'),
            mock.patch.object(hook, '_get_keystone_config',
                              return_value=config or self.KS_CONFIG),
            mock.patch('software.utils.get_endpoints_token',
                       return_value=token),
            mock.patch('software.sysinv_utils.get_sysinv_client',
                       return_value=client),
        ]
        mocks = [p.start() for p in patches]
        self.addCleanup(mock.patch.stopall)
        return hook, client, mocks[3]

    def test_update_sysinv_sw_version_controller(self):
        """Controller: local keystone creds are used to set sw_version"""
        hook, client, get_token = self._run_hook()
        hook.run()
        # once for the sw_version read, once in update_host_sw_version()
        self.assertEqual(get_token.call_count, 2)
        for c in get_token.call_args_list:
            self.assertEqual(c, mock.call(config=self.KS_CONFIG))
        client.ihost.get.assert_called_once_with('controller-1')
        client.ihost.update.assert_called_once_with(
            'controller-1',
            [{'op': 'replace', 'path': '/sw_version', 'value': '26.03'}])

    def test_update_sysinv_sw_version_uses_update_host_sw_version(self):
        """The existing sysinv_utils helper is used with the local creds"""
        hook, client, _ = self._run_hook()
        with mock.patch('software.sysinv_utils.update_host_sw_version') \
                as mock_update:
            hook.run()
        mock_update.assert_called_once_with('controller-1', '26.03',
                                            config=self.KS_CONFIG)
        client.ihost.update.assert_not_called()

    def test_update_sysinv_sw_version_already_correct(self):
        """No update when sysinv already has the to-release sw_version"""
        hook, client, _ = self._run_hook(current="26.03")
        hook.run()
        client.ihost.get.assert_called_once_with('controller-1')
        client.ihost.update.assert_not_called()

    def test_update_sysinv_sw_version_get_failure_propagates(self):
        """A failure reading the current sw_version is raised"""
        hook, client, _ = self._run_hook()
        client.ihost.get.side_effect = ConnectionError("sysinv down")
        with self.assertRaises(ConnectionError):
            hook.run()
        client.ihost.update.assert_not_called()

    def test_update_sysinv_sw_version_worker_skipped(self):
        """Non-controller: nothing is updated"""
        hook, client, get_token = self._run_hook(nodetype="worker")
        hook.run()
        get_token.assert_not_called()
        client.ihost.update.assert_not_called()

    def test_update_sysinv_sw_version_no_token_fails(self):
        """No token from keystone is raised so deploy host can be retried"""
        hook, client, _ = self._run_hook(token=(None, None))
        with self.assertRaises(RuntimeError):
            hook.run()
        client.ihost.update.assert_not_called()

    def test_update_sysinv_sw_version_failure_propagates(self):
        """A sysinv failure is raised so that deploy host can be retried"""
        hook, _, _ = self._run_hook(
            update_exc=ConnectionError("sysinv down"))
        with self.assertRaises(ConnectionError):
            hook.run()

    def test_get_keystone_config_reads_local_conf(self):
        """Credentials are read from [keystone_authtoken] of software.conf"""
        hook = UpdateSysinvHostSwVersionRollbackHook(self.attrs)
        content = "[keystone_authtoken]\n" + "".join(
            "%s = %s\n" % kv for kv in self.KS_CONFIG.items())
        with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
            f.write(content)
            f.flush()
            hook.SOFTWARE_CONFIG_FILE = f.name
            self.assertEqual(hook._get_keystone_config(), self.KS_CONFIG)

    def test_get_keystone_config_missing_section(self):
        hook = UpdateSysinvHostSwVersionRollbackHook(self.attrs)
        with tempfile.NamedTemporaryFile("w", suffix=".conf") as f:
            f.write("[runtime]\nfoo = bar\n")
            f.flush()
            hook.SOFTWARE_CONFIG_FILE = f.name
            with self.assertRaises(RuntimeError):
                hook._get_keystone_config()

    def test_get_keystone_config_missing_file(self):
        hook = UpdateSysinvHostSwVersionRollbackHook(self.attrs)
        hook.SOFTWARE_CONFIG_FILE = "/nonexistent/software.conf"
        with self.assertRaises(RuntimeError):
            hook._get_keystone_config()

    def test_update_sysinv_sw_version_hook_registered(self):
        """Hook is in the rollback list, before UsmInitHook, not in upgrade"""
        hooks = HookManager.AGENT_HOOKS[HookManager.MAJOR_RELEASE_ROLLBACK]
        self.assertIs(hooks[-2], UpdateSysinvHostSwVersionRollbackHook)
        self.assertIs(hooks[-1], UsmInitHook)
        self.assertNotIn(
            UpdateSysinvHostSwVersionRollbackHook,
            HookManager.AGENT_HOOKS[HookManager.MAJOR_RELEASE_UPGRADE])
