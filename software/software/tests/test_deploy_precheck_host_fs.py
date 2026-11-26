#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for the host-fs size checks in the deploy-precheck script."""
import importlib.machinery
import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock

from software.tests import base as test_base  # noqa: F401

SCRIPTS_DIR = os.path.normpath(os.path.join(
    os.path.dirname(__file__), "..", "..", "scripts"))


def _load_deploy_precheck():
    """Load the extension-less deploy-precheck script as a module."""
    # upgrade_utils pulls in keystoneauth1 and other service libraries that
    # the checks under test do not use.
    sys.modules.setdefault("upgrade_utils", MagicMock())
    path = os.path.join(SCRIPTS_DIR, "deploy-precheck")
    loader = importlib.machinery.SourceFileLoader("deploy_precheck", path)
    spec = importlib.util.spec_from_loader("deploy_precheck", loader)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    loader.exec_module(mod)
    return mod


deploy_precheck = _load_deploy_precheck()


def _host(hostname):
    host = MagicMock()
    host.hostname = hostname
    host.uuid = "uuid-" + hostname
    return host


def _fs(name, size):
    fs = MagicMock()
    fs.name = name
    fs.size = size
    return fs


class TestHostFsSizeChecks(unittest.TestCase):
    """Tests for UpgradeHealthCheck._check_sysroot_size/_check_docker_fs_size."""

    def _make_check(self, host_fs):
        """Build a check object with a fake sysinv client.

        :param host_fs: dict of {hostname: [(fs_name, size), ...]}
        """
        # HealthCheck.__init__ derives its state from the script path, so
        # bypass it and set only what the checks under test use.
        check = deploy_precheck.UpgradeHealthCheck.__new__(
            deploy_precheck.UpgradeHealthCheck)
        check._host_fs_sizes = None
        hosts = [_host(name) for name in host_fs]
        by_uuid = {"uuid-" + name: [_fs(n, s) for n, s in fss]
                   for name, fss in host_fs.items()}
        client = MagicMock()
        client.ihost.list.return_value = hosts
        client.host_fs.list.side_effect = lambda uuid: by_uuid[uuid]
        check._sysinv_client = client
        return check

    def test_hosts_listed_once_for_both_checks(self):
        host_fs = {"controller-0": [("root", 50), ("docker", 50)],
                   "controller-1": [("root", 50), ("docker", 50)]}
        host_fs.update({"compute-%d" % i: [("root", 50)] for i in range(100)})
        check = self._make_check(host_fs)

        self.assertEqual((True, ""), check._check_docker_fs_size())
        self.assertEqual((True, ""), check._check_sysroot_size())

        check._sysinv_client.ihost.list.assert_called_once_with()
        self.assertEqual(len(host_fs),
                         check._sysinv_client.host_fs.list.call_count)

    def test_sysroot_too_small(self):
        check = self._make_check({
            "controller-0": [("root", 50)],
            "compute-0": [("root", 20)]})

        success, output = check._check_sysroot_size()

        self.assertFalse(success)
        self.assertIn("The root filesystem on compute-0 is 20 GiB", output)
        self.assertIn("system host-fs-modify compute-0 root=%d"
                      % deploy_precheck.SYSROOT_MINIMUM_REQUIRED_SIZE_GIB,
                      output)
        self.assertNotIn("controller-0", output)

    def test_sysroot_missing_is_failure(self):
        check = self._make_check({
            "controller-0": [("root", 50)],
            "compute-0": [("docker", 50)]})

        success, output = check._check_sysroot_size()

        self.assertFalse(success)
        self.assertIn("Unable to determine root filesystem size for "
                      "compute-0", output)

    def test_docker_too_small_on_controller(self):
        check = self._make_check({
            "controller-0": [("root", 50), ("docker", 10)],
            "controller-1": [("root", 50), ("docker", 50)]})

        success, output = check._check_docker_fs_size()

        self.assertFalse(success)
        self.assertIn("The docker filesystem on controller-0 is 10 GiB",
                      output)
        self.assertIn("system host-fs-modify controller-0 docker=%d"
                      % deploy_precheck.DOCKER_FS_MINIMUM_REQUIRED_SIZE_GIB,
                      output)
        self.assertNotIn("controller-1", output)

    def test_docker_missing_is_skipped_and_workers_ignored(self):
        check = self._make_check({
            "controller-0": [("root", 50)],
            "compute-0": [("root", 50), ("docker", 1)]})

        self.assertEqual((True, ""), check._check_docker_fs_size())
