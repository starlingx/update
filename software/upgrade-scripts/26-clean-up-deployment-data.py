#!/usr/bin/env python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove the etcd folder of upgrade.

import logging
import os
import shutil
import subprocess
import sys

from software.utilities.constants import SW_VERSION
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging
from software import constants
from software import utils

LOG = logging.getLogger('main_logger')


def clean_up_luks_keyring(major_release):
    luks_keyring_path = os.path.join(
        "/var/luks/stx/luks_fs/controller/.keyring", major_release)
    if os.path.exists(luks_keyring_path):
        shutil.rmtree(luks_keyring_path)
        LOG.info("LUKS keyring removed: %s", luks_keyring_path)


def clean_up_deployment_data(major_release):
    for folder in constants.DEPLOY_CLEANUP_FOLDERS_NAME:
        path = os.path.join(constants.PLATFORM_PATH, folder, major_release, "")
        shutil.rmtree(path, ignore_errors=True)
    upgrade_folders = [
        os.path.join(constants.POSTGRES_PATH, constants.UPGRADE),
        os.path.join(constants.POSTGRES_PATH, major_release),
        os.path.join(constants.RABBIT_PATH, major_release),
    ]
    for folder in upgrade_folders:
        shutil.rmtree(folder, ignore_errors=True)
        LOG.info("Folder %s removed with success.", folder)


def restart_etcd_service():
    try:
        subprocess.run(["/usr/bin/sm-restart-safe", "service", "etcd"], check=True)
        LOG.info("Restarted etcd service")
    except subprocess.CalledProcessError as e:
        LOG.error("Error restarting etcd: %s", str(e))


class CleanUpDeploymentData(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='delete',
            required_state=None,
            plugin_name='clean-up-deployment-data',
            completed_state='clean-up-deployment-data-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        from_major_release = utils.get_major_release_version(from_release)
        to_major_release = utils.get_major_release_version(to_release)
        if SW_VERSION == from_major_release:
            major_release = to_major_release
        else:
            major_release = from_major_release
        clean_up_deployment_data(major_release)
        clean_up_luks_keyring(major_release)
        restart_etcd_service()


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = CleanUpDeploymentData()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
