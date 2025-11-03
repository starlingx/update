#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove the etcd folder of upgrade.
#
#
import logging
import os
import shutil
import subprocess
import sys

from software.utilities.constants import SW_VERSION
from software import constants
from software import utils
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')
ETCD_DIR_NAME = 'db'


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    configure_logging()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    from_major_release = utils.get_major_release_version(from_release)
    to_major_release = utils.get_major_release_version(to_release)
    if SW_VERSION == from_major_release:
        major_release = to_major_release
    else:
        major_release = from_major_release
    # Check delete action, upgrade and rollback scenario.
    if action == 'delete':
        try:
            clean_up_deployment_data(major_release)
            restart_etcd_service()
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def clean_up_deployment_data(major_release):
    """
    Clean up all data generated during deployment.

    :param major_release: Major release to be deleted.
    """
    # Delete the data inside /opt/platform/<folder>/<major_release>
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


if __name__ == "__main__":
    sys.exit(main())
