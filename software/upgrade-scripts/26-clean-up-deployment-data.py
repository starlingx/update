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
    # Check delete action, upgrade and rollback scenario.
    if action == 'delete' and (to_major_release == '25.09' or (from_major_release == '25.09'
                                                               and to_major_release == '24.09')):
        try:
            major_release = utils.get_major_release_version(from_release)
            clean_up_deployment_data(major_release)
            remove_etcd_hardlink_folder(major_release, from_release)
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


def remove_etcd_hardlink_folder(major_release, from_release):
    # etcd has different cleanup procedure:
    # - remove the to-release symlink
    # - rename from-release directory to to-release
    # - restart etcd process
    etcd_from_path = os.path.join(constants.ETCD_PATH, major_release)
    etcd_db_path = os.path.join(constants.ETCD_PATH, ETCD_DIR_NAME)
    if from_release == '24.09':
        if os.path.exists(etcd_from_path):
            shutil.rmtree(etcd_from_path)
            LOG.info("Removed %s folder.", etcd_from_path)
        try:
            subprocess.run(["/usr/bin/sm-restart-safe", "service", "etcd"], check=True)
            LOG.info("Restarted etcd service")
        except subprocess.CalledProcessError as e:
            LOG.error("Error restarting etcd: %s", str(e))
    # on rollback, remove db folder if it exists
    else:
        if os.path.exists(etcd_db_path):
            shutil.rmtree(etcd_db_path)
            LOG.info("Removed %s hardlink", etcd_db_path)


if __name__ == "__main__":
    sys.exit(main())
