#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script neeeds to be running on both N-1 runtime from
# a temporary directory and N runtime from /usr/ directory

import argparse
import json
import logging
import os

from software.utilities import utils
from software.utilities.plugin_runner import execute_migration_scripts
from software.utilities.plugin_runner import run_scripts


LOG = logging.getLogger('main_logger')

SOFTWARE_RELEASES_STORAGE_DIR = "/opt/software/releases"
UPGRADE_SCRIPTS_DIR = "upgrade-scripts"


def do_deploy_delete(from_release, to_release, plugin_path, is_major_release,
                     metapackages=None):
    # This is a "best effort" operation. Failing steps will be logged and move on

    if not is_major_release and not metapackages:
        return

    res = True
    try:
        if is_major_release and metapackages:
            # Major release per-metapackage: run all scripts in each dir
            LOG.info("Running delete scripts for major release (per-metapackage)")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name in metapackages:
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running delete scripts for metapackage: {mp_name}")
                execute_migration_scripts(from_release, to_release,
                                          utils.ACTION_DELETE,
                                          migration_script_dir=mp_dir)
        elif is_major_release:
            # Legacy major release: single directory
            LOG.info("Running delete scripts for major release (legacy)")
            if plugin_path:
                execute_migration_scripts(from_release, to_release,
                                          utils.ACTION_DELETE,
                                          migration_script_dir=plugin_path)
            else:
                execute_migration_scripts(from_release, to_release,
                                          utils.ACTION_DELETE)
        elif metapackages:
            # Patch per-metapackage: run only specific named scripts
            LOG.info("Running delete scripts for patch release")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name, scripts in metapackages.items():
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running delete scripts for metapackage: {mp_name}")
                run_scripts([mp_dir], action=utils.ACTION_DELETE,
                            filter_names=scripts,
                            from_release=from_release, to_release=to_release)
    except Exception as e:
        LOG.error(f"Error running deploy delete scripts: {str(e)}")
        res = False
    finally:
        if res:
            LOG.info("Deploy delete completed successfully")
        else:
            LOG.info("Errors occurred in deploy delete")


def deploy_delete():
    # this is the entry point to deploy delete plugin
    utils.configure_logging()
    parser = argparse.ArgumentParser(add_help=False)

    plugin_path = os.environ.get('plugin_path')
    parser.add_argument("from_release",
                        default=False,
                        help="From release")

    parser.add_argument("to_release",
                        default=False,
                        help="To release")

    # Optional flag --is_major_release
    parser.add_argument("--is_major_release",
                        action="store_true",
                        help="Specify if this is a major release")

    # Optional flag --plugin-path
    parser.add_argument("--plugin_path",
                        dest="plugin_path",
                        default=plugin_path,
                        help="Specify the path of action plugins")

    parser.add_argument("--metapackages",
                        type=str,
                        default=None,
                        help="JSON dict of {path_component: [scripts]}")

    args = parser.parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    do_deploy_delete(args.from_release, args.to_release, args.plugin_path,
                     args.is_major_release, metapackages)
