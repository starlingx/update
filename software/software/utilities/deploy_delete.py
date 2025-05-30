#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# This script neeeds to be running on both N-1 runtime from
# a temporary directory and N runtime from /usr/ directory

import argparse
import logging

from software.utilities import utils


LOG = logging.getLogger('main_logger')


def do_deploy_delete(from_release, to_release, plugin_path, is_major_release):
    # This is a "best effort" operation. Failing steps will be logged
    # and move on.

    if not is_major_release:
        return

    res = True
    try:
        if plugin_path:
            utils.execute_migration_scripts(from_release, to_release,
                                            utils.ACTION_DELETE,
                                            migration_script_dir=plugin_path)
        else:
            utils.execute_migration_scripts(from_release, to_release,
                                            utils.ACTION_DELETE)
    except Exception:
        res = False
    finally:
        if res:
            LOG.info("Deploy delete completed successfully")
        else:
            LOG.info("Errors occored in deploy delete.")


def deploy_delete():
    # this is the entry point to deploy delete plugin
    utils.configure_logging()
    parser = argparse.ArgumentParser(add_help=False)

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
                        default=None,
                        help="Specify the path of action plugins")

    args = parser.parse_args()

    do_deploy_delete(args.from_release, args.to_release, args.plugin_path, args.is_major_release)
