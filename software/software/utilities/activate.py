# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import os

from oslo_log import log

from software.states import DEPLOY_STATES
from software.utilities.update_deploy_state import update_deploy_state
from software.utilities.utils import ACTION_ACTIVATE
from software.utilities.utils import configure_logging
from software.utilities.plugin_runner import execute_migration_scripts
from software.utilities.plugin_runner import run_scripts
import software.utils as utils

SOFTWARE_RELEASES_STORAGE_DIR = "/opt/software/releases"
UPGRADE_SCRIPTS_DIR = "upgrade-scripts"

LOG = log.getLogger(__name__)


def do_activate(from_release, to_release, is_major_release, metapackages=None):
    agent = 'deploy-activate'
    res = True
    state = DEPLOY_STATES.ACTIVATE_DONE.value
    try:
        if is_major_release and metapackages:
            # Major release per-metapackage: run all scripts in each dir
            LOG.info("Running activate scripts for major release (per-metapackage)")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name in metapackages:
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running activate scripts for metapackage: {mp_name}")
                execute_migration_scripts(from_release, to_release,
                                          ACTION_ACTIVATE,
                                          migration_script_dir=mp_dir)
        elif is_major_release:
            # Legacy major release: single directory
            LOG.info("Running activate scripts for major release (legacy)")
            from_major_release = utils.get_major_release_version(from_release)
            to_major_release = utils.get_major_release_version(to_release)
            execute_migration_scripts(from_major_release, to_major_release, ACTION_ACTIVATE)
        elif metapackages:
            # Patch per-metapackage: run only specific named scripts
            LOG.info("Running activate scripts for patch release")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name, scripts in metapackages.items():
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running activate scripts for metapackage: {mp_name}")
                run_scripts([mp_dir], action=ACTION_ACTIVATE, filter_names=scripts,
                            from_release=from_release, to_release=to_release)
        else:
            LOG.warning("No metapackages were provided for activate")

    except Exception:
        state = DEPLOY_STATES.ACTIVATE_FAILED.value
        res = False
    finally:
        try:
            update_deploy_state(agent, deploy_state=state)
            if res:
                LOG.info("Deploy activate completed successfully")
            else:
                LOG.error("Deploy activate failed")
        except Exception:
            LOG.error("Update deploy state failed")
            res = False
    return res


def activate():
    # this is the entry point to start activate
    configure_logging()
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

    parser.add_argument("--metapackages",
                        type=str,
                        default=None,
                        help="JSON dict of {path_component: [scripts]}")

    args = parser.parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    if do_activate(args.from_release, args.to_release, args.is_major_release, metapackages):
        exit(0)
    else:
        exit(1)
