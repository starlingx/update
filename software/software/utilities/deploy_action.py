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
from software.utilities.utils import ACTION_ACTIVATE_ROLLBACK
from software.utilities.utils import ACTION_DELETE
from software.utilities.utils import configure_logging
from software.utilities.plugin_runner import execute_migration_scripts
from software.utilities.plugin_runner import run_scripts
import software.utils as utils

SOFTWARE_RELEASES_STORAGE_DIR = "/opt/software/releases"
UPGRADE_SCRIPTS_DIR = "upgrade-scripts"

LOG = log.getLogger(__name__)

# Map action to deploy states and agent names.
# agent=None means no state update (best-effort operation like delete).
ACTION_STATE_MAP = {
    ACTION_ACTIVATE: {
        "done": DEPLOY_STATES.ACTIVATE_DONE.value,
        "failed": DEPLOY_STATES.ACTIVATE_FAILED.value,
        "agent": "deploy-activate",
    },
    ACTION_ACTIVATE_ROLLBACK: {
        "done": DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value,
        "failed": DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value,
        "agent": "deploy-activate-rollback",
    },
    ACTION_DELETE: {
        "done": None,
        "failed": None,
        "agent": None,
    },
}

VALID_ACTIONS = [ACTION_ACTIVATE, ACTION_ACTIVATE_ROLLBACK, ACTION_DELETE]


def do_action(from_release, to_release, is_major_release, metapackages=None,
              action=ACTION_ACTIVATE):
    """
    Run upgrade scripts for a given action (activate, activate-rollback, or delete).

    :param from_release: current release version
    :param to_release: target release version
    :param is_major_release: whether this is a major release deployment
    :param metapackages: dict of {path_component: [scripts]} or list of path_components
    :param action: the action to perform
    """
    state_info = ACTION_STATE_MAP[action]
    agent = state_info["agent"]
    res = True
    state = state_info["done"]

    # For delete, skip if no major release and no metapackages
    if action == ACTION_DELETE and not is_major_release and not metapackages:
        LOG.info("No scripts to run for delete (not major release, no metapackages)")
        return True

    try:
        if is_major_release and metapackages:
            # Major release per-metapackage: run all scripts in each dir
            LOG.info(f"Running {action} scripts for major release (per-metapackage)")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name in metapackages:
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running {action} scripts for metapackage: {mp_name}")
                execute_migration_scripts(from_release, to_release,
                                          action,
                                          migration_script_dir=mp_dir)
        elif is_major_release:
            # Legacy major release: single directory
            LOG.info(f"Running {action} scripts for major release (legacy)")
            from_major_release = utils.get_major_release_version(from_release)
            to_major_release = utils.get_major_release_version(to_release)
            execute_migration_scripts(from_major_release, to_major_release, action)
        elif metapackages:
            # Patch per-metapackage: run only specific named scripts
            LOG.info(f"Running {action} scripts for patch release")
            scripts_release = max(from_release, to_release,
                                  key=lambda r: tuple(int(x) for x in r.split('.')))
            for mp_name, scripts in metapackages.items():
                mp_dir = os.path.join(SOFTWARE_RELEASES_STORAGE_DIR, scripts_release,
                                      mp_name, UPGRADE_SCRIPTS_DIR)
                LOG.info(f"Running {action} scripts for metapackage: {mp_name}")
                run_scripts([mp_dir], action=action, filter_names=scripts,
                            from_release=from_release, to_release=to_release)
        else:
            LOG.warning(f"No metapackages were provided for {action}")

    except Exception:
        if state_info["failed"]:
            state = state_info["failed"]
        res = False
    finally:
        # Only update deploy state if agent is defined (not for delete)
        if agent:
            try:
                update_deploy_state(agent, deploy_state=state)
                if res:
                    LOG.info(f"Deploy {action} completed successfully")
                else:
                    LOG.error(f"Deploy {action} failed")
            except Exception:
                LOG.error(f"Update deploy state failed for {action}")
                res = False
        else:
            if res:
                LOG.info(f"Deploy {action} completed successfully")
            else:
                LOG.error(f"Errors occurred in deploy {action}")
    return res


def _parse_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("from_release",
                        default=False,
                        help="From release")

    parser.add_argument("to_release",
                        default=False,
                        help="To release")

    parser.add_argument("--is_major_release",
                        action="store_true",
                        help="Specify if this is a major release")

    parser.add_argument("--metapackages",
                        type=str,
                        default=None,
                        help="JSON dict of {path_component: [scripts]}")

    parser.add_argument("--action",
                        type=str,
                        default=ACTION_ACTIVATE,
                        choices=VALID_ACTIONS,
                        help="Action to perform")

    return parser.parse_args()


def deploy_action():
    """Entry point for software-deploy-action (generic, uses --action arg)"""
    configure_logging()
    args = _parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    if do_action(args.from_release, args.to_release, args.is_major_release,
                 metapackages, args.action):
        exit(0)
    else:
        exit(1)


def activate():
    """Entry point for software-deploy-activate (backward compatibility)"""
    configure_logging()
    args = _parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    if do_action(args.from_release, args.to_release, args.is_major_release,
                 metapackages, ACTION_ACTIVATE):
        exit(0)
    else:
        exit(1)


def activate_rollback():
    """Entry point for software-deploy-activate-rollback (backward compatibility)"""
    configure_logging()
    args = _parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    if do_action(args.from_release, args.to_release, args.is_major_release,
                 metapackages, ACTION_ACTIVATE_ROLLBACK):
        exit(0)
    else:
        exit(1)


def delete():
    """Entry point for software-deploy-delete (backward compatibility)"""
    configure_logging()
    args = _parse_args()

    metapackages = json.loads(args.metapackages) if args.metapackages else None
    if do_action(args.from_release, args.to_release, args.is_major_release,
                 metapackages, ACTION_DELETE):
        exit(0)
    else:
        exit(1)
