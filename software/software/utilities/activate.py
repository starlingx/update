#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from oslo_log import log

from software.states import DEPLOY_STATES
from software.utilities.update_deploy_state import update_deploy_state
from software.utilities.utils import execute_migration_scripts
from software.utilities.utils import ACTION_ACTIVATE

LOG = log.getLogger(__name__)


def do_activate(from_release, to_release):
    agent = 'deploy-activate'
    res = True
    state = DEPLOY_STATES.ACTIVATE_DONE.value
    try:
        execute_migration_scripts(from_release, to_release, ACTION_ACTIVATE)
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
    # this is the entry point to start data migration

    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("from_release",
                        default=False,
                        help="From release")

    parser.add_argument("to_release",
                        default=False,
                        help="To release")

    args = parser.parse_args()

    if do_activate(args.from_release, args.to_release):
        exit(0)
    else:
        exit(1)
