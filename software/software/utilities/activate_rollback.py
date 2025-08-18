#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import argparse

from oslo_log import log

from software.states import DEPLOY_STATES
from software.utilities.update_deploy_state import update_deploy_state
from software.utilities.utils import configure_logging
from software.utilities.utils import execute_migration_scripts
from software.utilities.utils import ACTION_ACTIVATE_ROLLBACK

LOG = log.getLogger(__name__)


def do_activate_rollback(from_release, to_release):
    agent = 'deploy-activate-rollback'
    res = True
    state = DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE.value
    try:
        execute_migration_scripts(from_release, to_release, ACTION_ACTIVATE_ROLLBACK)
    except Exception:
        state = DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value
        res = False
    finally:
        try:
            update_deploy_state(agent, deploy_state=state)
            if res:
                LOG.info("Deploy activate-rollback completed successfully")
            else:
                LOG.error("Deploy activate-rollback failed")
        except Exception as err:
            LOG.error("Update deploy state activate-rollback failed: %s" % err)
            res = False
    return res


def activate_rollback():
    # this is the entry point to start activate-rollback
    configure_logging(LOG)
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("from_release",
                        default=False,
                        help="From release")

    parser.add_argument("to_release",
                        default=False,
                        help="To release")

    args = parser.parse_args()

    if do_activate_rollback(args.from_release, args.to_release):
        exit(0)
    else:
        exit(1)
