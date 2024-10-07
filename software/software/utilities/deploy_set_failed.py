#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Update deploy state and host state to fail and also informs next legit operation
"""

import argparse
import sys
from software.db.api import get_instance
from software.deploy_state import DeployState
from software.states import DEPLOY_STATES
from software.utils import is_active_controller

from software.deploy_host_state import DeployHostState
from software.states import DEPLOY_HOST_STATES

SOFTWARE_DEPLOY_COMMAND = "software deploy"

set_deploy_failed_states = {
    DEPLOY_STATES.START.value: DeployState().start_failed,
    DEPLOY_STATES.HOST.value: DeployState().deploy_host_failed,
    DEPLOY_STATES.HOST_DONE.value: DeployState().deploy_host_failed,
    DEPLOY_STATES.HOST_ROLLBACK.value: DeployState().deploy_host_failed,
    DEPLOY_STATES.ACTIVATE.value: DeployState().activate_failed,
    DEPLOY_STATES.ACTIVATE_ROLLBACK.value: DeployState().activate_rollback_failed,
}
next_operation = {
    DEPLOY_STATES.START_FAILED.value: "delete",
    DEPLOY_STATES.HOST_FAILED.value: "host <host> or abort",
    DEPLOY_STATES.HOST_ROLLBACK_FAILED.value: "host rollback <host>",
    DEPLOY_STATES.ACTIVATE_FAILED.value: "activate or abort",
    DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED.value: "activate rollback"
}
warn_next_operation_msg = {
    DEPLOY_STATES.START.value: "execute 'software deploy delete' and restart deploy by rerunning 'software deploy start <release>'",
    DEPLOY_STATES.HOST.value: "reattempt 'software deploy host <hostname>' or run 'software deploy abort' to abort",
    DEPLOY_STATES.HOST_DONE.value: "reattempt 'software deploy host <hostname>' or run 'software deploy abort' to abort",
    DEPLOY_STATES.HOST_ROLLBACK.value: "reattempt 'software deploy host-rollback <hostname>'",
    DEPLOY_STATES.ACTIVATE.value: "reattempt 'software deploy activate' or 'software deploy abort' to abort",
    DEPLOY_STATES.ACTIVATE_ROLLBACK.value: "reattempt 'software deploy activate rollback'"
}
required_hostname_deploy_states = [DEPLOY_STATES.HOST.value, DEPLOY_STATES.HOST_DONE.value,
                                   DEPLOY_STATES.HOST_ROLLBACK.value]


def get_current_deploy_state():
    db_api_instance = get_instance()
    current_deploy = db_api_instance.get_current_deploy()
    if current_deploy:
        return current_deploy.get('state')
    else:
        print('No deployment in progress.')
        sys.exit(1)


def get_current_deploy_host_state():
    db_api_instance = get_instance()
    current_deploy_host = db_api_instance.get_deploy_host()
    if current_deploy_host:
        return current_deploy_host.get('state')
    else:
        print('No deployment in progress.')
        sys.exit(1)


def acknowledge_operation(confirm):
    if not confirm:
        current_deploy_state = get_current_deploy_state()
        print("Current deploy is in %s state" % current_deploy_state)
        warning_message = \
            (f"WARNING: Fail the deployment now will require to {warn_next_operation_msg[current_deploy_state]}.\n"
             "Continue [yes/N]: ")
        confirm = input(warning_message)
        if confirm != 'yes':
            print("Operation cancelled.")
            sys.exit(1)


def get_deploy_host_fail_function(deploy_host):
    deploy_host_failed_states = {DEPLOY_HOST_STATES.DEPLOYING: deploy_host.failed,
                                 # Allow deployed to failed state in case of host came up with n-1 load
                                 # after a reboot before unlock.
                                 DEPLOY_HOST_STATES.DEPLOYED: deploy_host.failed,
                                 DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING: deploy_host.deploy_failed
                                 }
    deploy_host_state = deploy_host.get_deploy_host_state()
    if not deploy_host_state:
        print("Deploy host not found for the given hostname.")
        sys.exit(1)
    fail_function = deploy_host_failed_states.get(deploy_host_state, None)
    if fail_function is None:
        print("Operation not permitted for current deploy host state.")
        sys.exit(1)
    return fail_function


def start_set_fail(confirm, hostname):
    if not is_active_controller():
        print("This operation needs to be executed in active controller.")
        sys.exit(1)
    deploy_state = get_current_deploy_state()
    DeployState.get_instance()
    if deploy_state in required_hostname_deploy_states and not hostname:
        print("Operation not permitted for current deploy state without specifying a hostname. Please specify the "
              "hostname to be set failed.")
        sys.exit(1)
    fail_function = set_deploy_failed_states.get(deploy_state, None)
    if fail_function is None:
        print("Operation not permitted for current deploy state. Please follow the admin guide to complete the deploy.")
        sys.exit(1)
    acknowledge_operation(confirm)
    # Only enters this block if deploy state is in host, host-done or host-rollback state.
    if hostname and deploy_state in required_hostname_deploy_states:
        deploy_host = DeployHostState(hostname)
        host_fail_function = get_deploy_host_fail_function(deploy_host)
        # Call deploy fail function before set host to failed.
        fail_function()
        deploy_host_state = deploy_host.get_deploy_host_state()
        host_fail_function()
        after_deploy_host_state = deploy_host.get_deploy_host_state()
        print(f"Deploy host state {deploy_host_state.value} moved to {after_deploy_host_state.value} with success.")
    else:
        fail_function()
    failed_deploy_state = get_current_deploy_state()
    print(f"Deploy state {deploy_state} moved to {failed_deploy_state} with success.\n"
          f"Please proceed with {SOFTWARE_DEPLOY_COMMAND} {next_operation.get(failed_deploy_state)}.")


def deploy_set_failed():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument('--confirm', default=False, action='store_true',
                        help='Provide acknowledgement that the operation should continue as the action will need extra'
                             'steps.')
    parser.add_argument('-h', '--hostname',
                        default=False,
                        help="Host name to be set state to failed.")
    args = parser.parse_args()

    start_set_fail(confirm=args.confirm, hostname=args.hostname)
