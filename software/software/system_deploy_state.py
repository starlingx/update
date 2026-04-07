"""
Copyright (c) 2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging

from software.db.api import get_instance
from software.states import SYSTEM_DEPLOY_STATES

LOG = logging.getLogger('main_logger')

system_deploy_state_transition = {
    SYSTEM_DEPLOY_STATES.START: [SYSTEM_DEPLOY_STATES.START_DONE, SYSTEM_DEPLOY_STATES.START_FAILED]
}


class SystemDeployState(object):
    _callbacks = []

    def __init__(self):
        self.id = None
        self._to_release = None
        self._to_k8s_version = None

    @staticmethod
    def register_event_listener(callback):
        """register event listener to be triggered when a state transition is completed"""
        if callback is not None:
            if callback not in SystemDeployState._callbacks:
                LOG.debug("Register event listener %s", callback.__qualname__)
                SystemDeployState._callbacks.append(callback)

    @staticmethod
    def get_system_deploy_state():
        db_api_instance = get_instance()
        system_deploy = db_api_instance.get_system_deploy()
        if system_deploy is None:
            return None
        return SYSTEM_DEPLOY_STATES(system_deploy["state"])

    def transform(self, target_state: SYSTEM_DEPLOY_STATES):
        curr_state = SystemDeployState.get_system_deploy_state()
        db_api = get_instance()
        db_api.begin_update()

        try:
            if target_state is not None:
                db_api.update_system_deploy_state(target_state)
                LOG.info("System deploy state changed from %s to %s" % (curr_state, target_state))
            else:
                LOG.info("No system deploy state change!")
        finally:
            db_api.end_update()

    def check_transition(self, target_state):
        curr_state = SystemDeployState.get_system_deploy_state()
        if curr_state is None:
            return False
        if target_state in system_deploy_state_transition[curr_state]:
            return True
        return False
