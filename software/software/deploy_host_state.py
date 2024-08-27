"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging

from software.db.api import get_instance
from software.exceptions import InvalidOperation
from software.states import DEPLOY_HOST_STATES

LOG = logging.getLogger('main_logger')


deploy_host_state_transition = {
    DEPLOY_HOST_STATES.PENDING: [DEPLOY_HOST_STATES.DEPLOYING, DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED],
    DEPLOY_HOST_STATES.DEPLOYING: [DEPLOY_HOST_STATES.DEPLOYED, DEPLOY_HOST_STATES.FAILED],
    DEPLOY_HOST_STATES.FAILED: [DEPLOY_HOST_STATES.DEPLOYING, DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED,
                                DEPLOY_HOST_STATES.ROLLBACK_PENDING, DEPLOY_HOST_STATES.FAILED],
    DEPLOY_HOST_STATES.DEPLOYED: [DEPLOY_HOST_STATES.ROLLBACK_PENDING,
                                  DEPLOY_HOST_STATES.FAILED], # manual recovery scenario
    DEPLOY_HOST_STATES.ROLLBACK_PENDING: [DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING],
    DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING: [DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED,
                                            DEPLOY_HOST_STATES.ROLLBACK_FAILED],
    DEPLOY_HOST_STATES.ROLLBACK_FAILED: [DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING],
    DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED: []
}

deploy_host_reentrant_states = [DEPLOY_HOST_STATES.ROLLBACK_FAILED, DEPLOY_HOST_STATES.FAILED]


class DeployHostState(object):
    _callbacks = []

    @staticmethod
    def register_event_listener(callback):
        if callback not in DeployHostState._callbacks:
            LOG.info("Register event listener %s", callback.__qualname__)
            DeployHostState._callbacks.append(callback)

    def __init__(self, hostname):
        self._hostname = hostname

    def get_deploy_host_state(self):
        db_api = get_instance()
        deploy_host = db_api.get_deploy_host_by_hostname(self._hostname)
        if deploy_host is not None:
            return DEPLOY_HOST_STATES(deploy_host['state'])
        return None

    def check_transition(self, target_state: DEPLOY_HOST_STATES):
        cur_state = self.get_deploy_host_state()
        if cur_state:
            if target_state in deploy_host_state_transition[cur_state]:
                return True

            # Below is to tolerate reentrant of certain states, currently failed states.
            # by doing this it can simplify the workflow code to fire deploy_failed
            # event more than once.
            # note that it should not retrigger transition.
            # the workflow should ensure triggering deploy_started event to exit the
            # failed states when deploy attempt starts.
            if target_state == cur_state and cur_state in deploy_host_reentrant_states:
                return True

        else:
            LOG.error('Host %s is not part of deployment' % self._hostname)
        return False

    def transform(self, target_state: DEPLOY_HOST_STATES):
        db_api = get_instance()
        db_api.begin_update()
        try:
            if self.check_transition(target_state):
                db_api.update_deploy_host(self._hostname, target_state)
                LOG.info("Deploy host state for host %s updated to: %s" % (self._hostname, target_state.value))
                for callback in DeployHostState._callbacks:
                    callback(self._hostname, target_state)
            else:
                msg = "Host can not transform to %s from current state" % target_state.value
                raise InvalidOperation(msg)
        finally:
            db_api.end_update()

    def deploy_started(self):
        state = self.get_deploy_host_state()
        if state in [DEPLOY_HOST_STATES.PENDING, DEPLOY_HOST_STATES.FAILED]:
            self.transform(DEPLOY_HOST_STATES.DEPLOYING)
        else:
            self.transform(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING)

    def deployed(self):
        state = self.get_deploy_host_state()
        if state == DEPLOY_HOST_STATES.DEPLOYING:
            self.transform(DEPLOY_HOST_STATES.DEPLOYED)
        else:
            self.transform(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)

    def deploy_failed(self):
        state = self.get_deploy_host_state()
        if state == DEPLOY_HOST_STATES.DEPLOYING:
            self.transform(DEPLOY_HOST_STATES.FAILED)
        else:
            self.transform(DEPLOY_HOST_STATES.ROLLBACK_FAILED)

    def failed(self):
        """Transform deploy host state to failed without rollback logic."""
        self.transform(DEPLOY_HOST_STATES.FAILED)

    def abort(self):
        state = self.get_deploy_host_state()
        if state == DEPLOY_HOST_STATES.PENDING:
            self.transform(DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED)
        else:
            self.transform(DEPLOY_HOST_STATES.ROLLBACK_PENDING)
