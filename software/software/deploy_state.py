"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging

from software.db.api import get_instance
from software.exceptions import InvalidOperation
from software.release_data import SWRelease
from software.states import DEPLOY_STATES
from software.states import DEPLOY_HOST_STATES

LOG = logging.getLogger('main_logger')


deploy_state_transition = {
    None: [DEPLOY_STATES.START],  # Fake state for no deploy in progress
    DEPLOY_STATES.START: [DEPLOY_STATES.START_DONE, DEPLOY_STATES.START_FAILED],
    DEPLOY_STATES.START_FAILED: [DEPLOY_STATES.ABORT],
    DEPLOY_STATES.ABORT: [DEPLOY_STATES.ABORT_DONE],
    DEPLOY_STATES.START_DONE: [DEPLOY_STATES.ABORT, DEPLOY_STATES.HOST],
    DEPLOY_STATES.HOST: [DEPLOY_STATES.HOST,
                         DEPLOY_STATES.ABORT,
                         DEPLOY_STATES.HOST_FAILED,
                         DEPLOY_STATES.HOST_DONE],
    DEPLOY_STATES.HOST_FAILED: [DEPLOY_STATES.HOST,  # deploy-host can reattempt
                                DEPLOY_STATES.ABORT,
                                DEPLOY_STATES.HOST_FAILED,
                                DEPLOY_STATES.HOST_DONE],
    DEPLOY_STATES.HOST_DONE: [DEPLOY_STATES.ABORT, DEPLOY_STATES.ACTIVATE],
    DEPLOY_STATES.ACTIVATE: [DEPLOY_STATES.ACTIVATE_DONE, DEPLOY_STATES.ACTIVATE_FAILED],
    DEPLOY_STATES.ACTIVATE_DONE: [DEPLOY_STATES.ABORT, None],  # abort after deploy-activated?
    DEPLOY_STATES.ACTIVATE_FAILED: [DEPLOY_STATES.ACTIVATE, DEPLOY_STATES.ABORT],
    DEPLOY_STATES.ABORT_DONE: []  # waitng for being deleted
}


class DeployState(object):
    _callbacks = []
    _instance = None

    @staticmethod
    def register_event_listener(callback):
        """register event listener to be triggered when a state transition is completed"""
        if callback is not None:
            if callback not in DeployState._callbacks:
                LOG.debug("Register event listener %s", callback.__qualname__)
                DeployState._callbacks.append(callback)

    @staticmethod
    def get_deploy_state():
        db_api_instance = get_instance()
        deploys = db_api_instance.get_deploy_all()
        if not deploys:
            state = None  # No deploy in progress == None
        else:
            deploy = deploys[0]
            state = DEPLOY_STATES(deploy['state'])
        return state

    @staticmethod
    def get_instance():
        if DeployState._instance is None:
            DeployState._instance = DeployState()
        return DeployState._instance

    @staticmethod
    def host_deploy_updated(_hostname, _host_new_state):
        db_api_instance = get_instance()
        deploy_hosts = db_api_instance.get_deploy_host()
        deploy_state = DeployState.get_instance()
        all_states = []
        for deploy_host in deploy_hosts:
            if deploy_host['state'] not in all_states:
                all_states.append(deploy_host['state'])

        LOG.info("Host deploy state %s" % str(all_states))
        if DEPLOY_HOST_STATES.FAILED.value in all_states:
            deploy_state.deploy_host_failed()
        elif DEPLOY_HOST_STATES.PENDING.value in all_states or \
                DEPLOY_HOST_STATES.DEPLOYING.value in all_states:
            deploy_state.deploy_host()
        elif all_states == [DEPLOY_HOST_STATES.DEPLOYED.value]:
            deploy_state.deploy_host_completed()

    def __init__(self):
        self._from_release = None
        self._to_release = None
        self._reboot_required = None

    def check_transition(self, target_state: DEPLOY_STATES):
        cur_state = DeployState.get_deploy_state()
        if cur_state is not None:
            cur_state = DEPLOY_STATES(cur_state)
        if target_state in deploy_state_transition[cur_state]:
            return True
        # TODO(bqian) reverse lookup the operation that is not permitted, as feedback
        msg = f"Deploy state transform not permitted from {str(cur_state)} to {str(target_state)}"
        LOG.info(msg)
        return False

    def transform(self, target_state: DEPLOY_STATES):
        db_api = get_instance()
        db_api.begin_update()
        try:
            if self.check_transition(target_state):
                # None means not existing or deleting
                if target_state is not None:
                    db_api.update_deploy(target_state)
            else:
                # TODO(bqian) check the current state, and provide guidence on what is
                # the possible next operation
                if target_state is None:
                    msg = "Deployment can not deleted in current state."
                else:
                    msg = "Host can not transform to %s from current state" % target_state.value()
                raise InvalidOperation(msg)
        finally:
            db_api.end_update()

        for callback in DeployState._callbacks:
            LOG.debug("Calling event listener %s", callback.__qualname__)
            callback(target_state)

    # below are list of events to drive the FSM
    def start(self, from_release, to_release, feed_repo, commit_id, reboot_required):
        # start is special, it needs to create the deploy entity
        if isinstance(from_release, SWRelease):
            from_release = from_release.sw_release
        if isinstance(to_release, SWRelease):
            to_release = to_release.sw_release

        msg = f"Start deploy {to_release}, current sw {from_release}"
        LOG.info(msg)
        db_api_instance = get_instance()
        db_api_instance.create_deploy(from_release, to_release, feed_repo, commit_id, reboot_required)

    def start_failed(self):
        self.transform(DEPLOY_STATES.START_FAILED)

    def start_done(self):
        self.transform(DEPLOY_STATES.START_DONE)

    def deploy_host(self):
        self.transform(DEPLOY_STATES.HOST)

    def abort(self):
        self.transform(DEPLOY_STATES.ABORT)

    def deploy_host_completed(self):
        # depends on the deploy state, the deploy can be transformed
        # to HOST_DONE (from DEPLOY_HOST) or ABORT_DONE (ABORT)
        state = DeployState.get_deploy_state()
        if state == DEPLOY_STATES.ABORT:
            self.transform(DEPLOY_STATES.ABORT_DONE)
        else:
            self.transform(DEPLOY_STATES.HOST_DONE)

    def deploy_host_failed(self):
        self.transform(DEPLOY_STATES.HOST_FAILED)

    def activate(self):
        self.transform(DEPLOY_STATES.ACTIVATE)

    def activate_completed(self):
        self.transform(DEPLOY_STATES.ACTIVATE_DONE)

    def activate_failed(self):
        self.transform(DEPLOY_STATES.ACTIVATE_FAILED)

    def completed(self):
        self.transform(None)
        # delete the deploy and deploy host entities
        db_api = get_instance()
        db_api.begin_update()
        try:
            db_api.delete_deploy_host_all()
            db_api.delete_deploy()
        finally:
            db_api.end_update()


def require_deploy_state(require_states, prompt):
    def wrap(func):
        def exec_op(*args, **kwargs):
            state = DeployState.get_deploy_state()
            if state in require_states:
                res = func(*args, **kwargs)
                return res
            else:
                msg = ""
                if prompt:
                    msg = prompt.format(state=state, require_states=require_states)
                raise InvalidOperation(msg)
        return exec_op
    return wrap
