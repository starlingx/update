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

    # deploy start
    DEPLOY_STATES.START: [DEPLOY_STATES.START_DONE, DEPLOY_STATES.START_FAILED],
    DEPLOY_STATES.START_FAILED: [],  # waiting to be deleted
    DEPLOY_STATES.START_DONE: [DEPLOY_STATES.HOST],

    # deploy host
    DEPLOY_STATES.HOST: [DEPLOY_STATES.HOST,
                         DEPLOY_STATES.HOST_FAILED,
                         DEPLOY_STATES.HOST_DONE,
                         DEPLOY_STATES.HOST_ROLLBACK],
    DEPLOY_STATES.HOST_FAILED: [DEPLOY_STATES.HOST,  # deploy host is reentrant
                                DEPLOY_STATES.HOST_FAILED,
                                DEPLOY_STATES.HOST_DONE,
                                DEPLOY_STATES.HOST_ROLLBACK],
    DEPLOY_STATES.HOST_DONE: [DEPLOY_STATES.ACTIVATE, DEPLOY_STATES.HOST_ROLLBACK,
                              DEPLOY_STATES.HOST_FAILED],  # manual recovery scenario

    # deploy host rollback
    DEPLOY_STATES.HOST_ROLLBACK: [DEPLOY_STATES.HOST_ROLLBACK,
                                  DEPLOY_STATES.HOST_ROLLBACK_FAILED,
                                  DEPLOY_STATES.HOST_ROLLBACK_DONE],
    DEPLOY_STATES.HOST_ROLLBACK_FAILED: [DEPLOY_STATES.HOST_ROLLBACK,  # deploy host rollback is reentrant
                                         DEPLOY_STATES.HOST_ROLLBACK_DONE],
    DEPLOY_STATES.HOST_ROLLBACK_DONE: [],  # waiting to be deleted

    # deploy activate
    DEPLOY_STATES.ACTIVATE: [DEPLOY_STATES.ACTIVATE_DONE, DEPLOY_STATES.ACTIVATE_FAILED],
    DEPLOY_STATES.ACTIVATE_FAILED: [DEPLOY_STATES.ACTIVATE,  # deploy activate is reentrant
                                    DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING],
    DEPLOY_STATES.ACTIVATE_DONE: [DEPLOY_STATES.COMPLETED, DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING],

    # deploy activate rollback
    DEPLOY_STATES.ACTIVATE_ROLLBACK: [DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE, DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED],
    DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE: [DEPLOY_STATES.HOST_ROLLBACK],
    DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED: [DEPLOY_STATES.ACTIVATE_ROLLBACK],  # deploy activate rollback is reentrant
    DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING: [DEPLOY_STATES.ACTIVATE_ROLLBACK],

    # deploy complete
    DEPLOY_STATES.COMPLETED: [DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING, None]
}

deploy_reentrant_states = [DEPLOY_STATES.START_DONE,
                           DEPLOY_STATES.ACTIVATE_DONE,
                           DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE]


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
        current_state = DeployState.get_deploy_state()
        all_states = []
        for deploy_host in deploy_hosts:
            if deploy_host['state'] not in all_states:
                all_states.append(deploy_host['state'])

        LOG.info("Host deploy state %s" % str(all_states))
        if current_state in [DEPLOY_STATES.HOST, DEPLOY_STATES.HOST_FAILED,
                             DEPLOY_STATES.HOST_ROLLBACK, DEPLOY_STATES.HOST_ROLLBACK_FAILED]:
            if any(state in all_states for state in
                   [DEPLOY_HOST_STATES.FAILED.value,
                    DEPLOY_HOST_STATES.ROLLBACK_FAILED.value]):
                deploy_state.deploy_host_failed()
            elif any(state in all_states for state in
                     [DEPLOY_HOST_STATES.PENDING.value,
                      DEPLOY_HOST_STATES.DEPLOYING.value,
                      DEPLOY_HOST_STATES.ROLLBACK_PENDING.value,
                      DEPLOY_HOST_STATES.ROLLBACK_DEPLOYING.value]):
                deploy_state.deploy_host()
            elif (all_states == [DEPLOY_HOST_STATES.DEPLOYED.value] or
                  all_states == [DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED.value]):
                deploy_state.deploy_host_done()

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

        # Below is to tolerate reentrant of certain states.
        # by doing this it can simplify the workflow code to fire deploy_done
        # event more than once.
        # As "done" states are reported from an external process,
        # there could be race condition and double report could happen.
        # We should not fail the operation if it is the case
        if target_state == cur_state and cur_state in deploy_reentrant_states:
            return True

        return False

    def transform(self, target_state: DEPLOY_STATES):
        cur_state = DeployState.get_deploy_state()
        db_api = get_instance()
        db_api.begin_update()
        try:
            if self.check_transition(target_state):
                # None means not existing or deleting
                if target_state is not None:
                    db_api.update_deploy(state=target_state)
                    msg = f"[deploy state] from {cur_state.value} to {target_state.value}"
                    LOG.info(msg)
                else:
                    LOG.info("[deploy state] Deploy is deleted")
            else:
                # TODO(bqian) check the current state, and provide guidence on what is
                # the possible next operation
                if target_state is None:
                    msg = f"Can not delete deploy as it is {cur_state.value}."
                else:
                    msg = f"Can not transform deploy to {target_state.value} from {cur_state.value}"
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

        msg = f"[deploy state] deploy ({from_release} to {to_release}) started"
        LOG.info(msg)
        db_api_instance = get_instance()
        db_api_instance.create_deploy(from_release, to_release, feed_repo, commit_id, reboot_required)

    def start_failed(self):
        self.transform(DEPLOY_STATES.START_FAILED)

    def start_done(self, commit_id=None):
        db_api_instance = get_instance()
        db_api_instance.update_deploy(commit_id=commit_id)
        self.transform(DEPLOY_STATES.START_DONE)

    def deploy_host(self):
        state = DeployState.get_deploy_state()
        if state in [DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE, DEPLOY_STATES.HOST_ROLLBACK,
                     DEPLOY_STATES.HOST_ROLLBACK_FAILED]:
            self.transform(DEPLOY_STATES.HOST_ROLLBACK)
        else:
            self.transform(DEPLOY_STATES.HOST)

    def abort(self, feed_repo, commit_id):
        # depends on the deploy state, if pre-activate then go to
        # host rollback, if post-activate then go to activate rollback
        state = DeployState.get_deploy_state()
        if state in [DEPLOY_STATES.ACTIVATE_DONE, DEPLOY_STATES.ACTIVATE_FAILED, DEPLOY_STATES.COMPLETED]:
            self.transform(DEPLOY_STATES.ACTIVATE_ROLLBACK_PENDING)
        else:
            self.transform(DEPLOY_STATES.HOST_ROLLBACK)

        db_api_instance = get_instance()
        db_api_instance.reverse_deploy(feed_repo, commit_id)

    def deploy_host_done(self):
        # depends on the deploy state, the deploy can be transformed
        # to HOST_DONE (from DEPLOY_HOST) or HOST_ROLLBACK_DONE (ABORT)
        state = DeployState.get_deploy_state()
        if state == DEPLOY_STATES.HOST_ROLLBACK:
            self.transform(DEPLOY_STATES.HOST_ROLLBACK_DONE)
        else:
            self.transform(DEPLOY_STATES.HOST_DONE)

    def deploy_host_failed(self):
        state = DeployState.get_deploy_state()
        if state == DEPLOY_STATES.HOST_ROLLBACK:
            self.transform(DEPLOY_STATES.HOST_ROLLBACK_FAILED)
        elif state in [DEPLOY_STATES.HOST_ROLLBACK_FAILED, DEPLOY_STATES.HOST_FAILED]:
            LOG.warning("Deployment is already in a failed state")
        else:
            self.transform(DEPLOY_STATES.HOST_FAILED)

    def activate(self):
        self.transform(DEPLOY_STATES.ACTIVATE)

    def activate_done(self):
        self.transform(DEPLOY_STATES.ACTIVATE_DONE)

    def activate_failed(self):
        self.transform(DEPLOY_STATES.ACTIVATE_FAILED)

    def activate_rollback(self):
        self.transform(DEPLOY_STATES.ACTIVATE_ROLLBACK)

    def activate_rollback_done(self):
        self.transform(DEPLOY_STATES.ACTIVATE_ROLLBACK_DONE)

    def activate_rollback_failed(self):
        self.transform(DEPLOY_STATES.ACTIVATE_ROLLBACK_FAILED)

    def completed(self):
        self.transform(DEPLOY_STATES.COMPLETED)


def require_deploy_state(require_states, prompt):
    def wrap(func):
        def exec_op(*args, **kwargs):
            state = DeployState.get_deploy_state()
            if state in require_states:
                res = func(*args, **kwargs)
                return res
            else:
                msg = ""
                state_text = [state.value if state is not None else 'no deployment'
                              for state in require_states]
                require_states_text = ", ".join(state_text)
                if prompt:
                    msg = prompt.format(state=state, require_states=require_states_text)
                raise InvalidOperation(msg)
        return exec_op
    return wrap
