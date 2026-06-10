#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#

import logging

from software.exceptions import ReleaseNotFound
from software.release_data import get_SWReleaseCollection
from software.release_data import reload_release_data
from software import states


LOG = logging.getLogger('main_logger')

# valid release state transition below will still be changed as
# development continue
RELEASE_STATE_TRANSITION = {
    states.AVAILABLE: [states.DEPLOYING, states.UNAVAILABLE, states.DEPLOY_SELECTED],
    states.DEPLOYING: [states.DEPLOYED, states.AVAILABLE],
    states.DEPLOYED: [states.REMOVING, states.UNAVAILABLE, states.COMMITTED, states.REMOVE_SELECTED],
    states.REMOVING: [states.AVAILABLE],
    states.COMMITTED: [],
    states.UNAVAILABLE: [],
    states.DEPLOY_SELECTED: [states.DEPLOYING, states.AVAILABLE],
    states.REMOVE_SELECTED: [states.REMOVING, states.DEPLOYED],
}


class ReleaseState(object):
    _callbacks = []

    def __init__(self, release_ids=None, release_state=None):
        not_found_list = []
        release_list = []

        self._release_ids = []

        release_collection = get_SWReleaseCollection()
        if release_state:
            release_ids = [rel.id for rel in
                           release_collection.iterate_releases_by_state(release_state)]

        if release_ids:
            for rel_id in release_ids:
                rel = release_collection[rel_id]
                if rel is None:
                    not_found_list.append(rel_id)
                # If product release, return its metapackages
                elif rel.is_product_release:
                    release_list.extend(rel.metapackages.keys())
                # If legacy release, return the release itself
                else:
                    release_list.append(rel_id)
            self._release_ids = release_list[:]

        if len(not_found_list) > 0:
            raise ReleaseNotFound(not_found_list)

    @staticmethod
    def register_event_listener(callback):
        """register event listener to be triggered when a state transition is completed"""
        if callback is not None:
            if callback not in ReleaseState._callbacks:
                LOG.debug("Register event listener %s", callback.__qualname__)
                ReleaseState._callbacks.append(callback)

    @staticmethod
    def deploy_updated(target_state):
        if target_state is None:
            deploying = ReleaseState(release_state=states.DEPLOYING)

            if deploying.is_major_release_deployment():
                deployed = ReleaseState(release_state=states.DEPLOYED)
                deployed.replaced()

            deploying.deploy_completed()

    def check_transition(self, target_state):
        """check ALL releases can transform to target state"""
        release_collection = get_SWReleaseCollection()
        for rel_id in self._release_ids:
            state = release_collection[rel_id].state
            if target_state not in RELEASE_STATE_TRANSITION[state]:
                return False
        return True

    def transform(self, target_state):
        if self.check_transition(target_state):
            release_collection = get_SWReleaseCollection()
            release_collection.update_state(self._release_ids, target_state)
        reload_release_data()

        for callback in ReleaseState._callbacks:
            LOG.debug("Calling event listener %s", callback.__qualname__)
            callback(target_state)

    def is_major_release_deployment(self):
        release_collection = get_SWReleaseCollection()
        for rel_id in self._release_ids:
            release = release_collection.get_release_by_id(rel_id)
            if release.is_ga_release:
                return True
            elif release.prepatched_iso:
                return True
        return False

    def is_patched_major_release_deployment(self):
        release_collection = get_SWReleaseCollection()
        for rel_id in self._release_ids:
            release = release_collection.get_release_by_id(rel_id)
            if release.prepatched_iso:
                return True
        return False

    def has_release_id(self):
        return self._release_ids is not None and len(self._release_ids) > 0

    def get_release_ids(self):
        return self._release_ids

    def available(self):
        self.transform(states.AVAILABLE)

    def start_deploy(self):
        self.transform(states.DEPLOYING)

    def deploy_selected(self):
        self.transform(states.DEPLOY_SELECTED)

    def deploy_unselected(self):
        self.transform(states.AVAILABLE)

    def remove_selected(self):
        self.transform(states.REMOVE_SELECTED)

    def remove_unselected(self):
        self.transform(states.DEPLOYED)

    def deploy_completed(self):
        self.transform(states.DEPLOYED)

    def committed(self):
        self.transform(states.COMMITTED)

    def replaced(self):
        """
        Current running release is replaced with a new deployed release
        This indicates a major release deploy is completed and running
        release become "unavailable"
        """
        self.transform(states.UNAVAILABLE)

    def start_remove(self):
        self.transform(states.REMOVING)
