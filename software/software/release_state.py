#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
import logging

from software import states
from software.exceptions import ReleaseNotFound
from software.release_data import get_SWReleaseCollection
from software.release_data import reload_release_data


LOG = logging.getLogger('main_logger')

# valid release state transition below will still be changed as
# development continue
release_state_transition = {
    states.AVAILABLE: [states.DEPLOYING, states.UNAVAILABLE],
    states.DEPLOYING: [states.DEPLOYED, states.AVAILABLE],
    states.DEPLOYED: [states.REMOVING, states.UNAVAILABLE, states.COMMITTED],
    states.REMOVING: [states.AVAILABLE],
    states.COMMITTED: [],
    states.UNAVAILABLE: [],
}


class ReleaseState(object):
    def __init__(self, release_ids=None, release_state=None):
        not_found_list = []
        release_collection = get_SWReleaseCollection()
        if release_ids:
            self._release_ids = release_ids[:]
            not_found_list = [rel_id for rel_id in release_ids if release_collection[rel_id] is None]
        elif release_state:
            self._release_ids = [rel.id for rel in release_collection.iterate_releases_by_state(release_state)]

        if len(not_found_list) > 0:
            raise ReleaseNotFound(not_found_list)

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
            if target_state not in release_state_transition[state]:
                return False
        return True

    def transform(self, target_state):
        if self.check_transition(target_state):
            release_collection = get_SWReleaseCollection()
            release_collection.update_state(self._release_ids, target_state)

        reload_release_data()

    def is_major_release_deployment(self):
        release_collection = get_SWReleaseCollection()
        for rel_id in self._release_ids:
            release = release_collection.get_release_by_id(rel_id)
            if release.is_ga_release:
                return True
        return False

    def available(self):
        self.transform(states.AVAILABLE)

    def start_deploy(self):
        self.transform(states.DEPLOYING)

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
