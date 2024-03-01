#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#

import os
from packaging import version
import shutil
from software import constants
from software.exceptions import FileSystemError
from software.exceptions import InternalError
from software.software_functions import LOG
from software import utils


class SWRelease(object):
    '''wrapper class to group matching metadata and contents'''

    def __init__(self, rel_id, metadata, contents):
        self._id = rel_id
        self._metadata = metadata
        self._contents = contents
        self._sw_version = None

    @property
    def metadata(self):
        return self._metadata

    @property
    def contents(self):
        return self._contents

    @property
    def id(self):
        return self._id

    @property
    def state(self):
        return self.metadata['state']

    @staticmethod
    def is_valid_state_transition(from_state, to_state):
        if to_state not in constants.VALID_RELEASE_STATES:
            msg = "Invalid state %s." % to_state
            LOG.error(msg)
            # this is a bug
            raise InternalError(msg)

        if from_state in constants.RELEASE_STATE_VALID_TRANSITION:
            if to_state in constants.RELEASE_STATE_VALID_TRANSITION[from_state]:
                return True
        return False

    @staticmethod
    def ensure_state_transition(to_state):
        to_dir = constants.RELEASE_STATE_TO_DIR_MAP[to_state]
        if not os.path.isdir(to_dir):
            try:
                os.makedirs(to_dir, mode=0o755, exist_ok=True)
            except FileExistsError:
                error = "Cannot create directory %s" % to_dir
                raise FileSystemError(error)

    def update_state(self, state):
        if SWRelease.is_valid_state_transition(self.state, state):
            LOG.info("%s state from %s to %s" % (self.id, self.state, state))
            SWRelease.ensure_state_transition(state)

            to_dir = constants.RELEASE_STATE_TO_DIR_MAP[state]
            from_dir = constants.RELEASE_STATE_TO_DIR_MAP[self.state]
            try:
                shutil.move("%s/%s-metadata.xml" % (from_dir, self.id),
                            "%s/%s-metadata.xml" % (to_dir, self.id))
            except shutil.Error:
                msg = "Failed to move the metadata for %s" % self.id
                LOG.exception(msg)
                raise FileSystemError(msg)

            self.metadata['state'] = state
        else:
            # this is a bug
            error = "Invalid state transition %s, current is %s, target state is %s" % \
                    (self.id, self.state, state)
            LOG.info(error)
            raise InternalError(error)

    @property
    def sw_release(self):
        '''3 sections MM.mm.pp release version'''
        return self.metadata['sw_version']

    @property
    def sw_version(self):
        '''2 sections MM.mm software version'''
        if self._sw_version is None:
            self._sw_version = utils.get_major_release_version(self.sw_release)
        return self._sw_version

    def _get_latest_commit(self):
        num_commits = self.contents['number_of_commits']
        if int(num_commits) > 0:
            commit_tag = "commit%s" % num_commits
            return self.contents[commit_tag]
        else:
            # may consider raise InvalidRelease exception in this case after
            # iso metadata comes with commit id
            LOG.warning("Commit data not found in metadata. Release %s" %
                        self.id)
            return None

    @property
    def commit_id(self):
        commit = self._get_latest_commit()
        if commit is not None:
            return commit['commit']
        else:
            # may consider raise InvalidRelease exception when iso comes with
            # latest commit
            return None

    def _get_by_key(self, key, default=None):
        if key in self._metadata:
            return self._metadata[key]
        else:
            return default

    @property
    def summary(self):
        return self._get_by_key('summary')

    @property
    def description(self):
        return self._get_by_key('description')

    @property
    def install_instructions(self):
        return self._get_by_key('install_instructions')

    @property
    def warnings(self):
        return self._get_by_key('warnings')

    @property
    def status(self):
        return self._get_by_key('status')

    @property
    def unremovable(self):
        return self._get_by_key('unremovable')

    @property
    def reboot_required(self):
        return self._get_by_key('reboot_required')

    @property
    def restart_script(self):
        return self._get_by_key('restart_script')

    @property
    def commit_checksum(self):
        commit = self._get_latest_commit()
        if commit is not None:
            return commit['checksum']
        else:
            # may consider raise InvalidRelease exception when iso comes with
            # latest commit
            return None

    @property
    def is_ga_release(self):
        ver = version.parse(self.sw_release)
        _, _, pp = ver.release
        return pp == 0

    @property
    def is_deletable(self):
        return self.state in constants.DELETABLE_STATE


class SWReleaseCollection(object):
    '''SWReleaseCollection encapsulates aggregated software release collection
       managed by USM.
    '''

    def __init__(self, release_data):
        self._sw_releases = {}
        for rel_id in release_data.metadata:
            rel_data = release_data.metadata[rel_id]
            contents = release_data.contents[rel_id]
            sw_release = SWRelease(rel_id, rel_data, contents)
            self._sw_releases[rel_id] = sw_release

    def get_release_by_id(self, rel_id):
        if rel_id in self._sw_releases:
            return self._sw_releases[rel_id]
        return None

    def get_release_by_commit_id(self, commit_id):
        for _, sw_release in self._sw_releases:
            if sw_release.commit_id == commit_id:
                return sw_release
        return None

    def iterate_releases_by_state(self, state):
        '''return iteration of releases matching specified state.
        sorted by id in ascending order
        '''
        sorted_list = sorted(self._sw_releases)
        for rel_id in sorted_list:
            rel_data = self._sw_releases[rel_id]
            if rel_data.metadata['state'] == state:
                yield rel_data

    def iterate_releases(self):
        '''return iteration of all releases sorted by id in ascending order'''
        sorted_list = sorted(self._sw_releases)
        for rel_id in sorted_list:
            yield self._sw_releases[rel_id]

    def update_state(self, list_of_releases, state):
        for release_id in list_of_releases:
            release = self.get_release_by_id(release_id)
            if release is not None:
                if SWRelease.is_valid_state_transition(release.state, state):
                    SWRelease.ensure_state_transition(state)
            else:
                LOG.error("release %s not found" % release_id)

        for release_id in list_of_releases:
            release = self.get_release_by_id(release_id)
            if release is not None:
                release.update_state(state)
