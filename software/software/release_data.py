#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024 Wind River Systems, Inc.
#

import os
from packaging import version
import shutil
import threading
from software import states
from software.exceptions import FileSystemError
from software.exceptions import ReleaseNotFound
from software.software_functions import LOG
from software import utils
from software.software_functions import ReleaseData


class SWRelease(object):
    '''wrapper class to group matching metadata and contents'''

    def __init__(self, rel_id, metadata, contents):
        self._id = rel_id
        self._metadata = metadata
        self._contents = contents
        self._sw_version = None
        self._release = None

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
    def _ensure_state_transition(to_state):
        to_dir = states.RELEASE_STATE_TO_DIR_MAP[to_state]
        if not os.path.isdir(to_dir):
            try:
                os.makedirs(to_dir, mode=0o755, exist_ok=True)
            except FileExistsError:
                error = "Cannot create directory %s" % to_dir
                raise FileSystemError(error)

    def update_state(self, state):
        LOG.info("%s state from %s to %s" % (self.id, self.state, state))
        SWRelease._ensure_state_transition(state)

        to_dir = states.RELEASE_STATE_TO_DIR_MAP[state]
        from_dir = states.RELEASE_STATE_TO_DIR_MAP[self.state]
        try:
            shutil.move("%s/%s-metadata.xml" % (from_dir, self.id),
                        "%s/%s-metadata.xml" % (to_dir, self.id))
        except shutil.Error:
            msg = "Failed to move the metadata for %s" % self.id
            LOG.exception(msg)
            raise FileSystemError(msg)

        self.metadata['state'] = state

    @property
    def version_obj(self):
        '''returns packaging.version object'''
        if self._release is None:
            self._release = version.parse(self.sw_release)
        return self._release

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

    @property
    def component(self):
        return self._get_by_key('component')

    def _get_latest_commit(self):
        if 'number_of_commits' not in self.contents:
            return None

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

    @property
    def base_commit_id(self):
        commit = None
        base = self.contents.get('base')
        if base:
            commit = base.get('commit')
        return commit

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
        return self._get_by_key('unremovable') == "Y"

    @property
    def reboot_required(self):
        return self._get_by_key('reboot_required') == "Y"

    @property
    def prepatched_iso(self):
        return self._get_by_key('prepatched_iso') == "Y"

    @property
    def requires_release_ids(self):
        return self._get_by_key('requires') or []

    @property
    def packages(self):
        return self._get_by_key('packages')

    @property
    def pre_install(self):
        return self._get_by_key('pre_install')

    @property
    def post_install(self):
        return self._get_by_key('post_install')

    @property
    def apply_active_release_only(self):
        return self._get_by_key('apply_active_release_only')

    @property
    def commit_checksum(self):
        commit = self._get_latest_commit()
        if commit is not None:
            return commit['checksum']
        else:
            # may consider raise InvalidRelease exception when iso comes with
            # latest commit
            return None

    def get_all_dependencies(self, filter_states=None):
        """
        :return: sorted list of all direct and indirect required releases
        raise ReleaseNotFound if one of the release is not uploaded.
        """
        def _get_all_deps(release_id, release_collection, deps):
            release = release_collection[release_id]
            if release is None:
                raise ReleaseNotFound([release_id])

            if filter_states and release.state not in filter_states:
                return

            for id in release.requires_release_ids:
                if id not in deps:
                    deps.append(id)
                    _get_all_deps(id, release_collection, deps)

        all_deps = []
        release_collection = get_SWReleaseCollection()
        _get_all_deps(self.id, release_collection, all_deps)
        releases = sorted([release_collection[id] for id in all_deps])
        return releases

    def __lt__(self, other):
        return self.version_obj < other.version_obj

    def __le__(self, other):
        return self.version_obj <= other.version_obj

    def __eq__(self, other):
        return self.version_obj == other.version_obj

    def __ge__(self, other):
        return self.version_obj >= other.version_obj

    def __gt__(self, other):
        return self.version_obj > other.version_obj

    def __ne__(self, other):
        return self.version_obj != other.version_obj

    @property
    def is_ga_release(self):
        ver = version.parse(self.sw_release)
        if len(ver.release) == 2:
            pp = 0
        else:
            _, _, pp = ver.release
        return pp == 0

    @property
    def is_deletable(self):
        return self.state in states.DELETABLE_STATE

    def to_query_dict(self):
        data = {"release_id": self.id,
                "state": self.state,
                "sw_version": self.sw_release,
                "component": self.component,
                "status": self.status,
                "unremovable": self.unremovable,
                "summary": self.summary,
                "description": self.description,
                "install_instructions": self.install_instructions,
                "warnings": self.warnings,
                "reboot_required": self.reboot_required,
                "prepatched_iso": self.prepatched_iso,
                "requires": self.requires_release_ids[:],
                "packages": self.packages[:]}
        return data


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

    @property
    def running_release(self):
        latest = None
        for rel in self.iterate_releases_by_state(states.DEPLOYED):
            if latest is None or rel.version_obj > latest.version_obj:
                latest = rel

        return latest

    def get_release_by_id(self, rel_id):
        if rel_id in self._sw_releases:
            return self._sw_releases[rel_id]
        return None

    def __getitem__(self, rel_id):
        return self.get_release_by_id(rel_id)

    def get_release_by_commit_id(self, commit_id):
        for _, sw_release in self._sw_releases:
            if sw_release.commit_id == commit_id:
                return sw_release
        return None

    def get_release_id_by_sw_release(self, sw_release):
        sorted_list = sorted(self._sw_releases)
        for rel_id in sorted_list:
            rel_data = self._sw_releases[rel_id]
            if rel_data.sw_release == sw_release:
                return rel_data.id
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
                release.update_state(state)


class LocalStorage(object):
    def __init__(self):
        self._storage = threading.local()

    def get_value(self, key):
        if hasattr(self._storage, key):
            return getattr(self._storage, key)
        else:
            return None

    def set_value(self, key, value):
        setattr(self._storage, key, value)

    def void_value(self, key):
        if hasattr(self._storage, key):
            delattr(self._storage, key)


_local_storage = LocalStorage()


def get_SWReleaseCollection():
    release_data = _local_storage.get_value('release_data')
    if release_data is None:
        LOG.info("Load release_data")
        release_data = ReleaseData()
        release_data.load_all()
        LOG.info("release_data loaded")
        _local_storage.set_value('release_data', release_data)

    return SWReleaseCollection(release_data)


def reload_release_data():
    _local_storage.void_value('release_data')
