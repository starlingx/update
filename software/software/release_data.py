#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#

import os
import shutil
import threading

from packaging import version

from software.exceptions import FileSystemError
from software.exceptions import ReleaseInvalidData
from software.exceptions import ReleaseNotFound
from software.software_functions import LOG
from software.software_functions import ReleaseData
from software import constants
from software import states
from software import utils


class SWRelease(object):
    '''wrapper class to group matching metadata and contents'''

    def __init__(self, rel_id: str, metadata, contents):
        # id: The release identifier string
        # metadata: The release metadata dictionary
        # contents: The release contents dictionary
        self._id = rel_id
        self._metadata = metadata
        self._contents = contents

        # sw_version: The release software version MM.mm.pp
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
        if self.is_product_release:
            state = self.metapackage_based_state()
        else:
            state = self.directory_based_state()
        return state

    def metapackage_based_state(self):
        mp_states = []
        for _, metadata in self.metapackages.items():
            mp_states.append(metadata["state"])

        if all(state in [states.AVAILABLE, states.DEPLOY_SELECTED] for state in mp_states):
            return states.AVAILABLE
        elif all(state == states.UNAVAILABLE for state in mp_states):
            return states.UNAVAILABLE
        elif all(state in [states.DEPLOYED, states.REMOVE_SELECTED] for state in mp_states):
            return states.DEPLOYED
        elif states.DEPLOYING in mp_states:
            return states.DEPLOYING
        elif states.REMOVING in mp_states:
            return states.REMOVING
        elif (any(mp in mp_states for mp in (states.AVAILABLE, states.DEPLOY_SELECTED)) and
              states.DEPLOYED in mp_states):
            return states.DEPLOYED_PARTIAL
        elif (any(mp in mp_states for mp in (states.DEPLOYED, states.REMOVE_SELECTED)) and
              states.AVAILABLE in mp_states):
            return states.DEPLOYED_PARTIAL
        return None  # unexpected combination of metapackage states

    def directory_based_state(self):
        return self.metadata.get('state')

    @staticmethod
    def _ensure_state_transition(to_state):
        # Ignore non-existing states on the dictionaries
        dirs = filter(None, [
            states.RELEASE_STATE_TO_DIR_MAP.get(to_state),
            states.COMPONENT_RELEASE_STATE_TO_DIR_MAP.get(to_state),
        ])
        for to_dir in dirs:
            if not os.path.isdir(to_dir):
                try:
                    os.makedirs(to_dir, mode=0o755, exist_ok=True)
                except FileExistsError:
                    error = "Cannot create directory %s" % to_dir
                    raise FileSystemError(error)

    def update_state(self, state):
        LOG.info("%s state from %s to %s" % (self.id, self.state, state))
        SWRelease._ensure_state_transition(state)
        state_dir_map = states.RELEASE_STATE_TO_DIR_MAP
        if self.is_metapackage_release:
            state_dir_map = states.COMPONENT_RELEASE_STATE_TO_DIR_MAP

        to_dir = state_dir_map[state]
        from_dir = state_dir_map[self.state]
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
        if self.is_product_release:
            rr = self._metapackage_based_rr()
        else:
            rr = self._legacy_based_rr()
        return rr

    def _metapackage_based_rr(self):
        reboot_required = True
        for mp in self.metapackages:
            mp_data = self.metapackages[mp]
            if mp_data["reboot_required"] == "Y":
                # If at least one metapackages is Reboot Required,
                # the release is Reboot Required.
                reboot_required = True
                break
            if mp_data["deployable"] == "Y":
                # If the product release was uploaded as an ISO,
                # i.e. the metapackages are all deployable=False,
                # the release is Reboot Required.
                reboot_required = False
        return reboot_required

    def _legacy_based_rr(self):
        return self._get_by_key('reboot_required') == "Y"

    @property
    def prepatched_iso(self):
        return self._get_by_key('prepatched_iso') == "Y"

    @property
    def preinstalled_patches(self):
        return self._get_by_key('preinstalled_patches') or []

    @property
    def requires_release_ids(self):
        return self._get_by_key('requires') or []

    @property
    def packages(self):
        return self._get_by_key('packages') or []

    @property
    def activation_scripts(self):
        return self._get_by_key('activation_scripts') or []

    @property
    def pre_start(self):
        return self._get_by_key('pre_start')

    @property
    def post_start(self):
        return self._get_by_key('post_start')

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

    @property
    def deployable(self):
        return self._get_by_key('deployable') == "Y"

    @property
    def metapackages(self):
        return self._get_by_key('metapackages')

    @property
    def product(self):
        return self._get_by_key('product')

    @property
    def is_product_release(self):
        """Indicates whether this release is a product release.

        A product release represents the top-level layer in the release hierarchy.
        It defines a product and acts as a container for one or more metapackage
        releases. A release is identified as a product release when it has
        associated metapackages.
        """
        return self.metapackages is not None

    @property
    def is_metapackage_release(self):
        """Indicates whether this release is a metapackage release.

        A metapackage release represents the second layer in the release hierarchy.
        Multiple metapackage releases compose a single product release, allowing
        the system to be patched at a finer granularity than the product level.
        A release is identified as a metapackage release when it is associated
        with a parent product.
        """
        return self.product is not None

    @property
    def is_legacy_release(self):
        """Indicates whether this release follows the legacy release model.

        A legacy release predates the two-layer hierarchy. Under the legacy model,
        only the product layer existed and could be deployed directly, with no
        metapackage subdivision. A release is classified as legacy when it is
        neither a product release nor a metapackage release.
        """
        return not self.is_metapackage_release and not self.is_product_release

    @property
    def metapackage_dir(self):
        if self.is_metapackage_release:
            return os.path.join(constants.COMPONENT_SOFTWARE_STORAGE_DIR,
                                self.sw_release, self.component)
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
                "preinstalled_patches": self.preinstalled_patches[:],
                "requires": self.requires_release_ids[:],
                "activation_scripts": self.activation_scripts[:],
                "metapackages": {},
                "packages": []}
        if self.is_product_release:
            # For product releases, the pkg section is present only in
            # the metapackage metadata.
            data["metapackages"] = {mp: {} for mp in self.metapackages}
            for metapackage in self.metapackages:
                metapackage_data = self.metapackages[metapackage]
                if "packages" in metapackage_data:
                    data["packages"].extend(metapackage_data["packages"])
                if "state" in metapackage_data:
                    data["metapackages"][metapackage]["state"] = metapackage_data["state"]
            data["packages"].sort()
        elif self.packages:
            # Legacy releases have a pkg section in their metadata
            data["packages"] = sorted(self.packages[:])

        return data


class MetapackageDeploymentSet:
    """Encapsulate a set of SWRelease instances of metapackages to be deployed"""

    # TODO(heitormatsui): currently it will support only deploying metapackages
    #  belonging to a single product release at once, remove this limitation in the future
    def __init__(self, metapackages):
        """
        :param metapackages: list of SWRelease metapackages
        """
        if not metapackages:
            raise ReleaseInvalidData("Cannot deploy an empty list of metapackages")

        # Filter out no-op metapackages (already in target state) that won't be in selected state
        metapackages = [mp for mp in metapackages if mp.state in states.COMPONENT_SELECTED_STATES]

        if not metapackages:
            raise ReleaseInvalidData("All metapackages are already in the target state")

        self._metapackages = metapackages

        sw_releases = {mp.sw_release for mp in self._metapackages}
        if len(sw_releases) > 1:
            raise ReleaseInvalidData(f"Cannot deploy multiple releases: {', '.join(sw_releases)}")
        self._sw_release = sw_releases.pop()
        self._sw_version = self._metapackages[0].sw_version  # yy.mm
        self._version_obj = version.parse(self.sw_release)

        # Commit-ids stored in a set as there may be more than one when removing a product release
        self._commit_id = {mp.commit_id for mp in self._metapackages
                           if mp.commit_id is not None}
        self._base_commit_id = {mp.base_commit_id for mp in self._metapackages
                                if mp.base_commit_id is not None}

        # Review the filtered set of metapackages states
        mp_states = {mp.state for mp in self._metapackages}
        if len(mp_states) > 1:
            raise ReleaseInvalidData(f"Cannot deploy metapackages in different "
                                     f"states: {', '.join(mp_states)}")
        self._state = self._metapackages[0].state

        all_rr = {mp.reboot_required for mp in self._metapackages}
        if True in all_rr:
            self._reboot_required = True
        else:
            self._reboot_required = False

    def __str__(self):
        return ", ".join(self.metapackage_ids)

    def __iter__(self):
        return iter(self.metapackages)

    @property
    def product(self):
        return self._metapackages[0].product

    @property
    def metapackage_ids(self):
        return [mp.id for mp in self._metapackages]

    @property
    def metapackages(self):
        return self._metapackages

    @property
    def sw_release(self):
        return self._sw_release

    @property
    def sw_version(self):
        return self._sw_version

    @property
    def commit_id(self):
        return self._commit_id

    @property
    def base_commit_id(self):
        return self._base_commit_id

    @property
    def state(self):
        return self._state

    @property
    def reboot_required(self):
        return self._reboot_required

    @property
    def version_obj(self):
        """returns packaging.version object"""
        return self._version_obj

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


class SWReleaseCollection(object):
    '''SWReleaseCollection encapsulates aggregated software release collection
       managed by USM.
    '''

    def __init__(self, release_data):
        self._sw_releases = {}
        self._sw_metapackages = {}
        for rel_id in release_data.metadata:
            rel_data = release_data.metadata[rel_id]
            contents = release_data.contents[rel_id]
            sw_release = SWRelease(rel_id, rel_data, contents)
            if sw_release.is_product_release:
                for mp in sw_release.metapackages:
                    mp_data = sw_release.metapackages[mp]
                    mp_contents = sw_release.contents["metapackages"][mp]
                    mp_release = SWRelease(mp, mp_data, mp_contents)
                    self._sw_metapackages[mp] = mp_release
            self._sw_releases[rel_id] = sw_release

    def _running_release(self, partial=False):
        latest = None
        state_filter = [states.DEPLOYED, states.UNAVAILABLE]
        if partial:
            state_filter += [states.DEPLOYED_PARTIAL]
        for state in state_filter:
            for rel in self.iterate_releases_by_state(state):
                if latest is None or rel.version_obj > latest.version_obj:
                    latest = rel
        return latest

    @property
    def running_release(self):
        """Return the highest fully deployed release"""
        return self._running_release()

    @property
    def highest_release(self):
        """Return the highest deployed release, even if deployed-partial"""
        return self._running_release(partial=True)

    def get_release_by_id(self, rel_id):
        if rel_id in self._sw_releases:
            return self._sw_releases[rel_id]
        if rel_id in self._sw_metapackages:
            return self._sw_metapackages[rel_id]
        return None

    def __getitem__(self, rel_id):
        return self.get_release_by_id(rel_id)

    def get_release_by_commit_id(self, commit_id):
        for _, sw_release in self._sw_releases.items():
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

    def get_product_release_by_id(self, product_id):
        if product_id in self._sw_releases:
            return self._sw_releases[product_id]
        return None

    def get_metapackage_release_by_id(self, metapackage_id):
        if metapackage_id in self._sw_metapackages:
            return self._sw_metapackages[metapackage_id]
        return None

    def get_metapackages_id_by_product_id(self, product_id):
        if product_id in self._sw_releases:
            product_data = self._sw_releases[product_id]
            metapackages = []
            for mp in product_data.metapackages:
                metapackages.append(mp)
            return metapackages
        return None

    def get_product_release_by_metapackage_id(self, metapackage_id):
        if metapackage_id in self._sw_metapackages:
            metapackage_data = self._sw_metapackages[metapackage_id]
            if metapackage_data.product in self._sw_releases:
                return self._sw_releases[metapackage_data.product]
        return None

    def get_ordered_metapackages(self, **kwargs):
        '''
        Return a ordered list of metapackages. It can be filtered by state and formatted
        into a tuple with metapackage component and release, or any single metapackage
        property value.

        :param filter_by_states: list of states to be filtered in release collection.
        :param tuple_format: boolean value to format the filtered list in tuple format.
        E.g.: [(metapackage.component, metapackage.sw_release)]
        :param property_format: string representing a metapackage property name to
        format the filtered list.
        E.g.: property_format="id" -> [metapackage.id]
        E.g.: property_format="component" -> [metapackage.component]
        '''
        filter_by_states = kwargs.get("filter_by_states", [])
        if not isinstance(filter_by_states, list):
            filter_by_states = []

        filtered_metapackages = []
        sorted_list = sorted(self._sw_metapackages)
        if not filter_by_states:
            # Order metapackage list
            filtered_metapackages = [self._sw_metapackages[rel_id] for rel_id in sorted_list]
        else:
            # Apply filters to the ordered list
            for rel_id in sorted_list:
                rel_data = self._sw_metapackages[rel_id]
                if filter_by_states and rel_data.state in filter_by_states:
                    filtered_metapackages.append(rel_data)

        # Define format
        formatted_metapackages = []
        if kwargs.get("tuple_format", False):
            formatted_metapackages.extend(
                [(metapackage.component, metapackage.sw_release) for metapackage in filtered_metapackages])
        elif kwargs.get("property_format", None):
            property = kwargs["property_format"]
            formatted_metapackages.extend(
                [getattr(metapackage, property) for metapackage in filtered_metapackages])
        else:
            formatted_metapackages = filtered_metapackages

        return formatted_metapackages

    def iterate_releases_by_state(self, state):
        '''
        Return iteration of releases matching specified state.
        Sorted by id in ascending order
        '''
        sorted_list = sorted(self._sw_releases)
        for rel_id in sorted_list:
            rel_data = self._sw_releases[rel_id]
            if rel_data.state == state:
                yield rel_data

    def iterate_releases(self):
        '''
        Return iteration of all releases sorted by id in ascending order
        '''
        sorted_list = sorted(self._sw_releases)
        for rel_id in sorted_list:
            yield self._sw_releases[rel_id]

    def iterate_metapackages(self, state=None, query_all=False):
        '''
        Return iteration of metapackage data dicts. Can be filtered by state
        or all metapackages. Default output is the latest deployed version of
        each metapackage.

        Conditions:
        1) If state is provided, yield metapackages matching that state
           (regardless of query_all).
        2) If query_all is True and state is None, yield all metapackages.
        3) If state is None and query_all is False, for each metapackage name
           yield only the one from the latest release version that is in
           DEPLOYED state.
        '''
        if state is not None:
            # Case 1: filter by state
            for mp in self._sw_metapackages:
                mp_data = self._sw_metapackages[mp]
                if mp_data.state == state:
                    yield mp_data
        elif query_all:
            # Case 2: yield all metapackages
            for mp in self._sw_metapackages:
                mp_data = self._sw_metapackages[mp]
                yield mp_data
        else:
            # Case 3: for each metapackage name, yield only the instance
            # from the latest release version that is in DEPLOYED state
            latest_deployed = {}
            for mp in self._sw_metapackages:
                mp_data = self._sw_metapackages[mp]
                # The state remove-selected is semantically deployed as well
                if mp_data.state in [states.DEPLOYED, states.REMOVE_SELECTED]:
                    latest_mp = latest_deployed.get(mp_data.component)
                    if not latest_mp or mp_data > latest_mp:
                        latest_deployed[mp_data.component] = mp_data
            for mp in latest_deployed:
                yield latest_deployed[mp]

    def iterate_metapackages_by_state(self, filter_states):
        '''
        Return iteration of metapackage releases matching specified state.
        Sorted by id in ascending order
        '''
        if not isinstance(filter_states, list):
            filter_states = [filter_states]
        sorted_list = sorted(self._sw_metapackages)
        for rel_id in sorted_list:
            rel_data = self._sw_metapackages[rel_id]
            if rel_data.state in filter_states:
                yield rel_data

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
        release_data = ReleaseData()
        release_data.load_all()
        _local_storage.set_value('release_data', release_data)

    return SWReleaseCollection(release_data)


def reload_release_data():
    _local_storage.void_value('release_data')
