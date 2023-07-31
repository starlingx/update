"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import List

from software.utils import check_instances, check_state

LOG = logging.getLogger('main_logger')


class Release(ABC):

    def __init__(self):
        self.states = Enum('States', 'active deploying inactive')

    @abstractmethod
    def create(self, rel_ver: str, state: str):
        """
        Create a new release with the given release version and state

        :param rel_ver: The release version.
        :param state: The state of the release (active, deploying..).
        """
        check_instances([rel_ver, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def query(self, rel_ver: str):
        """
        Get information about a release based on its version.

        :param rel_ver: The release version.
        """
        check_instances([rel_ver], str)
        pass

    @abstractmethod
    def update(self, rel_ver: str, state: str):
        """
        Update the state of release based on its version.

        :param rel_ver: The release version
        :param state: The update state of the release.

        """
        check_instances([rel_ver, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def delete(self, rel_ver: str):
        """
        Delete a release based on its version.

        :param rel_ver: The release version.
        """
        check_instances([rel_ver], str)
        pass


class CompatibleRelease(ABC):

    @abstractmethod
    def create(self, rel_ver: str, compatible_ver: str, required_patches: List[str]):
        """
        Create a new compatible release entry.

        :param rel_ver: The release version.
        :param compatible_ver: The compatible release version
        :param required_patches: A list of required patches for compatibility

        """
        check_instances([rel_ver, compatible_ver], str)
        check_instances(required_patches, str)
        pass

    @abstractmethod
    def query(self, rel_ver: str):
        """
        Get compatible releases for a given release version.

        :param rel_ver: The release version

        """
        check_instances([rel_ver], str)
        pass

    @abstractmethod
    def update(self, rel_ver: str, compatible_ver: str, required_patches: List[str]):
        """
        Update a compatible release entry

        :param rel_ver: The release version.
        :param compatible_ver: The compatible release version
        :param required_patches: A list of required patches for compatibility

        """
        check_instances([rel_ver, compatible_ver], str)
        check_instances(required_patches, str)
        pass

    @abstractmethod
    def delete(self, rel_ver: str):
        """
        Delete compatible releases for a given release version.

        :param rel_ver: The release version.

        """
        check_instances([rel_ver], str)
        pass


class Deploy(ABC):

    def __init__(self):
        self.states = Enum('States', 'activate-failed activated '
                                     'data-migration-failed data-migration '
                                     'activating prestaged prestaging '
                                     'prestaging-failed '
                                     'upgrade-controller-failed upgrade-controllers '
                                     'upgrade-hosts')

    @abstractmethod
    def create(self, from_release: str, to_release: str, state: str):
        """
        Create a new deployment entry.

        :param from_release: The source release version.
        :param to_release: The target release version.
        :param state: The state of the deployment.

        """
        check_instances([from_release, to_release, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def query(self, from_release: str, to_release: str):
        """
        Get deployments based on source and target release versions.

        :param from_release: The source release version.
        :param to_release: The target release version.

        """
        check_instances([from_release, to_release], str)
        pass

    @abstractmethod
    def update(self, from_release: str, to_release: str, state: str):
        """
        Update a deployment entry.

        :param from_release: The source release version.
        :param to_release: The target release version.
        :param state: The state of the deployment.

        """
        check_instances([from_release, to_release, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def delete(self, from_release: str, to_release: str):
        """
        Delete a deployment entry based on source and target release versions.

        :param from_release: The source release version.
        :param to_release: The target release version.
        """
        check_instances([from_release, to_release], str)
        pass


class DeployHosts(ABC):

    def __init__(self):
        self.states = Enum('States', 'completed failed pending ready')

    @abstractmethod
    def create(self, host_name: str, software_release: str, target_release: str, state: str):
        """
        Create a new deploy-host entry

        :param host_name: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.
        :param state: The state of the deploy-host entry.

        """
        check_instances([host_name, software_release, target_release, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def query(self, host_name: str):
        """
        Get deploy-host entries for a given host.

        :param host_name: The name of the host.

        """
        check_instances([host_name], str)
        pass

    @abstractmethod
    def update(self, host_name: str, software_release: str, target_release: str, state: str):
        """
        update a deploy-host entry

        :param host_name: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.
        :param state: The state of the deploy-host entry.
        """
        check_instances([host_name, software_release, target_release, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def delete(self, host_name: str):
        """
        Delete deploy-host entries for a given host.

        :param host_name: The name of the host.
        """
        check_instances([host_name], str)
        pass
