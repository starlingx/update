"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging
from abc import ABC
from abc import abstractmethod
from enum import Enum
from typing import List

from software import constants
from software.exceptions import DeployDoNotExist
from software.exceptions import DeployAlreadyExist
from software.utils import check_instances
from software.utils import check_state
from software.utils import save_to_json_file
from software.utils import get_software_filesystem_data
from software.utils import validate_versions

from software.constants import DEPLOY_STATES

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
        pass

    @abstractmethod
    def create(self, from_release: str, to_release: str, reboot_required: bool, state: DEPLOY_STATES):
        """
        Create a new deployment entry.

        :param from_release: The source release version.
        :param to_release: The target release version.
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.

        """
        validate_versions([from_release, to_release])
        check_instances([reboot_required], bool)
        check_instances([state], DEPLOY_STATES)

    @abstractmethod
    def query(self):
        """
        Get deployments based on source and target release versions.
        """
        pass

    @abstractmethod
    def update(self, new_state: DEPLOY_STATES):
        """
        Update a deployment entry.

        :param state: The state of the deployment.

        """
        check_instances([new_state], DEPLOY_STATES)

    @abstractmethod
    def delete(self):
        """
        Delete a deployment entry based on source and target release versions.
        """
        pass


class DeployHosts(ABC):

    def __init__(self):
        self.states = Enum('States', 'aborted deployed deploying failed pending-deploy')

    @abstractmethod
    def create(self, hostname: str, state: str):
        """
        Create a new deploy-host entry

        :param hostname: The name of the host.
        :param state: The state of the deploy-host entry.

        """
        instances = [hostname]
        if state:
            check_state(state, self.states)
            instances.append(state)
        check_instances(instances, str)
        pass

    @abstractmethod
    def query(self, hostname: str):
        """
        Get deploy-host entries for a given host.

        :param hostname: The name of the host.

        """
        check_instances([hostname], str)
        pass

    @abstractmethod
    def update(self, hostname: str, state: str):
        """
        Update a deploy-host entry

        :param hostname: The name of the host.
        :param state: The state of the deploy-host entry.
        """
        check_instances([hostname, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def delete(self, hostname):
        """
        Delete deploy-host entries for a given host.

        :param hostname: The name of the host.
        """
        check_instances([hostname], str)
        pass


class DeployHandler(Deploy):
    def __init__(self):
        super().__init__()
        self.data = get_software_filesystem_data()

    def create(self, from_release, to_release, reboot_required, state=DEPLOY_STATES.DEPLOYING):
        """
        Create a new deploy with given from and to release version
        :param from_release: The source release version.
        :param to_release: The target release version.
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.
        """
        super().create(from_release, to_release, reboot_required, state)
        deploy = self.query()
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy already exists.")
        new_deploy = {
            "from_release": from_release,
            "to_release": to_release,
            "reboot_required": reboot_required,
            "state": state.value
        }

        try:
            self.data["deploy"] = new_deploy
            save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
        except Exception:
            self.data["deploy"] = {}

    def query(self):
        """
        Query deploy based on from and to release version
        :return: A deploy dictionary
        """
        super().query()
        return self.data.get("deploy", {})

    def update(self, new_state: DEPLOY_STATES):
        """
        Update deploy state based on from and to release version
        :param new_state: The new state
        """
        super().update(new_state)
        deploy = self.query()
        if not deploy:
            raise DeployDoNotExist("Error to update deploy state. No deploy in progress.")

        try:
            self.data["deploy"]["state"] = new_state.value
            save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
        except Exception:
            self.data["deploy"] = deploy

    def delete(self):
        """
        Delete a deploy based on given from and to release version
        """
        super().delete()
        deploy = self.query()
        if not deploy:
            raise DeployDoNotExist("Error to delete deploy state. No deploy in progress.")
        try:
            self.data["deploy"] = {}
            save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
        except Exception:
            self.data["deploy"] = deploy


class DeployHostHandler(DeployHosts):

    def __init__(self):
        super().__init__()
        self.data = get_software_filesystem_data()

    def create(self, hostname, state=None):
        super().create(hostname, state)
        deploy = self.query(hostname)
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy host already exist.")

        new_deploy_host = {
            "hostname": hostname,
            "state": state
        }

        deploy_data = self.data.get("deploy_host", [])
        if not deploy_data:
            deploy_data = {
                "deploy_host": []
            }
            deploy_data["deploy_host"].append(new_deploy_host)
            self.data.update(deploy_data)
        else:
            deploy_data.append(new_deploy_host)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def query(self, hostname):
        super().query(hostname)
        for deploy in self.data.get("deploy_host", []):
            if deploy.get("hostname") == hostname:
                return deploy
        return None

    def query_all(self):
        return self.data.get("deploy_host", [])

    def update(self, hostname, state):
        super().update(hostname, state)
        deploy = self.query(hostname)
        if not deploy:
            raise Exception("Error to update. Deploy host do not exist.")

        index = self.data.get("deploy_host", []).index(deploy)
        updated_entity = {
            "hostname": hostname,
            "state": state
        }
        self.data["deploy_host"][index].update(updated_entity)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
        return updated_entity

    def delete_all(self):
        self.data.get("deploy_host").clear()
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def delete(self, hostname):
        super().delete(hostname)
        deploy = self.query(hostname)
        if not deploy:
            raise DeployDoNotExist("Error to delete. Deploy host do not exist.")
        self.data.get("deploy_host").remove(deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
