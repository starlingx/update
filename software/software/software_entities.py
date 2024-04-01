"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

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

from software.states import DEPLOY_HOST_STATES
from software.states import DEPLOY_STATES

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
    def create(self, from_release: str, to_release: str, feed_repo: str,
               commit_id: str, reboot_required: bool, state: DEPLOY_STATES):
        """
        Create a new deployment entry.

        :param from_release: The current release version.
        :param to_release: The target release version.
        :param feed_repo: ostree repo feed path
        :param commit_id: commit-id to deploy
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.

        """
        validate_versions([from_release, to_release])
        check_instances([reboot_required], bool)
        check_instances([state], DEPLOY_STATES)

    @abstractmethod
    def query(self, from_release, to_release):
        """
        Get deployments based on current and target release versions.
        """
        validate_versions([from_release, to_release])
        pass

    @abstractmethod
    def update(self, new_state: DEPLOY_STATES):
        """
        Update a deployment entry.

        :param new_state: The state of the deployment.

        """
        check_instances([new_state], DEPLOY_STATES)

    @abstractmethod
    def delete(self):
        """
        Delete a deployment entry based on current and target release versions.
        """
        pass


class DeployHosts(ABC):

    def __init__(self):
        pass

    @abstractmethod
    def create(self, hostname: str, state: DEPLOY_HOST_STATES):
        """
        Create a new deploy-host entry

        :param hostname: The name of the host.
        :param state: The state of the deploy-host entry.

        """
        instances = [hostname]
        if state:
            check_instances([state], DEPLOY_HOST_STATES)
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
    def update(self, hostname: str, state: DEPLOY_HOST_STATES):
        """
        Update a deploy-host entry

        :param hostname: The name of the host.
        :param state: The state of the deploy-host entry.
        """
        check_instances([hostname], str)
        check_instances([state], DEPLOY_HOST_STATES)
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
    def create(self, from_release, to_release, feed_repo, commit_id, reboot_required, state=DEPLOY_STATES.START):
        """
        Create a new deploy with given from and to release version
        :param from_release: The current release version.
        :param to_release: The target release version.
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.
        """
        super().create(from_release, to_release, feed_repo, commit_id, reboot_required, state)
        deploy = self.query(from_release, to_release)
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy already exists.")
        new_deploy = {
            "from_release": from_release,
            "to_release": to_release,
            "feed_repo": feed_repo,
            "commit_id": commit_id,
            "reboot_required": reboot_required,
            "state": state.value
        }

        try:
            data = get_software_filesystem_data()
            deploy_data = data.get("deploy", [])
            if not deploy_data:
                deploy_data = {
                    "deploy": []
                }
                deploy_data["deploy"].append(new_deploy)
                data.update(deploy_data)
            else:
                deploy_data.append(new_deploy)
            save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
        except Exception:
            LOG.exception()

    def query(self, from_release, to_release):
        """
        Query deploy based on from and to release version
        :param from_release: The current release version.
        :param to_release: The target release version.
        :return: A list of deploy dictionary
        """
        super().query(from_release, to_release)
        data = get_software_filesystem_data()
        for deploy in data.get("deploy", []):
            if (deploy.get("from_release") == from_release and
                    deploy.get("to_release") == to_release):
                return deploy
        return []

    def query_all(self):
        """
        Query all deployments inside software.json file.
        :return: A list of deploy dictionary
        """
        data = get_software_filesystem_data()
        return data.get("deploy", [])

    def update(self, new_state: DEPLOY_STATES):
        """
        Update deploy state based on from and to release version
        :param new_state: The new state
        """
        super().update(new_state)
        deploy = self.query_all()
        if not deploy:
            raise DeployDoNotExist("Error to update deploy state. No deploy in progress.")

        data = get_software_filesystem_data()
        try:
            data["deploy"][0]["state"] = new_state.value
            save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
        except Exception:
            LOG.exception()

    def delete(self):
        """
        Delete a deploy based on given from and to release version
        """
        super().delete()
        deploy = self.query_all()
        if not deploy:
            raise DeployDoNotExist("Error to delete deploy state. No deploy in progress.")

        data = get_software_filesystem_data()
        try:
            data["deploy"].clear()
            save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
        except Exception:
            LOG.exception()


class DeployHostHandler(DeployHosts):
    def create(self, hostname, state: DEPLOY_HOST_STATES = DEPLOY_HOST_STATES.PENDING):
        super().create(hostname, state)
        deploy = self.query(hostname)
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy host already exist.")

        new_deploy_host = {
            "hostname": hostname,
            "state": state.value if state else None
        }

        data = get_software_filesystem_data()
        deploy_data = data.get("deploy_host", [])
        if not deploy_data:
            deploy_data = {
                "deploy_host": []
            }
            deploy_data["deploy_host"].append(new_deploy_host)
            data.update(deploy_data)
        else:
            deploy_data.append(new_deploy_host)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, data)

    def query(self, hostname):
        """
        Query deploy based on hostname
        :param hostname: The name of the host.
        :return: A list of deploy dictionary
        """
        super().query(hostname)
        data = get_software_filesystem_data()
        for deploy in data.get("deploy_host", []):
            if deploy.get("hostname") == hostname:
                return deploy
        return None

    def query_all(self):
        data = get_software_filesystem_data()
        return data.get("deploy_host", [])

    def update(self, hostname, state: DEPLOY_HOST_STATES):
        super().update(hostname, state)
        deploy = self.query(hostname)
        if not deploy:
            raise Exception("Error to update. Deploy host do not exist.")

        data = get_software_filesystem_data()
        index = data.get("deploy_host", []).index(deploy)
        updated_entity = {
            "hostname": hostname,
            "state": state.value
        }
        data["deploy_host"][index].update(updated_entity)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
        return updated_entity

    def delete_all(self):
        data = get_software_filesystem_data()
        data.get("deploy_host").clear()
        save_to_json_file(constants.SOFTWARE_JSON_FILE, data)

    def delete(self, hostname):
        super().delete(hostname)
        deploy = self.query(hostname)
        if not deploy:
            raise DeployDoNotExist("Error to delete. Deploy host do not exist.")
        data = get_software_filesystem_data()
        data.get("deploy_host").remove(deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
