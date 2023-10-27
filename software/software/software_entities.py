"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging
from abc import ABC, abstractmethod
from enum import Enum
from typing import List

from software import constants
from software.exceptions import DeployDoNotExist, DeployAlreadyExist
from software.utils import check_instances, check_state, save_to_json_file, get_software_filesystem_data

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
    def create(self, from_release: str, to_release: str, reboot_required:bool, state: str):
        """
        Create a new deployment entry.

        :param from_release: The source release version.
        :param to_release: The target release version.
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.

        """
        instances = [from_release, to_release]
        if state:
            check_state(state, self.states)
            instances.append(state)
        check_instances([reboot_required], bool)
        check_instances(instances, str)
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
    def update(self, from_release: str, to_release: str, reboot_required:bool, state: str):
        """
        Update a deployment entry.

        :param from_release: The source release version.
        :param to_release: The target release version.
        :param reboot_required: If is required to do host reboot.
        :param state: The state of the deployment.

        """
        check_instances([from_release, to_release, state], str)
        check_instances([reboot_required], bool)
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
    def create(self, hostname: str, software_release: str, target_release: str, state: str):
        """
        Create a new deploy-host entry

        :param hostname: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.
        :param state: The state of the deploy-host entry.

        """
        instances = [hostname, software_release, target_release]
        if state:
            check_state(state, self.states)
            instances.append(state)
        check_instances(instances, str)
        pass

    @abstractmethod
    def query_by_hostname(self, hostname: str):
        """
        Get deploy-host entries for a given host.

        :param hostname: The name of the host.

        """
        check_instances([hostname], str)
        pass

    @abstractmethod
    def query(self, hostname: str, software_release: str, target_release: str):
        """
        Get deploy-host entries for a given host.

        :param hostname: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.

        """
        check_instances([hostname, software_release, target_release], str)
        pass

    @abstractmethod
    def update(self, hostname: str, software_release: str, target_release: str, state: str):
        """
        Update a deploy-host entry

        :param hostname: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.
        :param state: The state of the deploy-host entry.
        """
        check_instances([hostname, software_release, target_release, state], str)
        check_state(state, self.states)
        pass

    @abstractmethod
    def delete_by_hostname(self, hostname: str):
        """
        Delete deploy-host entries for a given host.

        :param hostname: The name of the host.
        """
        check_instances([hostname], str)
        pass

    @abstractmethod
    def delete(self, hostname, software_release, target_release):
        """
        Delete deploy-host entries for a given host.

        :param hostname: The name of the host.
        :param software_release: The software release version.
        :param target_release: The target release version.
        """
        check_instances([hostname, software_release, target_release], str)
        pass

class DeployHandler(Deploy):
    def __init__(self):
        super().__init__()
        self.data = get_software_filesystem_data()

    def create(self, from_release, to_release, reboot_required, state=None):
        super().create(from_release, to_release, reboot_required, state)
        deploy = self.query(from_release, to_release)
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy already exist.")
        new_deploy = {
            "from_release": from_release,
            "to_release": to_release,
            "reboot_required": reboot_required,
            "state": state
        }
        deploy_data = self.data.get("deploy", [])
        if not deploy_data:
            deploy_data = {
                "deploy": []
            }
            deploy_data["deploy"].append(new_deploy)
            self.data.update(deploy_data)
        else:
            deploy_data.append(new_deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def query(self, from_release, to_release):
        super().query(from_release, to_release)
        for deploy in self.data.get("deploy", []):
            if deploy.get("from_release") == from_release and deploy.get("to_release") == to_release:
                return deploy
        return None

    def query_all(self):
        return self.data.get("deploy", [])

    def update(self, from_release, to_release, reboot_required, state):
        super().update(from_release, to_release, reboot_required, state)
        deploy = self.query(from_release, to_release)
        if not deploy:
            raise DeployDoNotExist("Error to update. Deploy do not exist.")
        deploy_data = {
            "deploy": []
        }
        deploy_data["deploy"].append({
            "from_release": from_release,
            "to_release": to_release,
            "reboot_required": reboot_required,
            "state": state
        })
        self.data.update(deploy_data)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def delete(self, from_release, to_release):
        super().delete(from_release, to_release)
        deploy = self.query(from_release, to_release)
        if not deploy:
            raise DeployDoNotExist("Error to delete. Deploy do not exist.")
        self.data.get("deploy").remove(deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)


class DeployHostHandler(DeployHosts):

    def __init__(self):
        super().__init__()
        self.data = get_software_filesystem_data()

    def create(self, hostname, software_release, target_release, state=None):
        super().create(hostname, software_release, target_release, state)
        deploy = self.query(hostname, software_release, target_release)
        if deploy:
            raise DeployAlreadyExist("Error to create. Deploy host already exist.")

        new_deploy_host = {
                "hostname": hostname,
                "software_release": software_release,
                "target_release": target_release,
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

    def query(self, hostname, software_release, target_release):
        super().query(hostname, software_release, target_release)
        for deploy in self.data.get("deploy_host", []):
            if (deploy.get("hostname") == hostname and deploy.get("software_release") == software_release
                    and deploy.get("target_release") == target_release):
                return deploy
        return None

    def query_by_hostname(self, hostname):
        super().query_by_hostname(hostname)
        for deploy in self.data.get("deploy_host", []):
            if deploy.get("hostname") == hostname:
                return deploy
        return None

    def query_all(self):
        return self.data.get("deploy_host", [])

    def update(self, hostname, software_release, target_release, state):
        super().update(hostname, software_release, target_release, state)
        deploy = self.query(hostname, software_release, target_release)
        if not deploy:
            raise Exception("Error to update. Deploy host do not exist.")

        index = self.data.get("deploy_host", []).index(deploy)
        self.data["deploy_host"][index].update({
            "hostname": hostname,
            "software_release": software_release,
            "target_release": target_release,
            "state": state
        })
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def delete_all(self):
        self.data.get("deploy_host").clear()
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def delete_by_hostname(self, hostname):
        super().delete_by_hostname(hostname)
        deploy = self.query_by_hostname(hostname)
        if not deploy:
            raise DeployDoNotExist("Error to delete. Deploy host do not exist.")
        self.data.get("deploy_host").remove(deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)

    def delete(self, hostname, software_release, target_release):
        super().delete(hostname, software_release, target_release)
        deploy = self.query(hostname, software_release, target_release)
        if not deploy:
            raise DeployDoNotExist("Error to delete. Deploy host do not exist.")
        self.data.get("deploy_host").remove(deploy)
        save_to_json_file(constants.SOFTWARE_JSON_FILE, self.data)
