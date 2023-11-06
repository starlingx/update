"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software.constants import DEPLOY_STATES


def get_instance():
    """Return a Software API instance."""
    return SoftwareAPI()


class SoftwareAPI:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SoftwareAPI, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.deploy_handler = DeployHandler()
        self.deploy_host_handler = DeployHostHandler()

    def create_deploy(self, from_release, to_release, reboot_required: bool):
        self.deploy_handler.create(from_release, to_release, reboot_required)

    def get_deploy(self):
        return self.deploy_handler.query()

    def update_deploy(self, state: DEPLOY_STATES):
        self.deploy_handler.update(state)

    def delete_deploy(self):
        self.deploy_handler.delete()

    def create_deploy_host(self, hostname):
        self.deploy_host_handler.create(hostname)

    def get_deploy_host(self):
        return self.deploy_host_handler.query_all()

    def update_deploy_host(self, hostname, state):
        return self.deploy_host_handler.update(hostname, state)

    def delete_deploy_host(self, hostname):
        self.deploy_host_handler.delete(hostname)

    def delete_deploy_host_all(self):
        self.deploy_host_handler.delete_all()
