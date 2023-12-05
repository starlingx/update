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

    def create_deploy_host(self, hostname, software_release, target_release):
        self.deploy_host_handler.create(hostname, software_release, target_release)

    def get_deploy_host_by_hostname(self, hostname):
        return self.deploy_host_handler.query_by_hostname(hostname)

    def get_deploy_host(self):
        return self.deploy_host_handler.query_all()

    def update_deploy_host(self, hostname, software_release, target_release, state):
        self.deploy_host_handler.update(hostname, software_release, target_release, state)

    def delete_deploy_host_by_hostname(self, hostname):
        self.deploy_host_handler.delete_by_hostname(hostname)

    def delete_deploy_host(self, hostname, software_release, target_release):
        self.deploy_host_handler.delete(hostname, software_release, target_release)

    def delete_deploy_host_all(self):
        self.deploy_host_handler.delete_all()
