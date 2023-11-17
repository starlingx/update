from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler

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

    def create_deploy(self, from_release, to_release, reboot_required):
        self.deploy_handler.create(from_release, to_release, reboot_required)

    def get_deploy(self, from_release, to_release):
        return self.deploy_handler.query(from_release, to_release)

    def get_deploy_all(self):
        return self.deploy_handler.query_all()

    def update_deploy(self, from_release, to_release, reboot_required, state):
        self.deploy_handler.update(from_release, to_release, reboot_required, state)

    def delete_deploy(self, from_release, to_release):
        self.deploy_handler.delete(from_release, to_release)

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
