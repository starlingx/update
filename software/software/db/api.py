"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging
import threading
from software import constants
from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software.states import DEPLOY_STATES
from software.utils import get_software_filesystem_data
from software.utils import save_to_json_file

LOG = logging.getLogger('main_logger')


def get_instance():
    """Return a Software API instance."""
    return SoftwareAPI()


class SoftwareAPI:
    _instance = None
    _lock = threading.RLock()

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(SoftwareAPI, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.deploy_handler = DeployHandler()
        self.deploy_host_handler = DeployHostHandler()

    def create_deploy(self, from_release, to_release, feed_repo,
                      commit_id, reboot_required: bool, **kwargs):
        self.begin_update()
        self.deploy_handler.create(from_release, to_release, feed_repo,
                                   commit_id, reboot_required, **kwargs)
        self.end_update()

    def get_deploy(self, from_release, to_release):
        self.begin_update()
        try:
            return self.deploy_handler.query(from_release, to_release)
        finally:
            self.end_update()

    def get_current_deploy(self):
        self.begin_update()
        try:
            deploy = self.deploy_handler.query_all()
            return deploy[0] if deploy else None
        finally:
            self.end_update()

    def get_deploy_all(self):
        self.begin_update()
        try:
            return self.deploy_handler.query_all()
        finally:
            self.end_update()

    def get_deploy_all_synced(self):
        self.begin_update()
        try:
            return self.deploy_handler.query_all_synced()
        finally:
            self.end_update()

    def update_deploy(self, from_release=None, to_release=None, feed_repo=None, commit_id=None,
                      reboot_required: bool = None, state: DEPLOY_STATES = None):
        self.begin_update()
        try:
            self.deploy_handler.update(
                from_release, to_release, feed_repo, commit_id, reboot_required, state)
        finally:
            self.end_update()

    def reverse_deploy(self, feed_repo, commit_id):
        """
        Reverse the deployment order, update the commit_id and feed_repo

        :param feed_repo: ostree repo feed path.
        :param commit_id: commit-id to deploy.
        """
        self.begin_update()
        try:
            deploy = self.get_current_deploy()
            to_release = deploy["to_release"]
            from_release = deploy["from_release"]
            self.deploy_handler.update(from_release=to_release, to_release=from_release, feed_repo=feed_repo,
                                       commit_id=commit_id)
        finally:
            self.end_update()

    def delete_deploy(self):
        self.begin_update()
        try:
            self.deploy_handler.delete()
        finally:
            self.end_update()

    def create_deploy_host(self, hostname):
        self.begin_update()
        try:
            self.deploy_host_handler.create(hostname)
        finally:
            self.end_update()

    def get_deploy_host(self):
        self.begin_update()
        try:
            return self.deploy_host_handler.query_all()
        finally:
            self.end_update()

    def get_deploy_host_synced(self):
        self.begin_update()
        try:
            return self.deploy_host_handler.query_all_synced()
        finally:
            self.end_update()

    def get_deploy_host_by_hostname(self, hostname):
        self.begin_update()
        try:
            return self.deploy_host_handler.query(hostname)
        finally:
            self.end_update()

    def update_deploy_host(self, hostname, state):
        self.begin_update()
        try:
            return self.deploy_host_handler.update(hostname, state)
        finally:
            self.end_update()

    def delete_deploy_host(self, hostname):
        self.begin_update()
        try:
            self.deploy_host_handler.delete(hostname)
        finally:
            self.end_update()

    def delete_deploy_host_all(self):
        self.begin_update()
        try:
            self.deploy_host_handler.delete_all()
        finally:
            self.end_update()

    def create_current_loads(self, current_load_data):
        self.begin_update()
        try:
            data = get_software_filesystem_data()
            data.update(current_load_data)
            save_to_json_file(constants.SOFTWARE_JSON_FILE, data)
        finally:
            self.end_update()

    def begin_update(self):
        tid = threading.get_native_id()
        msg = f"{tid} is to acquire lock."
        LOG.debug(msg)
        SoftwareAPI._lock.acquire()

    def end_update(self):
        SoftwareAPI._lock.release()
        tid = threading.get_native_id()
        msg = f"{tid} released lock."
        LOG.debug(msg)
