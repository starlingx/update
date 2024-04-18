"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import logging
import threading
from software.software_entities import DeployHandler
from software.software_entities import DeployHostHandler
from software.states import DEPLOY_STATES

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

    def create_deploy(self, from_release, to_release, feed_repo, commit_id, reboot_required: bool):
        self.begin_update()
        self.deploy_handler.create(from_release, to_release, feed_repo, commit_id, reboot_required)
        self.end_update()

    def get_deploy(self, from_release, to_release):
        self.begin_update()
        try:
            return self.deploy_handler.query(from_release, to_release)
        finally:
            self.end_update()

    def get_deploy_all(self):
        self.begin_update()
        try:
            return self.deploy_handler.query_all()
        finally:
            self.end_update()

    def update_deploy(self, state: DEPLOY_STATES):
        self.begin_update()
        try:
            self.deploy_handler.update(state)
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

    def begin_update(self):
        tid = threading.get_native_id()
        msg = f"{tid} is to acquire lock."
        LOG.info(msg)
        SoftwareAPI._lock.acquire()

    def end_update(self):
        SoftwareAPI._lock.release()
        tid = threading.get_native_id()
        msg = f"{tid} released lock."
        LOG.info(msg)
