#!/usr/bin/env python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import subprocess
import sys

from six.moves import configparser
from cgtsclient import client as cgts_client

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')


class CgtsClient(object):
    SYSINV_API_VERSION = "1"

    def __init__(self):
        self._sysinv_client = None

    @property
    def sysinv(self):
        if not self._sysinv_client:
            self._sysinv_client = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
                system_url=os.environ.get("SYSTEM_URL"),
            )
        return self._sysinv_client


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)
    if config_applied.has_option('DEFAULT', 'system_mode'):
        return config_applied.get('DEFAULT', 'system_mode')
    return None


def get_shared_services():
    client = CgtsClient()
    isystem = client.sysinv.isystem.list()[0]
    return isystem.capabilities.get('shared_services', '')


def activate_keystone():
    if get_system_mode() != "simplex":
        shared_services = get_shared_services()
        if 'identity' not in shared_services:
            keystone_cmd = 'keystone-manage db_sync --contract'
            subprocess.check_call([keystone_cmd], shell=True)
    return 0


class ActivateKeystone(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate',
            required_state=None,
            plugin_name='activate-keystone',
            completed_state='activate-keystone-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        activate_keystone()


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = ActivateKeystone()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
