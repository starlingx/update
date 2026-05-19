#!/usr/bin/env python
#
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import configparser
import logging
import pathlib
import subprocess
import sys

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')


def get_system_mode():
    with open("/etc/platform/platform.conf", "r") as fp:
        platform_conf = "[DEFAULT]\n" + fp.read()
    parser = configparser.ConfigParser()
    parser.read_string(platform_conf)
    if parser.has_option('DEFAULT', 'system_mode'):
        return parser.get('DEFAULT', 'system_mode')
    return None


def delete_lvm_snapshots():
    script_path = pathlib.Path("/usr/sbin/software-deploy/manage-lvm-snapshots")
    if not script_path.is_file():
        raise FileNotFoundError(f"{script_path} not found")
    cmd = [script_path, "--delete"]
    subprocess.run(cmd, check=True, capture_output=True, text=True)
    LOG.info("Snapshots deleted with success")


class RemoveLvmSnapshots(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='delete',
            required_state=None,
            plugin_name='remove-lvm-snapshots',
            completed_state='remove-lvm-snapshots-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        system_mode = get_system_mode()
        if system_mode == "simplex":
            delete_lvm_snapshots()
        else:
            LOG.info("The system_mode is %s, nothing to do", system_mode)


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

    plugin = RemoveLvmSnapshots()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
