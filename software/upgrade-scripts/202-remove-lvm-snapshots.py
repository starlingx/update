#!/usr/bin/env python
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import configparser
import logging
from pathlib import Path
import sys
import subprocess
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
    script_path = Path("/usr/sbin/software-deploy/manage-lvm-snapshots")
    if not script_path.is_file():
        raise FileNotFoundError(f"{script_path} not found")

    cmd = [script_path, "--delete"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        LOG.info("Snapshots deleted with success")
    except subprocess.CalledProcessError as e:
        LOG.error("Error deleting snapshots: %s", e.stderr)
        raise


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()

    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    res = 0
    if action == "delete":
        try:
            system_mode = get_system_mode()
            if system_mode == "simplex":
                delete_lvm_snapshots()
            else:
                LOG.info("The system_mode is %s, nothing to do", system_mode)
        except Exception as e:
            LOG.error("Error running script: %s", str(e))
            res = 1
    else:
        LOG.info("Nothing to do for action '%s'", action)
    return res


if __name__ == "__main__":
    sys.exit(main())
