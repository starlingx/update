#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# OpenBao upgrade-activate handling.
#
# PLACEHOLDER CONTENT (temporary): host OpenBao upgrade support is still
# in development. An upgraded node has no initialized bao, so this
# plugin currently writes a ward sentinel on the LUKS filesystem
# (controller/.openbao/.disabled).  Puppet on an upgraded controller
# will skip configurations if the ward is present
#
# FINAL INTENT (future): replace the ward within do_openbao_activate
# with OpenBao initialization, i.e., what bootstrap does.

import configparser
import json
import logging
import os
import sys

from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

# Authoritative LUKS mount path, read from the luks-fs-mgr created-config.
CREATED_LUKS_CONFIG = "/etc/luks-fs-mgr.d/created_luks.json"
# OpenBao LUKS subtree (under the rsync'd controller/ directory) and ward.
OPENBAO_LUKS_SUBDIR = "controller/.openbao"
WARD_FILENAME = ".disabled"


def get_nodetype():
    try:
        ini_str = "[DEFAULT]\n" + open("/etc/platform/platform.conf", "r").read()
        cp = configparser.RawConfigParser()
        cp.read_string(ini_str)
        if cp.has_option("DEFAULT", "nodetype"):
            return cp.get("DEFAULT", "nodetype")
    except Exception as e:
        LOG.warning("Could not read nodetype from platform.conf: %s", e)
    return None


def get_luks_mount_path():
    """Return the LUKS filesystem mount path from the luks-fs-mgr config.

    Returns None if the config is absent/unparseable or has no mount path.
    """
    try:
        with open(CREATED_LUKS_CONFIG, "r") as f:
            data = json.load(f)
    except (IOError, OSError, ValueError) as e:
        LOG.warning("Could not read %s: %s", CREATED_LUKS_CONFIG, e)
        return None

    volumes = data.get("luksvolumes") or []
    for vol in volumes:
        mount_path = vol.get("MOUNT_PATH")
        if mount_path:
            return mount_path
    LOG.warning("No MOUNT_PATH found in %s", CREATED_LUKS_CONFIG)
    return None


def do_openbao_activate():
    """Activate-phase OpenBao handling.

    PLACEHOLDER: write the LUKS ward that keeps host OpenBao disabled after
    the upgrade completes. Replace with real OpenBao upgrade bring-up when
    that support is implemented.
    """
    nodetype = get_nodetype()
    if nodetype != "controller":
        LOG.info("Not a controller (nodetype=%s); nothing to do.", nodetype)
        return

    luks_mount = get_luks_mount_path()
    if not luks_mount:
        LOG.warning("LUKS mount path unknown; skipping OpenBao ward.")
        return

    if not os.path.ismount(luks_mount):
        LOG.warning("LUKS filesystem not mounted at %s; skipping OpenBao ward.",
                    luks_mount)
        return

    openbao_dir = os.path.join(luks_mount, OPENBAO_LUKS_SUBDIR)
    ward_file = os.path.join(openbao_dir, WARD_FILENAME)
    try:
        os.makedirs(openbao_dir, exist_ok=True)
        os.chmod(openbao_dir, 0o755)
        with open(ward_file, "a"):
            os.utime(ward_file, None)
        os.chmod(ward_file, 0o644)
        LOG.info("Warded host OpenBao off after upgrade: %s", ward_file)
    except (IOError, OSError) as e:
        LOG.warning("Failed to write OpenBao ward %s: %s", ward_file, e)


class OpenbaoActivate(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate',
            required_state=None,
            plugin_name='openbao-activate',
            completed_state='openbao-activate-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        do_openbao_activate()


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

    if action != "activate":
        sys.exit(0)

    plugin = OpenbaoActivate()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
