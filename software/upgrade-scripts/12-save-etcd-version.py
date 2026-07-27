#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the to-release hieradata with the etcd version
# during platform upgrade (migrate action at deploy-start).
#
# For stx.12+: the stage0 symlink already exists and hieradata is
# already maintained by puppet/sysinv, so nothing to do.
#
# For stx.11: no versioned etcd infrastructure exists, so hieradata
# must be populated with the known etcd version so puppet uses the
# correct version after reboot.

import logging
import os
import re
import sys
import yaml

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

STATIC_FILE = "static.yaml"
HIERADATA_PATH = "/opt/platform/puppet/%s/hieradata"
HIERADATA_KEY = "platform::etcd::params::etcd_version"

ETCD_STAGE0_LINK = "/var/lib/etcd/stage0"

# Known etcd versions for releases without versioned etcd
# infrastructure (no stage0 symlink, no /usr/local/etcd/).
# Only stx.11 needs this; stx.12+ already has the symlink and
# hieradata is maintained by puppet/sysinv.
ETCD_KNOWN_VERSIONS = {
    "25.09": "3.4.37",
}


def get_etcd_version_from_symlink():
    """Read etcd version from the stage0 symlink."""
    try:
        if not os.path.islink(ETCD_STAGE0_LINK):
            LOG.info("stage0 symlink does not exist: %s" % ETCD_STAGE0_LINK)
            return None
        target = os.readlink(ETCD_STAGE0_LINK)
        pattern = r"/usr/local/etcd/(.*)/stage0"
        match = re.search(pattern, target)
        if match is None:
            LOG.warning("Unable to parse etcd version from symlink "
                        "target: %s" % target)
            return None
        ver = match.group(1)
        LOG.info("Read etcd version %s from symlink %s"
                 % (ver, ETCD_STAGE0_LINK))
        return ver
    except Exception as e:
        LOG.warning("Failed to read stage0 symlink: %s" % e)
    return None


def update_hieradata(to_release, etcd_version):
    """Write etcd version to the to-release static hieradata."""
    static_file = os.path.join(HIERADATA_PATH % to_release, STATIC_FILE)
    try:
        with open(static_file, "r") as f:
            static_config = yaml.load(f, Loader=yaml.Loader)

        static_config[HIERADATA_KEY] = etcd_version

        with open(static_file, "w") as f:
            yaml.dump(static_config, f, default_flow_style=False)

        LOG.info("Updated hieradata %s: %s = %s"
                 % (static_file, HIERADATA_KEY, etcd_version))
    except Exception as e:
        msg = "Failed to update hieradata %s: %s" % (static_file, e)
        LOG.error(msg)
        raise Exception(msg)


def do_update(from_release, to_release):
    """Main logic for preserving etcd version during upgrade.

    If the stage0 symlink exists (stx.12+), hieradata is already
    maintained by puppet/sysinv — nothing to do.

    If the symlink does not exist (stx.11), update hieradata with
    the known etcd version so puppet uses it after reboot.
    """
    symlink_version = get_etcd_version_from_symlink()

    if symlink_version:
        LOG.info("stage0 symlink exists with version %s, "
                 "hieradata already up to date" % symlink_version)
        return

    # No symlink — this is stx.11. Use known version.
    etcd_version = ETCD_KNOWN_VERSIONS.get(from_release)
    if not etcd_version:
        msg = ("No known etcd version for from_release %s "
               "and no symlink exists" % from_release)
        LOG.error(msg)
        raise Exception(msg)

    LOG.info("Updating hieradata with known etcd version %s "
             "for from_release %s" % (etcd_version, from_release))
    update_hieradata(to_release, etcd_version)


class SaveEtcdVersion(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='migrate',
            required_state=None,
            plugin_name='save-etcd-version',
            completed_state='save-etcd-version-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        do_update(from_release, to_release)


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

    plugin = SaveEtcdVersion()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
