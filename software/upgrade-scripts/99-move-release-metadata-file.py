#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script moves the product release metadata from
# /opt/software/metadata to /opt/software/releases/metadata
# when running upgrades from 26.03 to 26.10.
#

import logging
import sys
import shutil

from pathlib import Path

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging
from software.utils import get_major_release_version
from software.utils import get_patch_level_version

LOG = logging.getLogger('main_logger')
OLD_METADATA_DIR = Path("/opt/software/metadata")
NEW_METADATA_DIR = Path("/opt/software/releases/metadata")
PLUGIN_NAME = "move-release-metadata-file"


def do_delete(to_release):
    NEW_METADATA_DIR.mkdir(parents=True, exist_ok=True)

    versioned_to_release = get_patch_level_version(to_release)
    path_glob = f"*{versioned_to_release}-metadata.xml"
    files = list(OLD_METADATA_DIR.rglob(path_glob))
    if not files:
        raise FileNotFoundError("No metadata file found in %s matches pattern '%s'"
                                % (OLD_METADATA_DIR, path_glob))

    for file in files:
        target_path = NEW_METADATA_DIR / file.name
        shutil.move(str(file), str(target_path))

        if target_path.exists():
            LOG.info("Moved %s to %s" % (str(file), str(target_path)))
        else:
            raise FileNotFoundError("File not created in target directory: %s"
                                    % (str(target_path)))


class MoveReleaseMetadataFile(CPlugin):
    """USM upgrade plugin to move the software release metadata file to
    new directory structure introduced in 26.10.

    Registered as an 'delete' action plugin. The USM plugin runner
    calls _run() during 'software deploy delete' after activate and
    complete actions are done.
    """

    def __init__(self):
        super().__init__(
            matching_action=['delete'],
            required_state=None,
            plugin_name=PLUGIN_NAME,
            completed_state=f"{PLUGIN_NAME}-completed"
        )

    def _run(self, from_release, to_release, action, port):
        """Entry point called by the USM plugin runner."""
        configure_logging()
        LOG.info("%s invoked from_release=%s to_release=%s action=%s",
                 self.name, from_release, to_release, action)

        major_from_release = get_major_release_version(from_release)
        major_to_release = get_major_release_version(to_release)
        if major_from_release not in ["25.09", "26.03"] or major_to_release != "26.10" or action != "delete":
            LOG.info("Only applicable when upgrading from [25.09, 26.03] "
                     "to 26.10 upgrades in action delete. Skipping.")
        else:
            try:
                LOG.info("Start upgrade script")
                do_delete(to_release)
            except Exception as e:
                msg = f"Upgrade script failed: {str(e)}"
                LOG.error(msg)
                raise Exception(msg) from e
            LOG.info("End upgrade script")


if __name__ == "__main__":
    action = None
    from_release = None
    to_release = None

    if len(sys.argv) < 4:
        print("Usage: %s from_release to_release action" % sys.argv[0])
        sys.exit(1)

    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # Optional port
            # port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = MoveReleaseMetadataFile()
    result = plugin.run(from_release, to_release, action)
    if result and 'failed' in result:
        sys.exit(1)
