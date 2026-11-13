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
import re
import sys
import shutil

from pathlib import Path

from _loader import CPlugin

from software.utilities.constants import SW_VERSION
from software.utilities.utils import configure_logging
from software.utils import get_major_release_version

LOG = logging.getLogger('main_logger')
OLD_METADATA_DIR = Path("/opt/software/metadata")
NEW_METADATA_DIR = Path("/opt/software/releases/metadata")
PLUGIN_NAME = "move-release-metadata-file"


def get_release_metadata_files(to_release):
    """Return the to-release product metadata files in the legacy dir.

    The deploy delete action passes the major release (MM.mm), while the
    product metadata file is named after the full release version. That
    is MM.mm.0 for a GA release, but MM.mm.pp (pp > 0) for a prepatched
    release, so match any patch level of the to-release major version.

    :param to_release: to-release version ("MM.mm" or "MM.mm.pp")
    :returns: list of matching metadata file paths
    """
    major_release = get_major_release_version(to_release)
    pattern = re.compile(r"^.+-%s\.\d+-metadata\.xml$" % re.escape(major_release))
    return [f for f in OLD_METADATA_DIR.rglob("*-metadata.xml")
            if pattern.match(f.name)]


def do_delete(to_release):
    NEW_METADATA_DIR.mkdir(parents=True, exist_ok=True)

    files = get_release_metadata_files(to_release)
    if not files:
        raise FileNotFoundError("No %s release metadata file found in %s"
                                % (to_release, OLD_METADATA_DIR))

    # Move every file even if one of them fails, then report the failures
    failed = []
    for file in files:
        target_path = NEW_METADATA_DIR / file.name
        try:
            shutil.move(str(file), str(target_path))
        except Exception as e:
            LOG.error("Failed to move %s to %s: %s" % (str(file), str(target_path), e))
            failed.append(str(file))
            continue

        if target_path.exists():
            LOG.info("Moved %s to %s" % (str(file), str(target_path)))
        else:
            LOG.error("File not created in target directory: %s" % str(target_path))
            failed.append(str(file))

    if failed:
        raise RuntimeError("Failed to move release metadata files: %s" % ", ".join(failed))


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
        if (major_from_release not in ["26.03"] or major_to_release not in ["26.10", "27.03"] or
                action != "delete" or SW_VERSION in ["26.03"]):
            LOG.info("Only applicable when running on 27.03, upgrading "
                     "from [26.03] to 27.03 in action delete. "
                     "Skipping.")
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

    # TODO(lbonatti) remove this condition once stx13 become N release.
    if action != "delete":
        sys.exit(0)

    plugin = MoveReleaseMetadataFile()
    result = plugin.run(from_release, to_release, action)
    if result and 'failed' in result:
        sys.exit(1)
