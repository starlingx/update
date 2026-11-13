#!/usr/bin/python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script triggers the sysinv LVM snapshot restore lifecycle hook during
# activate-rollback, but only after a successful LVM snapshot restore.
# sysinv runs the hook on every applied application, so each app (e.g. rook-ceph)
# can restore the state the snapshot does not cover. In a regular activate-rollback
# (no snapshot restore) it does nothing.

import logging
import os
import sys

from cgtsclient import client as cgts_client
from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')


def get_sysinv_client():
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL")
    )


class AppsLvmSnapshotRestoreLifecycle(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate-rollback',
            required_state=None,
            plugin_name='apps-lvm-snapshot-restore-lifecycle',
            completed_state='apps-lvm-snapshot-restore-lifecycle-completed'
        )

    def run_after_snapshot_restore(self):
        return True

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        if self.snapshot_restored:
            LOG.info("Triggering the LVM snapshot restore lifecycle hook for applied apps")
            try:
                client = get_sysinv_client()
                client.kube_app.post_trigger_lvm_snapshot_restore_lifecycle()
            except Exception as e:
                LOG.error("Failed to trigger the LVM snapshot restore lifecycle "
                          "hook for applied apps, check sysinv.log for details: %s", e)
                # Re-raise so CPlugin.run() reports the '-failed' result
                raise
            LOG.info("LVM snapshot restore lifecycle hook completed")
        else:
            LOG.info("No LVM snapshot restore, skipping the lifecycle hook trigger")


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

    # TODO(lbonatti) remove this condition once stx13 become N release.
    if action != "activate-rollback":
        sys.exit(0)

    plugin = AppsLvmSnapshotRestoreLifecycle()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
