#!/usr/bin/python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script rolls back flux controllers in the fluxcd-helm namespace

import logging
import os
import sys

from cgtsclient import client as cgts_client
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import test_k8s_health
from sysinv.common.retrying import retry

LOG = logging.getLogger('main_logger')


def get_sysinv_client():
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL")
    )


@retry(retry_on_result=lambda x: x is False, stop_max_attempt_number=3)
@test_k8s_health
def rollback_controllers():
    LOG.info("Rolling back Flux controllers")
    client = get_sysinv_client()
    result = False
    try:
        result = client.flux.rollback_controllers()
        if result:
            LOG.info("Flux controllers successfully rolled back")
        else:
            LOG.error("Error while rolling back flux controllers. "
                      "Check /var/log/sysinv.log for more details.")
    except Exception as e:
        LOG.error("Cannot roll back flux controllers: %s", e)
    return result


class RollbackFluxcdControllers(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='activate-rollback',
            required_state=None,
            plugin_name='rollback-fluxcd-controllers',
            completed_state='rollback-fluxcd-controllers-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        if from_release >= "25.09":
            if not rollback_controllers():
                raise Exception("Failed to rollback Flux controllers")


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

    plugin = RollbackFluxcdControllers()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
