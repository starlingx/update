#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script rolls back flux controllers in the fluxcd-helm namespace

import logging
import os
import sys

from cgtsclient import client as cgts_client
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import test_k8s_health
from sysinv.common.retrying import retry


LOG = logging.getLogger('main_logger')


def get_sysinv_client():
    """ Get an authenticated cgts client

    Returns:
        Client: cgts client object
    """

    sysinv_client = cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL")
    )
    return sysinv_client


@retry(retry_on_result=lambda x: x is False, stop_max_attempt_number=3)
@test_k8s_health
def rollback_controllers():
    """ Rollback Flux controllers

    Returns:
        bool: True if rollback is sucessful. False otherwise.
    """

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
            # postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    configure_logging()

    if action == "activate-rollback" and from_release >= "25.09":
        LOG.info(
            "%s invoked with from_release = %s to_release = %s "
            "action = %s" % (sys.argv[0], from_release, to_release, action)
        )

        if rollback_controllers():
            return 0

        return 1


if __name__ == "__main__":
    sys.exit(main())
