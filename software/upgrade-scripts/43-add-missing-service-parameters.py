#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add missing service parameters during upgrade activation.
#
# NOTE: This script is only needed for the 26.03 -> 26.10 upgrade path.
#       It can be deleted after the 26.10 release.
#
# The following parameters are new in Trixie and are created by
# _create_default_service_parameter() on fresh install, but that
# path is never reached on upgrade:
#
#   platform | config | amd_pstate
#   identity | ldap-linux | lockout_seconds, lockout_retries,
#              inactive_session_term_timeout_seconds
#   identity | security_compliance | inactive_session_term_timeout_seconds

import logging
import os
import sys

from cgtsclient import client as cgts_client
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

# Parameters to add if missing: (service, section, name, default_value)
MISSING_PARAMS = [
    ("platform", "config", "amd_pstate", "passive"),
    ("identity", "ldap-linux", "lockout_seconds", "900"),
    ("identity", "ldap-linux", "lockout_retries", "5"),
    ("identity", "ldap-linux",
     "inactive_session_term_timeout_seconds", "900"),
    ("identity", "security_compliance",
     "inactive_session_term_timeout_seconds", "3000"),
]


def get_sysinv_client():
    """Create and return an authenticated sysinv API client.

    Uses OS_AUTH_TOKEN and SYSTEM_URL environment variables which are
    set by the upgrade plugin runner before invoking upgrade scripts.
    """
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL"),
    )


def get_existing_params(sysinv):
    """Retrieve all current service parameters from the database.

    Returns a set of (service, section, name) tuples representing
    every parameter that already exists, used for idempotent
    duplicate checking before inserting new entries.
    """
    return {
        (p.service, p.section, p.name)
        for p in sysinv.service_parameter.list()
    }


def do_activate(sysinv):
    """Main activation logic: add missing service parameters.

    Iterates over MISSING_PARAMS and for each one:
    1. Checks if it already exists in the DB (idempotent — safe to re-run).
    2. If missing, creates it via the sysinv API with its default value.
    3. After all inserts, calls service-parameter-apply once per affected
       service so that puppet picks up the new values.

    This handles the gap where _create_default_service_parameter() in
    conductor/manager.py only runs on first boot (inside
    _create_default_system) and is never invoked on upgrade.
    """
    existing = get_existing_params(sysinv)
    added = []

    for service, section, name, value in MISSING_PARAMS:
        if (service, section, name) in existing:
            LOG.info("Parameter %s/%s/%s already exists, skipping",
                     service, section, name)
            continue

        LOG.info("Adding parameter %s/%s/%s=%s",
                 service, section, name, value)
        sysinv.service_parameter.create(
            service,
            section,
            None,  # personality
            None,  # resource
            {name: value},
        )
        added.append((service, section, name))

    if added:
        # Apply each affected service once
        services_to_apply = set(s for s, _, _ in added)
        for svc in services_to_apply:
            LOG.info("Applying service parameters for %s", svc)
            sysinv.service_parameter.apply(svc)

    LOG.info("Completed: %d parameters added", len(added))


class AddMissingServiceParameters(CPlugin):
    """USM upgrade plugin to populate service parameters new in Trixie.

    Registered as an 'activate' action plugin.  The USM plugin runner
    calls _run() during 'software deploy activate' after all hosts
    have been upgraded and rebooted.
    """

    def __init__(self):
        super().__init__(
            matching_action=['activate'],
            required_state=None,
            plugin_name='add-missing-service-parameters',
            completed_state='add-missing-service-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        """Entry point called by the USM plugin runner.

        Authenticates to sysinv and delegates to do_activate() which
        performs the idempotent parameter insertion.
        """
        LOG.info("%s invoked from_release=%s to_release=%s action=%s",
                 self.name, from_release, to_release, action)

        if from_release != "26.03" or to_release != "26.10":
            LOG.info("Only applicable when upgrading from 26.03 "
                     "to 26.10. Skipping.")
            return

        sysinv = get_sysinv_client()

        if action == "activate":
            do_activate(sysinv)
        else:
            LOG.info("Nothing to do for action '%s'", action)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: %s from_release to_release action" % sys.argv[0])
        sys.exit(1)

    from_release = sys.argv[1]
    to_release = sys.argv[2]
    action = sys.argv[3]

    configure_logging()
    plugin = AddMissingServiceParameters()
    plugin.run(from_release, to_release, action)
