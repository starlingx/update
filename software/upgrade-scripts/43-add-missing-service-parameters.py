#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add missing service parameters during upgrade migration.
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
#
# This script uses action='migrate' (runs during 'deploy start') and
# inserts parameters directly into the to-release PostgreSQL database
# (port 6666). No sysinv API is available at migrate time.

import logging
import subprocess
import sys
import uuid

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

# All parameters to insert directly into the to-release DB.
# At migrate time there is no sysinv API — only a temporary
# PostgreSQL instance on the port passed by the plugin runner.
DB_PARAMS = [
    ("platform", "config", "amd_pstate", "passive"),
    ("identity", "ldap-linux", "lockout_seconds", "900"),
    ("identity", "ldap-linux", "lockout_retries", "5"),
    ("identity", "ldap-linux",
     "inactive_session_term_timeout_seconds", "900"),
    ("identity", "security_compliance",
     "inactive_session_term_timeout_seconds", "3000"),
]


def _insert_param_directly(service, section, name, value, port):
    """Insert a service parameter directly into PostgreSQL.

    Bypasses the sysinv API and conductor handlers. At migrate time
    the to-release DB runs on a temporary port (typically 6666).

    Uses sudo -u postgres psql since the migrate script runs as
    sysadmin and peer authentication requires the postgres OS user.
    """
    param_uuid = str(uuid.uuid4())

    sql = (
        "INSERT INTO service_parameter "
        "(uuid, service, section, name, value, personality, resource, created_at) "
        "VALUES ('%s', '%s', '%s', '%s', '%s', NULL, NULL, now());"
        % (param_uuid, service, section, name, value)
    )

    result = subprocess.run(
        ['sudo', '-u', 'postgres', 'psql', '-d', 'sysinv',
         '--port=%s' % port, '-c', sql],
        capture_output=True, text=True, check=True
    )
    LOG.info("Inserted %s/%s/%s=%s directly into DB (uuid=%s, port=%s): %s",
             service, section, name, value, param_uuid, port,
             result.stdout.strip())


def _param_exists_in_db(service, section, name, port):
    """Check if a service parameter already exists in the DB."""
    sql = (
        "SELECT COUNT(*) FROM service_parameter "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (service, section, name)
    )
    result = subprocess.run(
        ['sudo', '-u', 'postgres', 'psql', '-d', 'sysinv',
         '--port=%s' % port, '-t', '-c', sql],
        capture_output=True, text=True, check=True
    )
    count = int(result.stdout.strip())
    return count > 0


def do_migrate(port):
    """Main migration logic: add missing service parameters.

    Inserts all parameters directly into the to-release database
    running on the specified port. No sysinv API or conductor is
    involved — this is purely a DB-level operation.

    The parameters will be picked up by puppet when the host first
    boots into the new release. For amd_pstate specifically, the
    GRUB change is applied by UpdateKernelParametersHook during
    deploy-host.
    """
    added = 0
    skipped = 0

    for service, section, name, value in DB_PARAMS:
        if _param_exists_in_db(service, section, name, port):
            LOG.info("Parameter %s/%s/%s already exists, skipping",
                     service, section, name)
            skipped += 1
            continue
        _insert_param_directly(service, section, name, value, port)
        added += 1

    LOG.info("Completed: added %d parameters, skipped %d (already existed)",
             added, skipped)


class AddMissingServiceParameters(CPlugin):
    """USM upgrade plugin to populate service parameters new in Trixie.

    Registered as a 'migrate' action plugin. The USM plugin runner
    calls _run() during 'software deploy start' to populate the
    to-release database before hosts are upgraded.
    """

    def __init__(self):
        super().__init__(
            matching_action=['migrate'],
            required_state=None,
            plugin_name='add-missing-service-parameters',
            completed_state='add-missing-service-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        """Entry point called by the USM plugin runner.

        Inserts missing service parameters directly into the
        to-release database on the given port.
        """
        LOG.info("%s invoked from_release=%s to_release=%s action=%s port=%s",
                 self.name, from_release, to_release, action, port)

        if from_release != "26.03" or to_release != "26.10":
            LOG.info("Only applicable when upgrading from 26.03 "
                     "to 26.10. Skipping.")
            return

        if action == "migrate":
            do_migrate(port)
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
