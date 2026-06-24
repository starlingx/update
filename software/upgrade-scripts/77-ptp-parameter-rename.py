#!/usr/bin/python3
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script renames PTP parameters that were deprecated in
# linuxptp 4.0+ (shipped in Debian Trixie). The following renames are
# performed in the ptp_parameters database table:
#
#   masterOnly  -> serverOnly
#   slaveOnly   -> clientOnly
#
# These parameters are used in ptp4l configuration and their old names
# are no longer recognized by the newer linuxptp version.

import keyring
import logging
import os
import sys
import yaml

import psycopg2 as db
from psycopg2.extras import RealDictCursor

from controllerconfig.common import constants
from tsconfig.tsconfig import PLATFORM_PATH

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

# Mapping of deprecated PTP parameter names to their new equivalents.
# Key: old (deprecated) name, Value: new name
PTP_PARAMETER_RENAMES = {
    "masterOnly": "serverOnly",
    "slaveOnly": "clientOnly",
}


def get_db_credentials(release):
    """Get sysinv DB credentials."""
    static_file = os.path.join(
        PLATFORM_PATH,
        "puppet",
        release,
        "hieradata",
        "static.yaml"
    )
    with open(static_file, 'r') as s_file:
        static_config = yaml.safe_load(s_file)
        username = static_config[
            'sysinv::db::postgresql::user'
        ]
        password = keyring.get_password(
            'sysinv',
            'database'
        )
        if password is None:
            raise RuntimeError(
                "Failed to retrieve sysinv database password from keyring"
            )
        return username, password


def db_connect(username, password, port):
    return db.connect(
        dbname="sysinv",
        user=username,
        password=password,
        host="127.0.0.1",
        port=port
    )


def do_ptp_parameter_rename(username, password, port):
    """Rename deprecated PTP parameters in the sysinv database.

    This function queries the ptp_parameters table for any parameters
    using the deprecated names and renames them to their new equivalents.
    If a parameter with the new name already exists for the same owner,
    the deprecated entry is removed to avoid duplicates.
    """
    conn = db_connect(username, password, port)
    with conn:
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                for old_name, new_name in PTP_PARAMETER_RENAMES.items():
                    _rename_parameter(cursor, old_name, new_name)
            LOG.debug("commiting changes")
            conn.commit()
        except Exception as ex:
            LOG.exception(
                f"rename-deprecated-ptp-parameters-failed: {ex}"
            )
            conn.rollback()
            raise
    LOG.info("Rename deprecated PTP parameters completed")


def _rename_parameter(cursor, old_name, new_name):
    """Rename a single PTP parameter from old_name to new_name.

    If a row with new_name already exists (same value), the old row is
    simply deleted. Otherwise, the old row's name is updated to new_name.
    Ownership records (ptp_parameter_ownerships) are preserved since they
    reference the parameter by uuid.
    """
    # Find all parameters with the deprecated name
    cursor.execute(
        "SELECT * FROM ptp_parameters WHERE name = %s",
        (old_name,)
    )
    old_params = cursor.fetchall()

    if not old_params:
        LOG.debug(
            f"No PTP parameter found with name '{old_name}', skipping."
        )
        return

    # Find all parameters with the new name
    cursor.execute(
        "SELECT * FROM ptp_parameters WHERE name = %s",
        (new_name,)
    )
    new_params = cursor.fetchall()

    for old_param in old_params:
        LOG.debug(
            f"Parameter '{old_name}={old_param['value']}' "
            f"(uuid={old_param['uuid']})"
        )

        # Check if a parameter with the new name exists
        # with the same value
        existing_new = [
            new_param for new_param in new_params
            if new_param['value'] == old_param['value']
        ]

        if existing_new:
            # New parameter already exists.
            # To avoid duplicates, delete from ownership table
            # all entries of the old parameter that has the same
            # owner from the new parameter.
            new_param = existing_new[0]
            cursor.execute(
                "DELETE FROM ptp_parameter_ownerships "
                "WHERE owner_uuid IN "
                "( SELECT owner_uuid FROM ptp_parameter_ownerships "
                "WHERE parameter_uuid = %s ) "
                "AND parameter_uuid = %s",
                (new_param['uuid'], old_param['uuid'],)
            )
            # Change parameter ownership table, migrate all
            # older parameter reference to the new one.
            cursor.execute(
                "UPDATE ptp_parameter_ownerships "
                "SET parameter_uuid = %s "
                "WHERE parameter_uuid = %s",
                (new_param['uuid'], old_param['uuid'],)
            )
            # Delete the old parameter from parameters table.
            cursor.execute(
                "DELETE FROM ptp_parameters WHERE uuid = %s",
                (old_param['uuid'],)
            )
            LOG.debug(
                f"Deleted deprecated parameter '{old_name}' "
                f"(uuid={old_param['uuid']})."
            )
        else:
            # No equivalent new parameter exists, just rename
            cursor.execute(
                "UPDATE ptp_parameters SET name = %s WHERE uuid = %s",
                (new_name, old_param['uuid'],)
            )
            LOG.debug(
                f"Renamed PTP parameter '{old_name}' -> '{new_name}' "
                f"(uuid={old_param['uuid']})"
            )


class RenameDeprecatedPtpParameters(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='migrate',
            required_state=None,
            plugin_name='rename-deprecated-ptp-parameters',
            completed_state='rename-deprecated-ptp-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        postgres_port = port if port else constants.POSTGRESQL_DEFAULT_PORT
        LOG.info(
            f"{self.name} invoked from_release = {from_release} "
            f"to_release = {to_release} action = {action} "
            f"port = {postgres_port}"
        )
        db_username, db_password = get_db_credentials(to_release)
        do_ptp_parameter_rename(db_username, db_password, postgres_port)


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

    plugin = RenameDeprecatedPtpParameters()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
