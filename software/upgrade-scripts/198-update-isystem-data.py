#!/usr/bin/python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script is responsible for updating the software_version
# in i_system table during the USM upgrade

import logging
import sys

import psycopg2

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

DEFAULT_POSTGRES_PORT = 5432


def get_db_credentials():
    import re
    import configparser

    configparser = configparser.ConfigParser()
    configparser.read('/etc/sysinv/sysinv.conf')
    conn_string = configparser['database']['connection']
    match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@', conn_string)
    if match:
        return match.group(1), match.group(2)
    raise Exception("Failed to get database credentials from sysinv.conf")


def update_isystem_software_version(conn, new_sw_version):
    query = f"UPDATE i_system SET software_version='{new_sw_version}';"
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()
    LOG.info(f"Updated software_version to {new_sw_version}")


class UpdateISystemData(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='update-isystem-data',
            completed_state='update-isystem-data-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        postgres_port = port if port else DEFAULT_POSTGRES_PORT
        username, password = get_db_credentials()
        conn = psycopg2.connect("dbname=sysinv user=%s password=%s "
                                "host=localhost port=%s"
                                % (username, password, postgres_port))
        try:
            update_isystem_software_version(conn, to_release)
        finally:
            conn.close()


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

    plugin = UpdateISystemData()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
