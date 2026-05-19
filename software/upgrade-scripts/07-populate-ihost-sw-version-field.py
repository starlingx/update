#!/usr/bin/env python
# Copyright (c) 2025-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# The purpose of this script is to populate the sw_version
# field on i_host table.

import logging
import sys

from six.moves import configparser
import psycopg2

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

CONTROLLER_0_HOSTNAME = "controller-0"
CONTROLLER_1_HOSTNAME = "controller-1"
DEFAULT_POSTGRES_PORT = 5432

LOG = logging.getLogger('main_logger')


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open('/etc/platform/platform.conf', 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)
    if config_applied.has_option('DEFAULT', 'system_mode'):
        return config_applied.get('DEFAULT', 'system_mode')
    return None


def populate_ihost_sw_version(conn, to_release):
    """Populate the sw_version field of i_host table for simplex"""
    hostname = CONTROLLER_1_HOSTNAME
    if get_system_mode() == "simplex":
        hostname = CONTROLLER_0_HOSTNAME

    query = "UPDATE i_host SET sw_version = %s WHERE hostname = %s"
    with conn.cursor() as cur:
        cur.execute(query, (to_release, hostname))

    conn.commit()
    LOG.info("Updated sw_version to %s on %s" % (to_release, hostname))


class PopulateIHostSWVersion(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='migrate',
            required_state=None,
            plugin_name='populate-ihost-sw-version',
            completed_state='populate-ihost-sw-version-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info(
            "%s invoked from_release = %s to_release = %s action = %s"
            % (self.name, from_release, to_release, action)
        )
        postgres_port = port if port else DEFAULT_POSTGRES_PORT
        conn = psycopg2.connect("dbname=sysinv user=postgres port=%s"
                                % postgres_port)
        try:
            populate_ihost_sw_version(conn, to_release)
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

    plugin = PopulateIHostSWVersion()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        # the pluginrunner expectes plugin.run to return new estabilished state, which is
        # currently defined as '<plugin>-failed'
        sys.exit(1)
