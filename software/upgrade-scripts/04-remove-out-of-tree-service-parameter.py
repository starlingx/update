#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script removes the out_of_tree_drivers service parameter
# from sysinv DB during upgrade from 25.09 to 26.03.
#

import logging
import sys

from packaging import version
import psycopg2

from software.utilities.utils import configure_logging

DEFAULT_POSTGRES_PORT = 5432
LOG = logging.getLogger('main_logger')

PARAM_NAME = "out_of_tree_drivers"
PARAM_SERVICE = "platform"
PARAM_SECTION = "kernel"


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            postgres_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()
    LOG.info(
        "%s invoked from_release=%s to_release=%s action=%s",
        sys.argv[0], from_release, to_release, action
    )

    res = 0
    to_release_version = version.Version(to_release)
    target_version = version.Version("26.03")

    # Only remove service param on migrate to 26.03
    if action == 'migrate' and to_release_version == target_version:
        try:
            conn = psycopg2.connect(
                "dbname=sysinv user=postgres port=%s" % postgres_port
            )
            remove_service_param(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error removing service parameter: %s", e)
            res = 1

    return res


def remove_service_param(conn):
    """Remove out_of_tree_drivers service parameter from sysinv DB."""
    query = (
        "SELECT uuid, value FROM service_parameter "
        "WHERE name='%s' AND service='%s' AND section='%s';"
        % (PARAM_NAME, PARAM_SERVICE, PARAM_SECTION)
    )
    rows = db_query(conn, query)
    if not rows:
        LOG.info(
            "No service parameter '%s' found. Nothing to delete.", PARAM_NAME
        )
        return

    for uuid, value in rows:
        LOG.info(
            "Deleting service parameter '%s' (uuid=%s, value=%s)",
            PARAM_NAME, uuid, value
        )
        delete_query = (
            "DELETE FROM service_parameter WHERE uuid='%s';" % uuid
        )
        db_update(conn, delete_query)

    LOG.info(
        "Service parameter '%s' removed successfully.", PARAM_NAME
    )


def db_query(conn, query):
    """Execute a read-only query and return results."""
    result = []
    with conn.cursor() as cur:
        cur.execute(query)
        for rec in cur:
            result.append(rec)
    return result


def db_update(conn, query):
    """Execute a write query and commit changes."""
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        LOG.error("An error occurred: %s", e)
        raise
