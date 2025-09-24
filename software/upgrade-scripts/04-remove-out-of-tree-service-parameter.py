#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the out_of_tree_drivers service parameter
# name to backup_oot_drivers_24.09 from sysinv DB during upgrade
# from 24.09 to 25.09.
#


import logging
import sys

from packaging import version
import psycopg2

from software.utilities.utils import configure_logging

DEFAULT_POSTGRES_PORT = 5432
LOG = logging.getLogger('main_logger')

PARAM_NAME = "out_of_tree_drivers"
BACKUP_NAME = "backup_oot_drivers_24.09"
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
    target_version = version.Version("25.09")

    # Only remove service param on migrate to 25.09
    if action == 'migrate' and to_release_version == target_version:
        try:
            conn = psycopg2.connect(
                "dbname=sysinv user=postgres port=%s" % postgres_port
            )
            update_service_param(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error removing service parameter: %s", e)
            res = 1

    return res


def update_service_param(conn):
    """Update out_of_tree_drivers service parameter to backup_oot_drivers
    and ensure any old backup is cleaned up first.
    """
    # Delete any existing backup entry to avoid stale values
    cleanup_query = (
        "DELETE FROM service_parameter "
        "WHERE name='%s' AND service='%s' AND section='%s';"
        % (BACKUP_NAME, PARAM_SERVICE, PARAM_SECTION)
    )
    db_update(conn, cleanup_query)
    LOG.info("Cleaned up any existing '%s' backup entry.", BACKUP_NAME)

    # Update the original parameter to backup_oot_drivers_24.09
    update_query = (
        "UPDATE service_parameter "
        "SET name='%s' "
        "WHERE name='%s' AND service='%s' AND section='%s';"
        % (BACKUP_NAME, PARAM_NAME, PARAM_SERVICE, PARAM_SECTION)
    )
    db_update(conn, update_query)
    LOG.info(
        "Updated service parameter '%s' to '%s' successfully.",
        PARAM_NAME, BACKUP_NAME
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
