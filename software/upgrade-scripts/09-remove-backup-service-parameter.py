#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script deletes the backup_oot_drivers service parameter
# from the sysinv DB when invoked with action=delete.
#

import logging as LOG
import sys
import re
import configparser
import psycopg2

DEFAULT_POSTGRES_PORT = 5432
DB_NAME = "sysinv"
DB_HOST = "localhost"

BACKUP_NAME = "backup_oot_drivers_24.09"
PARAM_SERVICE = "platform"
PARAM_SECTION = "kernel"

LOG.basicConfig(
    filename="/var/log/software.log",
    format='%(asctime)s: [%(process)s]: %(filename)s(%(lineno)s): '
           '%(levelname)s: %(message)s',
    level=LOG.INFO,
    datefmt="%FT%T"
)


def get_db_credentials():
    """Retrieve DB credentials from sysinv.conf"""
    try:
        config = configparser.ConfigParser()
        config.read("/etc/sysinv/sysinv.conf")

        conn_string = config["database"]["connection"]
        match = re.match(r"postgresql\+psycopg2://([^:]+):([^@]+)@", conn_string)

        if match:
            username = match.group(1)
            password = match.group(2)
            return username, password
        else:
            raise Exception("Failed to parse DB credentials from sysinv.conf")
    except Exception as e:
        LOG.error(f"Error getting DB credentials: {e}")
        sys.exit(1)


def connect_to_db(port):
    """Establish DB connection"""
    username, password = get_db_credentials()
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=username,
            password=password,
            host=DB_HOST,
            port=port,
        )
        return conn
    except Exception as e:
        LOG.error(f"Database connection failed: {e}")
        sys.exit(1)


def db_query(conn, query, params=()):
    """Execute SELECT query and return results"""
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def db_update(conn, query, params=(), autocommit=True):
    """Execute UPDATE/DELETE query"""
    with conn.cursor() as cur:
        cur.execute(query, params)
    if autocommit:
        conn.commit()


def del_backup_param(conn):
    """Delete backup_oot_drivers_24.09 service parameter from sysinv DB."""
    delete_query = (
        "DELETE FROM service_parameter "
        "WHERE name=%s AND service=%s AND section=%s;"
    )
    db_update(conn, delete_query, (BACKUP_NAME, PARAM_SERVICE, PARAM_SECTION))

    rows = db_query(
        conn,
        "SELECT COUNT(*) FROM service_parameter "
        "WHERE name=%s AND service=%s AND section=%s;",
        (BACKUP_NAME, PARAM_SERVICE, PARAM_SECTION),
    )
    if rows and rows[0][0] > 0:
        LOG.info(
            "Deleted %d backup parameter(s) named '%s'.",
            rows[0][0], BACKUP_NAME
        )
    else:
        LOG.info("No backup parameter '%s' found to delete.", BACKUP_NAME)


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT

    if len(sys.argv) < 4:
        print("Usage: %s from_release to_release action [postgres_port]" % sys.argv[0])
        return 1

    from_release = sys.argv[1]
    to_release = sys.argv[2]
    action = sys.argv[3]
    if len(sys.argv) > 4:
        postgres_port = sys.argv[4]

    LOG.info(
        "%s invoked from_release=%s to_release=%s action=%s",
        sys.argv[0],
        from_release,
        to_release,
        action,
    )

    if action == "delete":
        try:
            conn = connect_to_db(postgres_port)
            del_backup_param(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error removing backup service parameter: %s", e)
            sys.exit(1)
    else:
        LOG.info("Nothing to do. Skipping")

    return 0


if __name__ == "__main__":
    sys.exit(main())
