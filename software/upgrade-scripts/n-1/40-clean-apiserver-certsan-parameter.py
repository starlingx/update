#!/usr/bin/env python
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Clean up of "apiserver_certsan" service parameter if present, used
# previously to configure extra SANs for kube-apiserver, which is being
# removed in stx 12.
#

import configparser
import logging as LOG
import psycopg2
import re
import sys

from software.utilities.utils import configure_logging

DEFAULT_POSTGRES_PORT = 5432
DB_NAME = "sysinv"
DB_HOST = "localhost"

PARAM_SERVICE = "kubernetes"
PARAM_SECTION = "certificates"
PARAM_NAME = "apiserver_certsan"


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


def db_get_query(conn, query, params=()):
    """Execute SELECT query and return results"""
    with conn.cursor() as cur:
        cur.execute(query, params)
        return cur.fetchall()


def db_update(conn, query, params=()):
    """Execute UPDATE/DELETE query"""
    with conn.cursor() as cur:
        cur.execute(query, params)
        LOG.info("# of rows updated: %d.", cur.rowcount)
    conn.commit()


def del_certsans_param(conn):
    """Delete apiserver_certsan service parameter from sysinv DB."""
    query = (
        " FROM service_parameter "
        "WHERE name=%s AND service=%s AND section=%s;"
    )
    rows = db_get_query(conn,
                        "SELECT *" + query,
                        (PARAM_NAME, PARAM_SERVICE, PARAM_SECTION))
    if rows:
        for item in rows:
            LOG.info("Found '%s' parameter, UUID: %s.", PARAM_NAME, item[4])
        db_update(conn,
                  "DELETE" + query,
                  (PARAM_NAME, PARAM_SERVICE, PARAM_SECTION))
    else:
        LOG.info("Parameter '%s' not present to delete.", PARAM_NAME)


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

    configure_logging()

    LOG.info(
        "%s invoked from_release=%s to_release=%s action=%s",
        sys.argv[0],
        from_release,
        to_release,
        action,
    )

    if action == "delete" and from_release.startswith("25.09"):
        try:
            conn = connect_to_db(postgres_port)
            del_certsans_param(conn)
            conn.close()
        except Exception as e:
            LOG.exception("Error removing apiserver_certsan parameter: %s", e)
            sys.exit(1)
    else:
        LOG.info("Nothing to do. Skipping")

    return 0


if __name__ == "__main__":
    sys.exit(main())
