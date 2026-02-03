#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script add the autoreapply_apps_after_apply_runtime_manifest service parameter
# from sysinv DB during upgrade from 25.09 to 26.03.
#

import logging
import sys
import uuid

from packaging import version
import psycopg2
from wsme import types as wtypes

from software.utilities.utils import configure_logging


LOG = logging.getLogger('main_logger')

DEFAULT_POSTGRES_PORT = 5432
PARAM_SERVICE = "platform"
PARAM_SECTION = "config"
PARAM_NAME = "autoreapply_apps_after_apply_runtime_manifest"


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

    # Only add service param on migrate to 26.03
    if action == 'migrate' and to_release_version == target_version:
        try:
            conn = psycopg2.connect(
                "dbname=sysinv user=postgres port=%s" % postgres_port
            )
            if not check_if_service_param_exists(conn):
                add_autoreapply_service_param(conn)
            else:
                LOG.info(
                    "Service parameter %s:%s:%s already exists, skipping addition",
                    PARAM_SERVICE, PARAM_SECTION, PARAM_NAME
                )
            conn.close()
        except Exception as e:
            LOG.exception("Error removing service parameter: %s", e)
            res = 1

    return res


def check_if_service_param_exists(conn):
    """Check if the service parameter already exists in sysinv DB."""
    query = (
        "SELECT COUNT(*) FROM service_parameter "
        "WHERE service=%s AND section=%s AND name=%s;"
    )
    values = (PARAM_SERVICE, PARAM_SECTION, PARAM_NAME)

    try:
        with conn.cursor() as cursor:
            cursor.execute(query, values)
            count = cursor.fetchone()[0]
            return count > 0
    except Exception as e:
        LOG.exception("Error checking service parameter existence: %s" % e)
        raise


def add_autoreapply_service_param(conn):
    """Add the autoreapply_apps_after_apply_runtime_manifest
    service parameter to sysinv DB.
    """
    LOG.info(
        "Adding service parameter %s:%s:%s",
        PARAM_SERVICE, PARAM_SECTION, PARAM_NAME
    )

    created_at = wtypes.datetime.datetime
    central_uuid = str(uuid.uuid4())

    insert_query = (
        "INSERT INTO service_parameter "
        "(uuid, service, section, name, value, personality, "
        "resource, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"
    )

    values = (
        central_uuid, PARAM_SERVICE, PARAM_SECTION, PARAM_NAME, "enabled",
        None, None, created_at.utcnow()
    )
    db_execute(conn, insert_query, values)
    LOG.info(
        "Service parameter %s:%s:%s added successfully",
        PARAM_SERVICE, PARAM_SECTION, PARAM_NAME
    )


def db_execute(conn, query, params):
    try:
        with conn.cursor() as cursor:
            cursor.execute(query, params)
            conn.commit()
    except Exception as e:
        conn.rollback()
        LOG.exception("Error executing query: %s" % e)
        raise


if __name__ == "__main__":
    sys.exit(main())
