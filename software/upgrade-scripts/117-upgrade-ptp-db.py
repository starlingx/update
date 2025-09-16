#!/usr/bin/env python
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration scripts is used to automaticaly upgrade the PTP
# system configuration, according to changes on linuxptp library,
# drivers, etc.

import logging as log
import psycopg2 as db
import sys
import uuid

from datetime import datetime
from datetime import timezone
from software.utilities.utils import configure_logging

DEFAULT_POSTGRES_PORT = 5432
DB_CONNECT_FORMAT = "dbname=sysinv user=postgres port=%s"


def db_connect(port):
    try:
        conn = db.connect(DB_CONNECT_FORMAT % port)
        return conn
    except Exception as e:
        log.exception(f"Error: {e}")


def db_close(conn):
    try:
        conn.close()
    except Exception as e:
        log.exception(f"Error: {e}")


def db_query(conn, query):
    result = []
    try:
        with conn.cursor() as curs:
            curs.execute(query)
            result = curs.fetchall()
    except Exception as e:
        log.exception(f"Error: {e}")
    return result


def db_execute(conn, query, params=None):
    try:
        with conn.cursor() as cursor:
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
    except Exception as e:
        conn.rollback()
        log.exception(f"Error executing query: {e}")
        raise


def get_instances(conn, service=None) -> list:
    """ get ts2phc instances from database """
    log.info("getting instances ...")

    query = (
        "SELECT ptp_instances.id, ptp_instances.name, "
        "ptp_parameter_owners.uuid "
        "FROM ptp_instances "
        "INNER JOIN ptp_parameter_owners "
        "ON ptp_instances.id = ptp_parameter_owners.id"
    )
    # Filter by PTP service type
    if service:
        query += f" WHERE service = '{service}';"
    instances = db_query(conn, query)

    instances_list = []
    for instance in instances:
        id = instance[0]
        name = instance[1]
        owner_id = instance[2]
        interfaces = get_interfaces(conn, id)
        for interface in interfaces:
            parameters = get_parameters(conn, interface['owner_id'])
            interface['parameters'] = parameters
        instances_list += [{
            'name': name,
            'id': id,
            'owner_id': owner_id,
            'interfaces': interfaces
        }]
    return instances_list


def get_interfaces(conn, instance_id=None) -> list:
    """ get interfaces """
    log.info("getting interfaces ...")

    query = (
        "SELECT ptp_interfaces.id, ptp_interfaces.name, "
        "ptp_parameter_owners.uuid "
        "FROM ptp_interfaces "
        "INNER JOIN ptp_parameter_owners "
        "ON ptp_interfaces.id = ptp_parameter_owners.id"
    )
    # Filter by PTP instance id
    if instance_id:
        query += f" WHERE ptp_interfaces.ptp_instance_id = '{instance_id}';"
    interfaces = db_query(conn, query)

    interface_list = []
    for interface in interfaces:
        id = interface[0]
        name = interface[1]
        owner_id = interface[2]
        interface_list += [{'name': name, 'id': id, 'owner_id': owner_id}]
    return interface_list


def get_parameters(conn, owner_id=None) -> list:
    """ get parameters """
    log.info("getting parameters ...")

    query = (
        "SELECT ptp_parameters.id, ptp_parameters.name, "
        "ptp_parameters.value "
        "FROM ptp_parameters "
        "INNER JOIN ptp_parameter_ownerships "
        "ON ptp_parameters.uuid = ptp_parameter_ownerships.parameter_uuid"
    )
    # Filter by owner id
    if owner_id:
        query += f" WHERE ptp_parameter_ownerships.owner_uuid = '{owner_id}';"
    parameters = db_query(conn, query)

    parameter_list = []
    for parameter in parameters:
        log.info(f"parameter: {parameter}")
        id = parameter[0]
        key = parameter[1]
        value = parameter[2]
        parameter_list += [{'id': id, 'key': key, 'value': value}]
    return parameter_list


def insert_parameter(conn, key, value, owner_uuid):
    """ insert ptp parameter """
    log.info("inserting parameter ...")

    parameter_uuid = str(uuid.uuid4())
    created_at = datetime.now(timezone.utc)

    query = (
        "INSERT INTO ptp_parameters "
        "(uuid, name, value, created_at) "
        "VALUES (%s, %s, %s, %s);"
    )
    values = (parameter_uuid, key, value, created_at)
    db_execute(conn, query, values)

    ownership_uuid = str(uuid.uuid4())
    query = (
        "INSERT INTO ptp_parameter_ownerships "
        "(uuid, parameter_uuid, owner_uuid, created_at) "
        "VALUES (%s, %s, %s, %s)"
    )
    values = (ownership_uuid, parameter_uuid, owner_uuid, created_at)
    db_execute(conn, query, values)


def migrate_ts2phc_database(conn):
    """ migrate ts2phc database """
    log.info("migrating ts2phc database ...")

    # Get list of ts2phc instances, interfaces and parameters.
    # If any interface hasn't the ts2phc.pin_index or the
    # ts2phc.channel parameter, add them as they're required.
    instances = get_instances(conn, 'ts2phc')
    for instance in instances:
        log.info(f"instance {instance}")
        for interface in instance['interfaces']:
            if not any(parameter['key'] == 'ts2phc.pin_index'
                       for parameter in interface['parameters']):
                log.info(f"ts2phc instance {instance['name']} "
                         f"interface {interface['name']} "
                         "'ts2phc.pin_index' parameter not found.")
                insert_parameter(conn, 'ts2phc.pin_index', '1',
                                 interface['owner_id'])
            if not any(parameter['key'] == 'ts2phc.channel'
                       for parameter in interface['parameters']):
                log.info(f"ts2phc instance {instance['name']} "
                         f"interface {interface['name']} "
                         "'ts2phc.channel' parameter not found.")
                insert_parameter(conn, 'ts2phc.channel', '1',
                                 interface['owner_id'])


def main():
    """" main - parsing args and call migration functions """
    # migration arguments
    action = None
    from_release = None
    to_release = None
    db_port = DEFAULT_POSTGRES_PORT
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            db_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()
    log.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == 'migrate' and from_release == "24.09":
        conn = db_connect(db_port)
        if conn:
            migrate_ts2phc_database(conn)
            db_close(conn)
        else:
            log.error("%s failed to connect to database." %
                      sys.argv[0])
    else:
        log.info("nothing to do")


if __name__ == "__main__":
    sys.exit(main())
