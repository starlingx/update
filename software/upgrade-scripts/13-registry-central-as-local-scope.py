#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging
import os
import psycopg2
import subprocess
import sys
import uuid
from cgtsclient import client as cgts_client
from software.utilities.utils import configure_logging
from sysinv.common import constants as sysinv_constants
from wsme import types as wtypes


DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"
LOG = logging.getLogger('main_logger')


# CgtsClient class to handle API interactions
class CgtsClient(object):
    SYSINV_API_VERSION = 1

    def __init__(self):
        self.conf = {}
        self._sysinv = None

        # Loading credentials and configurations from environment variables
        # typically set in OpenStack
        source_command = 'source /etc/platform/openrc && env'

        with open(os.devnull, "w") as fnull:
            proc = subprocess.Popen(
                ['bash', '-c', source_command],
                stdout=subprocess.PIPE, stderr=fnull,
                universal_newlines=True)

        # Strip the configurations starts with 'OS_' and change
        # the value to lower
        for line in proc.stdout:
            key, _, value = line.partition("=")
            if key.startswith('OS_'):
                self.conf[key[3:].lower()] = value.strip()

        proc.communicate()

    @property
    def sysinv(self):
        if not self._sysinv:
            self._sysinv = cgts_client.get_client(
                self.SYSINV_API_VERSION,
                os_username=self.conf['username'],
                os_password=self.conf['password'],
                os_auth_url=self.conf['auth_url'],
                os_project_name=self.conf['project_name'],
                os_project_domain_name=self.conf['project_domain_name'],
                os_user_domain_name=self.conf['user_domain_name'],
                os_region_name=self.conf['region_name'],
                os_service_type='platform',
                os_endpoint_type='internal')
        return self._sysinv


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
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    configure_logging()

    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    if action == "migrate" and from_release == "25.09":
        LOG.info("Create service parameter DNS local scope for "
                 "registry.central. Just for subclouds.")

        conn = None
        try:
            client = CgtsClient()
            virtual_system = check_virtual_system(client)

            conn = psycopg2.connect(
                "dbname=sysinv user=postgres port=%s" % postgres_port)

            floating_address_id = get_floating_sc_address_id(
                conn, virtual_system)
            # if system controller IP doesn't exist, it is not a subcloud
            # registry.central is not necessary
            if not floating_address_id:
                LOG.info("System controller address ID not found, exiting.")
                return 0

            update_dns_local_registry(conn, to_release)

        except Exception as ex:
            LOG.exception("Error: %s" % ex)
            print(ex)
            return 1

        finally:
            if conn:
                conn.close()

    return 0


def update_dns_local_registry(conn, to_release):
    # Add registry.central to DNS local domain

    try:
        # check if registry.central is in DNS local domain
        local_domain = get_dns_local_registry_central(conn)

        if local_domain:
            LOG.info("registry.central is already configured in dns local domain.")
            return 0

        created_at = wtypes.datetime.datetime
        central_uuid = str(uuid.uuid4())

        insert_central_query = (
            "INSERT INTO service_parameter "
            "(uuid, service, section, name, value, personality, "
            "resource, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s);"
        )
        central_values = (
            central_uuid, 'dns', 'local', 'registry.central',
            "registry.central",
            None, None, created_at.utcnow()
        )
        db_execute(conn, insert_central_query, central_values)

        config_dir = f"/opt/platform/config/{to_release}"
        config_file = os.path.join(config_dir, "dnsmasq.addn_conf")

        os.makedirs(config_dir, exist_ok=True)
        LOG.info("Created config directory: %s" % config_dir)

        existing_lines = []
        if os.path.exists(config_file):
            with open(config_file, "r") as f:
                existing_lines = f.readlines()

        updated_lines = []
        is_local_domain_present = False
        for line in existing_lines:
            if line.startswith("local=/registry.central/"):
                is_local_domain_present = True
            updated_lines.append(line.strip())

        # just updates the dnsmasq.addn_conf if entry does not exists
        if not is_local_domain_present:
            updated_lines.append(
                "local=/registry.central/"
            )

            with open(config_file, "w") as f:
                for line in updated_lines:
                    f.write(line + "\n")
                    LOG.info("Updated entry in %s: %s" % (config_file, line))

    except Exception as e:
        LOG.exception("Failed to update DNS local domain: %s" % e)
        raise


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
        LOG.exception("Error executing query: %s" % e)
        raise


def db_query(conn, query):
    try:
        with conn.cursor() as cursor:
            cursor.execute(query)
            result = cursor.fetchone()
            return result[0] if result else None
    except Exception as e:
        LOG.exception("Error executing query: %s" % e)
        raise


def check_virtual_system(client):
    parameters = client.sysinv.service_parameter.list()

    for parameter in parameters:
        if (parameter.name ==
                sysinv_constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL):
            return True

    return False


def get_floating_sc_address_id(conn, virtual_system):
    if virtual_system:
        query = (
            "SELECT floating_address_id FROM address_pools "
            "WHERE name = 'system-controller-subnet';"
        )
    else:
        query = (
            "SELECT floating_address_id FROM address_pools "
            "WHERE name = 'system-controller-oam-subnet';"
        )

    return db_query(conn, query)


def get_controller_mgmt_address(conn):
    query = "SELECT address FROM addresses WHERE name = 'controller-mgmt';"
    return db_query(conn, query)


def get_dns_local_registry_central(conn):
    query = (
        "SELECT name FROM service_parameter WHERE service = 'dns' \
        and section='local' and name='registry.central';"
    )
    return db_query(conn, query)


if __name__ == "__main__":
    sys.exit(main())
