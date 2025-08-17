#!/usr/bin/env python3
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

# This script is responsible to update swanctl configuration
# file in multinodes systems.

import logging
import sys
import time

from oslo_config import cfg
from oslo_context import context as mycontext
from six.moves import configparser
from software.utilities.utils import configure_logging
from sysinv.conductor import rpcapiproxy as conductor_rpcapi

# Constants
CONF = cfg.CONF
LOG = logging.getLogger('main_logger')
SYSINV_CONFIG_FILE = '/etc/sysinv/sysinv.conf'
PLATFORM_CONFIG_FILE = '/etc/platform/platform.conf'
ACTION_ACTIVATE = 'activate'
ACTION_ACTIVATE_ROLLBACK = 'activate-rollback'


def main():
    action = None
    from_release = None
    to_release = None
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
            # port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    configure_logging(LOG)
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    res = 0
    system_mode = get_system_mode()
    if system_mode != "simplex" and action in [ACTION_ACTIVATE,
                                               ACTION_ACTIVATE_ROLLBACK]:
        # Options of bind ip to the rpc call
        rpc_ip_options = [get_conductor_rpc_bind_ip(), 'controller.internal']
        while None in rpc_ip_options:
            rpc_ip_options.remove(None)

        for index, ip in enumerate(rpc_ip_options):
            try:
                CONF.rpc_zeromq_conductor_bind_ip = ip
                context = mycontext.get_admin_context()
                rpcapi = conductor_rpcapi.ConductorAPI(
                    topic=conductor_rpcapi.MANAGER_TOPIC)

                LOG.info("Call Conductor to reconfigure IPsec. "
                         "Bind ip: %s." % CONF.rpc_zeromq_conductor_bind_ip)
                rpcapi.reconfigure_ipsec(context, action)
            except Exception as e:
                if index == (len(rpc_ip_options) - 1):
                    LOG.error("Error configuring keystone endpoints. "
                              "Please verify logs.")
                    res = 1
                    break
                else:
                    LOG.exception(e)
                    LOG.error("Exception ocurred during script execution, "
                              "retrying after 5 seconds.")
                    time.sleep(5)
    else:
        LOG.info(f"Nothing to do for action {action} in {system_mode} environment.")
    LOG.info("%s completed execution." % (sys.argv[0]))
    return res


def get_system_mode():
    ini_str = '[DEFAULT]\n' + open(PLATFORM_CONFIG_FILE, 'r').read()

    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    if config_applied.has_option('DEFAULT', 'system_mode'):
        system_mode = config_applied.get('DEFAULT', 'system_mode')
    else:
        system_mode = None

    return system_mode


def get_conductor_rpc_bind_ip():
    ini_str = '[DEFAULT]\n' + open(SYSINV_CONFIG_FILE, 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    conductor_bind_ip = None
    if config_applied.has_option('DEFAULT', 'rpc_zeromq_conductor_bind_ip'):
        conductor_bind_ip = \
            config_applied.get('DEFAULT', 'rpc_zeromq_conductor_bind_ip')
    return conductor_bind_ip


if __name__ == "__main__":
    sys.exit(main())
