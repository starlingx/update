#!/usr/bin/python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script uses puppet to include the management IP on kube
# apiserver certificate SANs on upgrades from stx10 to stx11.
#

import logging
import os
import sys
import time

from oslo_config import cfg
from oslo_context import context as mycontext
from six.moves import configparser
from software.utilities.utils import configure_logging
from sysinv.conductor import rpcapiproxy as conductor_rpcapi

LOG = logging.getLogger('main_logger')

SUCCESS = 0
ERROR = 1
RETRIES = 3

CONF = cfg.CONF
SYSINV_CONFIG_FILE = '/etc/sysinv/sysinv.conf'
KUBE_CERT_SANS_UPDATE_FLAG = '/etc/platform/.upgrade_kube_apiserver_cert_sans_updated'


def get_conductor_rpc_bind_ip():
    ini_str = '[DEFAULT]\n' + open(SYSINV_CONFIG_FILE, 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    conductor_bind_ip = None
    if config_applied.has_option('DEFAULT', 'rpc_zeromq_conductor_bind_ip'):
        conductor_bind_ip = \
            config_applied.get('DEFAULT', 'rpc_zeromq_conductor_bind_ip')
    return conductor_bind_ip


def update_kube_apiserver_cert_rpc():
    CONF.rpc_zeromq_conductor_bind_ip = get_conductor_rpc_bind_ip()
    context = mycontext.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)
    rpcapi.update_kube_apiserver_cert_sans(context)


def check_kube_apiserver_cert_updated():
    return os.path.exists(KUBE_CERT_SANS_UPDATE_FLAG)


def main():
    # Initialize variables
    action = None
    from_release = None
    to_release = None
    arg = 1

    # Process command-line arguments
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # port = int(sys.argv[arg])
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return ERROR
        arg += 1

    configure_logging()
    LOG.info(
        "%s invoked from_release = %s invoked to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    for retry in range(0, RETRIES):
        try:
            if action == "activate" and from_release == "24.09":
                if not check_kube_apiserver_cert_updated():
                    update_kube_apiserver_cert_rpc()
            else:
                LOG.info("Nothing to do. "
                         "Skipping kube-apiserver certificate update.")
        except Exception as ex:
            if retry == RETRIES - 1:
                LOG.error("Error in kube-apiserver certificate update. "
                          "Please verify logs.")
                return ERROR
            else:
                LOG.exception(ex)
                LOG.error("Exception ocurred during script execution, "
                          "retrying after 5 seconds.")
                time.sleep(5)
        else:
            return SUCCESS


if __name__ == "__main__":
    sys.exit(main())
