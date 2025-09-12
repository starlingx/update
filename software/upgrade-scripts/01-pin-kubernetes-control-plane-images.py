#!/usr/bin/env python
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script uses sysinv-conductor API to pin kubernetes control plane containerd images
# particularly kube-apiserver, kube-controller-manager, kube-scheduler on controller hosts.
#
# Note: This script is only required for 24.09 to 25.09 upgrade and should be removed afterwards.

import logging
import sys

from oslo_config import cfg
from oslo_context import context as mycontext
from six.moves import configparser
from software.utilities.utils import configure_logging
from sysinv.conductor import rpcapiproxy as conductor_rpcapi

LOG = logging.getLogger('main_logger')

CONF = cfg.CONF
SYSINV_CONFIG_FILE = '/etc/sysinv/sysinv.conf'

# As this script is only required for 24.09 to 25.09 release, we do not need to use kubernetes APIs
# to get current running version.
KUBE_VERSION = "v1.29.2"


def get_conductor_rpc_bind_ip():
    ini_str = '[DEFAULT]\n' + open(SYSINV_CONFIG_FILE, 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    conductor_bind_ip = None
    if config_applied.has_option('DEFAULT', 'rpc_zeromq_conductor_bind_ip'):
        conductor_bind_ip = \
            config_applied.get('DEFAULT', 'rpc_zeromq_conductor_bind_ip')
    return conductor_bind_ip


def pin_kubernetes_control_plane_images():
    CONF.rpc_zeromq_conductor_bind_ip = get_conductor_rpc_bind_ip()
    context = mycontext.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)
    rpcapi.pin_kubernetes_control_plane_images(context, KUBE_VERSION)


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
        arg += 1

    configure_logging()
    LOG.info(
        "%s invoked from_release = %s invoked to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    try:
        if action == "activate" and from_release == "24.09":
            pin_kubernetes_control_plane_images()
        else:
            LOG.info("Nothing to do. Skipping pinning control plane images.")
    except Exception as ex:
        LOG.warning("Failed to pin kubernetes control-plane images. Ignoring... Error: [%s]" % (ex))


if __name__ == "__main__":
    main()
    sys.exit(0)
