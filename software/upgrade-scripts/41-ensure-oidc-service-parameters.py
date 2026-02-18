#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems
#
# SPDX-License-Identifier: Apache-2.0
#
# Ensure OIDC-apps Kubernetes service
# parameters are configured on the system
#
# *** THIS SCRIPT NEEDS TO BE EXECUTED BEFORE '#-k8s-app-upgrade.sh',
# In a system without OIDC configured, the new OIDC lifecycle
# will require the oidc-issuer-url configured by this script.

import logging
import os
import subprocess
import sys
import time

from cgtsclient import client as cgts_client
from software.utilities.utils import configure_logging
import sysinv.common.constants as c

LOG = logging.getLogger("main_logger")

DEFAULT_ISSUER_PORT = "30556"


def get_pidof(name):
    """
    Return the PID for the given process name.

    :param name: Process name
    :return: PID as integer, or -1 if not running
    """
    try:
        out = subprocess.check_output(["pidof", "-s", name], text=True).strip()
        return int(out) if out else -1
    except Exception:
        return -1


def get_sysinv_client():
    """
    Return an authenticated Sysinv (cgts) client.

    Authentication is performed using OS_AUTH_TOKEN and SYSTEM_URL
    from the environment.
    """
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL"),
    )


def is_subcloud(sysinv):
    """
    Return True if the system is a subcloud.

    :param sysinv: Authenticated Sysinv client
    """
    system = sysinv.isystem.list()[0]
    return system.distributed_cloud_role == c.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD


def is_k8s_oidc_param_configured(sysinv):
    """
    Check whether the kube-apiserver OIDC issuer URL is already configured.

    :param sysinv: Authenticated Sysinv client
    :return: True if OIDC issuer URL parameter exists, False otherwise
    """
    return any(
        p.service == c.SERVICE_TYPE_KUBERNETES
        and p.section == c.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER
        and p.name == c.SERVICE_PARAM_NAME_OIDC_ISSUER_URL
        for p in sysinv.service_parameter.list()
    )


def get_oam_address(sysinv, network_type):
    """
    Return the primary floating OAM address
    and IP family for the given network type.

    :param sysinv: Authenticated Sysinv client
    :param network_type: Address pool network type constant
    :return: Tuple (floating_address, family)
    """
    pool = sysinv.address_pool.list_by_network_type(network_type)[0]
    return pool.floating_address, pool.family


def configure_k8s_oidc_param(sysinv, oam_network):
    """
    Configure kube-apiserver OIDC parameters.

    :param sysinv: Authenticated Sysinv client
    :param oam_network: Tuple (floating_ip, family)
    """
    floating_ip, family = oam_network
    if not floating_ip:
        LOG.error("Missing floating OAM address")
        raise Exception("Missing floating OAM address")

    host = f"[{floating_ip}]" if family == c.IPV6_FAMILY else floating_ip
    issuer_url = f"https://{host}:{DEFAULT_ISSUER_PORT}/dex"

    LOG.info("Configuring Kubernetes OIDC parameters")
    LOG.info("OIDC issuer URL: %s", issuer_url)

    sysinv.service_parameter.create(
        c.SERVICE_TYPE_KUBERNETES,
        c.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
        None,   # personality
        None,   # resource
        {
            c.SERVICE_PARAM_NAME_OIDC_ISSUER_URL: issuer_url,
            c.SERVICE_PARAM_NAME_OIDC_CLIENT_ID: "stx-oidc-client-app",
            c.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM: "name",
            c.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM: "groups",
        },
    )


def wait_kube_apiserver_up(previous_pid, timeout=300, interval=5):
    """
    Wait until kube-apiserver is running again with a new PID.

    :param previous_pid: PID observed before restart
    :param timeout: Maximum wait time in seconds
    :param interval: Polling interval in seconds
    :raises TimeoutError: if kube-apiserver does not come back within timeout
    """
    attempts = timeout // interval
    LOG.info(
        "Waiting for kube-apiserver restart "
        "(previous PID: %s, max attempts: %d)",
        previous_pid,
        attempts,
    )

    for attempt in range(1, attempts + 1):
        pid = get_pidof("kube-apiserver")

        if pid > 0 and pid != previous_pid:
            LOG.info(f"kube-apiserver is up (new PID: {pid})")
            return

        LOG.info(f"Attempt {attempt}/{attempts}: kube-apiserver not ready")
        time.sleep(interval)

    LOG.error(f"Timed out waiting for kube-apiserver: {attempts} attempts")
    raise TimeoutError("Timed out waiting for kube-apiserver to come up")


def main():
    argv = sys.argv

    if len(argv) > 5:
        print(f"Invalid option {argv[5]}.")
        return 1

    from_release = argv[1] if len(argv) > 1 else None
    to_release = argv[2] if len(argv) > 2 else None
    action = argv[3] if len(argv) > 3 else None
    # Not used by this script.
    # postgres_port = argv[4] if len(argv) > 4 else None

    configure_logging()

    if action != "activate":
        LOG.info(f"Nothing to do for action '{action}'.")
        return 0

    if to_release != "26.03":
        LOG.info("OIDC is expected to always be applied after release 26.03")
        return 0

    LOG.info("%s invoked with from_release %s to_release %s and action %s",
             sys.argv[0], from_release, to_release, action)

    sysinv = get_sysinv_client()

    if is_k8s_oidc_param_configured(sysinv):
        LOG.info("OIDC kubernetes parameters already configured")
        return 0

    if is_subcloud(sysinv):
        network_type = c.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM
    else:
        network_type = c.NETWORK_TYPE_OAM

    oam_network = get_oam_address(sysinv, network_type)
    configure_k8s_oidc_param(sysinv, oam_network)

    previous_pid = get_pidof("kube-apiserver")

    LOG.info("Applying Kubernetes service parameters")
    sysinv.service_parameter.apply(c.SERVICE_TYPE_KUBERNETES)

    wait_kube_apiserver_up(previous_pid)

    return 0


# TODO(ealmeida): Remove this script on releases > 26.03
if __name__ == "__main__":
    sys.exit(main())
