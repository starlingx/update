#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add platform TLS service parameters (tls-min-version and
# tls-cipher-suite) and update kubernetes kube_apiserver
# tls-cipher-suites to include missing CHACHA20 cipher suites
# during upgrade activation.
#
# Platform parameters are new in 26.09 and do not exist in 25.09
# or 26.03.  Safe defaults (TLS 1.2, full 9-cipher list) are
# used so that TLS behaviour is unchanged after upgrade.
#
# The k8s CHACHA20 ciphers were added in 26.09 for fresh installs
# but were missing from the upgrade path.
#

import logging
import os
import subprocess
import sys
import time

from cgtsclient import client as cgts_client
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger("main_logger")

PARAM_SERVICE = "platform"
PARAM_SECTION = "config"
PARAM_TLS_MIN_VERSION = "tls-min-version"
PARAM_TLS_CIPHER_SUITE = "tls-cipher-suite"

DEFAULT_TLS_MIN_VERSION = "VersionTLS12"
DEFAULT_TLS_CIPHER_SUITE = (
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,"
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,"
    "TLS_AES_256_GCM_SHA384,"
    "TLS_AES_128_GCM_SHA256,"
    "TLS_CHACHA20_POLY1305_SHA256"
)

K8S_SERVICE = "kubernetes"
K8S_SECTION = "kube_apiserver"
K8S_TLS_CIPHER_SUITES = "tls-cipher-suites"

# Canonical cipher order for k8s kube_apiserver matching fresh install.
K8S_EXPECTED_CIPHER_ORDER = [
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_AES_128_GCM_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

K8S_MISSING_CIPHERS = [
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]


def get_sysinv_client():
    """Return an authenticated Sysinv (cgts) client."""
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL"),
    )


def get_pidof(name):
    """Return the PID for the given process name.

    :param name: Process name
    :return: PID as integer, or -1 if not running
    """
    try:
        out = subprocess.check_output(
            ["pidof", "-s", name], text=True).strip()
        return int(out) if out else -1
    except Exception:
        return -1


def wait_kube_apiserver_up(previous_pid, timeout=300, interval=5):
    """Wait until kube-apiserver is running again with a new PID.

    After service_parameter.apply("kubernetes"), the conductor
    dispatches a puppet manifest that restarts kube-apiserver.
    This function polls until the apiserver comes back with a
    different PID, ensuring downstream scripts do not encounter
    a restarting apiserver.

    :param previous_pid: PID observed before the apply
    :param timeout: Maximum wait time in seconds
    :param interval: Polling interval in seconds
    :raises TimeoutError: if kube-apiserver does not restart in time
    """
    attempts = timeout // interval
    LOG.info(
        "Waiting for kube-apiserver restart "
        "(previous PID: %s, max attempts: %d)",
        previous_pid,
        attempts,
    )

    for attempt in range(0, attempts):
        pid = get_pidof("kube-apiserver")

        if pid > 0 and pid != previous_pid:
            LOG.info("kube-apiserver is up (new PID: %d)", pid)
            return

        LOG.info("Attempt %d/%d: kube-apiserver not ready yet",
                 attempt + 1, attempts)
        time.sleep(interval)

    LOG.error("Timed out waiting for kube-apiserver after %d attempts",
              attempts)
    raise TimeoutError(
        "Timed out waiting for kube-apiserver to restart"
    )


def tls_params_exist(sysinv):
    """Return True if tls-min-version already exists in platform config."""
    return any(
        p.service == PARAM_SERVICE
        and p.section == PARAM_SECTION
        and p.name == PARAM_TLS_MIN_VERSION
        for p in sysinv.service_parameter.list()
    )


def add_platform_tls_params(sysinv):
    """Create platform TLS service parameters with safe defaults."""
    LOG.info("Adding platform TLS service parameters")
    sysinv.service_parameter.create(
        PARAM_SERVICE,
        PARAM_SECTION,
        None,  # personality
        None,  # resource
        {
            PARAM_TLS_MIN_VERSION: DEFAULT_TLS_MIN_VERSION,
            PARAM_TLS_CIPHER_SUITE: DEFAULT_TLS_CIPHER_SUITE,
        },
    )
    LOG.info("Platform TLS service parameters added successfully")


def normalize_cipher_order(cipher_list):
    """Sort ciphers into canonical fresh-install order."""
    order_map = {c: i for i, c in enumerate(K8S_EXPECTED_CIPHER_ORDER)}
    return sorted(cipher_list, key=lambda c: order_map[c])


def update_k8s_tls_cipher_suites(sysinv):
    """Add missing CHACHA20 ciphers to k8s tls-cipher-suites and
    normalize the cipher order to match fresh-install defaults.
    """
    param = None
    for p in sysinv.service_parameter.list():
        if (p.service == K8S_SERVICE
                and p.section == K8S_SECTION
                and p.name == K8S_TLS_CIPHER_SUITES):
            param = p
            break

    if param is None:
        LOG.info("k8s tls-cipher-suites parameter not found, skipping")
        return

    current_ciphers = param.value
    cipher_list = [c.strip() for c in current_ciphers.split(",")]

    # Add any missing CHACHA20 ciphers
    missing = [c for c in K8S_MISSING_CIPHERS if c not in cipher_list]
    if missing:
        LOG.info("Adding missing ciphers to k8s tls-cipher-suites: %s",
                 missing)
        cipher_list.extend(missing)

    # Normalize to canonical order
    cipher_list = normalize_cipher_order(cipher_list)

    new_value = ",".join(cipher_list)
    if new_value == current_ciphers:
        LOG.info("k8s tls-cipher-suites already correct, skipping")
        return

    LOG.info("Updating k8s tls-cipher-suites to: %s", new_value)
    patch = [{'op': 'replace', 'path': '/value', 'value': new_value}]
    sysinv.service_parameter.update(param.uuid, patch)
    LOG.info("k8s tls-cipher-suites updated successfully")

    previous_pid = get_pidof("kube-apiserver")

    LOG.info("Applying kubernetes service parameters")
    sysinv.service_parameter.apply(K8S_SERVICE)

    wait_kube_apiserver_up(previous_pid)


def do_activate(sysinv):
    """Add TLS params and apply during upgrade activation."""
    # Platform TLS parameters
    if tls_params_exist(sysinv):
        LOG.info("Platform TLS parameters already exist, skipping")
    else:
        add_platform_tls_params(sysinv)
        LOG.info("Applying platform service parameters")
        sysinv.service_parameter.apply(PARAM_SERVICE)

    # Kubernetes TLS cipher suites
    update_k8s_tls_cipher_suites(sysinv)


class AddTlsParameters(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate'],
            required_state=None,
            plugin_name='add-tls-parameters',
            completed_state='add-tls-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        LOG.info("%s invoked from_release=%s to_release=%s action=%s",
                 self.name, from_release, to_release, action)

        sysinv = get_sysinv_client()

        if action == "activate":
            do_activate(sysinv)
        else:
            LOG.info("Nothing to do for action '%s'", action)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: %s from_release to_release action" % sys.argv[0])
        sys.exit(1)

    from_release = sys.argv[1]
    to_release = sys.argv[2]
    action = sys.argv[3]

    configure_logging()
    plugin = AddTlsParameters()
    plugin.run(from_release, to_release, action)
