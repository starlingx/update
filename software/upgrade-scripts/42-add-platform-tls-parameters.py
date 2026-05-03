#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add platform TLS service parameters (tls-min-version and
# tls-cipher-suite) during upgrade activation.
#
# These parameters are new in 26.09 and do not exist in 25.09
# or 26.03.  Safe defaults (TLS 1.2, full 9-cipher list) are
# used so that TLS behaviour is unchanged after upgrade.

import logging
import os
import sys

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


def get_sysinv_client():
    """Return an authenticated Sysinv (cgts) client."""
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL"),
    )


def tls_params_exist(sysinv):
    """Return True if tls-min-version already exists in platform config."""
    return any(
        p.service == PARAM_SERVICE
        and p.section == PARAM_SECTION
        and p.name == PARAM_TLS_MIN_VERSION
        for p in sysinv.service_parameter.list()
    )


def add_tls_params(sysinv):
    """Create TLS service parameters with safe defaults."""
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


def do_activate(sysinv):
    """Add TLS params and apply during upgrade activation."""
    if tls_params_exist(sysinv):
        LOG.info("Platform TLS parameters already exist, skipping")
        return

    add_tls_params(sysinv)
    LOG.info("Applying platform service parameters")
    sysinv.service_parameter.apply(PARAM_SERVICE)


class AddPlatformTlsParameters(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate'],
            required_state=None,
            plugin_name='add-platform-tls-parameters',
            completed_state='add-platform-tls-parameters-completed'
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
    plugin = AddPlatformTlsParameters()
    plugin.run(from_release, to_release, action)
