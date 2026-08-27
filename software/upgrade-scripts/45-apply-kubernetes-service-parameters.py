#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Apply kubernetes service parameters if not yet applied.
#
# This script ensures that pending kubernetes service parameter
# changes (written to the DB by other scripts during migrate or
# activate) are applied to the kube-apiserver static pod manifest.
#
# In the N-2 path (25.09 -> 26.10):
#   - Script 42 (add-tls-parameters) writes CHACHA20 ciphers to
#     the DB during migrate but skips the apply during activate
#     (deferred to avoid a redundant kube-apiserver restart).
#   - Script 41 (ensure-oidc-service-parameters) applies if OIDC
#     was not yet configured. If OIDC was already configured, it
#     early-returns without applying.
#   - This script (45) runs last and catches any case where
#     the apply was not performed by an earlier script.
#
# In the N-1 path (26.03 -> 26.10):
#   - Script 42 performs the apply itself during activate.
#   - This script detects that the manifest already has all
#     expected ciphers and skips (idempotent/no-op).
#
# On reattempt (activate already completed):
#   - Manifest already has the ciphers, so this script skips.
#

import logging
import os
import subprocess
import sys
import time

from cgtsclient import client as cgts_client
from _loader import CPlugin
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import k8s_wait_for_endpoints_health

LOG = logging.getLogger("main_logger")

K8S_SERVICE = "kubernetes"

# CHACHA20 cipher suites that must be present in the kube-apiserver
# manifest after a successful apply.
K8S_CHACHA20_CIPHERS = [
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_CHACHA20_POLY1305_SHA256",
]

KUBE_APISERVER_MANIFEST = "/etc/kubernetes/manifests/kube-apiserver.yaml"


def _get_sysinv_client():
    """Return an authenticated Sysinv (cgts) client."""
    return cgts_client.get_client(
        "1",
        os_auth_token=os.environ.get("OS_AUTH_TOKEN"),
        system_url=os.environ.get("SYSTEM_URL"),
    )


def _get_pidof(name):
    """Return the PID for the given process name."""
    try:
        out = subprocess.check_output(
            ["pidof", "-s", name], text=True).strip()
        return int(out) if out else -1
    except Exception:
        return -1


def _manifest_already_applied():
    """Check if the kube-apiserver manifest already has CHACHA20 ciphers.

    Returns True if all expected ciphers are present (apply not needed).
    Returns False if any cipher is missing or manifest cannot be read.
    """
    try:
        with open(KUBE_APISERVER_MANIFEST, 'r') as f:
            manifest = f.read()
    except Exception:
        LOG.info("Cannot read kube-apiserver manifest, "
                 "assuming apply is needed")
        return False

    if all(c in manifest for c in K8S_CHACHA20_CIPHERS):
        LOG.info("kube-apiserver manifest already has all CHACHA20 "
                 "ciphers — apply not needed")
        return True

    LOG.info("kube-apiserver manifest missing CHACHA20 ciphers "
             "— apply needed")
    return False


def _wait_kube_apiserver_up(previous_pid, timeout=300, interval=5):
    """Wait for kube-apiserver restart and endpoint health.

    Polls for PID change to confirm restart has begun, then waits
    for all K8s control-plane endpoints to stabilize.

    :param previous_pid: PID observed before the apply
    :param timeout: Maximum wait time in seconds for PID change
    :param interval: Polling interval in seconds
    :raises TimeoutError: if kube-apiserver does not restart or
                          endpoints do not become healthy
    """
    attempts = timeout // interval
    LOG.info(
        "Waiting for kube-apiserver restart "
        "(previous PID: %s, max attempts: %d)",
        previous_pid,
        attempts,
    )

    for attempt in range(1, attempts + 1):
        pid = _get_pidof("kube-apiserver")

        if pid > 0 and pid != previous_pid:
            LOG.info("kube-apiserver is up (new PID: %d)", pid)
            break

        LOG.info("Attempt %d/%d: kube-apiserver not ready",
                 attempt, attempts)
        time.sleep(interval)
    else:
        LOG.error("Timed out waiting for kube-apiserver after %d "
                  "attempts", attempts)
        raise TimeoutError(
            "Timed out waiting for kube-apiserver to restart"
        )

    LOG.info("Waiting for all K8s control-plane endpoints to stabilize")
    if not k8s_wait_for_endpoints_health(tries=30, try_sleep=5):
        LOG.error("K8s control-plane endpoints not healthy after "
                  "kube-apiserver restart")
        raise TimeoutError(
            "K8s endpoints not healthy after service parameter apply"
        )
    LOG.info("All K8s control-plane endpoints are healthy")


def do_activate(from_release):
    """Apply kubernetes service parameters if manifest is stale.

    Checks the kube-apiserver manifest for CHACHA20 ciphers. If
    present, the apply was already performed (by script 41 or 42)
    and this script is a no-op. If missing, performs the apply and
    waits for kube-apiserver restart + endpoint health.
    """
    if _manifest_already_applied():
        return

    sysinv = _get_sysinv_client()
    previous_pid = _get_pidof("kube-apiserver")

    LOG.info("Applying kubernetes service parameters")
    sysinv.service_parameter.apply(K8S_SERVICE)

    _wait_kube_apiserver_up(previous_pid)


class ApplyKubernetesServiceParameters(CPlugin):
    """Apply pending kubernetes service parameter changes.

    Ensures the kube-apiserver manifest reflects all DB changes
    made by earlier scripts (42, 41). Idempotent — skips if
    manifest is already up to date.
    """

    def __init__(self):
        super().__init__(
            matching_action=['activate'],
            required_state=None,
            plugin_name='apply-kubernetes-service-parameters',
            completed_state='apply-kubernetes-service-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        LOG.info("%s invoked from_release=%s to_release=%s action=%s",
                 self.name, from_release, to_release, action)

        supported_from_releases = ["25.09", "26.03"]
        if from_release not in supported_from_releases:
            LOG.info("Only applicable when upgrading from %s. "
                     "Current: %s -> %s. Skipping.",
                     supported_from_releases, from_release, to_release)
            return

        if action == "activate":
            do_activate(from_release)
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
    if action != "activate":
        sys.exit(0)

    plugin = ApplyKubernetesServiceParameters()
    plugin.run(from_release, to_release, action)
