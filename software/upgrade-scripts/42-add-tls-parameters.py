#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Add platform TLS service parameters (tls-min-version and
# tls-cipher-suite) and update kubernetes kube_apiserver
# tls-cipher-suites to include missing CHACHA20 cipher suites.
#
# Platform parameters are new in 26.09 and do not exist in 25.09
# or 26.03.  Safe defaults (TLS 1.2, full 9-cipher list) are
# used so that TLS behaviour is unchanged after upgrade.
#
# The k8s CHACHA20 ciphers were added in 26.09 for fresh installs
# but were missing from the upgrade path.
#
# This script runs in three phases:
#
# 1. MIGRATE (deploy-start): Insert/update all TLS parameters
#    directly into the to-release PostgreSQL database. Platform
#    TLS params are applied by puppet on host unlock via the
#    normal config-target mechanism (haproxy, docker-registry,
#    LDAP, lighttpd). K8s cipher DB value is also written here.
#
# 2. ACTIVATE (deploy-activate): Call service_parameter.apply for
#    the kubernetes service to trigger puppet class
#    platform::kubernetes::master::change_apiserver_parameters.
#    This updates the kube-apiserver static pod manifest with the
#    cipher suites written to the DB during migrate. Waits for
#    kube-apiserver to restart with the new configuration and for
#    all K8s control-plane endpoints to be healthy before returning.
#
# 3. ACTIVATE-ROLLBACK (deploy-activate-rollback): Undo the
#    changes made by migrate and activate. Deletes the platform
#    TLS parameters from the DB, reverts k8s tls-cipher-suites
#    back to the original 6 ciphers (removing CHACHA20 entries),
#    then re-applies kubernetes service parameters to re-render
#    the kube-apiserver static pod manifest from the corrected DB
#    values. Waits for kube-apiserver to restart.
#

import logging
import os
import subprocess
import sys
import time
import uuid

from cgtsclient import client as cgts_client
from _loader import CPlugin
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import k8s_wait_for_endpoints_health

LOG = logging.getLogger("main_logger")

# Platform TLS service parameters (new in 26.09)
PLATFORM_TLS_PARAMS = [
    ("platform", "config", "tls-min-version", "VersionTLS12"),
    ("platform", "config", "tls-cipher-suite",
     "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,"
     "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,"
     "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,"
     "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,"
     "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,"
     "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,"
     "TLS_AES_256_GCM_SHA384,"
     "TLS_AES_128_GCM_SHA256,"
     "TLS_CHACHA20_POLY1305_SHA256"),
]

# Kubernetes kube_apiserver TLS cipher suites
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


# ============================================================
# Migrate phase helpers (direct PostgreSQL)
# ============================================================

def _run_psql(sql, port):
    """Execute a SQL statement against the to-release sysinv database."""
    result = subprocess.run(
        ['sudo', '-u', 'postgres', 'psql', '-d', 'sysinv',
         '--port=%s' % port, '-t', '-c', sql],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def _param_exists_in_db(service, section, name, port):
    """Check if a service parameter already exists in the DB."""
    sql = (
        "SELECT COUNT(*) FROM service_parameter "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (service, section, name)
    )
    count = int(_run_psql(sql, port))
    return count > 0


def _get_param_value(service, section, name, port):
    """Get the current value of a service parameter from the DB."""
    sql = (
        "SELECT value FROM service_parameter "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (service, section, name)
    )
    value = _run_psql(sql, port)
    return value if value else None


def _insert_param(service, section, name, value, port):
    """Insert a service parameter directly into PostgreSQL."""
    param_uuid = str(uuid.uuid4())
    sql = (
        "INSERT INTO service_parameter "
        "(uuid, service, section, name, value, personality, resource, created_at) "
        "VALUES ('%s', '%s', '%s', '%s', '%s', NULL, NULL, now());"
        % (param_uuid, service, section, name, value)
    )
    _run_psql(sql, port)
    LOG.info("Inserted %s/%s/%s (uuid=%s)",
             service, section, name, param_uuid)


def _update_param_value(service, section, name, value, port):
    """Update an existing service parameter value in PostgreSQL."""
    sql = (
        "UPDATE service_parameter SET value='%s', updated_at=now() "
        "WHERE service='%s' AND section='%s' AND name='%s';"
        % (value, service, section, name)
    )
    _run_psql(sql, port)
    LOG.info("Updated %s/%s/%s", service, section, name)


def _add_platform_tls_params(port):
    """Insert platform TLS service parameters with safe defaults."""
    added = 0
    skipped = 0

    for service, section, name, value in PLATFORM_TLS_PARAMS:
        if _param_exists_in_db(service, section, name, port):
            LOG.info("Parameter %s/%s/%s already exists, skipping",
                     service, section, name)
            skipped += 1
            continue
        _insert_param(service, section, name, value, port)
        added += 1

    LOG.info("Platform TLS params: added %d, skipped %d", added, skipped)


def _normalize_cipher_order(cipher_list):
    """Sort ciphers into canonical fresh-install order."""
    order_map = {c: i for i, c in enumerate(K8S_EXPECTED_CIPHER_ORDER)}
    return sorted(cipher_list, key=lambda c: order_map.get(c, len(order_map)))


def _update_k8s_tls_cipher_suites_db(port):
    """Add missing CHACHA20 ciphers to k8s tls-cipher-suites in the DB."""
    current_value = _get_param_value(K8S_SERVICE, K8S_SECTION,
                                     K8S_TLS_CIPHER_SUITES, port)
    if current_value is None:
        LOG.info("k8s %s/%s/%s not found in DB, skipping",
                 K8S_SERVICE, K8S_SECTION, K8S_TLS_CIPHER_SUITES)
        return

    cipher_list = [c.strip() for c in current_value.split(",")]

    missing = [c for c in K8S_MISSING_CIPHERS if c not in cipher_list]
    if missing:
        LOG.info("Adding missing ciphers to k8s tls-cipher-suites: %s",
                 missing)
        cipher_list.extend(missing)

    cipher_list = _normalize_cipher_order(cipher_list)

    new_value = ",".join(cipher_list)
    if new_value == current_value:
        LOG.info("k8s tls-cipher-suites already correct, skipping")
        return

    LOG.info("Updating k8s tls-cipher-suites to: %s", new_value)
    _update_param_value(K8S_SERVICE, K8S_SECTION,
                        K8S_TLS_CIPHER_SUITES, new_value, port)


def do_migrate(port):
    """Migrate phase: add TLS parameters to the to-release DB.

    Platform TLS params are applied by puppet on host unlock.
    K8s cipher params are applied during activate via
    service_parameter.apply.
    """
    LOG.info("Adding TLS parameters to to-release database (port=%s)", port)
    _add_platform_tls_params(port)
    _update_k8s_tls_cipher_suites_db(port)
    LOG.info("TLS parameters migration completed successfully")


# ============================================================
# Activate phase helpers (sysinv API)
# ============================================================

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


def _wait_kube_apiserver_up(previous_pid, timeout=300, interval=5):
    """Wait until kube-apiserver restarts and all K8s endpoints are healthy.

    This function first waits for the initial PID change (confirming
    the restart has begun), then calls k8s_wait_for_endpoints_health()
    to ensure ALL control-plane components (apiserver, controller-
    manager, scheduler, kubelet) are stable before returning.

    :param previous_pid: PID observed before the apply
    :param timeout: Maximum wait time in seconds for PID change
    :param interval: Polling interval in seconds
    :raises TimeoutError: if kube-apiserver does not restart in time
                          or endpoints do not become healthy
    """
    attempts = timeout // interval
    LOG.info(
        "Waiting for kube-apiserver restart "
        "(previous PID: %s, max attempts: %d)",
        previous_pid,
        attempts,
    )

    for attempt in range(0, attempts):
        pid = _get_pidof("kube-apiserver")

        if pid > 0 and pid != previous_pid:
            LOG.info("kube-apiserver is up (new PID: %d)", pid)
            break

        LOG.info("Attempt %d/%d: kube-apiserver not ready yet",
                 attempt + 1, attempts)
        time.sleep(interval)
    else:
        LOG.error("Timed out waiting for kube-apiserver after %d attempts",
                  attempts)
        raise TimeoutError(
            "Timed out waiting for kube-apiserver to restart"
        )

    # After the first PID change, wait for the entire puppet manifest
    # to finish. The manifest updates apiserver, controller-manager,
    # scheduler, and kubelet — triggering a second apiserver restart.
    # k8s_wait_for_endpoints_health checks all 4 endpoints in parallel
    # with retries, ensuring the control plane is fully stable.
    LOG.info("Waiting for all K8s control-plane endpoints to stabilize")
    if not k8s_wait_for_endpoints_health(tries=30, try_sleep=5):
        LOG.error("K8s control-plane endpoints not healthy after "
                  "kube-apiserver restart")
        raise TimeoutError(
            "K8s endpoints not healthy after service parameter apply"
        )
    LOG.info("All K8s control-plane endpoints are healthy")


def _fix_k8s_ciphers_via_api(sysinv):
    """Correct k8s tls-cipher-suites in the DB via the sysinv API.

    This is a fallback for the activate phase: if the migrate phase
    did not run or failed to update the cipher list, this function
    adds the missing CHACHA20 ciphers and normalizes the order using
    the sysinv API (service_parameter.modify).

    Returns True if correction was applied, False if not needed or
    parameter not found.
    """
    param = None
    for p in sysinv.service_parameter.list():
        if (p.service == K8S_SERVICE
                and p.section == K8S_SECTION
                and p.name == K8S_TLS_CIPHER_SUITES):
            param = p
            break

    if param is None:
        LOG.warning("k8s %s/%s/%s not found via API, cannot correct",
                    K8S_SERVICE, K8S_SECTION, K8S_TLS_CIPHER_SUITES)
        return False

    cipher_list = [c.strip() for c in param.value.split(",")]

    missing = [c for c in K8S_MISSING_CIPHERS if c not in cipher_list]
    if not missing:
        # Should not happen since caller checked, but be safe
        LOG.info("k8s tls-cipher-suites already has all ciphers")
        return False

    LOG.info("Adding missing ciphers via API: %s", missing)
    cipher_list.extend(missing)
    cipher_list = _normalize_cipher_order(cipher_list)

    new_value = ",".join(cipher_list)
    patch = [{'op': 'replace', 'path': '/value', 'value': new_value}]
    sysinv.service_parameter.update(param.uuid, patch)
    LOG.info("k8s tls-cipher-suites corrected via API to: %s", new_value)
    return True


def _k8s_ciphers_already_applied(sysinv):
    """Check if k8s cipher suites already match the expected value.

    Returns True if apply can be skipped (reattempt optimization).
    """
    for p in sysinv.service_parameter.list():
        if (p.service == K8S_SERVICE
                and p.section == K8S_SECTION
                and p.name == K8S_TLS_CIPHER_SUITES):
            cipher_list = [c.strip() for c in p.value.split(",")]
            missing = [c for c in K8S_MISSING_CIPHERS
                       if c not in cipher_list]
            return len(missing) == 0
    return True


def do_activate(from_release=None):
    """Activate phase: apply kubernetes service parameters.

    Triggers puppet class change_apiserver_parameters which updates
    the kube-apiserver static pod manifest. Waits for apiserver to
    restart and for all K8s control-plane endpoints to be healthy
    before returning.

    On reattempt, skips if ciphers are already correct in the DB
    and already present in the apiserver manifest.

    If the DB value is still incomplete (missing CHACHA20 ciphers),
    corrects it via the sysinv API before calling apply.

    When upgrading from 25.09 (N-2 path), the apply is deferred to
    script 45-apply-kubernetes-service-parameters.py which runs later
    in FEATURE_POST_APPS. This consolidates both OIDC and TLS cipher
    changes into a single kube-apiserver restart.
    """
    sysinv = _get_sysinv_client()

    if not _k8s_ciphers_already_applied(sysinv):
        LOG.warning("k8s cipher suites missing CHACHA20 ciphers in DB, "
                    "correcting before apply")
        _fix_k8s_ciphers_via_api(sysinv)

    # When upgrading from 25.09, defer the apply to
    # script 45-apply-kubernetes-service-parameters.py which runs
    # after script 41, covering both OIDC and TLS cipher changes
    # in a single kube-apiserver restart.
    if from_release == "25.09":
        LOG.info("Skipping kubernetes apply — will be performed by "
                 "script 45-apply-kubernetes-service-parameters.py "
                 "after OIDC parameters are handled")
        return

    # DB value is correct. Check if the manifest already has the
    # ciphers (reattempt after successful apply).
    try:
        out = subprocess.check_output(
            ['cat', '/etc/kubernetes/manifests/kube-apiserver.yaml'],
            text=True)
        if all(c in out for c in K8S_MISSING_CIPHERS):
            LOG.info("kube-apiserver manifest already has CHACHA20 "
                     "ciphers, skipping apply")
            return
    except Exception:
        pass

    previous_pid = _get_pidof("kube-apiserver")

    LOG.info("Applying kubernetes service parameters")
    sysinv.service_parameter.apply(K8S_SERVICE)

    _wait_kube_apiserver_up(previous_pid)


def _remove_platform_tls_params(sysinv):
    """Remove platform TLS parameters added during migrate.

    Deletes platform/config/tls-min-version and
    platform/config/tls-cipher-suite from the DB via the sysinv API.
    These parameters did not exist in 25.09/26.03 and must be removed
    on rollback.
    """
    params_to_delete = [
        ("platform", "config", "tls-min-version"),
        ("platform", "config", "tls-cipher-suite"),
    ]

    all_params = sysinv.service_parameter.list()

    for service, section, name in params_to_delete:
        param = None
        for p in all_params:
            if (p.service == service
                    and p.section == section
                    and p.name == name):
                param = p
                break

        if param is None:
            LOG.info("Parameter %s/%s/%s not found, already removed",
                     service, section, name)
            continue

        sysinv.service_parameter.delete(param.uuid)
        LOG.info("Deleted %s/%s/%s (uuid=%s)",
                 service, section, name, param.uuid)


def _revert_k8s_ciphers(sysinv):
    """Revert k8s tls-cipher-suites to original 6 ciphers.

    Removes the 3 CHACHA20 ciphers that were added during migrate,
    restoring the value to the pre-upgrade state.

    Returns True if the DB value was changed, False if already correct
    or parameter not found.
    """
    param = None
    for p in sysinv.service_parameter.list():
        if (p.service == K8S_SERVICE
                and p.section == K8S_SECTION
                and p.name == K8S_TLS_CIPHER_SUITES):
            param = p
            break

    if param is None:
        LOG.info("k8s %s/%s/%s not found, nothing to revert",
                 K8S_SERVICE, K8S_SECTION, K8S_TLS_CIPHER_SUITES)
        return False

    cipher_list = [c.strip() for c in param.value.split(",")]

    # Remove the CHACHA20 ciphers that were added during migrate
    original_ciphers = [c for c in cipher_list
                        if c not in K8S_MISSING_CIPHERS]

    if len(original_ciphers) == len(cipher_list):
        LOG.info("k8s tls-cipher-suites already at original value "
                 "(no CHACHA20 ciphers present)")
        return False

    new_value = ",".join(original_ciphers)
    patch = [{'op': 'replace', 'path': '/value', 'value': new_value}]
    sysinv.service_parameter.update(param.uuid, patch)
    LOG.info("Reverted k8s tls-cipher-suites to: %s", new_value)
    return True


def do_activate_rollback():
    """Activate-rollback phase: undo TLS changes from migrate/activate.

    The USM framework does not restore the database to its
    pre-migration state during activate-rollback. This function
    explicitly reverts the DB changes made by do_migrate():

    1. Delete platform/config/tls-min-version from the DB
    2. Delete platform/config/tls-cipher-suite from the DB
    3. Revert kubernetes/kube_apiserver/tls-cipher-suites back to
       the original 6 ciphers (remove the 3 CHACHA20 entries)
    4. Re-apply kubernetes service parameters to re-render the
       kube-apiserver static pod manifest with the reverted ciphers
    5. Wait for kube-apiserver to restart
    """
    sysinv = _get_sysinv_client()

    # Step 1 & 2: Remove platform TLS params that were added by migrate
    LOG.info("Removing platform TLS parameters added during migration")
    _remove_platform_tls_params(sysinv)

    # Step 3: Revert k8s cipher suites back to original 6 ciphers
    LOG.info("Reverting k8s tls-cipher-suites to pre-upgrade value")
    _revert_k8s_ciphers(sysinv)

    # Step 4 & 5: Re-apply kubernetes service parameters to update
    # the kube-apiserver manifest with the reverted cipher list.
    # Check if manifest already matches (idempotent on reattempt).
    try:
        out = subprocess.check_output(
            ['cat', '/etc/kubernetes/manifests/kube-apiserver.yaml'],
            text=True)
        if not any(c in out for c in K8S_MISSING_CIPHERS):
            LOG.info("kube-apiserver manifest already matches rolled-back "
                     "DB (no CHACHA20 ciphers), skipping apply")
            return
    except Exception:
        pass

    previous_pid = _get_pidof("kube-apiserver")

    LOG.info("Applying kubernetes service parameters (rollback)")
    sysinv.service_parameter.apply(K8S_SERVICE)

    _wait_kube_apiserver_up(previous_pid)


# ============================================================
# Plugin class
# ============================================================

class AddTlsParameters(CPlugin):
    """USM upgrade plugin to add TLS parameters.

    Runs in three phases:
    - migrate: Write params to DB (deploy-start)
    - activate: Apply k8s params to update apiserver (deploy-activate)
    - activate-rollback: Revert DB and manifest (deploy-activate-rollback)
    """

    def __init__(self):
        super().__init__(
            matching_action=['migrate', 'activate', 'activate-rollback'],
            required_state=None,
            plugin_name='add-tls-parameters',
            completed_state='add-tls-parameters-completed'
        )

    def _run(self, from_release, to_release, action, port):
        LOG.info("%s invoked from_release=%s to_release=%s action=%s port=%s",
                 self.name, from_release, to_release, action, port)

        supported_from_releases = ["25.09", "26.03"]
        if action in ("migrate", "activate"):
            if from_release not in supported_from_releases or \
                    to_release != "26.10":
                LOG.info("Only applicable when upgrading from %s "
                         "to 26.10. Current: %s -> %s. Skipping.",
                         supported_from_releases, from_release, to_release)
                return
        elif action == "activate-rollback":
            if to_release not in supported_from_releases or \
                    from_release != "26.10":
                LOG.info("Only applicable when rolling back from 26.10 "
                         "to %s. Current: %s -> %s. Skipping.",
                         supported_from_releases, from_release, to_release)
                return

        if action == "migrate":
            do_migrate(port)
        elif action == "activate":
            do_activate(from_release)
        elif action == "activate-rollback":
            do_activate_rollback()
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
    if action not in ("migrate", "activate", "activate-rollback"):
        sys.exit(0)

    plugin = AddTlsParameters()
    plugin.run(from_release, to_release, action)
