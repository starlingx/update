#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Relocate the etcd keyspace on a simplex upgrade.
#
# The previous release kept the single member's data on the DRBD-backed
# floating path. This release founds the cluster on a local-disk fixed
# member. Simplex has no second member to replicate from, so the data is
# moved. Applied on simplex; a no-op on duplex, where the fixed members join
# the running cluster and populate through raft replication.
#
# At activate:
#   - mounts drbd-etcd, which SM leaves Primary/UpToDate but unmounted
#   - copies the stopped member's database out of the floating data directory
#   - restores it into the fixed member's data directory
#   - writes /etc/default/etcd-fixed to match
#   - starts the fixed member and waits for it to serve, before the first
#     kubernetes-health-gated activate plugin runs
#
# The restore equivalent is the ansible role backup-restore/restore-etcd; the
# flags here are kept in step with it.

import configparser
import logging
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from _etcd_common import etcdctl_timeouts
from _loader import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

# Data directories. The floating path is what the N-1 release wrote; the fixed
# path is what this release expects the cluster to be founded on.
FLOATING_DATA_DIR = '/opt/etcd/db/controller.etcd'
FIXED_DATA_ROOT = '/opt/etcd-fixed/db'
FIXED_MEMBER_NAME = 'fixed-0'
FIXED_DATA_DIR = os.path.join(FIXED_DATA_ROOT, '%s.etcd' % FIXED_MEMBER_NAME)

# Written once the keyspace has been moved, so a repeated activate is a no-op.
MIGRATION_MARKER = '/etc/platform/.etcd_upgrade_data_migrated'

# Must match what puppet writes to /etc/default/etcd-fixed, otherwise the
# member will not start against the restored data directory.
CLUSTER_TOKEN = 'etcd-cluster'
PEER_PORT = 2380
CLIENT_PORT = 2379
CONTROLLER_0_CLUSTER_HOST = 'controller-0-cluster-host'

ETCD_FIXED_ENV_FILE = '/etc/default/etcd-fixed'

# Shared TLS material. Every member binds the same server certificate, whose
# SAN set covers each address they may bind.
ETCD_CA_CERT = '/etc/etcd/ca.crt'
ETCD_SERVER_CERT = '/etc/etcd/etcd-server.crt'
ETCD_SERVER_KEY = '/etc/etcd/etcd-server.key'
ETCD_CLIENT_CERT = '/etc/etcd/etcd-client.crt'
ETCD_CLIENT_KEY = '/etc/etcd/etcd-client.key'
ETCD_STAGE_0_SYMLINK = '/var/lib/etcd/stage0'
ETCD_FIXED_SERVICE = 'etcd-fixed'
ETCD_FLOATING_SERVICE = 'etcd'

# The floating member's name and a loopback client URL for its health probe.
# The floating member ('controller') binds the cluster floating address and
# loopback, and only loopback is guaranteed reachable regardless of which
# address SM has placed, so the rollback restore probes loopback.
FLOATING_MEMBER_NAME = 'controller'
FLOATING_CLIENT_URL = 'https://127.0.0.1:%d' % CLIENT_PORT

# The floating keyspace lives on the DRBD-backed volume. SM deprovisions
# drbd-etcd during the host deploy, so by activate time the device is still
# Primary/UpToDate but is no longer mounted and the data is invisible.
FLOATING_MOUNTPOINT = '/opt/etcd'
DRBD_ETCD_DEVICE = '/dev/drbd/by-res/drbd-etcd/0'
DRBD_ETCD_FALLBACK_DEVICE = '/dev/drbd7'

# Backend quota applied to every fixed member.
ETCD_QUOTA_BACKEND_BYTES = 5368508416

PLATFORM_CONF_FILE = '/etc/platform/platform.conf'
SIMPLEX = 'simplex'

# etcdctl needs the v3 API explicitly; etcdutl does not take the variable.
ETCD_API_ENV_VAR = {'ETCDCTL_API': '3'}

# etcdctl command and dial timeouts come from _etcd_common, shared with
# 206-duplex-etcd-peer-url-fixup.py. The bounds below are not etcdctl
# timeouts: they bound systemctl, mount and a local snapshot restore, none of
# which talk to a cluster.
SERVICE_TIMEOUT = 60
RESTORE_TIMEOUT = 60
MOUNT_TIMEOUT = 60

# A deadline for a polling loop, not a command timeout: the member has to
# answer before the first health-gated activate plugin runs.
HEALTH_TIMEOUT = 180
HEALTH_INTERVAL = 5

# A second polling deadline, for kubernetes rather than etcd. Both the
# migration and the rollback move the etcd client endpoint and the mount under
# it, so kube-apiserver has to rebuild its storage backend afterwards. It is
# restarted by kubelet, whose CrashLoopBackOff can reach five minutes, so this
# deadline is longer than the etcd one; it returns as soon as the API answers.
APISERVER_TIMEOUT = 300
APISERVER_INTERVAL = 5

# Bounds one kubectl invocation inside the polling loop above.
KUBECTL_TIMEOUT = 15
KUBE_ADMIN_CONF = '/etc/kubernetes/admin.conf'

# Control-plane clients that hold watches on kube-apiserver and are restarted
# when they are found to predate the API server they are talking to.
CONTROL_PLANE_CLIENTS = ('kube-scheduler', 'kube-controller-manager')
CRICTL_TIMEOUT = 30


def get_system_mode():
    """Read system_mode from the platform configuration.

    :returns: 'simplex', 'duplex', 'duplex-direct' etc, or None if unreadable
    """
    try:
        with open(PLATFORM_CONF_FILE, 'r') as conf_file:
            platform_conf = "[DEFAULT]\n" + conf_file.read()
    except OSError as ex:
        LOG.warning("Failed to read %s: %s", PLATFORM_CONF_FILE, ex)
        return None

    parser = configparser.ConfigParser()
    parser.read_string(platform_conf)
    if parser.has_option('DEFAULT', 'system_mode'):
        return parser.get('DEFAULT', 'system_mode')
    return None


def is_simplex():
    """Whether this system relocates etcd data rather than replicating it.

    Only simplex needs the keyspace physically moved. On duplex the fixed
    members join the running floating cluster and populate through Raft, so
    this script must not touch the data directories there.
    """
    system_mode = get_system_mode()
    if system_mode is None:
        # Fail safe: without a definite simplex answer, do nothing. A missed
        # migration is recoverable; clobbering a duplex member's data is not.
        LOG.warning("Unable to determine system_mode from %s, skipping.",
                    PLATFORM_CONF_FILE)
        return False
    return system_mode == SIMPLEX


def _execute(command, timeout, env=None):
    """Run a command, logging and raising on failure."""
    run_env = dict(os.environ)
    if env:
        run_env.update(env)

    LOG.info("Running: %s", " ".join(command))
    result = subprocess.run(command, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True,
                            timeout=timeout, env=run_env)
    if result.returncode != 0:
        raise Exception("Command %s failed with return code %d. Output: %s"
                        % (" ".join(command), result.returncode, result.stdout))
    return result.stdout


def get_etcd_version():
    """Read the installed etcd version from the stage0 symlink.

    Expecting /var/lib/etcd/stage0 -> /usr/local/etcd/<version>/stage0

    :returns: version string, or None if it cannot be determined
    """
    try:
        target = os.readlink(ETCD_STAGE_0_SYMLINK)
    except OSError as ex:
        LOG.warning("Failed to read symlink %s: %s", ETCD_STAGE_0_SYMLINK, ex)
        return None

    match = re.search(r"/usr/local/etcd/(.*)/stage0", target)
    if match is None:
        LOG.warning("Unable to find etcd version in symlink target %s", target)
        return None
    return match.group(1)


def use_etcdutl(etcd_version):
    """etcd 3.6 removed 'etcdctl snapshot restore' in favour of etcdutl."""
    if not etcd_version:
        # Unknown version: prefer etcdutl only if the binary is available.
        return shutil.which('etcdutl') is not None
    try:
        major, minor = (int(part) for part in etcd_version.split('.')[:2])
    except (ValueError, IndexError):
        LOG.warning("Unrecognised etcd version %s", etcd_version)
        return shutil.which('etcdutl') is not None
    return (major, minor) >= (3, 6)


def get_fixed_0_address():
    """Resolve the controller-0 cluster-host address, bracketed when IPv6.

    The ipwrap filter used elsewhere is deliberately avoided here; plain
    formatting keeps this script free of ansible collection dependencies.
    """
    try:
        results = socket.getaddrinfo(CONTROLLER_0_CLUSTER_HOST, None)
    except socket.gaierror as ex:
        raise Exception("Failed to resolve %s: %s"
                        % (CONTROLLER_0_CLUSTER_HOST, ex))
    if not results:
        raise Exception("No address returned for %s" % CONTROLLER_0_CLUSTER_HOST)

    family, _, _, _, sockaddr = results[0]
    address = sockaddr[0]
    if family == socket.AF_INET6:
        address = "[%s]" % address
    return address


def get_fixed_0_peer_url():
    """Build the fixed-0 peer URL from the controller-0 cluster-host address."""
    return "https://%s:%d" % (get_fixed_0_address(), PEER_PORT)


def get_fixed_0_client_url():
    """Build the fixed-0 client URL from the controller-0 cluster-host address."""
    return "https://%s:%d" % (get_fixed_0_address(), CLIENT_PORT)


def is_mounted(path):
    """Whether path is a mountpoint, read from the kernel mount table."""
    with open('/proc/mounts', 'r') as mounts:
        for line in mounts:
            fields = line.split()
            if len(fields) >= 2 and fields[1] == path:
                return True
    return False


def drbd_etcd_device():
    """Resolve the drbd-etcd block device.

    Preferred by resource name so the minor number is not baked in; the
    numbered device is only a fallback for older layouts.
    """
    if os.path.exists(DRBD_ETCD_DEVICE):
        return DRBD_ETCD_DEVICE
    if os.path.exists(DRBD_ETCD_FALLBACK_DEVICE):
        return DRBD_ETCD_FALLBACK_DEVICE
    raise Exception("No drbd-etcd device found at %s or %s"
                    % (DRBD_ETCD_DEVICE, DRBD_ETCD_FALLBACK_DEVICE))


def ensure_floating_volume_mounted():
    """Make the floating keyspace visible, mounting drbd-etcd if required.

    SM deprovisions drbd-etcd during the host deploy, so at activate time the
    volume is Primary/UpToDate but unmounted and FLOATING_DATA_DIR appears to
    be missing. Without this the migration would conclude there is nothing to
    carry forward and leave the upgraded system on an empty datastore.

    :returns: True when this call performed the mount, so the caller can undo
              it and leave the system as it was found.
    """
    if is_mounted(FLOATING_MOUNTPOINT):
        LOG.info("%s is already mounted", FLOATING_MOUNTPOINT)
        return False

    device = drbd_etcd_device()
    os.makedirs(FLOATING_MOUNTPOINT, mode=0o755, exist_ok=True)
    LOG.info("Mounting %s at %s to expose the floating keyspace",
             device, FLOATING_MOUNTPOINT)
    _execute(["mount", device, FLOATING_MOUNTPOINT], MOUNT_TIMEOUT)
    return True


def unmount_floating_volume():
    """Undo ensure_floating_volume_mounted().

    Failures are logged rather than raised: the keyspace has already been
    relocated by this point, and a left-over mount is recoverable by hand
    whereas failing the activate is not.
    """
    result = subprocess.run(["umount", FLOATING_MOUNTPOINT],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
    if result.returncode == 0:
        LOG.info("Unmounted %s", FLOATING_MOUNTPOINT)
    else:
        LOG.warning("Could not unmount %s: %s",
                    FLOATING_MOUNTPOINT, result.stderr.strip())


def floating_snapshot_source():
    """Return the stopped floating member's backing store.

    The relocation runs while no etcd is up: this release deliberately does not
    start a fixed member during an upgrade, and SM has already taken the
    floating member away. So the source cannot be produced with 'etcdctl
    snapshot save' against a live endpoint -- the member database on disk is
    used directly instead.
    """
    snap_db = os.path.join(FLOATING_DATA_DIR, 'member', 'snap', 'db')
    if not os.path.isfile(snap_db):
        raise Exception("Floating member database %s not found; cannot "
                        "relocate the keyspace" % snap_db)
    return snap_db


def restore_to_fixed_0(snapshot_file, etcd_version):
    """Restore snapshot_file into the fixed-0 data directory.

    Membership must be supplied explicitly: etcd validates that --name appears
    in --initial-cluster, and the built-in default does not contain fixed-0.
    """
    peer_url = get_fixed_0_peer_url()

    if use_etcdutl(etcd_version):
        command = ["etcdutl", "snapshot", "restore", snapshot_file]
        env = None
        # Added to etcdutl only. They keep the revision monotonic and
        # invalidate stale kubernetes informer caches, per the etcd
        # disaster-recovery guide.
        extra = ["--mark-compacted", "--bump-revision", "1000000000",
                 "--skip-hash-check"]
    else:
        command = ["etcdctl", "snapshot", "restore", snapshot_file]
        env = ETCD_API_ENV_VAR
        extra = ["--skip-hash-check"]

    command += ["--data-dir", FIXED_DATA_DIR,
                "--name", FIXED_MEMBER_NAME,
                "--initial-cluster", "%s=%s" % (FIXED_MEMBER_NAME, peer_url),
                "--initial-cluster-token", CLUSTER_TOKEN,
                "--initial-advertise-peer-urls", peer_url]
    command += extra

    _execute(command, RESTORE_TIMEOUT, env=env)
    LOG.info("Restored keyspace into %s as member %s (%s)",
             FIXED_DATA_DIR, FIXED_MEMBER_NAME, peer_url)


def stop_etcd_fixed():
    """Stop etcd-fixed if it is running; its data directory is replaced."""
    result = subprocess.run(["systemctl", "is-active", ETCD_FIXED_SERVICE],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True)
    if result.stdout.strip() == "active":
        LOG.info("Stopping %s before replacing its data directory",
                 ETCD_FIXED_SERVICE)
        _execute(["systemctl", "stop", ETCD_FIXED_SERVICE], SERVICE_TIMEOUT)


def disable_floating_etcd():
    """Take the floating etcd instance out of service on simplex.

    Taking the floating etcd instance out of service prevents collision of
    floating client and peer ports with the fixed instance, and prevents
    unwanted SM/swact interactions.

    The N-1 release ran etcd as an SM-managed service on the DRBD-backed
    floating path. On current release, simplex runs only the fixed instance,
    so the floating instance must be unmanaged by SM and disabled in systemd.

    Failures here are logged rather than raised: the keyspace has already been
    relocated by the time this runs, and a stale service definition is
    recoverable by hand whereas failing the activate is not.
    """
    result = subprocess.run(["sm-unmanage", "service", ETCD_FLOATING_SERVICE],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, check=False)
    if result.returncode == 0:
        LOG.info("SM service %s unmanaged", ETCD_FLOATING_SERVICE)
    else:
        LOG.warning("Could not unmanage SM service %s: %s",
                    ETCD_FLOATING_SERVICE, result.stderr.strip())

    for action in ("stop", "disable"):
        result = subprocess.run(["systemctl", action, ETCD_FLOATING_SERVICE],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=False)
        if result.returncode == 0:
            LOG.info("systemd %s %s", action, ETCD_FLOATING_SERVICE)
        else:
            LOG.warning("Could not %s %s: %s", action,
                        ETCD_FLOATING_SERVICE, result.stderr.strip())


def restore_floating_etcd():
    """Bring the floating instance back into service on rollback.

    The exact inverse of disable_floating_etcd(), applied in reverse order.
    Rolling back to the N-1 release means the DRBD-backed floating member is
    authoritative again, so it must be mounted, started, handed back to SM and
    confirmed serving. disable_floating_etcd() left the unit stopped and
    unmanaged and the volume unmounted; simply re-enabling the unit, as the
    rollback used to do, starts nothing.

    Unlike disable_floating_etcd(), a failure here is raised, not logged. On
    the activate path the keyspace has already moved and a stale unit is a
    lesser evil than failing the activate; on rollback the opposite holds --
    returning without a serving etcd guarantees the rollback fails anyway, two
    plugins later, as a misleading "Failed to generate bootstrap token" from
    the next script that needs kube-apiserver. Failing here names etcd as the
    cause and, because the caller has not yet removed the fixed keyspace,
    leaves the system recoverable by hand.
    """
    # The floating keyspace lives on the DRBD volume; the unit cannot serve
    # without it. ensure_floating_volume_mounted() is a no-op if already
    # mounted.
    ensure_floating_volume_mounted()

    _execute(["systemctl", "enable", ETCD_FLOATING_SERVICE], SERVICE_TIMEOUT)
    _execute(["systemctl", "start", ETCD_FLOATING_SERVICE], SERVICE_TIMEOUT)

    # Hand the service back to SM, which owned it on the N-1 release.
    _execute(["sm-manage", "service", ETCD_FLOATING_SERVICE], SERVICE_TIMEOUT)

    # Confirm it actually serves before the caller removes the fixed keyspace.
    # The floating member binds loopback (its cert SAN set covers the floating
    # address and 127.0.0.1), so loopback is the reliable probe here.
    _wait_for_healthy(FLOATING_MEMBER_NAME, FLOATING_CLIENT_URL)


def ensure_fixed_env_file():
    """Write /etc/default/etcd-fixed when it is absent.

    etcd-fixed.service declares this file as a mandatory EnvironmentFile (no
    '-' prefix), so systemd refuses to start the unit without it. On the
    upgrade path nothing writes it: etcd.pp declares it only in
    platform::etcd::bootstrap, which is fresh-install only, and in
    platform::etcd::membership, which does not run during activate.

    Written only when missing, so puppet stays authoritative wherever puppet
    runs.

    TODO(bdhikale): interim until a manifest owns this file on the upgrade
    path, at which point this becomes dead code.
    """
    if os.path.exists(ETCD_FIXED_ENV_FILE):
        LOG.info("%s already present, leaving it alone", ETCD_FIXED_ENV_FILE)
        return

    peer_url = get_fixed_0_peer_url()
    client_url = get_fixed_0_client_url()

    settings = [
        ('ETCD_NAME', FIXED_MEMBER_NAME),
        ('ETCD_DATA_DIR', FIXED_DATA_DIR),
        ('ETCD_LISTEN_CLIENT_URLS', client_url),
        ('ETCD_ADVERTISE_CLIENT_URLS', client_url),
        ('ETCD_LISTEN_PEER_URLS', peer_url),
        ('ETCD_INITIAL_ADVERTISE_PEER_URLS', peer_url),
        # Simplex is founded on this member alone; it is the whole cluster.
        ('ETCD_INITIAL_CLUSTER', '%s=%s' % (FIXED_MEMBER_NAME, peer_url)),
        ('ETCD_INITIAL_CLUSTER_STATE', 'new'),
        ('ETCD_INITIAL_CLUSTER_TOKEN', CLUSTER_TOKEN),
        ('ETCD_CERT_FILE', ETCD_SERVER_CERT),
        ('ETCD_KEY_FILE', ETCD_SERVER_KEY),
        ('ETCD_TRUSTED_CA_FILE', ETCD_CA_CERT),
        ('ETCD_PEER_CERT_FILE', ETCD_SERVER_CERT),
        ('ETCD_PEER_KEY_FILE', ETCD_SERVER_KEY),
        ('ETCD_PEER_TRUSTED_CA_FILE', ETCD_CA_CERT),
        ('ETCD_CLIENT_CERT_AUTH', 'true'),
        ('ETCD_PEER_CLIENT_CERT_AUTH', 'true'),
        ('ETCD_QUOTA_BACKEND_BYTES', str(ETCD_QUOTA_BACKEND_BYTES)),
    ]

    LOG.info("Writing %s for member %s", ETCD_FIXED_ENV_FILE, FIXED_MEMBER_NAME)
    with open(ETCD_FIXED_ENV_FILE, 'w') as env_file:
        env_file.write("# Written by the etcd keyspace migration during "
                       "platform upgrade activate.\n")
        for key, value in settings:
            env_file.write('%s="%s"\n' % (key, value))
    os.chmod(ETCD_FIXED_ENV_FILE, 0o644)


def _wait_for_healthy(member_name, client_url):
    """Poll an etcd member until it answers on its client URL, or raise.

    Checked on the address the member actually binds rather than on loopback
    for a fixed member; the floating member always binds loopback as well. A
    single implementation serves both the fixed member started by the
    migration and the floating member restored on rollback -- they differ only
    in the member name and the endpoint probed.
    """
    command = ["etcdctl",
               "--cert", ETCD_CLIENT_CERT,
               "--key", ETCD_CLIENT_KEY,
               "--cacert", ETCD_CA_CERT,
               "--endpoints", client_url,
               "endpoint", "health"] + etcdctl_timeouts()

    deadline = time.time() + HEALTH_TIMEOUT
    last_output = ''
    while time.time() < deadline:
        run_env = dict(os.environ)
        run_env.update(ETCD_API_ENV_VAR)
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                env=run_env, check=False)
        if result.returncode == 0:
            LOG.info("Member %s is healthy at %s", member_name, client_url)
            return
        last_output = result.stdout.strip()
        time.sleep(HEALTH_INTERVAL)

    raise Exception("Member %s did not become healthy at %s within %d seconds. "
                    "Last output: %s"
                    % (member_name, client_url, HEALTH_TIMEOUT, last_output))


def wait_for_fixed_0_healthy():
    """Poll fixed-0 until it answers, or raise.

    Checked on the address the member actually binds rather than on loopback:
    etcd binds a single client address, so a loopback probe does not reach a
    member bound to the cluster-host address.
    """
    _wait_for_healthy(FIXED_MEMBER_NAME, get_fixed_0_client_url())


def wait_for_apiserver_ready():
    """Poll kube-apiserver until it serves /readyz, or raise.

    This check is used instead of verifying that etcd is running because etcd
    availability alone does not guarantee Kubernetes is operational. After
    migration or rollback, kube-apiserver must reconnect to etcd and rebuild
    its storage state before it can serve requests. Poll /readyz until that
    process completes or the timeout is reached.

    Raising on timeout is deliberate: if the API is still down after this
    deadline every following plugin fails anyway, and failing here names the
    real cause instead of surfacing it as an unrelated connection error.
    """
    command = ["kubectl", "--kubeconfig", KUBE_ADMIN_CONF,
               "get", "--raw", "/readyz"]

    deadline = time.time() + APISERVER_TIMEOUT
    last_output = ''
    while time.time() < deadline:
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True,
                                    timeout=KUBECTL_TIMEOUT, check=False)
        except subprocess.TimeoutExpired:
            # The API can accept a connection and then stall while it waits on
            # etcd, so the command needs its own bound inside the loop.
            last_output = "kubectl did not return within %d seconds" \
                          % KUBECTL_TIMEOUT
        else:
            if result.returncode == 0 and result.stdout.strip() == 'ok':
                LOG.info("kube-apiserver is ready")
                return
            last_output = result.stdout.strip()
        time.sleep(APISERVER_INTERVAL)

    raise Exception("kube-apiserver did not become ready within %d seconds. "
                    "The plugins that follow require it. Last output: %s"
                    % (APISERVER_TIMEOUT, last_output))


def _container_started_at(component):
    """Return the start time of a control-plane static pod container.

    None while kubelet is recreating it, which callers treat as "cannot tell".
    """
    hostname = socket.gethostname()
    command = ["kubectl", "--kubeconfig", KUBE_ADMIN_CONF,
               "-n", "kube-system", "get", "pod",
               "%s-%s" % (component, hostname),
               "-o", "jsonpath={.status.containerStatuses[0]"
                     ".state.running.startedAt}"]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True,
                                timeout=KUBECTL_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _restart_static_pod(component):
    """Stop a control-plane container so kubelet recreates it.

    Stopped rather than the mirror pod deleted, since kubelet acts on that
    directly and it leaves the static pod manifest untouched. Best effort.
    """
    try:
        container_id = _execute(
            ["crictl", "ps", "--name", component, "-q"],
            CRICTL_TIMEOUT).strip().splitlines()
    except Exception as e:
        LOG.warning("Could not list the %s container: %s", component, e)
        return

    if not container_id:
        LOG.info("No running %s container to restart", component)
        return

    try:
        _execute(["crictl", "stop", container_id[0]], CRICTL_TIMEOUT)
    except Exception as e:
        LOG.warning("Could not restart %s: %s", component, e)
        return

    LOG.info("Restarted %s; kubelet will recreate it", component)


def restart_stale_control_plane_clients():
    """Restart scheduler and controller-manager left behind by an API restart.

    Both hold watches on kube-apiserver and are not guaranteed to recover once
    it returns: they stay running and healthy while binding nothing and
    reconciling nothing.

    A client whose container predates the API server's lived through the
    restart, so only that one is bounced. Timestamps are RFC 3339 in UTC, as
    kubelet reports them, and order correctly as strings.

    Best effort: anything that cannot be determined is left alone.
    """
    apiserver_started = _container_started_at('kube-apiserver')
    if apiserver_started is None:
        LOG.info("Could not read the kube-apiserver start time; leaving the "
                 "control-plane clients alone")
        return

    for component in CONTROL_PLANE_CLIENTS:
        client_started = _container_started_at(component)
        if client_started is None:
            LOG.info("Could not read the %s start time; leaving it alone",
                     component)
            continue
        if client_started < apiserver_started:
            LOG.info("%s started %s, before kube-apiserver at %s; restarting "
                     "it so it rebuilds its watches", component,
                     client_started, apiserver_started)
            _restart_static_pod(component)
        else:
            LOG.info("%s started %s, after kube-apiserver at %s; leaving it",
                     component, client_started, apiserver_started)


def start_etcd_fixed():
    """Enable and start the fixed member, then wait for it to answer.

    Enabling alone is not enough. The activate plugins that follow are gated on
    kubernetes health, and kubernetes cannot come up until this member serves
    the keyspace that was just relocated into it.
    """
    _execute(["systemctl", "enable", "--now", ETCD_FIXED_SERVICE],
             SERVICE_TIMEOUT)
    wait_for_fixed_0_healthy()


def migrate_keyspace():
    """Move the keyspace from the floating path to the fixed-0 path.

    Simplex only. On duplex the fixed members join the running cluster through
    'etcdctl member add' and replicate via Raft, so nothing is relocated here.
    """
    if not is_simplex():
        LOG.info("System mode is %s, not %s. The fixed members join the "
                 "running cluster and replicate via Raft; no keyspace "
                 "relocation is required. Skipping.",
                 get_system_mode(), SIMPLEX)
        return

    if os.path.exists(MIGRATION_MARKER):
        LOG.info("Marker %s present, etcd keyspace already migrated. Skipping.",
                 MIGRATION_MARKER)
        return

    mounted_here = ensure_floating_volume_mounted()
    temp_dir = tempfile.mkdtemp(prefix='etcd-keyspace-migration-')
    try:
        if not os.path.isdir(FLOATING_DATA_DIR):
            # Reached only when the volume is mounted and still has no member
            # data. Raised rather than skipped: continuing would leave the
            # upgraded system on an empty datastore, which is the outcome this
            # script exists to prevent.
            raise Exception(
                "No floating etcd data at %s even with %s mounted; refusing to "
                "continue and leave the system on an empty datastore."
                % (FLOATING_DATA_DIR, FLOATING_MOUNTPOINT))

        etcd_version = get_etcd_version()
        LOG.info("Migrating etcd keyspace from %s to %s (etcd version %s)",
                 FLOATING_DATA_DIR, FIXED_DATA_DIR, etcd_version or "unknown")

        # Copied out before the restore so the source is never touched.
        snapshot_file = os.path.join(temp_dir, 'etcd-snapshot.db')
        shutil.copyfile(floating_snapshot_source(), snapshot_file)
        LOG.info("Copied floating member database to %s", snapshot_file)

        stop_etcd_fixed()

        os.makedirs(FIXED_DATA_ROOT, mode=0o755, exist_ok=True)
        if os.path.exists(FIXED_DATA_DIR):
            # Puppet may have founded an empty fixed-0 on this release; the
            # migrated keyspace supersedes it.
            LOG.info("Removing existing %s before restore", FIXED_DATA_DIR)
            shutil.rmtree(FIXED_DATA_DIR)

        restore_to_fixed_0(snapshot_file, etcd_version)

        ensure_fixed_env_file()

        disable_floating_etcd()

        start_etcd_fixed()

        # Written last: until the member answers, the migration is not done and
        # a repeated activate should be free to try again.
        with open(MIGRATION_MARKER, 'w') as marker:
            marker.write("migrated from %s\n" % FLOATING_DATA_DIR)
        LOG.info("etcd keyspace migration complete, marker written to %s",
                 MIGRATION_MARKER)
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        if mounted_here:
            unmount_floating_volume()

    # Reached only when the keyspace actually moved: the early returns above
    # leave etcd untouched and need no wait. Wait for kube-apiserver to
    # prevent failures in the downstream upgrade scripts, which are gated on
    # kubernetes and do not retry: netapp-trident-migration, the first of them
    # on this path, spends its three urllib3 connect retries within
    # milliseconds.
    wait_for_apiserver_ready()
    restart_stale_control_plane_clients()


def rollback_migration():
    """Restore the floating member and undo the migration on rollback.

    On activate-rollback the system returns to the N-1 release, where the
    DRBD-backed floating member is authoritative. This stops and disables the
    fixed member, brings the floating member back into service -- mounting its
    volume, starting it under SM and waiting for it to serve -- and only then
    removes the now-stale fixed-0 data directory and the marker, so a later
    activate starts from a clean, correct snapshot.

    Restoring the floating member before removing the fixed keyspace is
    deliberate: it is what leaves the system with a working etcd. The previous
    version only re-enabled the floating systemd unit without mounting or
    starting it, so from rollback until the next reboot there was no etcd at
    all, and the first activate-rollback plugin needing kube-apiserver failed
    with a misleading bootstrap-token error.

    Simplex only, for the same reason as the migration: on duplex this script
    never created the data directory, so it must not remove it. Rollback there
    is handled by remove_fixed_etcd_members_for_rollback().
    """
    if not is_simplex():
        LOG.info("System mode is %s, not %s. Fixed member removal on rollback "
                 "is handled by the conductor. Skipping.",
                 get_system_mode(), SIMPLEX)
        return

    # Stopped before its data directory is removed, otherwise the member keeps
    # serving a keyspace that is about to disappear and systemd restarts it
    # against a directory that no longer exists.
    stop_etcd_fixed()
    for action in ("disable",):
        result = subprocess.run(["systemctl", action, ETCD_FIXED_SERVICE],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, check=False)
        if result.returncode == 0:
            LOG.info("systemd %s %s", action, ETCD_FIXED_SERVICE)
        else:
            LOG.warning("Could not %s %s: %s", action, ETCD_FIXED_SERVICE,
                        result.stderr.strip())

    # Restore the floating member before removing the fixed keyspace. The N-1
    # release is authoritative on the floating member, so it has to be mounted,
    # started, handed back to SM and confirmed serving. This raises if the
    # floating member does not come up, and it runs before the fixed keyspace
    # is removed, so a failure leaves the fixed data intact and the system
    # recoverable rather than with no etcd at all.
    restore_floating_etcd()

    # Only now that the floating member is serving is it safe to drop the
    # fixed keyspace and the marker, so a later activate migrates again from a
    # clean, correct snapshot.
    if os.path.exists(FIXED_DATA_DIR):
        LOG.info("Removing stale %s on rollback", FIXED_DATA_DIR)
        shutil.rmtree(FIXED_DATA_DIR, ignore_errors=True)

    if os.path.exists(MIGRATION_MARKER):
        LOG.info("Removing marker %s on rollback", MIGRATION_MARKER)
        os.remove(MIGRATION_MARKER)

    # Same reasoning as the migration path, and the same exposure: the
    # activate-rollback queue continues into RollbackFluxcdControllers and
    # K8sAppUpgrade, both of which need the API. The endpoint has just moved
    # back to the floating member, so kube-apiserver is restarting again here.
    wait_for_apiserver_ready()
    restart_stale_control_plane_clients()


class SimplexEtcdKeyspaceMigration(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='simplex-etcd-keyspace-migration',
            completed_state='simplex-etcd-keyspace-migration-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))

        if action == 'activate':
            migrate_keyspace()
        elif action == 'activate-rollback':
            rollback_migration()


def main():
    """Entrypoint for etcd keyspace migration.

    This is intended to be applied on simplex. Running on a duplex system is
    safe, a no-op.
    """
    from_release = sys.argv[1] if len(sys.argv) > 1 else None
    to_release = sys.argv[2] if len(sys.argv) > 2 else None
    action = sys.argv[3] if len(sys.argv) > 3 else None

    configure_logging()
    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    try:
        if action == 'activate':
            migrate_keyspace()
        elif action == 'activate-rollback':
            rollback_migration()
    except Exception as ex:
        LOG.exception("etcd keyspace migration failed: %s", ex)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
