#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Correct the floating etcd member's registered peer URL on duplex.
#
# etcd-fixed writes the floating member's registered peer URL verbatim into
# ETCD_INITIAL_CLUSTER, so a loopback or non-TLS URL leaves the fixed member
# unable to open a peer connection. A certificate naming only the floating
# and loopback addresses is likewise rejected when the fixed member presents
# it from its unit address.
#
# Applied at activate on duplex:
#   - rewrites a registered floating peer URL that is not TLS-enabled and
#     remotely reachable
#   - regenerates the etcd certificate with the full SAN set
#
# Both conditions are tested for rather than gated on the from-release,
# because both are properties of the running configuration. A no-op on
# simplex, on rollback, and when the peer URL is already correct, so it is
# safe to re-run. Runs before
# 10-add-cluster-host-ip-to-kube-apiserver-cert.py.

import logging
import os
import re
import subprocess
import sys
import time

from _etcd_common import canonical_address
from _etcd_common import ETCDCTL_COMMAND_TIMEOUT
from _etcd_common import etcdctl_timeouts
from _etcd_common import format_url_address
from _etcd_common import subprocess_timeout
from software.utilities.utils import configure_logging

LOG = logging.getLogger(__name__)

PLATFORM_CONF = '/etc/platform/platform.conf'
ETCD_CA = '/etc/etcd/ca.crt'
ETCD_CERT = '/etc/etcd/etcd-client.crt'
ETCD_KEY = '/etc/etcd/etcd-client.key'
ETCD_CA_KEY = '/etc/etcd/ca.key'
ETCD_SERVER_CERT = '/etc/etcd/etcd-server.crt'
ETCD_SERVER_KEY = '/etc/etcd/etcd-server.key'
FLOATING_MEMBER_NAME = 'controller'
MARKER = '/etc/platform/.etcd_peer_url_fixed'


try:
    from _loader import CPlugin
except ImportError:
    class CPlugin:
        def __init__(self, **kwargs):
            pass


def _get_system_mode():
    """Read system_mode from platform.conf."""
    try:
        with open(PLATFORM_CONF) as f:
            for line in f:
                if line.startswith('system_mode='):
                    return line.strip().split('=', 1)[1]
    except Exception:
        pass
    return None


def _get_cluster_host_floating():
    """Resolve the floating cluster-host IP from /etc/hosts."""
    try:
        with open('/etc/hosts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and 'controller-cluster-host' in parts[1:]:
                    return parts[0]
    except Exception:
        pass
    return None


def _get_cluster_host_units():
    """Resolve the controller unit cluster-host addresses from /etc/hosts."""
    units = []
    try:
        with open('/etc/hosts') as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue
                for name in parts[1:]:
                    if name in ('controller-0-cluster-host',
                                'controller-1-cluster-host'):
                        units.append(parts[0])
    except Exception:
        pass
    return sorted(set(units))


def _etcdctl(args, timeout=None, command_timeout=None):
    """Run etcdctl against the floating cluster-host endpoint.

    The endpoint is resolved rather than hardcoded: the address depends on the
    cluster-host subnet, and on an IPv6 system it has to be bracketed.
    """
    floating_ip = _get_cluster_host_floating()
    if not floating_ip:
        raise RuntimeError(
            'cannot resolve controller-cluster-host from /etc/hosts')
    endpoint = 'https://%s:2379' % format_url_address(floating_ip)
    cmd = [
        'etcdctl',
        '--cacert', ETCD_CA,
        '--cert', ETCD_CERT,
        '--key', ETCD_KEY,
        '--endpoints', endpoint,
    ] + etcdctl_timeouts(command_timeout) + args
    if timeout is None:
        timeout = subprocess_timeout(
            command_timeout or ETCDCTL_COMMAND_TIMEOUT)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc


def _wait_for_healthy(seconds=60, interval=5):
    """Poll the floating endpoint until etcd answers, or the bound expires.

    A fixed sleep was not enough: after the restart below, etcd reloads the
    regenerated certificate and replays its WAL before it serves, and how
    long that takes scales with the keyspace. Every caller past this point
    talks to etcd, so a premature return surfaces as "context deadline
    exceeded" on the first etcdctl call and fails the activate.
    """
    deadline = time.time() + seconds
    while True:
        try:
            proc = _etcdctl(['endpoint', 'health'])
            if proc.returncode == 0:
                return True
        except (subprocess.SubprocessError, RuntimeError, OSError) as exc:
            LOG.info("etcd not healthy yet: %s", exc)
        if time.time() >= deadline:
            LOG.error("etcd did not become healthy within %ds", seconds)
            return False
        time.sleep(interval)


def _get_floating_peer_url():
    """Get the floating member's registered peer URL from the cluster."""
    proc = _etcdctl(['member', 'list', '-w', 'simple'])
    if proc.returncode != 0:
        return None, None
    for line in proc.stdout.strip().split('\n'):
        # Format: id, status, name, peerURLs, clientURLs, isLearner
        parts = [p.strip() for p in line.split(',')]
        if len(parts) >= 4 and parts[2] == FLOATING_MEMBER_NAME:
            return parts[0], parts[3]
    return None, None


def _regenerate_cert(floating_ip):
    """Regenerate etcd-server cert with full SANs."""
    if not os.path.isfile(ETCD_CA_KEY):
        LOG.warning("CA key not found at %s; cannot regenerate cert", ETCD_CA_KEY)
        return False

    # Resolve controller unit IPs from /etc/hosts
    unit_ips = []
    try:
        with open('/etc/hosts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    for name in parts[1:]:
                        if re.match(r'controller-[0-9]+-cluster-host$', name):
                            unit_ips.append(parts[0])
    except Exception:
        pass

    all_ips = sorted(set([floating_ip] + unit_ips + ['127.0.0.1', '::1']))
    san_str = ','.join('IP:' + ip for ip in all_ips)
    LOG.info("Regenerating etcd cert with SANs: %s", san_str)

    # Generate key + CSR
    ext_conf = (
        "[req]\n"
        "distinguished_name=dn\nreq_extensions=san\n"
        "[dn]\n"
        "[san]\n"
        "subjectAltName=%s\n"
        "keyUsage=digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth,clientAuth\n" % san_str
    )
    ext_file = '/tmp/.etcd-cert-ext.cnf'
    with open(ext_file, 'w') as f:
        f.write(ext_conf)

    new_key = ETCD_SERVER_KEY + '.new'
    new_csr = '/tmp/.etcd-server.csr'
    new_crt = ETCD_SERVER_CERT + '.new'

    try:
        subprocess.run([
            'openssl', 'req', '-new', '-nodes', '-newkey', 'rsa:4096',
            '-keyout', new_key, '-subj', '/CN=etcd-server',
            '-reqexts', 'san', '-config', ext_file,
            '-out', new_csr
        ], check=True, capture_output=True, timeout=30)

        subprocess.run([
            'openssl', 'x509', '-req', '-in', new_csr,
            '-CA', ETCD_CA, '-CAkey', ETCD_CA_KEY, '-CAcreateserial',
            '-days', '3650', '-sha256',
            '-extfile', ext_file, '-extensions', 'san',
            '-out', new_crt
        ], check=True, capture_output=True, timeout=30)

        # Replace
        os.replace(new_crt, ETCD_SERVER_CERT)
        os.replace(new_key, ETCD_SERVER_KEY)
        os.chmod(ETCD_SERVER_KEY, 0o600)
        LOG.info("etcd cert regenerated successfully")

        # Restart the floating etcd to pick up the new cert. Use systemctl
        # rather than sm-restart: on duplex, sm-restart triggers a service
        # failover that causes SM to SWACT the controller, killing the
        # activate process that called us.
        subprocess.run(['systemctl', 'restart', 'etcd'],
                       capture_output=True, timeout=30)
        return _wait_for_healthy()

    except Exception as e:
        LOG.error("Failed to regenerate cert: %s", e)
        return False
    finally:
        for f in (new_csr, ext_file):
            try:
                os.unlink(f)
            except OSError:
                pass


def fixup_duplex_peer_url(from_release, to_release, action, port):
    """Fix the floating etcd member's peer URL on a duplex activate.

    Shared by the plugin path (26.10) and the standalone __main__ entry so
    the older release, which invokes upgrade scripts directly, runs the same
    logic.
    """
    LOG.info("duplex-etcd-peer-url-fixup invoked from_release=%s "
             "to_release=%s action=%s", from_release, to_release, action)

    if action != 'activate':
        LOG.info("action=%s, nothing to do", action)
        return 0

    mode = _get_system_mode()
    if mode == 'simplex':
        LOG.info("simplex: nothing to fix")
        return 0

    if os.path.isfile(MARKER):
        LOG.info("marker %s exists; already fixed", MARKER)
        return 0

    floating_ip = _get_cluster_host_floating()
    if not floating_ip:
        LOG.error("Cannot resolve floating cluster-host IP")
        return 1

    # Step 1: Check if cert needs regeneration (missing unit IPs in SAN)
    proc = subprocess.run(
        ['openssl', 'x509', '-in', ETCD_SERVER_CERT, '-noout', '-text'],
        capture_output=True, text=True, timeout=10)
    # Derived, not hardcoded: the unit addresses depend on the
    # cluster-host subnet. Compared as addresses rather than as text
    # because openssl prints an IPv6 SAN expanded and upper case
    # ("AEFD:205:0:0:0:0:0:2") while /etc/hosts carries it compressed
    # and lower case ("aefd:205::2"). Matching on text reports every
    # address as missing on IPv6, which regenerates the certificate --
    # and restarts etcd -- on every activate.
    unit_ips = _get_cluster_host_units()
    have = set()
    for san in re.findall(r'IP Address:([0-9A-Fa-f:.]+)', proc.stdout):
        canonical = canonical_address(san)
        if canonical is not None:
            have.add(canonical)
    needs_cert_regen = any(
        canonical_address(ip) not in have for ip in unit_ips
    ) if unit_ips else True

    if needs_cert_regen:
        LOG.info("Cert SANs missing unit IPs — regenerating")
        if not _regenerate_cert(floating_ip):
            LOG.error("Cert regeneration failed")
            return 1

    # Step 2: Check and fix floating peer URL.
    # Health is confirmed even when the certificate did not need
    # regenerating: this runs during activate, when something else may
    # have restarted etcd, and _get_floating_peer_url() failing is a
    # hard failure of the activate rather than something retried.
    if not _wait_for_healthy():
        LOG.error("etcd is not healthy; cannot fix the floating peer URL")
        return 1

    member_id, peer_url = _get_floating_peer_url()
    if not member_id:
        LOG.error("Cannot get floating member from cluster")
        return 1

    expected_peer = ('https://%s:2380'
                     % format_url_address(floating_ip))
    if peer_url == expected_peer:
        LOG.info("Floating peer URL already correct: %s", peer_url)
    else:
        LOG.info("Fixing floating peer URL: %s → %s", peer_url, expected_peer)
        proc = _etcdctl(['member', 'update', member_id,
                         '--peer-urls=' + expected_peer])
        if proc.returncode != 0:
            LOG.error("member update failed: %s", proc.stderr.strip())
            return 1
        LOG.info("Floating peer URL updated successfully")

    # Write marker
    with open(MARKER, 'w') as f:
        f.write("fixed by 206-duplex-etcd-peer-url-fixup.py\n")

    LOG.info("Done — etcd ready for fixed member join")
    return 0


class DuplexEtcdPeerUrlFixup(CPlugin):

    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='duplex-etcd-peer-url-fixup',
            completed_state='duplex-etcd-peer-url-fixup-completed'
        )

    def _run(self, from_release, to_release, action, port):
        return fixup_duplex_peer_url(from_release, to_release, action, port)


def main():
    """Standalone entrypoint.

    The older release invokes upgrade scripts directly rather than through
    the plugin framework, so the same fixup is reachable from the command
    line as 'script from_release to_release action [port]'.
    """
    from_release = sys.argv[1] if len(sys.argv) > 1 else None
    to_release = sys.argv[2] if len(sys.argv) > 2 else None
    action = sys.argv[3] if len(sys.argv) > 3 else None
    port = sys.argv[4] if len(sys.argv) > 4 else None

    configure_logging()
    try:
        return fixup_duplex_peer_url(from_release, to_release, action, port)
    except Exception as ex:
        LOG.exception("duplex etcd peer-url fixup failed: %s", ex)
        return 1


if __name__ == "__main__":
    sys.exit(main())
