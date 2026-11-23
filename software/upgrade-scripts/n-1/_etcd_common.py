#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Shared etcdctl timeouts for the etcd upgrade scripts.
#
# The underscore prefix keeps this out of plugin discovery, which only loads
# the numbered scripts. Both 205-simplex-etcd-keyspace-migration.py and
# 206-duplex-etcd-peer-url-fixup.py import from here so the values are
# defined once.
#
# These match the constants in sysinv/common/etcd.py. They are duplicated
# rather than imported because importing sysinv into an upgrade script costs
# significant start-up time, so the scripts stay self-contained.
#
# etcdctl's own timeouts are used rather than only a wall-clock bound on the
# subprocess: --dial-timeout bounds reaching the endpoint, --command-timeout
# bounds the operation once connected.

import ipaddress

# Ordinary read-only calls. A member that has not answered within a couple of
# seconds is overloaded rather than slow.
ETCDCTL_COMMAND_TIMEOUT = '5s'
ETCDCTL_DIAL_TIMEOUT = '2s'

# Membership changes commit through raft before the leader replies.
ETCDCTL_MEMBERSHIP_COMMAND_TIMEOUT = '15s'

# A snapshot streams the whole keyspace.
ETCDCTL_SNAPSHOT_COMMAND_TIMEOUT = '30s'

# Outer bound on the subprocess, so a client that ignores its own timeouts
# cannot hold the caller: dial + command + a safety margin.
ETCD_SUBPROCESS_MARGIN = 1


def _seconds(value):
    """Seconds as an int from an etcdctl duration string such as '5s'."""
    return int(value.rstrip('s'))


def subprocess_timeout(command_timeout=ETCDCTL_COMMAND_TIMEOUT):
    """Outer subprocess bound for an etcdctl call."""
    return (_seconds(command_timeout) + _seconds(ETCDCTL_DIAL_TIMEOUT)
            + ETCD_SUBPROCESS_MARGIN)


def etcdctl_timeouts(command_timeout=None, dial_timeout=None):
    """Return the timeout flags to pass to etcdctl."""
    ct = command_timeout or ETCDCTL_COMMAND_TIMEOUT
    dt = dial_timeout or ETCDCTL_DIAL_TIMEOUT
    return ['--command-timeout', ct, '--dial-timeout', dt]


def format_url_address(address):
    """Bracket an IPv6 address for use in a URL, per RFC 2732."""
    if address and ':' in address:
        return '[%s]' % address
    return address


def canonical_address(address):
    """Return an address in a form two spellings of it can be compared in.

    openssl prints an IPv6 SAN expanded and upper case
    ("AEFD:205:0:0:0:0:0:2") while the address read from /etc/hosts is
    compressed and lower case ("aefd:205::2"). Comparing the two as text
    reports the address as absent when it is present, so addresses are
    compared as IPv4Address/IPv6Address objects instead. Returns None for
    a value that is not an address.
    """
    try:
        return ipaddress.ip_address(u'%s' % address)
    except ValueError:
        return None
