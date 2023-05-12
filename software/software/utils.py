"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
from netaddr import IPAddress
import os
import socket
from socket import if_nametoindex as if_nametoindex_func

import software.constants as constants


LOG = logging.getLogger('main_logger')


def if_nametoindex(name):
    try:
        return if_nametoindex_func(name)
    except Exception:
        return 0


def get_major_release_version(sw_release_version):
    """Gets the major release for a given software version """
    if not sw_release_version:
        return None
    else:
        try:
            separator = '.'
            separated_string = sw_release_version.split(separator)
            major_version = separated_string[0] + separator + separated_string[1]
            return major_version
        except Exception:
            return None


def gethostbyname(hostname):
    """gethostbyname with IPv6 support """
    try:
        return socket.getaddrinfo(hostname, None)[0][4][0]
    except Exception:
        return None


def get_management_version():
    """Determine whether management is IPv4 or IPv6 """
    controller_ip_string = gethostbyname(constants.CONTROLLER_FLOATING_HOSTNAME)
    if controller_ip_string:
        controller_ip_address = IPAddress(controller_ip_string)
        return controller_ip_address.version
    else:
        return constants.ADDRESS_VERSION_IPV4


def get_management_family():
    ip_version = get_management_version()
    if ip_version == constants.ADDRESS_VERSION_IPV6:
        return socket.AF_INET6
    else:
        return socket.AF_INET


def get_versioned_address_all():
    ip_version = get_management_version()
    if ip_version == constants.ADDRESS_VERSION_IPV6:
        return "::"
    else:
        return "0.0.0.0"


def ip_to_url(ip_address_string):
    """Add brackets if an IPv6 address """
    try:
        ip_address = IPAddress(ip_address_string)
        if ip_address.version == constants.ADDRESS_VERSION_IPV6:
            return "[%s]" % ip_address_string
        else:
            return ip_address_string
    except Exception:
        return ip_address_string


def ip_to_versioned_localhost(ip_address_string):
    """Add brackets if an IPv6 address """
    ip_address = IPAddress(ip_address_string)
    if ip_address.version == constants.ADDRESS_VERSION_IPV6:
        return "::1"
    else:
        return "localhost"


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        LOG.debug("Reloading cached file %s", filename)
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


def safe_rstrip(value, chars=None):
    """Removes trailing characters from a string if that does not make it empty

    :param value: A string value that will be stripped.
    :param chars: Characters to remove.
    :return: Stripped value.

    """
    if not isinstance(value, str):
        LOG.warning("Failed to remove trailing character. Returning original "
                    "object. Supplied object is not a string: %s", value)
        return value

    return value.rstrip(chars) or value
