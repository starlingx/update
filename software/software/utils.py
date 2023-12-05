"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import json
import logging
import re
import shutil
from netaddr import IPAddress
import os
import socket
from socket import if_nametoindex as if_nametoindex_func

import software.constants as constants

from software.exceptions import StateValidationFailure

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


def compare_release_version(sw_release_version_1, sw_release_version_2):
    """Compares release versions and returns True if first is higher than second """
    if not sw_release_version_1 or not sw_release_version_2:
        return None
    else:
        try:
            separator = '.'
            separated_string_1 = sw_release_version_1.split(separator)
            separated_string_2 = sw_release_version_2.split(separator)
            if len(separated_string_1) != len(separated_string_2):
                return None
            for index, val in enumerate(separated_string_1):
                if int(val) > int(separated_string_2[index]):
                    return True
            return False
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


def save_temp_file(file_item, temp_dir=constants.SCRATCH_DIR):
    """Save a temporary file
    param file_item: file to save
    param temp_dir: directory to save file in
    """
    try:
        if not os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
            os.makedirs(temp_dir)
    except Exception:
        raise Exception("Failed to create directory {}".format(temp_dir))

    file_name = file_item.filename
    try:
        file_item.file.seek(0, os.SEEK_END)
        file_size = file_item.file.tell()
        avail_space = shutil.disk_usage(temp_dir).free
        if file_size > avail_space:
            LOG.error("Not enough space to save file %s in %s \n \
                Available %s bytes. File size %s", file_name, temp_dir, avail_space, file_size)
    except Exception:
        LOG.exception("Failed to get file size in bytes for %s or disk space for %s", file_item, temp_dir)

    saved_file = os.path.join(temp_dir, os.path.basename(file_name))
    try:
        with open(saved_file, 'wb') as destination_file:
            destination_file.write(file_item.value)
    except Exception:
        LOG.exception("Failed to save file %s", file_name)


def delete_temp_file(file_name, temp_dir=constants.SCRATCH_DIR):
    """Delete a temporary file
    param file_name: file to delete
    param temp_dir: directory to delete file from
    """
    try:
        os.remove(os.path.join(temp_dir, os.path.basename(file_name)))
    except Exception:
        LOG.exception("Failed to delete file %s", file_name)


def get_all_files(temp_dir=constants.SCRATCH_DIR):
    """Get all files in a directory
    param temp_dir: directory to get files from
    return: list of files
    """
    try:
        files = os.listdir(temp_dir)
        return [os.path.join(temp_dir, file) for file in files]
    except Exception:
        LOG.exception("Failed to get files from %s", temp_dir)
        return []


def get_auth_token_and_endpoint(user: dict, service_type: str, region_name: str, interface: str):
    """Get the auth token and endpoint for a service

    :param user: user dict
    :param service_type: service type
    :param region_name: region name
    :param interface: interface type
    :return: auth token and endpoint
    """

    from keystoneauth1 import exceptions
    from keystoneauth1 import identity
    from keystoneauth1 import session

    required_user_keys = ['auth_url',
                          'username',
                          'password',
                          'project_name',
                          'user_domain_name',
                          'project_domain_name']
    if not all(key in user for key in required_user_keys):
        raise Exception("Missing required key(s) to authenticate to Keystone")

    try:
        LOG.info("Authenticating for service type: %s, region name: %s, interface: %s",
                 service_type,
                 region_name,
                 interface)
        auth = identity.Password(
            auth_url=user['auth_url'],
            username=user['username'],
            password=user['password'],
            project_name=user['project_name'],
            user_domain_name=user['user_domain_name'],
            project_domain_name=user['project_domain_name']
        )
        sess = session.Session(auth=auth)
        return sess.get_token(), sess.get_endpoint(service_type=service_type,
                                                   region_name=region_name,
                                                   interface=interface)
    except exceptions.http.Unauthorized:
        LOG.error("Failed to authenticate to Keystone. Request unauthorized")
        raise
    except Exception as e:
        LOG.exception("Failed to get token and endpoint. Error: %s", str(e))
        raise


def save_to_json_file(file, data):
    try:
        with open(file, "w") as f:
            json.dump(data, f)
    except Exception as e:
        LOG.error("Problem saving file %s: %s", file, e)
        raise


def load_from_json_file(file):
    try:
        with open(file, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        LOG.error("File %s not found", file)
        return None
    # Avoid error to read an empty file
    except ValueError:
        return {}

    except Exception as e:
        LOG.error("Problem reading from %s: %s", file, e)
        return None


def check_state(state, states):
    """
    Check if the given state is one of the defined states in the Enum.
    :param state: String value.
    :param states: An Enum object.
    """
    if not state in states.__members__:
        msg = "State %s not in valid states: %s" % (state, list(states.__members__.keys()))
        LOG.exception(msg)
        raise StateValidationFailure(msg)


def check_instances(params: list, instance):
    for p in params:
        if not isinstance(p, instance):
            msg = "Param with value %s must be type: %s" % (p, instance)
            LOG.exception(msg)
            raise ValueError(msg)


def get_software_filesystem_data():
    if os.path.exists(constants.SOFTWARE_JSON_FILE):
        return load_from_json_file(constants.SOFTWARE_JSON_FILE)
    else:
        return {}


def validate_versions(versions):
    """
    Validate a list of versions
    :param versions: list of versions
    :raise: ValueError if version is invalid
    """
    for version in versions:
        if not re.match(r'[0-9]+\.[0-9]+(\.[0-9]+)?$', version):
            msg = "Invalid version: %s" % version
            LOG.exception(msg)
            raise ValueError(msg)
