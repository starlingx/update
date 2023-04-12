"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import configparser
import io
import logging
import os
import socket

import tsconfig.tsconfig as tsc

import software.utils as utils
import software.constants as constants

controller_mcast_group = None
agent_mcast_group = None
controller_port = 0
agent_port = 0
api_port = 0
mgmt_if = None
nodetype = None
platform_conf_mtime = 0
software_conf_mtime = 0
software_conf = '/etc/software/software.conf'


def read_config():
    global software_conf_mtime
    global software_conf

    if software_conf_mtime == os.stat(software_conf).st_mtime:
        # The file has not changed since it was last read
        return

    defaults = {
        'controller_mcast_group': "239.1.1.3",
        'agent_mcast_group': "239.1.1.4",
        'api_port': "5493",
        'controller_port': "5494",
        'agent_port': "5495",
    }

    global controller_mcast_group
    global agent_mcast_group
    global api_port
    global controller_port
    global agent_port

    config = configparser.ConfigParser(defaults)

    config.read(software_conf)
    software_conf_mtime = os.stat(software_conf).st_mtime

    controller_mcast_group = config.get('runtime',
                                        'controller_multicast')
    agent_mcast_group = config.get('runtime', 'agent_multicast')

    api_port = config.getint('runtime', 'api_port')
    controller_port = config.getint('runtime', 'controller_port')
    agent_port = config.getint('runtime', 'agent_port')

    # The platform.conf file has no section headers, which causes problems
    # for ConfigParser. So we'll fake it out.
    ini_str = '[platform_conf]\n' + open(tsc.PLATFORM_CONF_FILE, 'r').read()
    ini_fp = io.StringIO(ini_str)
    config.read_file(ini_fp)

    try:
        value = str(config.get('platform_conf', 'nodetype'))

        global nodetype
        nodetype = value
    except configparser.Error:
        logging.exception("Failed to read nodetype from config")


def get_mgmt_ip():
    # Check if initial config is complete
    if not os.path.exists('/etc/platform/.initial_config_complete'):
        return None
    mgmt_hostname = socket.gethostname()
    return utils.gethostbyname(mgmt_hostname)


# Because the software daemons are launched before manifests are
# applied, the content of some settings in platform.conf can change,
# such as the management interface. As such, we can't just directly
# use tsc.management_interface
#
def get_mgmt_iface():
    # Check if initial config is complete
    if not os.path.exists(constants.INITIAL_CONFIG_COMPLETE_FLAG):
        return None

    global mgmt_if
    global platform_conf_mtime

    if mgmt_if is not None and \
       platform_conf_mtime == os.stat(tsc.PLATFORM_CONF_FILE).st_mtime:
        # The platform.conf file hasn't been modified since we read it,
        # so return the cached value.
        return mgmt_if

    config = configparser.ConfigParser()

    # The platform.conf file has no section headers, which causes problems
    # for ConfigParser. So we'll fake it out.
    ini_str = '[platform_conf]\n' + open(tsc.PLATFORM_CONF_FILE, 'r').read()
    ini_fp = io.StringIO(ini_str)
    config.read_file(ini_fp)

    try:
        value = str(config.get('platform_conf', 'management_interface'))

        mgmt_if = value

        platform_conf_mtime = os.stat(tsc.PLATFORM_CONF_FILE).st_mtime
    except configparser.Error:
        logging.exception("Failed to read management_interface from config")
        return None
    return mgmt_if
