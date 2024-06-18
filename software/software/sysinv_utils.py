"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging

from software.exceptions import SysinvClientNotInitialized
from software import constants
from software import utils


LOG = logging.getLogger('main_logger')


def get_sysinv_client(token, endpoint):
    try:
        from cgtsclient import client
        sysinv_client = client.Client(version='1', endpoint=endpoint, token=token, timeout=600)
        return sysinv_client
    except ImportError:
        msg = "Failed to import cgtsclient"
        LOG.exception(msg)
        raise ImportError(msg)
    except Exception as e:
        msg = "Failed to get sysinv client. Error: %s" % str(e)
        LOG.exception(msg)
        raise SysinvClientNotInitialized(msg)


def get_k8s_ver():
    try:
        token, endpoint = utils.get_endpoints_token()
        sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
        k8s_vers = sysinv_client.kube_version.list()
    except Exception as err:
        LOG.error("Error getting k8s version: %s", err)
        raise

    for k8s_ver in k8s_vers:
        if k8s_ver.state == "active":
            return k8s_ver.version
    raise Exception("Failed to get current k8s version")


def get_ihost_list():
    try:
        token, endpoint = utils.get_endpoints_token()
        sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
        return sysinv_client.ihost.list()
    except Exception as err:
        LOG.error("Error getting ihost list: %s", err)
        raise


def is_host_locked_and_online(host):
    for ihost in get_ihost_list():
        if (host == ihost.hostname and ihost.availability == constants.AVAILABILITY_ONLINE and
                ihost.administrative == constants.ADMIN_LOCKED):
            return True
    return False


def get_system_info():
    """Returns system type and system mode"""
    token, endpoint = utils.get_endpoints_token()
    sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
    system_info = sysinv_client.isystem.list()[0]
    return system_info.system_type, system_info.system_mode


def get_dc_role():
    try:
        token, endpoint = utils.get_endpoints_token()
        sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
        system = sysinv_client.isystem.list()[0]
        return system.distributed_cloud_role
    except Exception as err:
        LOG.error("Error getting DC role: %s", err)
        raise


def is_system_controller():
    return get_dc_role() == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER


def get_sw_version_from_host(hostname):
    for host in get_ihost_list():
        if host.hostname == hostname:
            return host.sw_version
    return None


def update_host_sw_version(hostname, sw_version):
    token, endpoint = utils.get_endpoints_token()
    sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)

    patch = [{'op': 'replace', 'path': '/sw_version', 'value': sw_version}]
    try:
        # TODO(bqian) should enhance below simple REST API call to guaranteed delivery
        sysinv_client.ihost.update(hostname, patch)
    except Exception:
        LOG.exception("Failed to update %s sw_version %s" % (hostname, sw_version))
        raise
