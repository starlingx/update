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
