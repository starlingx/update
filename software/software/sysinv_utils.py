"""
Copyright (c) 2023-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging

from software.exceptions import SysinvClientNotInitialized
from software.exceptions import ServiceParameterNotFound
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


def are_all_hosts_unlocked_and_online():
    for ihost in get_ihost_list():
        if (ihost.administrative != constants.ADMIN_UNLOCKED or
                ihost.availability not in [constants.AVAILABILITY_AVAILABLE,
                                           constants.AVAILABILITY_DEGRADED]):
            return False
    return True


def get_system_info():
    """Returns system type and system mode"""
    system_type = utils.get_platform_conf("system_type")
    system_mode = utils.get_platform_conf("system_mode")
    return system_type, system_mode


def get_dc_role():
    return utils.get_platform_conf("distributed_cloud_role")


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


def trigger_vim_host_audit(hostname):
    """Trigger for the sysinv function vim_host_audit."""
    token, endpoint = utils.get_endpoints_token()
    sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
    try:
        host = sysinv_client.ihost.get(hostname)
        sysinv_client.ihost.vim_host_audit(host.uuid)
    except Exception as err:
        LOG.error("Failed to trigger VIM host audit for %s: %s", hostname, err)
        raise


def get_service_parameter(service=None, section=None, name=None):
    """return a list of dictionaries with keys
       uuid, service, section, name, personality, resource, value
    """

    try:
        token, endpoint = utils.get_endpoints_token()
        sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
        service_parameters = sysinv_client.service_parameter.list()
    except Exception as err:
        LOG.error("Error getting service parameters: %s", err)
        raise

    fields = ['uuid', 'service', 'section', 'name', 'value',
              'personality', 'resource']

    data = []
    for sp in service_parameters:
        # pylint: disable=R0916
        if (service is None or sp.service == service) and \
                (section is None or sp.section == section) and \
                (name is None or sp.name == name):

            v = {f: getattr(sp, f, '') for f in fields}
            data.append(v)

    return data


def get_backup_oot_drivers():
    # get the value of backup service parameter backup_oot_drivers
    name = "backup_oot_drivers_24.09"
    res_list = get_service_parameter(name=name)
    if not res_list:
        raise ServiceParameterNotFound(name)

    parameter = res_list[0]
    return parameter["value"]


def trigger_evaluate_apps_reapply(trigger):
    """Trigger for the sysinv function evaluate_apps_reapply.

    This function gets a sysinv_client and calls post_evaluate_apps_reapply,
    passing the trigger parameter, thereby starting the evaluation process.
    The evaluate_apps_reapply function synchronously determines whether
    an application re-apply is needed. If so, it raises a re-apply flag.

    :param trigger: dictionary containing at least the 'type' field.
    """
    token, endpoint = utils.get_endpoints_token()
    sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
    sysinv_client.kube_app.post_evaluate_apps_reapply(trigger)
    LOG.info("Succesfully trigger the sysinv evaluate apps reapply")
