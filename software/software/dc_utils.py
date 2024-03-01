"""
Copyright (c) 2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import json
import logging
from keystoneauth1 import exceptions
from keystoneauth1 import identity
from keystoneauth1 import session

from oslo_config import cfg
from oslo_utils import encodeutils
from six.moves.urllib.request import Request
from six.moves.urllib.request import urlopen

from software import utils
from software.constants import SYSTEM_CONTROLLER_REGION


LOG = logging.getLogger('main_logger')
CONF = cfg.CONF


def get_token_endpoint(service_type, region_name=None, interface="internal"):
    config = CONF.get('keystone_authtoken')
    if region_name is None:
        region_name = config.region_name

    try:
        auth = identity.Password(
            auth_url=config.auth_url,
            username=config.username,
            password=config.password,
            project_name=config.project_name,
            user_domain_name=config.user_domain_name,
            project_domain_name=config.project_domain_name
        )
        sess = session.Session(auth=auth)
        token = sess.get_token()
        endpoint = sess.get_endpoint(service_type=service_type,
                                     region_name=region_name,
                                     interface=interface)
    except exceptions.http.Unauthorized:
        raise Exception("Failed to authenticate to Keystone. Request unauthorized")
    except Exception as e:
        msg = "Failed to get token and endpoint. Error: %s", str(e)
        raise Exception(msg)
    return token, endpoint


def rest_api_request(token, method, api_cmd,
                     api_cmd_payload=None, timeout=45):
    """
    Make a rest-api request
    Returns: response as a dictionary
    """
    api_cmd_headers = dict()
    api_cmd_headers['Content-type'] = "application/json"
    api_cmd_headers['User-Agent'] = "usm/1.0"

    request_info = Request(api_cmd)
    request_info.get_method = lambda: method
    if token:
        request_info.add_header("X-Auth-Token", token)
    request_info.add_header("Accept", "application/json")

    if api_cmd_headers is not None:
        for header_type, header_value in api_cmd_headers.items():
            request_info.add_header(header_type, header_value)

    if api_cmd_payload is not None:
        request_info.data = encodeutils.safe_encode(api_cmd_payload)

    request = None
    try:
        request = urlopen(request_info, timeout=timeout)
        response = request.read()
    finally:
        if request:
            request.close()

    if response == "":
        response = json.loads("{}")
    else:
        response = json.loads(response)

    return response


def get_subclouds_from_dcmanager():
    token, api_url = get_token_endpoint("dcmanager", region_name=SYSTEM_CONTROLLER_REGION)

    api_cmd = api_url + '/subclouds'
    LOG.debug('api_cmd %s' % api_cmd)
    data = rest_api_request(token, "GET", api_cmd)
    if 'subclouds' in data:
        return data['subclouds']
    raise Exception(f"Incorrect response from dcmanager for querying subclouds {data}")


def get_subcloud_groupby_version():
    subclouds = get_subclouds_from_dcmanager()
    grouped_subclouds = {}
    for subcloud in subclouds:
        major_ver = utils.get_major_release_version(subcloud['software_version'])
        if major_ver not in grouped_subclouds:
            grouped_subclouds[major_ver] = [subcloud]
        else:
            grouped_subclouds[major_ver].append(subcloud)

    msg = "total %s subclouds." % len(subclouds)
    for ver in grouped_subclouds:
        msg = msg + " %s: %s subclouds." % (ver, len(grouped_subclouds[ver]))

    LOG.info(msg)
    return grouped_subclouds
