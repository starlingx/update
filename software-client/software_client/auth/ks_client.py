#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_utils import importutils
from urllib.parse import urljoin

from software_client import exc
from software_client.common import http


SERVICE_NAME = 'usm'
SERVICE_TYPE = 'usm'


def _make_session(**kwargs):
    from keystoneauth1 import loading
    """Construct a session based on authentication information

    :param kwargs: keyword args containing credentials, either:
        * os_auth_token: pre-existing token to re-use
        * system_url: system API endpoint
        or:
        * os_username: name of user
        * os_password: user's password
        * os_auth_url: endpoint to authenticate against
        * insecure: allow insecure SSL (no cert verification)
        * os_tenant_{name|id}: name or ID of tenant
        * os_region_name: region of the service
        * os_project_name: name of a project
        * os_project_id: ID of a project
        * os_user_domain_name: name of a domain the user belongs to
        * os_user_domain_id: ID of a domain the user belongs to
        * os_project_domain_name: name of a domain the project belongs to
        * os_project_domain_id: ID of a domain the project belongs to
        * timeout: request timeout (in seconds)
        * ca_file: trusted CA file
        * cert_file: client certificate file
        * key_file: client key file
    """
    session = None
    if (kwargs.get('os_username') and
        kwargs.get('os_password') and
        kwargs.get('os_auth_url') and
        (kwargs.get('os_project_id') or
         kwargs.get('os_project_name'))):
        auth_kwargs = {}
        auth_url = kwargs.get('os_auth_url')
        project_id = kwargs.get('os_project_id')
        project_name = kwargs.get('os_project_name')
        user_domain_id = kwargs.get('os_user_domain_id')
        user_domain_name = kwargs.get('os_user_domain_name') or "Default"
        project_domain_id = kwargs.get('os_project_domain_id')
        project_domain_name = kwargs.get('os_project_domain_name') or "Default"

        auth_type = 'password'
        username = kwargs.get('os_username')
        password = kwargs.get('os_password')
        auth_kwargs.update({
            'auth_url': auth_url,
            'project_id': project_id,
            'project_name': project_name,
            'user_domain_id': user_domain_id,
            'user_domain_name': user_domain_name,
            'project_domain_id': project_domain_id,
            'project_domain_name': project_domain_name,
            'username': username,
            'password': password
        })

        # construct the appropriate session
        timeout = kwargs.get('timeout')
        insecure = kwargs.get('insecure')
        cacert = kwargs.get('ca_file')
        cert = kwargs.get('cert_file')
        key = kwargs.get('key_file')

        loader = loading.get_plugin_loader(auth_type)
        auth_plugin = loader.load_from_options(**auth_kwargs)
        session = loading.session.Session().load_from_options(auth=auth_plugin,
                                                              timeout=timeout,
                                                              insecure=insecure,
                                                              cacert=cacert,
                                                              cert=cert,
                                                              key=key)
    # session could still be None
    return session


def get_ks_client(api_version, service_type=SERVICE_TYPE, endpoint=None, **kwargs):
    """Get an authenticated client, based on credentials in the keyword args.

    :param api_version: the API version to use ('1' or '2')
    :param session: the session to use (if it exists)
    :param service_type: service_type should always be 'usm'
    :param kwargs: additional keyword args to pass to the client or auth
    """
    # Make a session to determine the endpoint
    session = _make_session(**kwargs)

    if not endpoint:
        if session:
            try:
                interface = kwargs.get('os_endpoint_type')
                region_name = kwargs.get('os_region_name')
                endpoint = session.get_endpoint(service_type=service_type,
                                                interface=interface,
                                                region_name=region_name)
                api_version_str = 'v' + api_version
                if api_version_str not in endpoint.split('/'):
                    endpoint = urljoin(endpoint, api_version_str)

            except Exception as e:
                msg = ('Failed to get openstack endpoint')
                raise exc.EndpointException(
                    ('%(message)s, error was: %(error)s') % {'message': msg, 'error': e})
        else:
            exception_msg = ('Missing / invalid authorization credentials')
            raise exc.AmbigiousAuthSystem(exception_msg)

    # this will be a LegacyJsonAdapter
    cli_kwargs = {
        'session': session,
        'service_type': service_type,
        'service_name': SERVICE_NAME,
        'interface': kwargs.get('os_endpoint_type'),
        'region_name': kwargs.get('os_region_name'),
        'endpoint_override': endpoint,
        'global_request_id': kwargs.get('global_request_id'),
        'user_agent': kwargs.get('user_agent', 'software_client'),
        'api_version': kwargs.get('system_api_version')
    }
    return Client(api_version, endpoint, session, **cli_kwargs)


def Client(version, *args, **kwargs):
    http_adaptor = http.construct_http_client(*args, **kwargs)
    module = importutils.import_versioned_module('software_client',
                                                 version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(http_adaptor=http_adaptor)
