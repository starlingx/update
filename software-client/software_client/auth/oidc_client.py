#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from urllib.parse import urlparse

from oslo_utils import importutils
from software_client.common import http2
from software_client import exc
from software_client.constants import ADMIN
from software_client.constants import DEFAULT_REGION
from software_client.constants import INTERFACE_MAP
from software_client.constants import INTERNAL
from software_client.constants import PUBLIC
from software_client.constants import PORT_MAP


def get_oidc_client(api_version, endpoint, **kwargs):
    auth_ref = None
    cli_kwargs = {
        'insecure': kwargs.get('insecure'),
        'cacert': kwargs.get('cacert'),
        'timeout': kwargs.get('timeout'),
        'ca_file': kwargs.get('ca_file'),
        'cert_file': kwargs.get('cert_file'),
        'key_file': kwargs.get('key_file'),
        'auth_ref': auth_ref,
        'auth_url': kwargs.get('os_auth_url'),
        'api_version': api_version,
        'stx_auth_type': kwargs.get('stx_auth_type'),
        'oidc_username': kwargs.get('os_username')
    }

    http_adaptor = http2.construct_http_client(endpoint, **cli_kwargs)
    module = importutils.import_versioned_module('software_client',
                                                 api_version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(http_adaptor=http_adaptor)


def validate_oidc_params(**kwargs):
    """Validate required OIDC parameters."""
    required_params = ['os_auth_url', 'os_username']
    missing = [p for p in required_params if not kwargs.get(p)]
    if missing:
        raise exc.InvalidEndpoint(f'Missing required OIDC parameters: {missing}')


def build_oidc_endpoint(api_version, **kwargs):
    """Build OIDC endpoint URL from configuration."""
    interface = _normalize_interface(kwargs.get('os_endpoint_type'))
    protocol = 'https' if interface in [PUBLIC, ADMIN] else 'http'

    auth_url = kwargs.get('os_auth_url')
    addr_parts = urlparse(auth_url)
    hostname = addr_parts.hostname
    if ':' in hostname and not hostname.startswith('['):
        hostname = f"[{hostname}]"

    region_name = kwargs.get('os_region_name', DEFAULT_REGION)
    port_map = kwargs.get('port_map', PORT_MAP)
    region_ports = port_map.get(region_name, port_map.get(DEFAULT_REGION, {}))
    port = region_ports.get(interface)

    if not port:
        raise exc.InvalidEndpoint(f'No port for region {region_name} interface {interface}')
    return f"{protocol}://{hostname}:{port}/v{api_version}"


def _normalize_interface(interface):
    """Normalize interface type to standard values."""
    normalized = INTERFACE_MAP.get(interface, interface)
    return normalized if normalized in (ADMIN, INTERNAL, PUBLIC) else PUBLIC
