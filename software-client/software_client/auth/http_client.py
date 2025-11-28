from oslo_utils import importutils
from software_client.common import http2


def get_http_client(api_version, endpoint, token=None, **kwargs):
    auth_ref = None
    cli_kwargs = {
        'local_root': True,
        'token': token,
        'insecure': kwargs.get('insecure'),
        'cacert': kwargs.get('cacert'),
        'timeout': kwargs.get('timeout'),
        'ca_file': kwargs.get('ca_file'),
        'cert_file': kwargs.get('cert_file'),
        'key_file': kwargs.get('key_file'),
        'auth_ref': auth_ref,
        'auth_url': kwargs.get('os_auth_url'),
        'api_version': api_version
    }

    http_adaptor = http2.construct_http_client(endpoint, **cli_kwargs)
    module = importutils.import_versioned_module('software_client',
                                                 api_version, 'client')
    client_class = getattr(module, 'Client')
    return client_class(http_adaptor=http_adaptor)
