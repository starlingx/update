from .ks_client import get_ks_client
from .http_client import get_http_client
from .oidc_client import get_oidc_client
from .oidc_client import build_oidc_endpoint
from .oidc_client import validate_oidc_params
from software_client.constants import KEYSTONE
from software_client.constants import OIDC
from software_client.constants import TOKEN
from software_client.constants import LOCAL_ROOT


SERVICE_NAME = 'usm'
SERVICE_TYPE = 'usm'
API_PORT = "5493"
API_ENDPOINT = "http://127.0.0.1:" + API_PORT


def get_client(api_version, auth_type, service_type=SERVICE_TYPE, endpoint=None, **kwargs):
    # below logic can/should be moved to get_xx_client if getting more complicated.
    if auth_type == KEYSTONE:
        # basic keystone auth, capable to get endpoint, authenticate
        return get_ks_client(api_version, service_type, endpoint=endpoint, **kwargs)
    elif auth_type == LOCAL_ROOT:
        # local host use default lo endpoint, no token
        if not endpoint:
            endpoint = API_ENDPOINT
        return get_http_client(api_version, endpoint, **kwargs)
    elif auth_type == TOKEN:
        # token is provided, it'd better comes with endpoint, then no keystone catelog query needed
        token = kwargs.get("os_auth_token")
        return get_http_client(api_version, endpoint, token=token, **kwargs)
    elif auth_type == OIDC:
        validate_oidc_params(**kwargs)
        endpoint = build_oidc_endpoint(api_version, **kwargs)
        return get_oidc_client(api_version, endpoint, **kwargs)
