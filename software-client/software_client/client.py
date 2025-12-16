from software_client import auth
from software_client import constants


def Client(api_version, auth_mode=constants.KEYSTONE, **kwargs):
    client = auth.get_client(api_version, auth_mode, **kwargs)
    return client
