#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This is an utility module used by standalone USM upgrade scripts
# that runs on the FROM-side context but using TO-side code base
#

from keystoneauth1 import exceptions
from keystoneauth1 import identity
from keystoneauth1 import session


def get_token_endpoint(config, service_type="platform"):
    """Returns an endpoint and a token for a service

    :param config: A configuration dictionary containing the
    authentication credentials
    :param service_type: The service to get the related token
    and endpoint
    """
    required_user_keys = ['auth_url',
                          'username',
                          'password',
                          'project_name',
                          'user_domain_name',
                          'project_domain_name']
    if not all(key in config for key in required_user_keys):
        raise Exception("Missing required key(s) to authenticate to Keystone")

    try:
        auth = identity.Password(
            auth_url=config["auth_url"],
            username=config["username"],
            password=config["password"],
            project_name=config["project_name"],
            user_domain_name=config["user_domain_name"],
            project_domain_name=config["project_domain_name"]
        )
        sess = session.Session(auth=auth)
        token = sess.get_token()
        endpoint = sess.get_endpoint(service_type=service_type,
                                     region_name=config["region_name"],
                                     interface="public")
    except exceptions.http.Unauthorized:
        raise Exception("Failed to authenticate to Keystone. Request unauthorized")
    except Exception as e:
        raise Exception("Failed to get token and endpoint. Error: %s", str(e))

    if service_type == "usm":
        endpoint += "/software"

    return token, endpoint


def get_sysinv_client(token, endpoint):
    """Returns a sysinv client instance

    :param token: auth token
    :param endpoint: service endpoint
    """
    # if platform type is sysinv then return the client as well
    try:
        from cgtsclient import client
        return client.Client(version='1', endpoint=endpoint, token=token, timeout=600)
    except ImportError:
        msg = "Failed to import cgtsclient"
        raise ImportError(msg)
    except Exception as e:
        msg = "Failed to get sysinv client. Error: %s" % str(e)
        raise Exception(msg)
