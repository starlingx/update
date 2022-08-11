#
# Copyright (c) 2014-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Access Control Lists (ACL's) control access the API server."""
from cgcs_patch.authapi import auth_token

OPT_GROUP_NAME = 'keystone_authtoken'
OPT_GROUP_PROVIDER = 'keystonemiddleware.auth_token'


def install(app, conf, public_routes):
    """Install ACL check on application.

    :param app: A WSGI application.
    :param conf: Settings. Must include OPT_GROUP_NAME section.
    :param public_routes: The list of the routes which will be allowed
                          access without authentication.
    :return: The same WSGI application with ACL installed.

    """
    keystone_config = dict(conf.get(OPT_GROUP_NAME))
    return auth_token.AuthTokenMiddleware(app,
                                          conf=keystone_config,
                                          public_api_routes=public_routes)
