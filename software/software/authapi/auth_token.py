# -*- encoding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging

from platform_util.oidc import oidc_utils
from keystonemiddleware import auth_token
from webob import exc
from webob import Response

from software import utils

LOG = logging.getLogger("main_logger")


class OIDCTokenMiddleware():
    def __init__(self, app, conf):
        self._app = app
        self._token_cache = {}
        self._domain = conf.get("oidc_default_domain", "Default")
        self._project = conf.get("oidc_default_project", "admin")

    def __call__(self, env, start_response):
        token = env.get("HTTP_OIDC_TOKEN")
        try:
            claims = self._authenticate(token)
        except exc.HTTPForbidden as e:
            msg = f"OIDC authentication: {str(e)}."
            return self._error_response(message=msg)

        self._inject_claims(env, claims)
        return self._app(env, start_response)

    def _authenticate(self, token):
        try:
            claims = oidc_utils.get_oidc_token_claims(token, self._token_cache)
            parsed_claims = oidc_utils.parse_oidc_token_claims(claims, self._domain, self._project)
        except Exception as e:
            raise exc.HTTPForbidden(str(e))
        return parsed_claims

    def _inject_claims(self, env, claims):
        roles = claims.get("roles", [])
        username = claims.get("username", "")
        env['HTTP_X_ROLES'] = ','.join(roles)
        env['HTTP_X_USER_NAME'] = username
        env['HTTP_X_PROJECT_NAME'] = self._project

    @staticmethod
    def _error_response(message):
        return Response(json_body={'error': message})


class AuthTokenMiddleware(auth_token.AuthProtocol):
    """A wrapper on Keystone auth_token middleware.

    Does not perform verification of authentication tokens
    for public routes in the API.

    """
    def __init__(self, app, conf, public_api_routes=None):
        self._software_app = app

        if public_api_routes is None:
            public_api_routes = []
        self.public_api_routes = set(public_api_routes)

        self.oidc_middleware = OIDCTokenMiddleware(app, conf)

        super(AuthTokenMiddleware, self).__init__(app, conf)

    def __call__(self, env, start_response):
        path = utils.safe_rstrip(env.get('PATH_INFO'), '/')

        if path in self.public_api_routes:
            return self.app(env, start_response)  # pylint: disable=no-member

        oidc_token = env.get("HTTP_OIDC_TOKEN")
        if oidc_token:
            resp = self.oidc_middleware(env, start_response)
            if isinstance(resp, Response):
                return resp(env, start_response)
            return resp

        return super(AuthTokenMiddleware, self).__call__(env, start_response)  # pylint: disable=too-many-function-args
