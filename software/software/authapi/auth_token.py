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
# Copyright (c) 2023,2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
from keystonemiddleware import auth_token
from platform_util.oidc import oidc_utils
from software import utils
from webob import exc
from webob import Response

LOG = logging.getLogger("main_logger")


class AuthTokenMiddleware(auth_token.AuthProtocol):
    """A wrapper on Keystone auth_token middleware.

    Does not perform verification of authentication tokens
    for public routes in the API.

    """
    def __init__(self, app, conf, public_api_routes=None):
        self._software_app = app
        self._oidc_token_cache = {}
        self._default_domain = conf.get('oidc_default_domain', 'Default')
        self._default_project = conf.get('oidc_default_project', 'admin')

        if public_api_routes is None:
            public_api_routes = []
        self.public_api_routes = set(public_api_routes)

        super(AuthTokenMiddleware, self).__init__(app, conf)

    @staticmethod
    def _error_response(message):
        return Response(status=403, json_body={'error': message})

    # TODO(heitormatsui): migrate the token validation
    #  functions to a common library
    def _validate_oidc_token(self, oidc_token):
        try:
            oidc_config = oidc_utils.get_apiserver_oidc_args()
        except Exception as e:
            msg = 'Get OIDC config failed: %s' % e
            LOG.error(msg)
            raise exc.HTTPForbidden(msg) from e

        if oidc_config is None:
            msg = 'OIDC config is empty'
            LOG.error(msg)
            raise exc.HTTPForbidden(msg)

        issuer_url = oidc_config.get('oidc-issuer-url')
        client_id = oidc_config.get('oidc-client-id')
        username_claim = oidc_config.get('oidc-username-claim')
        group_claim = oidc_config.get('oidc-groups-claim')

        # Validate token
        try:
            oidc_token_dict = oidc_utils.validate_oidc_token(
                oidc_token,
                self._oidc_token_cache,
                issuer_url,
                client_id
            )
        except Exception as e:
            msg = 'OIDC token validation failed: %s' % e
            LOG.error(msg)
            raise exc.HTTPForbidden(msg) from e

        if not oidc_token_dict:
            msg = 'Failed OIDC validation for token details'
            LOG.error(msg)
            raise exc.HTTPForbidden(msg)

        return oidc_token_dict, username_claim, group_claim

    def _authenticate_oidc_token(self, oidc_token, env):
        if not oidc_token:
            msg = 'Missing OIDC token in the request'
            LOG.error(msg)
            return self._error_response(message=msg)

        try:
            oidc_token_dict, username_claim, group_claim = \
                self._validate_oidc_token(oidc_token)
        except Exception as e:
            return self._error_response(message=str(e))

        # Get username
        try:
            username = oidc_utils.get_username_from_oidc_token(
                oidc_token_dict, username_claim)
        except Exception as e:
            msg = 'Failed to extract username from OIDC token: %s' % e
            LOG.error(msg)
            return self._error_response(message=msg)

        if not username:
            msg = 'Invalid username for the OIDC token'
            LOG.error(msg)
            return self._error_response(message=msg)

        # Get roles
        try:
            roles = oidc_utils.get_keystone_roles_for_oidc_token(
                oidc_token_dict, username_claim, group_claim,
                domain=self._default_domain, project=self._default_project)
        except Exception as e:
            msg = 'Failed to get roles from OIDC token: %s' % e
            LOG.error(msg)
            return self._error_response(message=msg)

        if not roles:
            msg = 'Invalid roles for the OIDC token'
            LOG.error(msg)
            return self._error_response(message=msg)

        env['HTTP_X_ROLES'] = ','.join(roles)
        env['HTTP_X_USER_NAME'] = username
        env['HTTP_X_PROJECT_NAME'] = self._default_project
        return self._software_app

    def __call__(self, env, start_response):
        path = utils.safe_rstrip(env.get('PATH_INFO'), '/')

        if path in self.public_api_routes:
            return self.app(env, start_response)  # pylint: disable=no-member

        oidc_token = env.get("HTTP_OIDC_TOKEN")
        if oidc_token:
            resp = self._authenticate_oidc_token(oidc_token, env)
            return resp(env, start_response)

        return super(AuthTokenMiddleware, self).__call__(env, start_response)  # pylint: disable=too-many-function-args
