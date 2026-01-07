# -*- encoding: utf-8 -*-
#
# Copyright © 2012 New Dream Network, LLC (DreamHost)
#
# Author: Doug Hellmann <doug.hellmann@dreamhost.com>  # noqa: H105
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
from oslo_config import cfg
from oslo_serialization import jsonutils
from pecan import hooks
from webob import exc

from software.authapi.policies import base as base_policy
from software.authapi.context import RequestContext
from software.authapi import policy
from software import utils


class ConfigHook(hooks.PecanHook):
    """Attach the config object to the request so controllers can get to it."""

    def before(self, state):
        state.request.cfg = cfg.CONF


class ContextHook(hooks.PecanHook):
    """Configures a request context and attaches it to the request.

    The following HTTP request headers are used:

    X-User-Id or X-User:
        Used for context.user_id.

    X-Tenant-Id or X-Tenant:
        Used for context.tenant.

    X-Auth-Token:
        Used for context.auth_token.

    X-Roles:
        Used for setting context.is_admin flag to either True or False.
        The flag is set to True, if X-Roles contains either an administrator
        or admin substring. Otherwise it is set to False.

    X-Project-Name:
        Used for context.project_name.

    """
    def __init__(self, public_api_routes):
        self.public_api_routes = public_api_routes
        super(ContextHook, self).__init__()

    def before(self, state):
        user_id = state.request.headers.get('X-User-Id')
        user_id = state.request.headers.get('X-User', user_id)
        tenant = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant)
        project_name = state.request.headers.get('X-Project-Name')
        domain_id = state.request.headers.get('X-User-Domain-Id')
        domain_name = state.request.headers.get('X-User-Domain-Name')
        auth_token = state.request.headers.get('X-Auth-Token', None)
        roles = state.request.headers.get('X-Roles', '').split(',')
        catalog_header = state.request.headers.get('X-Service-Catalog')
        service_catalog = None
        if catalog_header:
            try:
                service_catalog = jsonutils.loads(catalog_header)
            except ValueError:
                raise exc.HTTPInternalServerError(
                    'Invalid service catalog json.')

        credentials = {
            'project_name': project_name,
            'roles': roles
        }
        is_admin = policy.authorize(base_policy.ADMIN_OR_CONFIGURATOR, {},
                                    credentials, do_raise=False)

        path = utils.safe_rstrip(state.request.path, '/')
        is_public_api = path in self.public_api_routes

        state.request.context = RequestContext(
            auth_token=auth_token,
            user=user_id,
            tenant=tenant,
            domain_id=domain_id,
            domain_name=domain_name,
            is_admin=is_admin,
            is_public_api=is_public_api,
            project_name=project_name,
            roles=roles,
            service_catalog=service_catalog)


class AccessPolicyHook(hooks.PecanHook):
    """Verify that the user has the needed credentials
       to execute the action.
    """
    def before(self, state):
        context = state.request.context
        if not context.is_public_api:
            controller = state.controller.__self__
            if hasattr(controller, 'enforce_policy'):
                try:
                    controller_method = state.controller.__name__
                    controller.enforce_policy(controller_method, state.request)
                except Exception:
                    raise exc.HTTPForbidden()
            else:
                role = ""
                method = state.request.method
                if method == 'GET':
                    role = "reader or operator"
                    has_api_access = policy.authorize(
                        base_policy.READER_OR_OPERATOR_OR_CONFIGURATOR, {},
                        context.to_dict(), do_raise=False)
                else:
                    role = "admin or configurator"
                    has_api_access = policy.authorize(
                        base_policy.ADMIN_OR_CONFIGURATOR, {},
                        context.to_dict(), do_raise=False)
                if not has_api_access:
                    raise exc.HTTPForbidden("Not allowed, role " + role + " is needed")
