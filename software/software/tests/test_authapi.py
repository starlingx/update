#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from unittest.mock import MagicMock
from unittest.mock import patch
import unittest
from webob import exc

from software.tests import base  # noqa: F401
from software.authapi.auth_token import OIDCTokenMiddleware
from software.authapi.context import make_context
from software.authapi.context import RequestContext
from software.authapi.hooks import AccessPolicyHook
from software.authapi.hooks import ConfigHook
from software.authapi.hooks import ContextHook


class TestConfigHook(unittest.TestCase):
    @patch('software.authapi.hooks.cfg')
    def test_before(self, mock_cfg):
        hook = ConfigHook()
        state = MagicMock()
        hook.before(state)
        self.assertEqual(state.request.cfg, mock_cfg.CONF)


class TestContextHook(unittest.TestCase):

    @patch('software.authapi.hooks.policy')
    @patch('software.authapi.hooks.utils')
    def test_before_bad_catalog(self, mock_utils, mock_policy):
        mock_policy.authorize.return_value = False
        mock_utils.safe_rstrip.return_value = '/public'
        hook = ContextHook(public_api_routes=['/public'])
        state = MagicMock()
        state.request.headers = {
            'X-Roles': 'reader',
            'X-Service-Catalog': '{bad json',
        }
        state.request.path = '/public'
        with self.assertRaises(exc.HTTPInternalServerError):
            hook.before(state)


class TestAccessPolicyHook(unittest.TestCase):

    @patch('software.authapi.hooks.policy')
    def test_post_forbidden(self, mock_policy):
        hook = AccessPolicyHook()
        state = MagicMock()
        state.request.context.is_public_api = False
        state.request.method = 'POST'
        state.controller.__self__ = MagicMock(spec=[])
        state.controller.__name__ = 'post'
        mock_policy.authorize.return_value = False
        with self.assertRaises(exc.HTTPForbidden):
            hook.before(state)

    @patch('software.authapi.hooks.policy')
    def test_enforce_policy_exception(self, _mock_policy):
        hook = AccessPolicyHook()
        state = MagicMock()
        state.request.context.is_public_api = False
        ctrl = MagicMock()
        ctrl.enforce_policy.side_effect = Exception("denied")
        state.controller.__self__ = ctrl
        state.controller.__name__ = 'post'
        with self.assertRaises(exc.HTTPForbidden):
            hook.before(state)


class TestOIDCTokenMiddleware(unittest.TestCase):
    def test_call_success(self):
        app = MagicMock()
        mw = OIDCTokenMiddleware(app, {})
        env = {'HTTP_OIDC_TOKEN': 'tok123'}
        start_response = MagicMock()
        with patch('software.authapi.auth_token.oidc_utils') as mock_oidc:
            mock_oidc.get_oidc_token_claims.return_value = {'sub': 'u'}
            mock_oidc.parse_oidc_token_claims.return_value = {
                'roles': ['admin'], 'username': 'user1'
            }
            mw(env, start_response)
        app.assert_called_once()
        self.assertEqual(env['HTTP_X_USER_NAME'], 'user1')

    def test_call_auth_failure(self):
        app = MagicMock()
        mw = OIDCTokenMiddleware(app, {})
        env = {'HTTP_OIDC_TOKEN': 'bad'}
        with patch('software.authapi.auth_token.oidc_utils') as mock_oidc:
            mock_oidc.get_oidc_token_claims.side_effect = Exception(
                "bad token")
            result = mw(env, MagicMock())
        self.assertIsNotNone(result)


class TestRequestContext(unittest.TestCase):
    def test_with_catalog(self):
        catalog = [{'type': 'faultmanagement'}, {'type': 'compute'}]
        ctx = RequestContext(service_catalog=catalog, roles=['admin'])
        self.assertEqual(len(ctx.service_catalog), 1)

    def test_to_dict(self):
        ctx = RequestContext(roles=['admin'])
        d = ctx.to_dict()
        self.assertIn('is_public_api', d)

    def test_make_context(self):
        ctx = make_context(roles=['reader'])
        self.assertFalse(ctx.is_public_api)
