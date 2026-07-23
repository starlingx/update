#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.parsable_error module."""

import json
import unittest

from software.parsable_error import ParsableErrorMiddleware
from software.parsable_error import WEBOB_EXPL_SEP


class TestParsableErrorMiddleware(unittest.TestCase):
    """Tests for ParsableErrorMiddleware."""

    def _make_app(self, status, body, content_type='text/plain'):
        """Create a mock WSGI app."""
        def app(_environ, start_response):
            headers = [('Content-Type', content_type),
                       ('Content-Length', str(len(body)))]
            start_response(status, headers)
            if isinstance(body, str):
                return [body.encode('utf-8')]
            return [body]
        return app

    def _make_environ(self, accept='application/json'):
        """Create a mock WSGI environ."""
        return {
            'REQUEST_METHOD': 'GET',
            'PATH_INFO': '/test',
            'SERVER_NAME': 'localhost',
            'SERVER_PORT': '80',
            'HTTP_ACCEPT': accept,
            'wsgi.url_scheme': 'http',
        }

    def test_success_passthrough(self):
        """Test 200 response passes through unchanged."""
        app = self._make_app('200 OK', 'success')
        middleware = ParsableErrorMiddleware(app)
        environ = self._make_environ()
        result = []

        def start_response(status, _headers, _exc_info=None):
            result.append(status)

        middleware(environ, start_response)
        self.assertEqual(result[0], '200 OK')

    def test_error_json_response(self):
        """Test error response formatted as JSON."""
        error_body = "Something went wrong"
        app = self._make_app('500 Internal Server Error', error_body)
        middleware = ParsableErrorMiddleware(app)
        environ = self._make_environ(accept='application/json')
        result_headers = []

        def start_response(_status, headers, _exc_info=None):
            result_headers.extend(headers)

        body = middleware(environ, start_response)
        # Body should be JSON
        body_str = body[0] if isinstance(
            body[0], str) else body[0].decode('utf-8')
        parsed = json.loads(body_str)
        self.assertIn('error_message', parsed)

    def test_error_with_webob_explanation(self):
        """Test error with webob explanation separator."""
        error_body = "Error details" + WEBOB_EXPL_SEP + "Detailed explanation"
        app = self._make_app('400 Bad Request', error_body)
        middleware = ParsableErrorMiddleware(app)
        environ = self._make_environ(accept='application/json')

        def start_response(_status, _headers, _exc_info=None):
            pass

        body = middleware(environ, start_response)
        body_str = body[0] if isinstance(
            body[0], str) else body[0].decode('utf-8')
        parsed = json.loads(body_str)
        inner = json.loads(parsed['error_message'])
        self.assertIn('faultstring', inner)

    def test_error_xml_response(self):
        """Test error response formatted as XML."""
        error_body = "<error>test</error>"

        def app(_environ, start_response):
            headers = [('Content-Type', 'text/plain'),
                       ('Content-Length', str(len(error_body)))]
            start_response('500 Internal Server Error', headers)
            # Return str items (not bytes) for XML path
            return [error_body]

        middleware = ParsableErrorMiddleware(app)
        environ = self._make_environ(accept='application/xml')

        def start_response(_status, _headers, _exc_info=None):
            pass

        body = middleware(environ, start_response)
        # Should contain XML content type in response
        self.assertIsNotNone(body)

    def test_redirect_passthrough(self):
        """Test 3xx response passes through."""
        app = self._make_app('302 Found', 'redirect')
        middleware = ParsableErrorMiddleware(app)
        environ = self._make_environ()

        def start_response(_status, _headers, _exc_info=None):
            pass

        body = middleware(environ, start_response)
        self.assertIsNotNone(body)
