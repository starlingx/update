#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# pylint: disable=unused-argument,protected-access
# pylint: disable=wrong-import-position,ungrouped-imports,reimported
import sys
import unittest.mock
for _m in ["jwkest", "jwkest.jwk", "jwkest.jws",
           "oic", "oic.exception", "oic.oic", "oic.oic.message",
           "oic.utils", "oic.utils.keyio", "oic.utils.jwt"]:
    sys.modules.setdefault(_m, unittest.mock.MagicMock())

import unittest  # noqa: E402
from unittest.mock import patch  # noqa: E402
from unittest.mock import MagicMock  # noqa: E402

from software_client.common import base  # noqa: E402
from software_client.common import http  # noqa: E402


class TestResourceGetattr(unittest.TestCase):
    def test_getattr_lazy_load(self):
        mgr = MagicMock()
        info = {"id": "1", "name": "test"}
        res = base.Resource(mgr, info)
        res._loaded = False
        mgr.get.return_value = base.Resource(mgr, {"id": "1", "extra": "val"})
        val = res.name
        self.assertEqual(val, "test")

    def test_getattr_not_found(self):
        mgr = MagicMock()
        res = base.Resource(mgr, {"id": "1"})
        res._loaded = True
        with self.assertRaises(AttributeError):  # noqa: H202
            _ = res.nonexistent

    def test_resource_get_no_manager_get(self):
        mgr = MagicMock(spec=[])
        res = base.Resource(mgr, {"id": "1"})
        res.get()

    def test_resource_eq_different_class(self):
        mgr = MagicMock()
        res = base.Resource(mgr, {"id": "1"})
        self.assertNotEqual(res, "string")

    def test_resource_eq_same(self):
        mgr = MagicMock()
        res1 = base.Resource(mgr, {"id": "1"})
        res2 = base.Resource(mgr, {"id": "1"})
        self.assertEqual(res1, res2)


class TestHttpErrorJson(unittest.TestCase):
    def test_error_with_info(self):
        body = {"error_message": '{"error": "fail", "info": "detail"}'}
        result = http._extract_error_json_text(body)
        self.assertEqual(result["faultstring"], "fail")


class TestHttpConstructClient(unittest.TestCase):
    @patch(
        'software_client.common.http.SessionClient.__init__',
        return_value=None)
    def test_construct(self, mock_init):
        c = http.construct_http_client("http://localhost:5493")
        self.assertIsNotNone(c)


class TestHttp2ConstructClient(unittest.TestCase):
    @patch(
        'software_client.common.http2.HTTPClient.__init__',
        return_value=None)
    def test_construct(self, mock_init):
        from software_client.common import http2
        c = http2.construct_http_client("http://localhost:5493")
        self.assertIsNotNone(c)
