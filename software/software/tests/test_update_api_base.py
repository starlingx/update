#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.api.controllers.v1.base and link modules."""

import unittest

import wsme
from wsme import types as wtypes

from software.api.controllers.v1.base import APIBase
from software.api.controllers.v1.link import Link
from software.tests import base as test_base  # noqa: F401


class SampleAPI(APIBase):
    """A minimal APIBase subclass for testing."""

    name = wtypes.text
    value = wtypes.text

    @property
    def fields(self):
        return [a.key for a in getattr(self, '_wsme_attributes', [])]


class FakeRPCObject(object):
    """A fake RPC object with as_dict support."""

    def __init__(self, data):
        self._dict = data

    def as_dict(self):
        return dict(self._dict)


class TestAPIBaseAsDict(unittest.TestCase):
    """Tests for APIBase.as_dict method."""

    def test_as_dict_returns_set_fields(self):
        """Test as_dict returns only fields that are set."""
        obj = SampleAPI(name="test")
        result = obj.as_dict()
        self.assertEqual(result["name"], "test")
        self.assertNotIn("value", result)

    def test_as_dict_all_fields_set(self):
        """Test as_dict with all fields set."""
        obj = SampleAPI(name="n", value="v")
        result = obj.as_dict()
        self.assertEqual(result["name"], "n")
        self.assertEqual(result["value"], "v")

    def test_as_dict_no_fields_set(self):
        """Test as_dict with no fields set returns empty dict."""
        obj = SampleAPI()
        result = obj.as_dict()
        self.assertEqual(result, {})


class TestAPIBaseUnsetFieldsExcept(unittest.TestCase):
    """Tests for APIBase.unset_fields_except method."""

    def test_unset_fields_except_keeps_listed(self):
        """Test that fields in except_list are kept."""
        obj = SampleAPI(name="keep", value="drop")
        obj.unset_fields_except(["name"])
        result = obj.as_dict()
        self.assertIn("name", result)
        self.assertNotIn("value", result)

    def test_unset_fields_except_none_unsets_all(self):
        """Test that None except_list unsets all fields."""
        obj = SampleAPI(name="n", value="v")
        obj.unset_fields_except()
        result = obj.as_dict()
        self.assertEqual(result, {})

    def test_unset_fields_except_empty_list(self):
        """Test that empty except_list unsets all fields."""
        obj = SampleAPI(name="n", value="v")
        obj.unset_fields_except([])
        result = obj.as_dict()
        self.assertEqual(result, {})


class TestAPIBaseFromRPCObject(unittest.TestCase):
    """Tests for APIBase.from_rpc_object classmethod."""

    def test_from_rpc_object_all_fields(self):
        """Test from_rpc_object with no field filter."""
        rpc = FakeRPCObject({"name": "rpc_name", "value": "rpc_val"})
        obj = SampleAPI.from_rpc_object(rpc)
        self.assertEqual(obj.name, "rpc_name")
        self.assertEqual(obj.value, "rpc_val")

    def test_from_rpc_object_with_fields_filter(self):
        """Test from_rpc_object filters to specified fields."""
        rpc = FakeRPCObject({"name": "rpc_name", "value": "rpc_val"})
        obj = SampleAPI.from_rpc_object(rpc, fields=["name"])
        self.assertEqual(obj.name, "rpc_name")
        self.assertEqual(obj.value, wsme.Unset)

    def test_from_rpc_object_fields_none(self):
        """Test from_rpc_object with fields=None keeps all."""
        rpc = FakeRPCObject({"name": "a", "value": "b"})
        obj = SampleAPI.from_rpc_object(rpc, fields=None)
        self.assertEqual(obj.name, "a")
        self.assertEqual(obj.value, "b")


class TestLinkMakeLink(unittest.TestCase):
    """Tests for Link.make_link classmethod."""

    def test_make_link_no_bookmark(self):
        """Test make_link with bookmark=False includes v1."""
        link = Link.make_link("self", "http://host", "res", "123")
        self.assertEqual(link.href, "http://host/v1/res/123")
        self.assertEqual(link.rel, "self")

    def test_make_link_bookmark(self):
        """Test make_link with bookmark=True omits v1."""
        link = Link.make_link("bookmark", "http://host", "res", "123",
                              bookmark=True)
        self.assertEqual(link.href, "http://host/res/123")
        self.assertEqual(link.rel, "bookmark")

    def test_make_link_query_string(self):
        """Test make_link with query string resource_args."""
        link = Link.make_link("self", "http://host", "res", "?key=val")
        self.assertEqual(link.href, "http://host/v1/res?key=val")

    def test_make_link_type_default(self):
        """Test make_link default type is Unset."""
        link = Link.make_link("self", "http://host", "res", "1")
        self.assertEqual(link.type, wsme.Unset)
