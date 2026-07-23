#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import unittest
from unittest import mock

from software.tests import base as test_base  # noqa: F401
from software.agent_hooks import BaseHook

# agent_hooks.py calls LOG.basicConfig at module
# level with /var/log/software.log
# which is not writable in test env, so we mock it before import
mock.patch('logging.basicConfig').start()


class TestBaseHookInit(unittest.TestCase):

    def test_init_full_attrs(self):
        attrs = {
            "major_release": "10.0",
            "from_release": "9.0",
            "to_release": "10.0",
            "hook_action": "upgrade",
            "additional_data": {
                "to_commit_id": "abc123",
                "from_commit_id": "def456",
            },
        }
        hook = BaseHook(attrs)
        self.assertEqual(hook._major_release, "10.0")
        self.assertEqual(hook._from_release, "9.0")
        self.assertEqual(hook._to_release, "10.0")
        self.assertEqual(hook._action, "upgrade")
        self.assertEqual(hook._additional_data, attrs["additional_data"])
        self.assertEqual(hook._to_commit_id, "abc123")
        self.assertEqual(hook._from_commit_id, "def456")

    def test_init_empty_attrs(self):
        hook = BaseHook({})
        self.assertIsNone(hook._major_release)
        self.assertIsNone(hook._from_release)
        self.assertIsNone(hook._to_release)
        self.assertIsNone(hook._action)
        self.assertEqual(hook._additional_data, {})
        self.assertIsNone(hook._to_commit_id)
        self.assertIsNone(hook._from_commit_id)

    def test_init_partial_attrs(self):
        attrs = {
            "major_release": "10.0",
            "hook_action": "rollback",
        }
        hook = BaseHook(attrs)
        self.assertEqual(hook._major_release, "10.0")
        self.assertIsNone(hook._from_release)
        self.assertIsNone(hook._to_release)
        self.assertEqual(hook._action, "rollback")
        self.assertEqual(hook._additional_data, {})
        self.assertIsNone(hook._to_commit_id)
        self.assertIsNone(hook._from_commit_id)

    def test_init_additional_data_none(self):
        attrs = {
            "major_release": "10.0",
            "additional_data": None,
        }
        hook = BaseHook(attrs)
        self.assertEqual(hook._additional_data, {})
        self.assertIsNone(hook._to_commit_id)
        self.assertIsNone(hook._from_commit_id)

    def test_init_additional_data_partial(self):
        attrs = {
            "additional_data": {
                "to_commit_id": "abc123",
            },
        }
        hook = BaseHook(attrs)
        self.assertEqual(hook._to_commit_id, "abc123")
        self.assertIsNone(hook._from_commit_id)

    def test_run_returns_none(self):
        hook = BaseHook({})
        self.assertIsNone(hook.run())
