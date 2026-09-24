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
from unittest.mock import patch, MagicMock  # noqa: H301,E402
from io import StringIO  # noqa: E402

from software_client.v1 import deploy_shell  # noqa: E402
from software_client.common import utils  # noqa: E402


# ===== deploy_shell tests =====

class TestDoShow(unittest.TestCase):
    def test_no_deploy(self):
        cc = MagicMock()
        cc.deploy.show.return_value = (MagicMock(status_code=200), [])
        args = MagicMock(debug=False)
        with patch('builtins.print'):
            rc = deploy_shell.do_show(cc, args)
        self.assertEqual(rc, 0)

    def test_with_data(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        data = [{"from_release": "24.09", "to_release": "25.03",
                 "reboot_required": "Y", "pre_upgrade_deploy": False,
                 "state": "start-done"}]
        cc.deploy.show.return_value = (resp, data)
        args = MagicMock(debug=False)
        rc = deploy_shell.do_show(cc, args)
        self.assertEqual(rc, 0)

    def test_error(self):
        cc = MagicMock()
        resp = MagicMock(status_code=500, text='{"error": "fail"}')
        cc.deploy.show.return_value = (resp, {"error": "fail"})
        args = MagicMock(debug=False)
        rc = deploy_shell.do_show(cc, args)
        self.assertNotEqual(rc, 0)

    @patch('software_client.common.utils.display_result_list')
    def test_metapackages_sorted_by_release_then_name(self, mock_display):
        # metapackage entries are (metapackage, from_release, to_release);
        # a span deploy yields an unordered mix that must be sorted by
        # to-release then name for display
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        metapackages = [
            ("infra", "26.10.0", "27.03.1"),
            ("k8s-1.32.13-controlplane", "26.10.0", "27.03.0"),
            ("base", "26.10.0", "27.03.0"),
            ("k8s-1.32.2-controlplane", "26.10.0", "27.03.0"),
        ]
        data = [{"metapackages": metapackages, "product_deploy": False,
                 "reboot_required": "Y", "pre_upgrade_deploy": False,
                 "state": "start-done"}]
        cc.deploy.show.return_value = (resp, data)
        args = MagicMock(debug=False)
        rc = deploy_shell.do_show(cc, args)
        self.assertEqual(rc, 0)
        # 27.03.0 group first (name-sorted within), then 27.03.1. Names are
        # compared lexicographically after unifying -_. separators, matching
        # the ordering of `software metapackage list`
        self.assertEqual([mp[0] for mp in data[0]["metapackages"]], [
            "base",
            "k8s-1.32.13-controlplane",
            "k8s-1.32.2-controlplane",
            "infra",
        ])


class TestDoStart(unittest.TestCase):
    def test_success(self):
        cc = MagicMock()
        resp = MagicMock(status_code=200)
        cc.deploy.start.return_value = (resp, {"info": "started"})
        args = MagicMock(debug=False, deployment="24.09",
                         remove=False, pre_upgrade_deploy=False)
        rc = deploy_shell.do_start(cc, args)
        self.assertEqual(rc, 0)

    def test_error(self):
        cc = MagicMock()
        resp = MagicMock(status_code=500, text='{"error": "fail"}')
        cc.deploy.start.return_value = (resp, {"error": "fail"})
        args = MagicMock(debug=False, deployment="24.09",
                         remove=False, pre_upgrade_deploy=False)
        rc = deploy_shell.do_start(cc, args)
        self.assertNotEqual(rc, 0)


# ===== common/utils tests =====

class TestDisplayResultList(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_displays_data(self, mock_stdout):
        header = {"Name": "name", "State": "state"}
        data = [{"name": "P1", "state": "deployed"}]
        utils.display_result_list(header, data)
        output = mock_stdout.getvalue()
        self.assertIn("P1", output)


class TestDisplayDetailResult(unittest.TestCase):
    @patch('sys.stdout', new_callable=StringIO)
    def test_displays(self, mock_stdout):
        data = {"release_id": "P1", "state": "deployed"}
        utils.display_detail_result(data)
        output = mock_stdout.getvalue()
        self.assertIn("P1", output)


class TestCheckRcExtended(unittest.TestCase):
    def test_200_no_error(self):
        req = MagicMock(status_code=200)
        self.assertEqual(utils.check_rc(req, {}), 0)

    def test_200_with_error(self):
        req = MagicMock(status_code=200)
        self.assertNotEqual(utils.check_rc(req, {"error": "something"}), 0)

    def test_500(self):
        req = MagicMock(status_code=500)
        self.assertNotEqual(utils.check_rc(req, {}), 0)
