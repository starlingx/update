#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
from oslo_config import cfg
from pecan import set_config
from pecan.testing import load_test_app
from unittest import TestCase


class SWPatchAPITest(TestCase):
    """API Tests for sw-patch"""

    def setUp(self):
        # trigger oslo_config to load a config file
        # so that it can co-locate a policy file
        config_file = os.path.join(os.path.dirname(__file__),
                                   'patching.conf')
        cfg.CONF((),
                 default_config_files=[config_file, ])
        # config.py sets acl to False
        self.app = load_test_app(os.path.join(
            os.path.dirname(__file__),
            'config.py'
        ))

    def tearDown(self):
        set_config({}, overwrite=True)


class TestRootController(SWPatchAPITest):

    def test_get(self):
        response = self.app.get('/')
        assert response.status_int == 200

    def test_get_not_found(self):
        response = self.app.get('/a/bogus/url', expect_errors=True)
        assert response.status_int == 404
