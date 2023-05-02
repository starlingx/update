#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#
import sys
from unittest import mock

import testtools

# disable importing these modules
sys.modules['daemon'] = mock.Mock()
sys.modules['daemon.runner'] = mock.Mock()
sys.modules['fm_core'] = mock.Mock()

# this import needs to be done after fm_core is turned off
from patch_alarm import patch_alarm_manager  # noqa: E402  pylint: disable=wrong-import-position


class PatchAlarmTestCase(testtools.TestCase):

    def test_patch_alarm_instantiate(self):
        patch_alarm_manager.PatchAlarmDaemon()
