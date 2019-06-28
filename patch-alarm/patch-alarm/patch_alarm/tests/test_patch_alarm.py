#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019 Wind River Systems, Inc.
#

import mock
import sys
import testtools

sys.modules['daemon'] = mock.Mock()
sys.modules['daemon.runner'] = mock.Mock()
sys.modules['fm_core'] = mock.Mock()

import patch_alarm.patch_alarm_manager  # noqa: E402


class PatchAlarmTestCase(testtools.TestCase):

    def test_patch_alarm_instantiate(self):
        patch_alarm.patch_alarm_manager.PatchAlarmDaemon()
