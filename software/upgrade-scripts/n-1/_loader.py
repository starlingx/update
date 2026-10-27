# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Shared helper that dynamically loads plugin_runner.py from the same
# directory.  All upgrade scripts using plugin should use:
#
#     from _loader import CPlugin
#

import importlib.util
import os

_plugin_runner_path = os.path.join(os.path.dirname(__file__), "plugin_runner.py")

_spec = importlib.util.spec_from_file_location("plugin_runner", _plugin_runner_path)
_module = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_module)

CPlugin = _module.CPlugin
ScriptPlugin = _module.ScriptPlugin
APlugin = _module.APlugin
