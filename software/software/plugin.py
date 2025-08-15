"""
Copyright (c) 2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
from packaging.version import Version
import re
import os
import tempfile
import subprocess

from software import constants
from software import utils
from software.utilities.utils import SOFTWARE_LOG_FILE


LOG = logging.getLogger('main_logger')
USM_PLUGIN_PATH = "/usr/local/share/upgrade.d"


# run deploy plugin such as deploy delete, with pre-acquired
# auth token, deploy context
# the plugin runner will automatically determine the higher sw-version from
# the deploy entity, and run the higher sw-version (to-release on deploy)
# plugin, unless plugin_path is specified.
# in the case that the higher sw-version plugin is not on the file system,
# the runner will pull the feed repo and run it.
# TODO(bqian) at this point the patching behaviour of delete action is not
# defined. When determined, the ostree pull command should include proper
# commit-id in order to pull the right release.
class DeployPluginRunner(object):
    def __init__(self, deploy, plugin_path=None):
        self._deploy = deploy
        self._temp_plugin_path = None
        self._bin_path = plugin_path
        if plugin_path is None:
            sw_version = DeployPluginRunner.get_higher_version(deploy)
            self._source_repo = f"/var/www/pages/feed/rel-{sw_version}/ostree_repo"
            if constants.SW_VERSION != sw_version:
                # create temp directory to pull and run usm-plugin from N+1 release
                self._temp_plugin_path = os.path.join(tempfile.mkdtemp(prefix="usm-plugin", dir="/tmp"))
                self._bin_path = os.path.join(self._temp_plugin_path, "upgrade.d")
            else:
                self._bin_path = USM_PLUGIN_PATH

        self._env = None

    @staticmethod
    def get_higher_version(deploy):
        from_release = deploy.get("from_release")
        to_release = deploy.get("to_release")
        higher_release = from_release
        if Version(to_release) > Version(from_release):
            higher_release = to_release

        return utils.get_major_release_version(higher_release)

    @property
    def plugin_path(self):
        return self._bin_path

    def set_auth_token(self):
        token, endpoint = utils.get_endpoints_token()
        self._env["ANSIBLE_LOG_PATH"] = SOFTWARE_LOG_FILE
        self._env["OS_AUTH_TOKEN"] = token
        self._env["SYSTEM_URL"] = re.sub('/v[1,9]$', '', endpoint)  # remove ending /v1

    def set_deploy_options(self):
        options = self._deploy.get("options", None)
        if not options:
            options = {}
        for k, v in options.items():
            self._env[k] = v

    def set_execution_context(self, context):
        self._env["from_release"] = self._deploy.get("from_release")
        self._env["to_release"] = self._deploy.get("to_release")
        self._env["plugin_path"] = self.plugin_path

        for k, v in context:
            if k in self._env:
                LOG.warning(f"context {k} overwrites deploy option value: {self._env[k]}")
            self._env[k] = v

    def execute(self, cmd, context=None):
        if not context:
            context = {}

        if self._temp_plugin_path:
            checkout_cmd = f"ostree --repo={self._source_repo} checkout " + \
                           f"--subpath=/usr/local/share/upgrade.d {constants.OSTREE_REF} " + \
                           f"{self._bin_path}"
            try:
                subprocess.run(checkout_cmd, check=True, shell=True, stderr=subprocess.STDOUT)
                LOG.info(f"Checkout deploy plugins to {self._bin_path} completed successfully")
            except subprocess.CalledProcessError as e:
                LOG.error(f"Failed to checkout deploy plugins {checkout_cmd}. Error output:")
                LOG.error(f"{e.output}")
                raise
            except subprocess.SubprocessError:
                LOG.error(f"Checkout deploy plugins has timeout.  {checkout_cmd}")
                raise

        self._env = os.environ.copy()
        # option comes from API, is the least priority, can be overwritten
        # by any system internal context
        self.set_deploy_options()

        self.set_auth_token()
        self.set_execution_context(context)

        plugin_cmd = ' '.join(["source", "/etc/platform/openrc;", cmd])

        try:
            LOG.info("starting subprocess %s" % plugin_cmd)
            subprocess.Popen(plugin_cmd, start_new_session=True, shell=True, env=self._env)
            LOG.info("subprocess started")
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to start command: %s. Error %s" % (plugin_cmd, e))
            raise
