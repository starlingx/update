#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from abc import ABC
from abc import abstractmethod
from concurrent.futures import as_completed
from concurrent.futures import ThreadPoolExecutor
from packaging import version
from software.constants import COMPONENT_SOFTWARE_STORAGE_DIR
from software.utilities import constants

import importlib.util
import json
import logging
import os
import subprocess
import sys
import threading

from typing import List
from typing import Optional
from typing import Tuple

LOG = logging.getLogger('main_logger')


# This file is currently categorized as independent from framework,
# which is runnable w/ N+1 code on a N runtime environment. The exception class
# is defined here instead of software.exceptions module as result.
# TODO(bqian) move the exception definition to software.exceptions if this code
# becomes part of framework.
class MigrationScriptFailed(Exception):
    def __init__(self, msg, inner_exception):
        super().__init__(msg)
        self._inner_exception = inner_exception

    @property
    def inner_exception(self):
        return self._inner_exception


class APlugin(ABC):
    def __init__(self, matching_action, required_state, plugin_name, completed_state):
        self._required_state = required_state
        self._matching_action = matching_action if isinstance(matching_action, list) else [matching_action]
        self._plugin_name = plugin_name
        self._completed_state = completed_state

    @property
    def name(self):
        return self._plugin_name

    def should_run(self, action):
        return action in self._matching_action

    def required_state(self):
        return self._required_state

    @abstractmethod
    def _run(self, from_release, to_release, action, port):
        pass

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name

    def run(self, from_release, to_release, action, port=None):
        try:
            self._run(from_release, to_release, action, port)
            return self._completed_state
        except Exception:
            LOG.exception(f"{self.name} failed")
            return f"{self.name}-failed"
        except (KeyboardInterrupt, SystemExit, GeneratorExit):
            LOG.exception(f"{self.name} was interrupted")
            raise


class ScriptPlugin(APlugin):
    def __init__(self, matching_action, required_state, script, completed_state, extra_args=None):
        self._script = script
        self._extra_args = extra_args or []
        plugin_name = os.path.basename(script)
        super().__init__(matching_action, required_state, plugin_name, completed_state)

    def __str__(self):
        return self._script

    def _run(self, from_release, to_release, action, port):
        def _run_script(script, from_release, to_release, action, port):
            MSG_SCRIPT_FAILURE = "Deployment script %s failed with return code %d" \
                                 "\nScript output:\n%s"
            try:
                cmdline = [script] + [p for p in (from_release, to_release, action) if p]
                if port is not None:
                    cmdline.append(str(port))
                cmdline.extend(self._extra_args)

                # Let subprocess.run handle non-zero exit codes via check=True
                subprocess.run(cmdline,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT,
                               text=True,
                               check=True)

            except subprocess.CalledProcessError as e:
                # Deduplicate output lines using set and create error message
                unique_output = "\n".join(e.output.splitlines()) + "\n"
                error = MSG_SCRIPT_FAILURE % (script, e.returncode, unique_output)
                raise MigrationScriptFailed(error, e)
            except Exception as ee:
                # Log exception but continue processing
                error = f"Unexpected error executing {script}: {str(ee)}"
                raise MigrationScriptFailed(error, ee)

        LOG.info(f"Executing deployment script {self._script}")
        _run_script(self._script, from_release, to_release, action, port)
        LOG.info(f'Deployment script {self._script} completed successfully')


class CPlugin(APlugin):
    def _run(self, from_release, to_release, action, port):
        """Subclass must override this function"""
        raise NotImplementedError


class PluginRunner:
    def __init__(self, tasks, max_parallel=1):
        self._tasks = tasks
        self._max_parallel = max_parallel
        self._states = set()
        self._lock = threading.Lock()
        self._ignore_errors = os.environ.get("IGNORE_ERRORS", 'False').upper() == 'TRUE'

    def run(self, from_release, to_release, action, port=None):
        pending = [t for t in self._tasks if t.should_run(action)]

        while pending:
            ready = []
            still_pending = []
            for t in pending:
                with self._lock:
                    if t.required_state() is None or t.required_state() in self._states:
                        LOG.info(f"{t.name} is ready")
                        ready.append(t)
                    else:
                        LOG.info(f"{t.name} is pending")
                        still_pending.append(t)

            if not ready:
                if still_pending:
                    LOG.error(f"Plugins {[s.name for s in still_pending]} were not scheduled as required state was not met")
                else:
                    LOG.info("All plugins have completed.")
                break  # no progress possible, avoid infinite loop

            with ThreadPoolExecutor(max_workers=self._max_parallel) as executor:
                futures = {executor.submit(t.run, from_release, to_release, action, port): t for t in ready}
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        with self._lock:
                            self._states.add(result)
                            LOG.info(f"result: {result}")

                        if result.endswith("-failed"):
                            if self._ignore_errors:
                                LOG.info("Update plugins continue as 'IGNORE_ERRORS' set")
                            else:
                                # when running plugins in parallel is supported, the runner will wait for the plugins
                                # that have already scheduled to complete.
                                # the plugins that have not been scheduled should not start
                                for f in futures:
                                    if f.cancel():
                                        still_pending.append(futures[f])
                                LOG.error(f"Update plugins {[str(p) for p in still_pending]} are skipped as previous plugin failure")
                                still_pending = []

            pending = still_pending
        return self._states


def get_migration_scripts(plugin_dir, from_release, action):
    def get_plugins_mgr(plugin_dir):
        module_init = os.path.join(plugin_dir, "__init__.py")
        if os.path.isfile(module_init):
            spec = importlib.util.spec_from_file_location(
                "plugin_scripts",
                module_init,
                submodule_search_locations=[plugin_dir]
            )
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        else:
            return None

    if not os.path.isdir(plugin_dir):
        msg = "Folder %s does not exist" % plugin_dir
        LOG.exception(msg)
        raise Exception(msg)

    try:
        plugins_mgr = get_plugins_mgr(plugin_dir)
    except Exception as e:
        msg = f"Error getting plugins: {str(e)}"
        LOG.exception(msg)
        raise

    if plugins_mgr:
        return plugins_mgr.get_plugins(from_release, action)
    return []


def execute_migration_scripts(from_release, to_release, action, port=None,
                              migration_script_dir="/usr/local/share/upgrade.d"):
    LOG.info("Executing deployment scripts from: %s with from_release: %s, to_release: %s, "
             "action: %s" % (migration_script_dir, from_release, to_release, action))
    plugins = get_migration_scripts(migration_script_dir, from_release, action)
    runner = PluginRunner(plugins)
    states = runner.run(from_release, to_release, action, port)
    failed = [s for s in states if s.endswith('-failed')]
    if failed:
        raise Exception(f"Deployment plugins failed: {failed}")


def execute_agent_hooks(major_release, metapackages: Optional[List[Tuple]] = None,
                        additional_data=None):
    """Run agent hooks for a major release deployment.
    :param major_release: target major release version
    :param metapackages: list of tuples containing metapackage name and release,
                         e.g. (swmgmt, 26.10.0)
    :param additional_data: dict of additional data passed to the hook script
    """
    LOG.info("Running agent hooks...")

    extra_args = ["--software-version", major_release]
    if additional_data:
        extra_args.extend(["--additional-data", json.dumps(additional_data)])

    if metapackages:
        LOG.info("Executing componentized method")
        for mp_name, mp_version in metapackages:
            LOG.info("Running agent hooks for metapackage %s (%s)",
                     mp_name, mp_version)
            script_dir = os.path.join(
                COMPONENT_SOFTWARE_STORAGE_DIR,
                mp_version,
                mp_name,
                constants.HOST_SCRIPTS_DIR)

            if not os.path.isdir(script_dir):
                LOG.warning("Could not find host-scripts directory in "
                            f"metapackage {mp_name} for release "
                            f"{mp_version}. Script directory: {script_dir}")
                continue

            run_scripts(
                [script_dir],
                filter_names=constants.AGENT_HOOKS_SCRIPT,
                extra_args=extra_args)
    else:
        if version.Version(major_release) > version.Version(constants.SW_VERSION):
            ostree_path = "/ostree/1"
        else:
            ostree_path = "/ostree/2"

        LOG.info("No metapackages available, executing legacy method")
        script_dir = os.path.normpath(ostree_path + "/usr/lib/python3/dist-packages/software/")
        if not os.path.isdir(script_dir):
            raise Exception(f"Could not find software path. Script directory: {script_dir}")
        run_scripts([script_dir], filter_names=constants.AGENT_HOOKS_SCRIPT, extra_args=extra_args)

    LOG.info("Agent hooks executed successfully")


def execute_host_scripts(metapackages: List[Tuple], filter_names=None, extra_args=None):
    """Run host scripts for metapackages in a deployment.
    :param metapackages: list of tuples containing metapackage info in the format
                         of (metapackage.path_component, metapackage.sw_release), used
                         to build the path to the host-scripts.
    :param filter_names: list of script names to filter execution (optional)
    :param extra_args: extra arguments to pass to the scripts
    """
    if not metapackages:
        raise Exception("No metapackages found to run host-scripts.")

    host_scripts = []
    for mp_component, mp_release in metapackages:
        # The host-scripts are located at:
        # /opt/software/releases/<metapackage_release>/<path_component>/host-scripts/
        mp_dir = os.path.join(
            COMPONENT_SOFTWARE_STORAGE_DIR, mp_release,
            mp_component, constants.HOST_SCRIPTS_DIR)
        if not os.path.isdir(mp_dir):
            LOG.info("Metapackage %s does not have host-scripts directory in release %s. "
                     "Skipping...", mp_component, mp_release)
        else:
            host_scripts.append(mp_dir)

    if host_scripts:
        run_scripts(host_scripts, filter_names=filter_names, extra_args=extra_args)
    LOG.info("Host scripts executed successfully.")


def discover_scripts(script_dirs, action="", filter_names=None, extra_args=None):
    """Discover shell/python scripts from one or more directories."""
    plugins = []
    for d in script_dirs:
        for f in sorted(os.listdir(d)):
            if filter_names and f not in filter_names:
                continue
            path = os.path.join(d, f)
            if not os.path.isfile(path) or not os.access(path, os.X_OK):
                continue
            plugins.append(ScriptPlugin(
                matching_action=action,
                required_state=None,
                script=path,
                completed_state=f"{os.path.basename(path)}-done",
                extra_args=extra_args,
            ))
    return plugins


def run_scripts(script_dirs, action="", from_release="", to_release="",
                filter_names=None, extra_args=None):
    plugins = discover_scripts(script_dirs, action, filter_names=filter_names, extra_args=extra_args)
    runner = PluginRunner(plugins, max_parallel=1)
    states = runner.run(from_release=from_release, to_release=to_release, action=action)
    failed = [s for s in states if s.endswith("-failed")]
    if failed:
        raise Exception(f"Scripts failed: {failed}")
