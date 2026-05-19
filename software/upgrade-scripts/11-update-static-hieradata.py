#!/usr/bin/env python
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import logging
import os
import shutil
import subprocess
import sys
import tempfile
import yaml

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

SYSTEM_STATIC_FILE = "static.yaml"
SECURE_STATIC_FILE = "secure_static.yaml"
HIERADATA_PATH = "/opt/platform/puppet/%s/hieradata"


def get_list_of_keys(from_release, to_release):
    return {"static": [], "secure_static": []}


def do_update(from_release, to_release):
    with tempfile.TemporaryDirectory() as tempdir:
        _do_update_under_temp(from_release, to_release, tempdir)


def _do_update_under_temp(from_release, to_release, tempdir):
    system_static_file = os.path.join(HIERADATA_PATH % to_release, SYSTEM_STATIC_FILE)
    secure_static_file = os.path.join(HIERADATA_PATH % to_release, SECURE_STATIC_FILE)
    tmp_system_static_file = os.path.join(tempdir, SYSTEM_STATIC_FILE)
    tmp_secure_static_file = os.path.join(tempdir, SECURE_STATIC_FILE)
    files_to_copy = {system_static_file: tmp_system_static_file,
                     secure_static_file: tmp_secure_static_file}

    for src, dest in files_to_copy.items():
        try:
            shutil.copyfile(src, dest)
        except IOError as e:
            LOG.error("Failed copying file %s to %s. Error %s", src, dest, e)
            raise

    cmd = ["sysinv-puppet", "create-static-config"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, universal_newlines=True)
    out, err = process.communicate()
    if process.returncode != 0:
        msg = "Failed to generate static config. Command output: \n%s" % err
        LOG.error(msg)
        raise Exception(msg)

    src_file_mapping = {"static": system_static_file,
                        "secure_static": secure_static_file}
    tmp_file_mapping = {"static": tmp_system_static_file,
                        "secure_static": tmp_secure_static_file}
    list_of_keys = get_list_of_keys(from_release, to_release)

    for tag in list_of_keys:
        keys = list_of_keys[tag]
        if len(keys) > 0:
            tmp_file = tmp_file_mapping[tag]
            src_file = src_file_mapping[tag]

            with open(src_file, "r") as src:
                src_data = yaml.load(src, Loader=yaml.Loader)

            with open(tmp_file, "r") as dest:
                dest_data = yaml.load(dest, Loader=yaml.Loader)

            for key in keys:
                if key in src_data:
                    dest_data[key] = src_data[key]
                else:
                    LOG.warn("Expect %s generated in %s, but is not found" %
                             (key, src_file))

                with open(tmp_file, "w") as dest:
                    yaml.dump(dest_data, dest, default_flow_style=False)

    dest_system_static_file = os.path.join(HIERADATA_PATH % to_release, SYSTEM_STATIC_FILE)
    dest_secure_static_file = os.path.join(HIERADATA_PATH % to_release, SECURE_STATIC_FILE)
    dest_file_mapping = {"static": dest_system_static_file,
                         "secure_static": dest_secure_static_file}
    for tag in ["static", "secure_static"]:
        try:
            shutil.copyfile(tmp_file_mapping[tag], dest_file_mapping[tag])
        except Exception as e:
            msg = "Failed to copy file %s to %s. Error %s" % (
                  tmp_file_mapping[tag], dest_file_mapping[tag], e)
            LOG.error(msg)
            raise Exception(msg)


class UpdateStaticHieradata(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action='migrate',
            required_state=None,
            plugin_name='update-static-hieradata',
            completed_state='update-static-hieradata-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        do_update(from_release, to_release)


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = UpdateStaticHieradata()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
