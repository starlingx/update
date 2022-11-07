#!/bin/python3
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Debian Build Test Patches:

PATCH A) Reboot required - all nodes
    Update package - logmgmt
    rebuild the pkg
    build-image to generate a new commit in the build ostree_repo
    build a patch

PATCH B) In Service patch
    Update the metadata
    Uses the example-restart script
    Uses the same ostree commit as PATCH A so they can't be applied together
    build a patch

PATCH C) Patch with dependency (reboot required, depends on PATCH A)
    build PATCH A
    update package - logmgmt
    build-image to generate a new commit in the build ostree_repo
    build Patch C (requires A)

Requires:
    debchange (devscripts) - Tool for maintenance of the debian/changelog file in a source package
    https://manpages.debian.org/jessie/devscripts/debchange.1.en.html

Steps to run:
    # Setup debian build env
    # For more information about how to setup the environment:
        https://wiki.openstack.org/wiki/StarlingX/DebianBuildEnvironment

    export PROJECT="stx-debian-build"
    export STX_BUILD_HOME="/localdisk/designer/${USER}/${PROJECT}"
    # Initialize the build containers
    stx control start
    ./build_test_patches.py --help

"""
import argparse
import logging
import os
import shutil
import subprocess
import sys

from requests import patch

sys.path.insert(0, "../cgcs-patch")
from cgcs_make_patch.make_patch import PatchBuilder  # noqa: E402 pylint: disable=wrong-import-position
from cgcs_make_patch.make_patch import PatchRecipeData  # noqa: E402 pylint: disable=wrong-import-position

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('build_test_patches')


def run_cmd(cmd):
    '''
    Run a cmd and return
    param command: string representing the command to be executed
    '''
    log.debug("Running: %s", cmd)
    return subprocess.run(
        cmd,
        shell=True,
        executable='/bin/bash',
        check=True)


class TestPatchInitException(Exception):
    """TestPatch initialization error"""


class TestPatchCreationException(Exception):
    """Patch creation error"""


class TestPatchBuilder():
    """
    Build test patches
    """
    def __init__(self, sw_version):
        try:
            self.project = os.environ.get("PROJECT")
            self.build_home = os.environ.get("STX_BUILD_HOME")
            self.repo = os.path.join(self.build_home, "repo")
            self.repo_root = os.path.join(self.repo, "cgcs-root")
            self.patch_repo_base = os.path.join(self.repo_root, "stx/update")
            self.sw_version = sw_version
            self.restart_script = os.path.join(self.patch_repo_base, "patch-scripts/EXAMPLE_0001/scripts/example-restart")
        except TestPatchInitException:
            log.exception("TestPatchBuilder initialization failure")
            sys.exit(1)

    def __upversion_pkg(self, pkg_dir):
        """
        Updates changelog version in pkg_dir/debian/deb_folder
        """
        log.info("Upversioning package %s", pkg_dir)
        # cd pkg_dir/debian/deb_folder; dch -q "PATCH TEST" --changelog changelog
        pwd = os.getcwd()
        os.chdir(pkg_dir)
        # Increase the change log version
        cmd = "dch -q 'PATCH TEST' --changelog debian/deb_folder/changelog"
        ret = run_cmd(cmd)
        if ret.returncode != 0:
            raise Exception("Error while changing the package version")
        os.chdir(pwd)

    def __delete_dir(self, dir_path):
        """
        Deletes a directory - called when cleaning up the cloned ostree
        param dir_path: Path to the directory
        """
        if os.path.isdir(dir_path):
            log.info("removing %s", dir_path)
            shutil.rmtree(dir_path)

    def build_pkg(self, pkg_name):
        """
        Build package
        """
        os.chdir(os.path.join(self.repo, "stx-tools"))
        cmd = f'''
            source import-stx
            stx shell -c "build-pkgs -c -p {pkg_name}"
        '''
        ret = run_cmd(cmd)
        log.info("Build pkgs return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to build packages")

    def build_image(self):
        """
        Build image - generates new ostree commit
        """
        cmd = '''
            source import-stx
            stx shell -c "build-image --keep"
        '''
        ret = run_cmd(cmd)
        log.info("Build image return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to build image")

    def update_pkg(self, pname):
        """
        Make a change on the logmgmt package and upversions it
        param pname: patch name that is added to the script and can be used as patch validation
        """
        pkg_name = "logmgmt"
        log.info("Updating package %s", pkg_name)
        pkg_dir = os.path.join(self.repo_root, "stx/utilities/utilities", pkg_name)
        pkg_script = os.path.join(pkg_dir, "scripts/init.d/logmgmt")
        # Insert a message into /etc/init.d/$(basename $SCRIPT)
        cmd = "sed -i 's|start).*|start) logger -t \\$(basename \\$0) \"" + pname + " patch is applied\"|' " + pkg_script
        run_cmd(cmd)
        self.__upversion_pkg(pkg_dir)
        # build the pkg to apply the change
        self.build_pkg(pkg_name)

    def create_test_patches(self, pname, requires=False, inservice=False, formal=False):
        """
        Creates test patches:
        RR, INSVC and RR_Requires
        param pname: Patch ID and file name
        param requires: If set it will build the 2nd patch
        param inservice: If set it will build the insvc patch
        param formal: Signs the patch with formal key
        """
        ostree_clone_name = "ostree_repo_patch"
        patch_builder = PatchBuilder()
        # Generating ostree_repo clone
        patch_builder.prepare_env(ostree_clone_name)
        # Update pkg
        self.update_pkg(pname)
        log.info("Generating RR patch for all nodes")
        # build image to trigger a new ostree commit
        self.build_image()

        rr_patch_name = pname + "_RR_ALL_NODES"
        insvc_patch_name = pname + "_NRR_INSVC"
        rr_requires_patch_name = pname + "_RR_ALL_NODES_REQUIRES"

        patch_data = PatchRecipeData()
        patch_data.patch_id = rr_patch_name
        patch_data.sw_version = self.sw_version
        patch_data.metadata = {
            "SUMMARY": "RR ALL NODES",
            "DESCRIPTION": "Test patch",
            "INSTALL_INSTRUCTIONS": "Sample instructions",
            "WARNINGS": "Sample Warning",
            "STATUS": "DEV",
            "UNREMOVABLE": "N",
            "REBOOT_REQUIRED": "Y"
        }
        # Create a patch
        log.info("Creating RR patch %s", patch_data.patch_id)
        patch_builder.create_patch(patch_data, ostree_clone_name, formal)
        log.info("RR Patch build done")

        if inservice:
            patch_data = PatchRecipeData()
            patch_data.patch_id = insvc_patch_name
            patch_data.sw_version = self.sw_version
            patch_data.metadata = {
                "SUMMARY": "IN SVC PATCH",
                "DESCRIPTION": "Test In Service patch",
                "INSTALL_INSTRUCTIONS": "Sample instructions",
                "WARNINGS": "Sample Warning",
                "STATUS": "DEV",
                "UNREMOVABLE": "N",
                "REBOOT_REQUIRED": "N"
            }
            patch_data.restart_script["full_path"] = self.restart_script
            patch_data.restart_script["metadata_name"] = os.path.basename(self.restart_script)
            log.info("Creating inservice patch %s", patch_data.patch_id)
            log.info("restart script %s", patch_data.restart_script["full_path"])
            patch_builder.create_patch(patch_data, ostree_clone_name, formal)
            log.info("Inservice patch build done")

        clone_repo_path = os.path.join(patch_builder.deploy_dir, ostree_clone_name)
        self.__delete_dir(clone_repo_path)

        if requires:
            # Build the 2nd patch which will follow similar steps but will set the requires flag
            patch_builder.prepare_env(ostree_clone_name)
            # Update pkg
            self.update_pkg(pname + "_REQUIRES")
            # build image to trigger a new ostree commit
            self.build_image()
            # Update patch ID and set requires
            patch_data = PatchRecipeData()
            patch_data.patch_id = rr_requires_patch_name
            patch_data.sw_version = self.sw_version
            patch_data.metadata = {
                "SUMMARY": "RR ALL NODES REQUIRES",
                "DESCRIPTION": "Test patch with dependency",
                "INSTALL_INSTRUCTIONS": "Sample instructions",
                "WARNINGS": "Sample Warning",
                "STATUS": "DEV",
                "UNREMOVABLE": "N",
                "REBOOT_REQUIRED": "Y"
            }
            patch_data.requires.append(rr_patch_name)
            # Create a patch
            log.info("Creating RR Requires patch %s", patch_data.patch_id)
            patch_builder.create_patch(patch_data, ostree_clone_name, formal)
            log.info("Requires patch build done")
            self.__delete_dir(clone_repo_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debian build_test_patches")

    parser.add_argument("-sw", "--software-version", type=str, help="Patch Software version, will prefix the patch name", default=None, required=True)
    parser.add_argument("-r", "--requires", action="store_true", help="Builds the 2nd patch which requires the rr_patch")
    parser.add_argument("-i", "--inservice", action="store_true", help="Builds the in service patch")
    parser.add_argument("-f", "--formal", action="store_true", help="Signs the patch with formal key")
    args = parser.parse_args()
    log.debug("Args: %s", args)

    try:
        log.info("Building test patches")
        patch_name = args.software_version
        test_patch_builder = TestPatchBuilder(args.software_version)
        test_patch_builder.create_test_patches(patch_name, args.requires, args.inservice, args.formal)
        log.info("Test patch build completed")

    except TestPatchCreationException:
        log.exception("Error while creating test patches")
