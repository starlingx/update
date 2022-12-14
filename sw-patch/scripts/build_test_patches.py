#!/usr/bin/env python3
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Debian Build Test Patches:

Default option (type=default) builds 4 patches using the logmgmt package:
    PATCH A) Reboot required - all nodes
        Update package - logmgmt
        rebuild the pkg
        build-image to generate a new commit in the build ostree_repo
        build a patch

    PATCH B) In Service patch - Example restart
        Update the metadata
        Uses the example-restart script
        Uses the same ostree commit as PATCH A so they can't be applied together
        build a patch

    PATCH C) In Service patch - Restart failure
        Update the metadata
        Uses the restart-failure script
        Uses the same ostree commit as PATCH A so they can't be applied together
        build a patch

    PATCH D) Patch with dependency (reboot required, depends on PATCH A)
        build PATCH A
        update package - logmgmt
        build-image to generate a new commit in the build ostree_repo
        build Patch C (requires A)

Kernel option (type=kernel) builds 1 patch after rebuilding the kernel:
    PATCH E) Reboot required - all nodes
        update kernel-std and kernel-rt
        rebuild the packages linux and linux-rt
        build-image to generate a new commit in the build ostree_repo
        build a patch with new initramfs
        build a patch reusing initramfs

Large option (type=large)
    PATCH F) Reboot required - all nodes (Large Patch)
        upverion all packages
        rebuild all packages
        build-image to generate a new commit in the build ostree_repo
        build a patch with new initramfs

Steps to run:
    # Setup debian build env
    # For more information about how to setup the environment:
        https://wiki.openstack.org/wiki/StarlingX/DebianBuildEnvironment

    # Sample variables
    export PROJECT="stx-debian-build"
    export STX_BUILD_HOME="/localdisk/designer/${USER}/${PROJECT}"
    export MY_REPO="/localdisk/designer/${USER}/${PROJECT}/repo/cgcs-root
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
import yaml
import xml.etree.ElementTree as ET

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
log = logging.getLogger('build_test_patches')

SAMPLE_RR_XML = "patch_recipe_rr_sample.xml"
SAMPLE_INSVC_XML = "patch_recipe_insvc_sample.xml"

# IN Service restart scripts
RESTART_SCRIPT = "patch-scripts/EXAMPLE_0001/scripts/example-restart"
RESTART_FAILURE_SCRIPT = "patch-scripts/test-patches/INSVC_RESTART_FAILURE/scripts/restart-failure"


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
            self.deploy_dir = os.path.join(os.environ.get("STX_BUILD_HOME"), "localdisk", "deploy")
            self.repo_root = os.environ.get("MY_REPO")
            self.stx_tools = os.path.join(self.repo_root, "..", "stx-tools")
            self.patch_repo_base = os.path.join(self.repo_root, "stx", "update")
            self.patch_tools_dir = os.path.join(self.patch_repo_base, "sw-patch", "cgcs-patch", "cgcs_make_patch")
            self.sw_version = sw_version
        except TestPatchInitException:
            log.exception("TestPatchBuilder initialization failure")
            sys.exit(1)

    def __upversion_pkg(self, pkg_dir):
        """
        Update package version using stx_patch
        """
        log.info("Upversioning package %s", pkg_dir)
        pwd = os.getcwd()
        os.chdir(pkg_dir)
        meta_data_path = os.path.join(pkg_dir, "debian", "meta_data.yaml")
        with open(meta_data_path) as f:
            meta_data = yaml.safe_load(f)

        if "revision" in meta_data:
            if "stx_patch" in meta_data["revision"]:
                meta_data["revision"]["stx_patch"] += 1
            else:
                meta_data["revision"]["stx_patch"] = 1

            # Save updated meta_data.yaml
            with open(meta_data_path, "w") as f:
                yaml.dump(meta_data, f)

        os.chdir(pwd)

    def delete_ostree_prepatch(self, dir_name):
        """
        Deletes ostree_repo prepatch generated during prepare
        """
        cmd = f'''
            source import-stx
            stx shell --container lat -c \
                "cd \\$DEPLOY_DIR; rm -rf {dir_name}"
        '''
        ret = run_cmd(cmd)
        log.info("Clean up ostree prepatch directory returned %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to delete directory")

    def build_pkg(self, pkg_name=None):
        """
        Build package(s)
        """
        if pkg_name:
            cmd = f'''
                source import-stx
                stx shell -c "build-pkgs -c -p {pkg_name}"
            '''
        else:
            cmd = '''
                source import-stx
                stx shell -c "build-pkgs --parallel 10"
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

    def update_logmgmt_pkg(self, pname):
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

    def prepare_env(self, ostree_clone_name):
        """
        Generates ostree_repo snapshot before creating a patch
        It executes the command inside the LAT container
        """
        cmd = f'''
            source import-stx
            stx shell --container lat -c \
                "cd \\$PATCH_TOOLS; python3 make_patch.py prepare --clone-repo {ostree_clone_name}"
        '''
        ret = run_cmd(cmd)
        log.info("Patch prepare return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to run patch prepare")

    def create_patch_xml(self, patch_id, sw_version, require_id, reboot=True, insvc_script=None):
        """
        Create patch xml at the patch_tools_dir
        param patch_id: patch name/id
        param sw_version: software version, e.g: 21.12
        param required_id: patch id for prereq patch
        param reboot: reboot required or insvc patch
        param insvc_script: full path to restart script

        return: file name
        """
        os.chdir(self.patch_tools_dir)

        tree = ET.parse(SAMPLE_RR_XML) if reboot else ET.parse(SAMPLE_INSVC_XML)
        metadata = tree.find("METADATA")
        metadata.find("ID").text = patch_id
        metadata.find("SW_VERSION").text = sw_version

        if require_id:
            requires_tag = metadata.find("REQUIRES")
            reqid_tag = ET.SubElement(requires_tag, "ID")
            reqid_tag.text = require_id

        if not reboot and insvc_script:
            # Copy restart script to localdisk/deploy and update path
            shutil.copy2(insvc_script, self.deploy_dir)
            metadata.find("RESTART_SCRIPT").text = os.path.join("/localdisk", "deploy", os.path.basename(insvc_script))

        file_name = f"{patch_id}.xml"
        tree.write(file_name)
        os.chdir(self.stx_tools)
        return file_name

    def make_patch_lat(self, xml_path, ostree_clone, formal=False, reuse_initramfs=True):
        """
        Calls the make_patch utility inside LAT container to generate our patch
        param xml_path: path to the patch recipe/xml
        param ostree_clone: path to the ostree_clone repo generated during the prepare stage
        """
        ostree_clone_lat = os.path.join("/localdisk", "deploy", ostree_clone)
        delta_dir_lat = os.path.join("/localdisk", "deploy", "delta-dir")

        if not reuse_initramfs:
            reuse_env_var = "export NO_REUSE_INITRAMFS=True;"
        else:
            reuse_env_var = ""

        cmd = f'''
            source import-stx
            stx shell --container lat -c "cd \\$PATCH_TOOLS; {reuse_env_var} python3 make_patch.py create \
                --patch-recipe {xml_path} --clone-repo {ostree_clone_lat}/ \
                    --delta-dir {delta_dir_lat}"
        '''
        if formal:
            index = cmd.find("--clone-repo")
            cmd = f"{cmd[:index]} --formal {cmd[index:]}"

        ret = run_cmd(cmd)
        log.info("Patch create return code %s", ret.returncode)
        if ret.returncode != 0:
            raise Exception("Failed to create patch")

    def pull_local_patch_repo(self):
        cmd = f'''
            source import-stx
            stx shell --container lat -c "cd \\$DEPLOY_DIR; \
                ostree --repo=ostree_repo pull-local \
                     {os.path.join('patch_work', 'patch_repo')} starlingx; \
                        ostree --repo=ostree_repo summary --update"
            '''
        ret = run_cmd(cmd)
        if ret.returncode != 0:
            raise Exception("Failed to pull ostree from patch_repo process returned non-zero exit status %i", ret.returncode)

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
        os.chdir(self.stx_tools)
        # Generating ostree_repo clone
        self.prepare_env(ostree_clone_name)
        # Update pkg
        self.update_logmgmt_pkg(pname)
        log.info("Generating Reboot required patch")
        # build image to trigger a new ostree commit
        self.build_image()

        rr_patch_name = pname + "_RR_ALL_NODES"
        rr_xml_path = self.create_patch_xml(rr_patch_name, self.sw_version, None)

        # In service patch
        if inservice:
            insvc_patch_name = pname + "_NRR_INSVC"
            insvc_script_path = os.path.join(self.patch_repo_base, RESTART_SCRIPT)
            insvc_xml_path = self.create_patch_xml(insvc_patch_name, self.sw_version, None, reboot=False, insvc_script=insvc_script_path)
            # build patch
            log.info("Creating inservice sample restart patch %s", insvc_patch_name)
            log.info("restart script %s", insvc_script_path)
            self.make_patch_lat(insvc_xml_path, ostree_clone_name, formal)
            log.info("Inservice sample restart patch build done")

            # Restart failure
            insvc_patch_name = pname + "_RESTART_FAILURE_INSVC"
            insvc_script_path = os.path.join(self.patch_repo_base, RESTART_FAILURE_SCRIPT)
            insvc_xml_path = self.create_patch_xml(insvc_patch_name, self.sw_version, None, reboot=False, insvc_script=insvc_script_path)
            # build patch
            log.info("Creating inservice restart failure patch %s", insvc_patch_name)
            log.info("restart script %s/%s", insvc_script_path)
            self.make_patch_lat(insvc_xml_path, ostree_clone_name, formal)
            log.info("Inservice restart failure patch build done")

        # RR Patch
        log.info("Creating RR patch %s", rr_xml_path)
        self.make_patch_lat(rr_xml_path, ostree_clone_name, formal)
        log.info("RR Patch build done")

        # Cleans up the ostree_clone to generate a new one for the requires patch
        self.delete_ostree_prepatch(ostree_clone_name)

        if requires:
            # Build the 2nd patch which will follow similar steps but will set the requires flag
            # If re-using initramfs it needs to pull the previous patch commit into ostree_repo
            rr_req_patch_name = pname + "_RR_ALL_NODES_REQUIRES"
            rr_req_xml_path = self.create_patch_xml(rr_req_patch_name, self.sw_version, rr_patch_name)

            self.prepare_env(ostree_clone_name)
            # Update pkg
            self.update_logmgmt_pkg(rr_req_patch_name)
            # build image to trigger a new ostree commit
            self.build_image()
            # Create a patch
            log.info("Creating RR Requires patch %s", rr_req_patch_name)
            self.make_patch_lat(rr_req_xml_path, ostree_clone_name, formal)
            log.info("Requires patch build done")
            self.delete_ostree_prepatch(ostree_clone_name)

    def create_kernel_patch(self, sw_version, formal=False):
        '''
        Upversion and rebuilds the kernel
        param sw_version: software version, e.g 22.12
        param formal: Signs the patch with formal key
        '''
        ostree_clone_name = "ostree_repo_patch"
        os.chdir(self.patch_tools_dir)
        # Create patch recipe/xml
        patch_name = sw_version + "_KERNEL"
        kernel_patch_xml = self.create_patch_xml(patch_name, self.sw_version, None)
        kernel_patch_reuse_xml = self.create_patch_xml(patch_name + "_REUSE", self.sw_version, None)

        os.chdir(self.stx_tools)
        # Generating ostree_repo clone
        self.prepare_env(ostree_clone_name)
        # Update pkg
        kernel_std_dir = os.path.join(self.repo_root, "stx/kernel", "kernel-std")
        kernel_rt_dir = os.path.join(self.repo_root, "stx/kernel", "kernel-rt")
        self.__upversion_pkg(kernel_std_dir)
        self.__upversion_pkg(kernel_rt_dir)
        log.info("Generating Kernel patch")
        # Rebuild the kernel
        self.build_pkg("linux")
        self.build_pkg("linux-rt")
        # build image to trigger a new ostree commit
        self.build_image()

        # Create a patch
        log.info("Creating Kernel patch %s", kernel_patch_xml)
        # Create patch with new initramfs
        self.make_patch_lat(kernel_patch_xml, ostree_clone_name, formal, reuse_initramfs=False)
        # Create patch reusing initramfs
        self.make_patch_lat(kernel_patch_reuse_xml, ostree_clone_name, formal)
        log.info("Kernel patch build done")
        self.delete_ostree_prepatch(ostree_clone_name)

    def create_large_patch(self, sw_version, formal=False):
        '''
        Upversion all available packages and creates a patch
        This step takes time as all packages are rebuilt
        param sw_version: software version, e.g 22.12
        param formal: Signs the patch with formal key
        '''
        log.info("Creating Large Patch")

        ostree_clone_name = "ostree_repo_patch"
        os.chdir(self.patch_tools_dir)
        # Create patch recipe/xml
        patch_name = sw_version + "_LARGE"
        large_patch_xml = self.create_patch_xml(patch_name, self.sw_version, None)

        os.chdir(self.repo_root)
        file_list = []
        for root, dirs, files in os.walk(os.getcwd()):
            for file in files:
                if file == "meta_data.yaml":
                    file_list.append(os.path.join(root, file))

        log.info("Total files found %s" % len(file_list))
        log.info("Upversioning all packages")
        for f in file_list:
            pkg_dir = f.split("/debian/")[0]
            self.__upversion_pkg(pkg_dir)

        os.chdir(self.stx_tools)
        # Generating ostree_repo clone
        self.prepare_env(ostree_clone_name)
        # Rebuild the packages
        self.build_pkg()
        # build image to trigger a new ostree commit
        self.build_image()
        # Create a patch
        log.info("large patch xml %s", large_patch_xml)
        # Create patch with new initramfs
        self.make_patch_lat(large_patch_xml, ostree_clone_name, formal, reuse_initramfs=False)
        log.info("Large patch build done")
        self.delete_ostree_prepatch(ostree_clone_name)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debian build_test_patches")

    parser.add_argument("-t", "--type", default="default", type=str, help="Default (logmgmt patches), kernel or large")
    parser.add_argument("-sw", "--software-version", type=str, help="Patch Software version, will prefix the patch name", default=None, required=True)
    parser.add_argument("-r", "--requires", action="store_true", help="Builds the 2nd patch which requires the rr_patch")
    parser.add_argument("-i", "--inservice", action="store_true", help="Builds the in service patch")
    parser.add_argument("-f", "--formal", action="store_true", help="Signs the patch with formal key")
    args = parser.parse_args()
    log.debug("Args: %s", args)

    try:
        log.info("Building test patches")
        sw_version = args.software_version
        test_patch_builder = TestPatchBuilder(args.software_version)
        if args.type == "default":
            test_patch_builder.create_test_patches(sw_version, args.requires, args.inservice, args.formal)
        elif args.type == "kernel":
            test_patch_builder.create_kernel_patch(sw_version, args.formal)
        elif args.type == "large":
            test_patch_builder.create_large_patch(sw_version, args.formal)

        log.info("Test patch build completed")
    except TestPatchCreationException:
        log.exception("Error while creating test patches")
