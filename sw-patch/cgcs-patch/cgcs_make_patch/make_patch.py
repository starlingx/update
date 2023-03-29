#!/usr/bin/env python3
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Creates Debian patches

Steps to create a debian patch:
1) Export env variables, e.g:
export PROJECT='stx-debian-desktop'
export STX_BUILD_HOME='/localdisk/designer/${USER}/${PROJECT}'

2) Run prepare to create a clone of the STX_BUILD_HOME ostree_repo
./make_patch.py prepare --clone-repo ostree_test

3) Make changes to the environment
- update a package
- build-pkgs -c -p <package name>
- build-image
This will create a new commit in the build ostree_repo

4) Create your patch.xml (samples provided)
- patch_recipe_rr_sample.xml
- patch_recipe_insvc_sample.xml

5) Run create to build the patch
./make_patch.py create --patch-recipe patch_recipe_rr_sample.xml \
    --clone-repo ostree_test

Once the script is done the .patch file can be located at:
$STX_BUILD_HOME/localdisk/deploy/
"""
import argparse
import filecmp
import hashlib
import logging
import tarfile
import time
import tempfile
import os
import shutil
import subprocess
import sys
import yaml
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Signing function
sys.path.insert(0, "../../cgcs-patch")
from cgcs_patch.patch_signing import sign_files  # noqa: E402 pylint: disable=wrong-import-position
from cgcs_patch.patch_verify import verify_files  # noqa: E402 pylint: disable=wrong-import-position

PATCH_STATUS = {
    'release': 'REL',
    'obsolete': 'OBS',
    'development': 'DEV'
}

METADATA_TAGS = ['ID', 'SW_VERSION', 'SUMMARY', 'DESCRIPTION', 'INSTALL_INSTRUCTIONS', 'WARNINGS', 'STATUS',
                 'UNREMOVABLE', 'REBOOT_REQUIRED', 'REQUIRES', 'RESTART_SCRIPT', 'APPLY_ACTIVE_RELEASE_ONLY']

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s.%(msecs)03d %(levelname)s %(module)s - %(funcName)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

log = logging.getLogger("make_patch")


def get_md5(path):
    '''
    Utility function for generating the md5sum of a file
    :param path: Path to file
    '''
    md5 = hashlib.md5()
    block_size = 8192
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            md5.update(chunk)
    return int(md5.hexdigest(), 16)


class PatchError(Exception):
    """Base class for patch exceptions."""

    def __init__(self, message=None):
        super(PatchError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message or ""


class PatchBuilderInitError(PatchError):
    """Problem during PatchBuilder initialization."""
    pass


class PatchRecipeXMLFail(PatchError):
    """Unkown tag"""
    pass


class PatchInvalidStatus(PatchError):
    """Invalid status"""
    pass


class PatchModifyError(PatchError):
    """Error while modifying patch"""
    pass


class PatchValidationFailure(PatchError):
    """Patch validation failure"""
    pass


class PatchRecipeData(object):
    """
    Patch data
    """
    def __init__(self):
        self.patch_id = None
        self.sw_version = None
        self.requires = []
        self.metadata = {}
        self.restart_script = {}
        self.ostree_content = {}

    def __parse_root(self, e):
        for child in e:
            if child.tag == "METADATA":
                self.__parse_metadata(child)
            else:
                msg = f"Unknown tag '{child.tag}' under <PATCH_RECIPE>"
                log.exception(msg)
                raise PatchRecipeXMLFail(msg)

        if "ID" in self.metadata:
            self.patch_id = self.metadata["ID"]
            # Update restart script name - prefix with patch_id
            if self.restart_script:
                self.restart_script["metadata_name"] = self.patch_id + "_" \
                    + self.restart_script["name"]
        else:
            msg = "patch is missing required field <PATCH_RECIPE><METADATA><ID>"
            log.exception(msg)
            raise PatchRecipeXMLFail(msg)

        if "SW_VERSION" in self.metadata:
            self.sw_version = self.metadata["SW_VERSION"]
        else:
            msg = f"patch '{self.patch_id}' is missing required field <PATCH_RECIPE><METADATA><SW_VERSION>"
            log.exception(msg)
            raise PatchRecipeXMLFail(msg)

    def __parse_metadata(self, e):
        for child in e:
            if child.tag == "REQUIRES":
                self.__parse_requires(child)
            elif child.tag == "RESTART_SCRIPT":
                self.__parse_restart_script(child)
            elif child.tag in METADATA_TAGS:
                self.metadata[child.tag] = child.text.strip() if child.text else ""
            else:
                msg = f"Unknow tag '{child.tag}' under <PATCH_RECIPE><METADATA>"
                log.exception(msg)
                raise PatchRecipeXMLFail(msg)

    def __parse_restart_script(self, e):
        e.text = e.text.strip()
        if os.path.isfile(e.text):
            self.restart_script["name"] = os.path.basename(e.text)
            self.restart_script["full_path"] = e.text
        else:
            msg = f"Restart script not found {e.text}"
            log.exception(msg)
            raise PatchRecipeXMLFail(msg)

    def __parse_requires(self, e):
        for child in e:
            if child.tag == "ID":
                req = child.text.strip() if child.text else None
                if req is None:
                    msg = "Patch id missing under <PATCH_RECIPE><METADATA><REQUIRES><ID>"
                    log.exception(msg)
                    raise PatchRecipeXMLFail(msg)
                self.requires.append(req)
            else:
                msg = f"Unknow tag '{child.tag}' under <PATCH_RECIPE><METADATA><REQUIRES>"
                log.exception(msg)
                raise PatchRecipeXMLFail(msg)

    def parse_xml(self,
                  filename):
        """
        Parse an individual patch recipe XML file
        :param filename: XML file
        :return: Patch ID
        """
        tree = ET.parse(filename)
        root = tree.getroot()

        self.__parse_root(root)
        log.info("patch_id: %s", str(self.patch_id))
        log.info("metadata: %s", str(self.metadata))


class PatchBuilder(object):
    """
    Patch Builder - Create debian patches based on ostree changes
    """

    def __init__(self, delta_dir="delta_dir"):
        try:
            # ostree repo location
            self.deploy_dir = os.path.join(os.environ["STX_BUILD_HOME"], "localdisk/deploy")
            self.ostree_repo = os.path.join(self.deploy_dir, "ostree_repo")
            self.delta_dir = delta_dir
            self.detached_signature_file = "signature.v2"
            self.restart_script = None
            self.patch_path = None
            self.patch_data = None
            self.patch_file_name = None
            self.ostree_content = None
        except PatchBuilderInitError:
            log.error("Error while initializing PatchBuilder")

    def __add_text_tag_to_xml(self, parent, name, text):
        """
        Utility function for adding a text tag to an XML object
        :param parent: Parent element
        :param name: Element name
        :param text: Text value
        :return:The created element
        """
        tag = ET.SubElement(parent, name)
        tag.text = text
        return tag

    def __gen_xml(self, file_name="metadata.xml"):
        """
        Generate patch metadata XML file
        :param file_name: Path to output file
        """
        top = ET.Element("patch")

        self.__add_text_tag_to_xml(top, "id", self.patch_data.patch_id)
        self.__add_text_tag_to_xml(top, "sw_version", self.patch_data.sw_version)
        self.__add_text_tag_to_xml(top, "summary", self.patch_data.metadata["SUMMARY"])
        self.__add_text_tag_to_xml(top, "description", self.patch_data.metadata["DESCRIPTION"])
        self.__add_text_tag_to_xml(top, "install_instructions", self.patch_data.metadata["INSTALL_INSTRUCTIONS"])
        self.__add_text_tag_to_xml(top, "warnings", self.patch_data.metadata["WARNINGS"])

        if "STATUS" in self.patch_data.metadata:
            self.__add_text_tag_to_xml(top, "status", self.patch_data.metadata["STATUS"])
        else:
            self.__add_text_tag_to_xml(top, "status", PATCH_STATUS['development'])

        self.__add_text_tag_to_xml(top, "unremovable", self.patch_data.metadata["UNREMOVABLE"])
        self.__add_text_tag_to_xml(top, "reboot_required", self.patch_data.metadata["REBOOT_REQUIRED"])

        if "APPLY_ACTIVE_RELEASE_ONLY" in self.patch_data.metadata:
            self.__add_text_tag_to_xml(top, "apply_active_release_only", self.patch_data.metadata["APPLY_ACTIVE_RELEASE_ONLY"])

        if self.patch_data.restart_script:
            self.__add_text_tag_to_xml(
                top,
                "restart_script",
                self.patch_data.restart_script["metadata_name"]
            )

        # Parse ostree_content
        content = ET.SubElement(top, "contents")
        ostree = ET.SubElement(content, "ostree")

        self.__add_text_tag_to_xml(ostree, "number_of_commits", str(len(self.ostree_content["commits"])))
        base_commit = ET.SubElement(ostree, "base")
        self.__add_text_tag_to_xml(base_commit, "commit", self.ostree_content["base"]["commit"])
        self.__add_text_tag_to_xml(base_commit, "checksum", self.ostree_content["base"]["checksum"])

        for i, c in enumerate(self.ostree_content["commits"]):
            commit = ET.SubElement(ostree, "commit" + str(i + 1))
            self.__add_text_tag_to_xml(commit, "commit", c["commit"])
            self.__add_text_tag_to_xml(commit, "checksum", c["checksum"])

        req = ET.SubElement(top, 'requires')
        for req_patch in sorted(self.patch_data.requires):
            self.__add_text_tag_to_xml(req, 'req_patch_id', req_patch)

        self.__add_text_tag_to_xml(top, "semantics", "")

        # Save xml
        outfile = open(file_name, "w")
        tree = ET.tostring(top)
        outfile.write(minidom.parseString(tree).toprettyxml(indent="  "))

    def __reuse_initramfs(self, rootfs_base_dir, rootfs_new_dir):
        """
        Try to reuse the initramfs file /usr/lib/ostree-boot/initramfs-xxx and its signature
        :param rootfs_base_dir: original root filesystem
        :param rootfs_new_dir: newest root filesystem
        :return: True if reuse the initramfs.
        """
        # Compare the version of package initramfs-trigger, not same, not reuse.
        if "NO_REUSE_INITRAMFS" in os.environ.keys():
            return False
        base_trigger_version = new_trigger_version = ""
        cmd = f"dpkg --root {rootfs_base_dir} -l initramfs-trigger | tail -n 1"
        ret = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        if ret:
            base_trigger_version = ret.split()[2].split(".stx")[0]
        cmd = f"dpkg --root {rootfs_new_dir} -l initramfs-trigger | tail -n 1"
        ret = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        if ret:
            new_trigger_version = ret.split()[2].split(".stx")[0]
        # If feed rootfs has no package "initramfs-trigger", or the version of this package is not same,
        # do not reuse the initramfs file.
        if not new_trigger_version:
            log.error("New build rootfs %s has no package initramfs-trigger!", rootfs_new_dir)
            raise Exception("New build rootfs has no package initramfs-trigger!")
        if not base_trigger_version or base_trigger_version != new_trigger_version:
            log.info("We can not reuse the initramfs file for the versio of initramfs-trigger changed")
            return False

        # unpack two initramfs files
        initramfs_base_dir = initramfs_new_dir = ""
        os.path.join(os.path.dirname(rootfs_base_dir), "initramfs_base")
        initramfs_new_dir = os.path.join(os.path.dirname(rootfs_new_dir), "initramfs_new")
        for initrd_type, hugefs_dir in [("base", rootfs_base_dir), ("new", rootfs_new_dir)]:
            initramfs_dir = os.path.join(os.path.dirname(hugefs_dir), "initramfs_" + initrd_type)
            if initrd_type == "base":
                initramfs_base_dir = initramfs_dir
            else:
                initramfs_new_dir = initramfs_dir
            log.info("Unpack %s initramfs into %s", initrd_type, initramfs_dir)
            os.mkdir(initramfs_dir)
            cmd = f"cp {hugefs_dir}/usr/lib/ostree-boot/initramfs-* {initramfs_dir}/initrd.gz"
            subprocess.call([cmd], shell=True)
            cmd = f"gunzip {initramfs_dir}/initrd.gz"
            subprocess.call([cmd], shell=True)
            os.chdir(initramfs_dir)
            cmd = "cpio -idm < initrd; rm -f initrd"
            subprocess.call([cmd], shell=True)

        # compare its log file /var/log/rootfs_install.log
        base_install_log = os.path.join(initramfs_base_dir, "var/log/rootfs_install.log")
        new_install_log = os.path.join(initramfs_new_dir, "var/log/rootfs_install.log")
        if not os.path.exists(new_install_log):
            log.error("Log file %s does not exist.", new_install_log)
            raise Exception("Initramfs, install log file does not exist.")
        if not os.path.exists(base_install_log):
            log.info("The feed initramfs file has no install log, please careful.")
        if os.path.exists(base_install_log) and os.path.exists(new_install_log):
            initramfs_delta_dir = os.path.join(os.path.dirname(rootfs_new_dir), "initramfs_delta")
            if filecmp.cmp(base_install_log, new_install_log):
                log.info("Two initramfs have same install log files.")
            else:
                log.warning("install log files of two initramfs are NOT same:")
                log.warning("Log file of feed initramfs: %s", base_install_log)
                log.warning("Log file of new initramfs: %s", new_install_log)

        os.mkdir(initramfs_delta_dir)
        # Add "-q" to make the output clean
        # subprocess.call(["rsync", "-rpgoc", "--compare-dest", initramfs_base_dir + "/", initramfs_new_dir + "/", initramfs_delta_dir + "/"])
        subprocess.call(["rsync", "-rpgocq", "--compare-dest", initramfs_base_dir + "/", initramfs_new_dir + "/", initramfs_delta_dir + "/"])
        log.info("The delta folder of two initramfs: %s.", initramfs_delta_dir)
        log.info("Reuse initramfs files to shrink Debian patch...")
        # reuse boot-initramfs files and their signature.
        cmd = " ".join([
            "rm -f",
            os.path.join(rootfs_new_dir, 'usr/lib/ostree-boot/initramfs*'),
            os.path.join(rootfs_new_dir, 'boot/initrd.img*'),
            os.path.join(rootfs_new_dir, 'var/miniboot/initrd-mini*')
        ])
        subprocess.call(cmd, shell=True)
        cmd = " ".join(["cp -a", os.path.join(rootfs_base_dir, 'usr/lib/ostree-boot/initramfs*'), os.path.join(rootfs_new_dir, 'usr/lib/ostree-boot/')])
        subprocess.call(cmd, shell=True)
        cmd = " ".join(["cp -a", os.path.join(rootfs_base_dir, 'var/miniboot/initrd-mini*'), os.path.join(rootfs_new_dir, 'var/miniboot/')])
        subprocess.call(cmd, shell=True)
        cmd = " ".join(["cp -a", os.path.join(rootfs_base_dir, 'boot/initrd.img*'), os.path.join(rootfs_new_dir, 'boot/')])
        subprocess.call(cmd, shell=True)
        # Find and get checksum of necessary images: kernel_rt_file + kernel_file + vmlinuz_file + initramfs_file
        ostree_boot_dir = os.path.join(rootfs_new_dir, 'usr/lib/ostree-boot')
        kernel_rt_file = kernel_file = vmlinuz_file = initramfs_file = ""
        for file_name in os.listdir(ostree_boot_dir):
            if not os.path.isfile(os.path.join(ostree_boot_dir, file_name)):
                continue
            file_path = os.path.join(ostree_boot_dir, file_name)
            if file_name.endswith(".sig"):
                continue
            if file_name.startswith("vmlinuz-") and file_name.endswith("-amd64"):
                if file_name.find("-rt-") == -1:
                    kernel_file = file_path
                else:
                    kernel_rt_file = file_path
                continue
            if file_name.startswith("vmlinuz-") and len(file_name) == len("vmlinuz-") + 64:
                vmlinuz_file = file_path
                continue
            if file_name.startswith("initramfs-") and len(file_name) == len("initramfs-") + 64:
                initramfs_file = file_path
                continue
        # Any file missed, raise exception.
        if not kernel_rt_file or not kernel_file or not vmlinuz_file or not initramfs_file:
            log.error("Miss key file when calculate sha256 checksum")
            log.info("RT kernel image: %s", kernel_rt_file)
            log.info("STD kernel image: %s", kernel_file)
            log.info("vmlinuz image: %s", vmlinuz_file)
            log.info("initramfs image: %s", initramfs_file)
            raise Exception("Miss key file when calculate sha256 checksum")
        # Order: std, rt, vmlinuz, initramfs
        cmd = " ".join(["cat", kernel_file, kernel_rt_file, vmlinuz_file, initramfs_file, "| sha256sum | cut -d' ' -f 1"])
        new_checksum = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        log.info("New checksum is %s", new_checksum)
        vmlinuz_new_name = "vmlinuz-" + new_checksum
        initramfs_new_name = "initramfs-" + new_checksum
        os.rename(vmlinuz_file, os.path.join(ostree_boot_dir, vmlinuz_new_name))
        os.rename(initramfs_file, os.path.join(ostree_boot_dir, initramfs_new_name))
        return True

    def __create_patch_repo(self, clone_dir="ostree-clone"):
        """
        Create the ostree contains delta content
        Used to compare with the feed ostree repo
        :param clone_dir: clone dir name
        """
        log.info("Creating patch ostree")

        workdir = os.path.join(self.deploy_dir, "patch_work")
        if os.path.exists(workdir):
            shutil.rmtree(workdir)
        os.mkdir(workdir)
        os.chdir(workdir)

        # Checkout both ostree repos
        repo_base_dir = clone_dir
        cmd = f"cat {repo_base_dir}/refs/heads/starlingx"
        commit_id_base = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        rootfs_base_dir = os.path.join(workdir, "rootfs_base")
        log.info("Checkout commit %s from base OSTree %s, it may take several minutes.", commit_id_base[:6], repo_base_dir)
        cmd = f"ostree --repo={repo_base_dir} checkout {commit_id_base} {rootfs_base_dir}"
        log.info("Command line: %s", cmd)
        subprocess.call([cmd], shell=True)
        log.info("Done. Checkout base root fs in %s", rootfs_base_dir)

        repo_new_dir = self.ostree_repo
        cmd = f"cat {repo_new_dir}/refs/heads/starlingx"
        commit_id_new = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        rootfs_new_dir = os.path.join(workdir, "rootfs_new")
        log.info("Checkout commit %s from new OSTree %s, it may take several minutes.", commit_id_new[:6], repo_new_dir)
        cmd = f"ostree --repo={repo_new_dir} checkout {commit_id_new} {rootfs_new_dir}"
        log.info("Command line: %s", cmd)
        subprocess.call([cmd], shell=True)
        log.info("Done. Checkout new root fs in %s", rootfs_new_dir)

        # Try to reuse files from feed rootfs.
        try:
            initrd_reused = self.__reuse_initramfs(rootfs_base_dir, rootfs_new_dir)
            # Nothing can be reused, just use the self.ostree_repo as the patch repo
            if not initrd_reused:
                log.info("No file can be reused, we can just use the original repo: %s", self.ostree_repo)
                return self.ostree_repo, False
        except Exception as e:
            log.exception("Failed on reusing files of feed repo. %s", e)
            return self.ostree_repo, False

        # create patch repo
        tmp_patch_repo_dir = os.path.join(workdir, "patch_repo_tmp")
        patch_repo_dir = os.path.join(workdir, "patch_repo")
        log.info("Create a new OSTree repo in %s, may take a few minutes", patch_repo_dir)
        cmd = f"ostree --repo={tmp_patch_repo_dir} init --mode=bare"
        subprocess.call([cmd], shell=True)
        self.__check_gnupg_folder()
        # Pull history from ostree prepatch (clone_dir)
        log.info("Pull history from %s.", clone_dir)
        cmd = f"ostree --repo={tmp_patch_repo_dir} pull-local {clone_dir}"
        subprocess.call([cmd], shell=True)
        timestamp = time.asctime()
        gpg_id = self.__get_yaml_info('gpg.ostree.gpgid')
        subject = "Commit-id: starlingx-intel-x86-64-" + time.strftime("%Y%m%d%H%M%S", time.localtime())
        cmd = " ".join(["ostree", "--repo=" + tmp_patch_repo_dir, "commit", "--tree=dir=" + rootfs_new_dir,
                        "--skip-if-unchanged", "--gpg-sign=" + gpg_id + " --gpg-homedir=/tmp/.lat_gnupg_root",
                        "--branch=starlingx", "'--timestamp=" + timestamp + "'",
                        "'--subject=" + subject + "'",
                        "'--parent=" + commit_id_base + "'"])
        subprocess.call([cmd], shell=True)
        cmd = f"ostree --repo={patch_repo_dir} init --mode=archive-z2"
        subprocess.call([cmd], shell=True)
        # Pull with depth=1 to get parent data
        cmd = f"ostree --repo={patch_repo_dir} pull-local --depth=1 {tmp_patch_repo_dir}"
        subprocess.call([cmd], shell=True)
        cmd = f"ostree summary -u --repo={patch_repo_dir}"
        subprocess.call([cmd], shell=True)
        log.info("New ostree repo been created: %s", patch_repo_dir)
        log.info("  Based on bare repo %s", tmp_patch_repo_dir)
        log.info("    Based on root filesystem %s", rootfs_new_dir)
        return patch_repo_dir, True

    def __check_gnupg_folder(self):
        """
        Check if GPG homedir exists and create it if necessary
        """
        gpg_home = "/tmp/.lat_gnupg_root"
        if not os.path.exists(gpg_home):
            log.info("Creating %s", gpg_home)
            os.environ["OECORE_NATIVE_SYSROOT"] = "/opt/LAT/SDK/sysroots/x86_64-wrlinuxsdk-linux"
            ostree_gpg_id = self.__get_yaml_info("gpg.ostree.gpgid")
            ostree_gpg_key = self.__get_yaml_info("gpg.ostree.gpgkey")
            ostree_gpg_pass = self.__get_yaml_info("gpg.ostree.gpg_password")
            os.makedirs(gpg_home)

            cmd = f"chmod 700 {gpg_home}"
            subprocess.call([cmd], shell=True)
            cmd = f"echo allow-loopback-pinentry > {gpg_home}/gpg-agent.conf"
            subprocess.call([cmd], shell=True)
            cmd = f"gpg-connect-agent --homedir {gpg_home} reloadagent /bye"
            subprocess.call([cmd], shell=True)
            cmd = f"gpg --homedir {gpg_home} --import {ostree_gpg_key}"
            subprocess.call([cmd], shell=True)
            cmd = f"gpg --homedir {gpg_home} --list-keys {ostree_gpg_id}"
            subprocess.call([cmd], shell=True)
            cmd = f"gpg --homedir={gpg_home} -o /dev/null -u \"{ostree_gpg_id}\" --pinentry=loopback --passphrase {ostree_gpg_pass} -s /dev/null"
            subprocess.call([cmd], shell=True)
            log.info("GPG homedir created with success.")
        else:
            log.info("GPG home (%s) folder already exist.", gpg_home)

    def __get_yaml_info(self, keys_to_get):
        """
        Get data from base-bullseye yaml file
        :param keys_to_get: keys sequence to get
        """
        with open(os.path.join(os.environ["MY_REPO_ROOT_DIR"],
                               "stx-tools/debian-mirror-tools/config/debian/common/base-bullseye.yaml"), "r") as stream:
            try:
                keys = keys_to_get.split('.')
                data = yaml.safe_load(stream)
                for key in keys:
                    data = data.get(key)
                    if data is None:
                        log.error("keys sequence '%s' not found in base-bullseye.yaml", keys_to_get)
                        sys.exit(1)
            except FileNotFoundError:
                log.error("base-bullseye.yaml not found")
                sys.exit(1)
        return data

    def __create_delta_dir(self, patch_repo_dir, clone_dir="ostree-clone"):
        """
        Creates the ostree delta directory
        Contains the changes from the REPO (updated) and the cloned dir (pre update)
        :param clone_dir: clone dir name
        """
        log.info("Creating ostree delta")

        clone_dir = os.path.join(self.deploy_dir, clone_dir)

        os.chdir(self.deploy_dir)
        # self.delta_dir is 'relative' to self.deploy_dir
        if os.path.isdir(self.delta_dir):
            log.error("Delta dir exists '%s', clean it up and try again", self.delta_dir)
            exit(1)

        if not os.path.isdir(clone_dir):
            log.error("Clone dir not found")
            exit(1)

        subprocess.call(["rsync", "-rcpgo",
                         "--exclude=/.lock",
                         "--exclude=/config",
                         "--no-owner",
                         "--compare-dest",
                         clone_dir,
                         patch_repo_dir + "/",
                         self.delta_dir + "/"])
        log.info("Delta dir created")

    def __get_commit_checksum(self, commit_id, repo="ostree_repo"):
        """
        Get commit checksum from a commit id
        :param commit_id
        :param repo
        """
        # get all checksums
        cmd = f"ostree --repo={repo} log starlingx | grep -i checksum | sed \"s/.* //\""
        cksums = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split("\n")
        return(cksums[commit_id])

    def __get_commits_from_base(self, base_sha, repo="ostree_repo"):
        """
        Get a list of commits from base sha
        :param base_sha
        :param repo
        """
        commits_from_base = []

        cmd = f"ostree --repo={repo} log starlingx | grep \"^commit\" | sed \"s/.* //\""
        commits = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split("\n")
        log.info("Patch repo commits %s", commits)

        if commits[0] == base_sha:
            log.info("base and top commit are the same")
            return commits_from_base

        # find base and add the commits to the list
        for i, commit in enumerate(commits):
            if commit == base_sha:
                break
            log.info("saving commit %s", commit)
            # find commit checksum
            cksum = self.__get_commit_checksum(i, repo)
            commits_from_base.append({
                "commit": commit,
                "checksum": cksum
            })

        return commits_from_base

    def __sign_official_patches(self, patch_file):
        """
        Sign formal patch
        Called internally once a patch is created and formal flag is set to true
        :param patch_file full path to the patch file
        """
        log.info("Signing patch %s", patch_file)
        try:
            # patch_file_path = os.path.join(self.deploy_dir, self.patch_file_name)
            subprocess.check_call(["sign_patch_formal.sh", patch_file])
        except subprocess.CalledProcessError as e:
            log.exception("Failed to sign official patch. Call to sign_patch_formal.sh process returned non-zero exit status %i", e.returncode)
        except FileNotFoundError:
            log.exception("sign_patch_formal.sh not found, make sure $STX_BUILD_HOME/repo/cgcs-root/build-tools is in the $PATH")

    def __sign_and_pack(self, patch_file, formal=False):
        """
        Generates the patch signatures and pack the .patch file
        :param patch_file .patch file full path
        """
        filelist = ["metadata.tar", "software.tar"]
        # Generate the local signature file
        sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for f in filelist:
            sig ^= get_md5(f)

        sigfile = open("signature", "w")
        sigfile.write("%x" % sig)
        sigfile.close()

        # this comes from patch_functions write_patch
        # Generate the detached signature
        #
        # Note: if cert_type requests a formal signature, but the signing key
        #    is not found, we'll instead sign with the "dev" key and
        #    need_resign_with_formal is set to True.
        need_resign_with_formal = sign_files(
            filelist,
            self.detached_signature_file,
            cert_type=None)

        log.debug("Formal signing status %s", need_resign_with_formal)

        # Save files into .patch
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        tar = tarfile.open(patch_file, "w:gz")
        for file in files:
            log.info("Saving file %s", file)
            tar.add(file)
        tar.close()
        log.info("Patch file created %s", patch_file)
        if formal:
            log.info("Trying to sign formal patch")
            self.__sign_official_patches(patch_file)

    def prepare_env(self, clone_repo="ostree-clone"):
        """
        Generates a copy of the current ostree_repo which is used
        to create the delta dir during patch creation
        :param clone_repo: name of the cloned directory
        """
        log.info("Preparing ostree clone directory")
        os.chdir(self.deploy_dir)
        clone_dir = os.path.join(self.deploy_dir, clone_repo)
        if os.path.isdir(clone_dir):
            log.error("Clone directory exists %s", clone_repo)
            sys.exit(1)

        os.mkdir(clone_dir)
        current_sha = open(os.path.join(self.ostree_repo, "refs/heads/starlingx"), "r").read()
        log.info("Current SHA: %s", current_sha)
        log.info("Cloning the directory...")
        # Clone the ostree_repo dir using hard-links (ignores the .lock file)
        subprocess.call(["rsync", "-a", "--exclude", ".lock", "--link-dest", "../ostree_repo", self.ostree_repo + "/", clone_dir])
        log.info("Prepared ostree repo clone at %s", clone_dir)

    def create_patch(self, patch_data: PatchRecipeData, clone_dir="ostree-clone", formal=False):
        """
        Creates a debian patch using ostree delta between 2 repos (rsync)
        :param patch_data: PatchRecipeData object
        :param clone_dir: repo cloned before the changes
        """
        self.patch_data = patch_data
        self.patch_file_name = patch_data.patch_id + ".patch"

        os.chdir(self.deploy_dir)
        # read the base sha from the clone/ga directory
        base_sha = open(os.path.join(clone_dir, "refs/heads/starlingx"), "r").read().strip()

        log.info("Generating delta ostree repository")
        patch_repo_dir, reuse_initramfs = self.__create_patch_repo(clone_dir=clone_dir)

        log.info("Generating delta dir")
        self.__create_delta_dir(patch_repo_dir, clone_dir=clone_dir)

        # ostree --repo=ostree_repo show  starlingx | grep -i checksum |  sed "s/.* //"
        cmd = f"ostree --repo={clone_dir} show starlingx | grep -i checksum | sed \"s/.* //\""
        base_checksum = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        # Get commits from updated ostree repo
        commits = self.__get_commits_from_base(base_sha, patch_repo_dir)

        if commits:
            self.ostree_content = {
                "base": {
                    "commit": base_sha,
                    "checksum": base_checksum
                },
            }
            self.ostree_content["commits"] = commits
        else:
            log.info("No changes detected")
            # clean it up delta_dir
            shutil.rmtree(self.delta_dir)
            sys.exit(0)

        log.info("Generating patch file...")
        # Create software.tar, metadata.tar and signatures
        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")
        # Change to the tmpdir
        os.chdir(tmpdir)
        tar = tarfile.open("software.tar", "w")
        tar.add(os.path.join(self.deploy_dir, self.delta_dir), arcname="")
        tar.close()

        log.info("Generating xml with ostree content %s", commits)
        self.__gen_xml()
        tar = tarfile.open("metadata.tar", "w")
        tar.add("metadata.xml")
        tar.close()
        os.remove("metadata.xml")

        if self.patch_data.restart_script:
            log.info("Saving restart scripts")
            shutil.copyfile(
                self.patch_data.restart_script["full_path"],
                os.path.join(tmpdir, self.patch_data.restart_script["metadata_name"])
            )
            subprocess.call(["ls", "-lhrt"])

        # Sign and create the .patch file
        self.__sign_and_pack(
            os.path.join(self.deploy_dir, self.patch_file_name),
            formal
        )

        os.chdir(self.deploy_dir)
        shutil.rmtree(tmpdir)
        shutil.rmtree(self.delta_dir)

        if reuse_initramfs:
            # If initramfs is reused it needs to update the ostree_repo commit to match the patch_repo
            cmd = f"ostree --repo={self.ostree_repo} pull-local \
                     {patch_repo_dir} starlingx; \
                        ostree --repo={self.ostree_repo} summary --update"
            try:
                subprocess.check_call([cmd], shell=True)
            except subprocess.CalledProcessError as e:
                log.exception("Failed pull patch_repo commit into ostree_repo. %s", e.stderr)

        log.info("Patch file created %s at %s", self.patch_file_name, self.deploy_dir)

    def modify_metadata_text(self, filename, key, value):
        """
        Open an xml file, find first element matching 'key' and replace the text with 'value'
        """
        new_filename = "%s.new" % filename
        tree = ET.parse(filename)

        # Prevent a proliferation of carriage returns when we write this XML back out to file.
        for e in tree.iter():
            if e.text is not None:
                e.text = e.text.rstrip()
            if e.tail is not None:
                e.tail = e.tail.rstrip()

        root = tree.getroot()
        # Make the substitution
        e = root.find(key)
        if e is None:
            msg = "modify_metadata_text: failed to find tag '%s'" % key
            log.error(msg)
            raise PatchValidationFailure(msg)
        e.text = value

        # write the modified file
        outfile = open(new_filename, 'w')
        rough_xml = ET.tostring(root)
        outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))
        outfile.close()
        os.rename(new_filename, filename)

    def read_patch(self, path):
        """
        Extract the patch to current dir and validate signature
        """
        # Open the patch file and extract the contents to the current dir
        tar = tarfile.open(path, "r:gz")
        tar.extractall()
        # Checks signature
        sigfile = open("signature", "r")
        sig = int(sigfile.read(), 16)
        sigfile.close()

        filelist = ["metadata.tar", "software.tar"]
        expected_sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for f in filelist:
            sig ^= get_md5(f)

        if sig != expected_sig:
            msg = "Patch failed verification"
            log.error(msg)
            raise PatchValidationFailure(msg)

        # Verify detached signature
        if os.path.exists(self.detached_signature_file):
            sig_valid = verify_files(
                filelist,
                self.detached_signature_file,
                cert_type=None)
            sig_valid = True
            if sig_valid is True:
                msg = "Signature verified, patch has been signed"
            else:
                msg = "Signature check failed"
                raise PatchValidationFailure(msg)
        else:
            msg = "Patch has not been signed"
            raise PatchValidationFailure(msg)

        # Extract metadata xml
        tar = tarfile.open("metadata.tar")
        tar.extractall()

    def write_patch(self, patch_file, formal=False):
        """
        Write files into .patch file and sign
        """
        log.info("Saving patch file")
        tar = tarfile.open("metadata.tar", "w")
        tar.add("metadata.xml")
        tar.close()
        # remove the xml
        os.remove("metadata.xml")

        # Sign and create the .patch file
        self.__sign_and_pack(patch_file, formal)


def handle_create(params):
    """
    Create a patch
    :param params: argparser parameters
    """
    log.info("Creating patch")
    if os.path.isfile(params.patch_recipe):
        patch_data = PatchRecipeData()
        patch_data.parse_xml(params.patch_recipe)
    else:
        raise FileNotFoundError("Patch recipe not found")

    # continue steps to create a patch
    patch_builder = PatchBuilder(params.delta_dir)
    patch_builder.create_patch(patch_data, params.clone_repo, params.formal)


def handle_prepare(params):
    """
    Prepare the environment by creating an ostree_repo clone
    :param params: argparser parameters
    """
    log.info("Preparing environment")
    patch_builder = PatchBuilder()
    log.info("Deploy dir %s", patch_builder.deploy_dir)
    patch_builder.prepare_env(params.clone_repo)


def handle_modify(params):
    """
    Modify patch status and resigns
    """
    log.info("Modifying patch %s", params.patch_file)
    if not os.path.isfile(params.patch_file):
        raise FileNotFoundError("Patch file not found")

    if params.status not in PATCH_STATUS:
        raise PatchInvalidStatus(f"Supported status are {PATCH_STATUS}")

    # Modify patch
    orig_wd = os.getcwd()
    workdir = tempfile.mkdtemp(prefix="patch_modify_")
    os.chdir(workdir)

    try:
        p = PatchBuilder()
        # extract and validate signatures
        p.read_patch(params.patch_file)
        log.info("Updating patch status to %s", PATCH_STATUS[params.status])
        # Update Status
        p.modify_metadata_text("metadata.xml", "status", PATCH_STATUS[params.status])
        p.write_patch(params.patch_file, params.formal)

    except PatchModifyError:
        log.exception("Error while modifying patch")
    finally:
        shutil.rmtree(workdir)
        os.chdir(orig_wd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Debian make_patch helper")

    subparsers = parser.add_subparsers(dest="cmd")

    # Prepare env Action
    prepare_parser = subparsers.add_parser("prepare",
                                           add_help=False,
                                           description="Prepare environment",
                                           help="Prepare the environment for patching by creating a clone of ostree_repo")
    prepare_parser.add_argument("-c", "--clone-repo", type=str, help="Clone repo directory name", default=None, required=True)

    # Create Patch Action
    create_parser = subparsers.add_parser("create",
                                          add_help=False,
                                          description="Create patch",
                                          help="Create patch, should be executed after changes are done to the environment")
    create_parser.add_argument("-p", "--patch-recipe", type=str, help="Patch recipe xml", required=True)
    create_parser.add_argument("-f", "--formal", action="store_true", help="Formal patch flag")
    create_parser.add_argument("-d", "--delta-dir", type=str, help="Delta dir name", default="delta-dir")
    create_parser.add_argument("-c", "--clone-repo", type=str, help="Clone repo directory name", default=None, required=True)

    # Modify Patch action
    modify_parser = subparsers.add_parser("modify",
                                          add_help=False,
                                          description="modify patch status",
                                          help="Modify patch status - DEV, REL, OBS")
    modify_parser.add_argument("-s", "--status", type=str, help="Patch status", required=True)
    modify_parser.add_argument("-f", "--formal", action="store_true", help="Formal patch flag")
    modify_parser.add_argument("-pf", "--patch-file", type=str, help="Patch file", required=True)

    args = parser.parse_args()
    log.debug("Args: %s", args)

    if args.cmd == "create":
        handle_create(args)
    elif args.cmd == "prepare":
        handle_prepare(args)
    elif args.cmd == "modify":
        handle_modify(args)

    log.info("Done")
