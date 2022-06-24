#!/bin/python3
#
# Copyright (c) 2022 Wind River Systems, Inc.
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
$STX_BUILD_HOME/localdisk/lat/std/deploy/

Pending items:
- Modify patch Status

"""
import argparse
import hashlib
import logging
import tarfile
import tempfile
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from xml.dom import minidom

# Signing function
sys.path.insert(0, "../../cgcs-patch")
from cgcs_patch.patch_signing import sign_files  # noqa: E402 pylint: disable=wrong-import-position

# STATUS_OBSOLETE = 'OBS'
# STATUS_RELEASED = 'REL'
STATUS_DEVELOPEMENT = 'DEV'

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
            self.deploy_dir = os.path.join(os.environ["STX_BUILD_HOME"], "localdisk/lat/std/deploy")
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
            self.__add_text_tag_to_xml(top, "status", STATUS_DEVELOPEMENT)

        self.__add_text_tag_to_xml(top, "unremovable", self.patch_data.metadata["UNREMOVABLE"])
        self.__add_text_tag_to_xml(top, "reboot_required", self.patch_data.metadata["REBOOT_REQUIRED"])

        if "APPLY_ACTIVE_RELEASE_ONLY" in self.patch_data.metadata:
            self.__add_text_tag_to_xml(top, "apply_active_release_only", self.patch_data.metadata["APPLY_ACTIVE_RELEASE_ONLY"])

        if self.patch_data.restart_script:
            self.__add_text_tag_to_xml(top, "restart_script", self.patch_data.restart_script["name"])

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

    def __create_delta_dir(self, clone_dir="ostree-clone"):
        """
        Creates the ostree delta directory
        Contains the changes from the REPO (updated) and the cloned dir (pre update)
        :param clone_dir: clone dir name
        """
        log.info("Creating ostree delta")

        clone_dir = os.path.join(self.deploy_dir, clone_dir)

        if os.path.isdir(self.delta_dir):
            log.error("Delta dir exists '%s', clean it up and try again", self.delta_dir)
            exit(1)

        if not os.path.isdir(clone_dir):
            log.error("Clone dir not found")
            exit(1)

        subprocess.call(["rsync", "-rpgo", "--exclude", ".lock", "--compare-dest", clone_dir, self.ostree_repo + "/", self.delta_dir + "/"])
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

        cmd = f"ostree --repo={repo} log starlingx | grep commit | sed \"s/.* //\""
        commits = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip().split("\n")

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

    def __sign_official_patches(self):
        """
        Sign formal patch
        Called internally once a patch is created and formal flag is set to true
        """
        log.info("Signing patch %s", self.patch_file_name)
        try:
            patch_file_path = os.path.join(self.deploy_dir, self.patch_file_name)
            subprocess.check_call(["sign_patch_formal.sh", patch_file_path])
        except subprocess.CalledProcessError as e:
            log.exception("Failed to sign official patch. Call to sign_patch_formal.sh process returned non-zero exit status %i", e.returncode)
            raise SystemExit(e.returncode)

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
        # Clone the ostree_repo dir (ignores the .lock file)
        subprocess.call(["rsync", "-a", "--exclude", ".lock", self.ostree_repo + "/", clone_dir])
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

        log.info("Generating delta dir")
        self.__create_delta_dir(clone_dir=clone_dir)

        # ostree --repo=ostree_repo show  starlingx | grep -i checksum |  sed "s/.* //"
        cmd = f"ostree --repo={clone_dir} show starlingx | grep -i checksum | sed \"s/.* //\""
        base_checksum = subprocess.check_output(cmd, shell=True).decode(sys.stdout.encoding).strip()
        # Get commits from DEPLOY_DIR/ostree_repo
        commits = self.__get_commits_from_base(base_sha, self.ostree_repo)

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

        if self.patch_data.restart_script:
            log.info("Saving restart scripts")
            shutil.copyfile(self.patch_data.restart_script["full_path"], self.patch_data.restart_script["name"])

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

        # Create the patch
        tar = tarfile.open(os.path.join(self.deploy_dir, self.patch_file_name), "w:gz")
        for file in filelist:
            tar.add(file)
        tar.add("signature")
        tar.add(self.detached_signature_file)
        if self.patch_data.restart_script and os.path.isfile(self.patch_data.restart_script["name"]):
            tar.add(self.patch_data.restart_script["name"])
        tar.close()

        os.chdir(self.deploy_dir)
        shutil.rmtree(tmpdir)
        shutil.rmtree(self.delta_dir)

        log.info("Patch file created %s at %s", self.patch_file_name, self.deploy_dir)

        if formal:
            log.info("Trying to sign formal patch")
            self.__sign_official_patches()


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

    args = parser.parse_args()
    log.debug("Args: %s", args)

    if args.cmd == "create":
        handle_create(args)
    elif args.cmd == "prepare":
        handle_prepare(args)

    log.info("Done")
