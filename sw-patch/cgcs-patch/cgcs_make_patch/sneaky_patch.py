"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

This utility creates an ostree patch using .deb files
This utility is meant to be run on the controller
It writes to /opt/backups because it needs lots of disk space

Future Improvements:
1) support wildcards for .debs
2) Verify debs are newer than what is installed (otherwise the install fails)
3) Figure out how to run before bootstrap (not enough disk space)
4) Figure out how to avoid these GPG workarounds
   sudo sed -i '$a gpg-verify=false' /var/www/pages/feed/rel-23.09/ostree_repo/config
   sudo sed -i '$a gpg-verify=false' /sysroot/ostree/repo/config

The following is a sample patch.yaml that shows how a series of 2 patches can be made:

---
SNEAKY_1:
  debs:
    - sysinv-1.deb
    - software-1.deb
  sneaky_script: restart.sh

SNEAKY_2:
  debs:
    - sysinv-2.deb
  sneaky_script: restart2.sh

"""
import argparse
from cgcs_patch import ostree_utils
from cgcs_patch import patch_functions
from cgcs_patch import patch_verify
from cgcs_patch.patch_signing import sign_files
from datetime import datetime
import urllib.request
import os
import shutil
import subprocess
from subprocess import CalledProcessError
import tarfile
import tempfile
import time
from tsconfig.tsconfig import SW_VERSION
import xml.etree.ElementTree as ET
from xml.dom import minidom
import yaml


class PatchInfo(object):

    def __init__(self,
                 patch_id,
                 debs,
                 install_instructions=None,
                 pem_file=None,
                 req_patch=None,
                 sneaky_script=None,
                 description=None,
                 summary=None,
                 sw_version=None,
                 warnings=None):
        # debs must be a string and not a list
        if not isinstance(debs, list):
            raise ValueError("debs for %s must be a list and not %s" % (patch_id, type(debs)))
        self.debs = debs
        self.patch_id = patch_id
        self.install_instructions = install_instructions
        self.pem_file = pem_file
        self.req_patch = req_patch
        self.sneaky_script = sneaky_script
        self.description = description
        self.summary = summary
        self.sw_version = sw_version
        self.warnings = warnings

    @classmethod
    def from_args(cls, args):
        """Construct a list of a single PatchInfo based on args"""
        return [cls(args.patch_id,
                    args.debs,
                    install_instructions=args.install_instructions,
                    pem_file=args.pem_file,
                    req_patch=args.req_patch,
                    sneaky_script=args.sneaky_script,
                    description=args.description,
                    summary=args.summary,
                    sw_version=args.sw_version,
                    warnings=args.warnings), ]

    @staticmethod
    def get_val(some_key, patch_dict, args):
        return patch_dict.get(some_key, getattr(args, some_key))

    @classmethod
    def from_yaml(cls, some_yaml, args):
        """Construct a list of a PatchInfo based on parsing yaml"""

        patch_info_list = []
        with open(some_yaml) as f:
            yaml_data = yaml.safe_load(f)
            invalid_yaml = set()
            req_patch = None
            for patch_id, patch_contents in yaml_data.items():
                # validate the patch_contents
                for patch_key in patch_contents.keys():
                    if not hasattr(args, patch_key):
                        print("invalid patch attribute: %s" % patch_key)
                        invalid_yaml.add(patch_key)
                if invalid_yaml:
                    raise ValueError("yaml contains invalid entries %s" % invalid_yaml)

                # When creating a chain of patches, they need to 'require' the previous one
                # if the req_patch was passed in the yaml or args, use it.
                req_patch_cur = cls.get_val('req_patch', patch_contents, args)
                if req_patch_cur is None:
                    req_patch_cur = req_patch

                patch_info_list.append(cls(patch_id,
                                           patch_contents.get('debs'),
                                           install_instructions=cls.get_val('install_instructions', patch_contents, args),
                                           pem_file=cls.get_val('pem_file', patch_contents, args),
                                           req_patch=req_patch_cur,
                                           sneaky_script=cls.get_val('sneaky_script', patch_contents, args),
                                           description=cls.get_val('description', patch_contents, args),
                                           summary=cls.get_val('summary', patch_contents, args),
                                           sw_version=cls.get_val('sw_version', patch_contents, args),
                                           warnings=cls.get_val('warnings', patch_contents, args)))

                # set the 'next' req_patch to be this patch_id
                req_patch = patch_id
        return patch_info_list


def setup_argparse():
    parser = argparse.ArgumentParser(prog="sneaky_patch",
                                     description="Creates a patch from a deb file")
    parser.add_argument('debs',
                        nargs="+",  # accepts a list
                        help='List of deb files to install to a patch or a yaml file')
    parser.add_argument('--verbose',
                        action='store_true',
                        help="Display verbose output")
    parser.add_argument('--debug',
                        action='store_true',
                        help="Display debugging output")
    parser.add_argument('--sw-version',
                        default=SW_VERSION,
                        help="Version being patched.  Usually same as what is running")
    parser.add_argument('--patch-id',
                        default="SNEAKY",
                        help="Patch ID")
    parser.add_argument('--summary',
                        default="SNEAKY Summary",
                        help="Summary for this patch.")
    parser.add_argument('--description',
                        # this defaults to the list of deb files
                        help="Description for this patch")
    parser.add_argument('--install-instructions',
                        default="SNEAKY Install Instructions",
                        help="Install instructions for this patch")
    parser.add_argument('--warnings',
                        default="SNEAKY Warnings",
                        help="Warnings for this patch")
    parser.add_argument('--sneaky-script',
                        help="A script, making this a no-reboot patch")
    parser.add_argument('--req-patch',
                        help="ID of any required patch")
    parser.add_argument('--pem-file',
                        help="An already downloaded patch signing key. Default is to download the dev key")
    return parser


def print_duration(action, prev, verbose):
    now = datetime.now()
    duration = now - prev
    if verbose:
        print("%s took %.2f seconds" % (action, duration.total_seconds()))
    return now


def print_debug(output, debug):
    """Print the output if we are in debug mode"""
    if debug:
        print("%s" % output)


def get_major_release_version(sw_release_version):
    """Gets the major release for a given software version """
    if not sw_release_version:
        return None
    else:
        try:
            separator = '.'
            separated_string = sw_release_version.split(separator)
            major_version = separated_string[0] + separator + separated_string[1]
            return major_version
        except Exception:
            return None


def get_repo_src(sw_version):
    return "/var/www/pages/feed/rel-%s/ostree_repo" % get_major_release_version(sw_version)


def add_text_tag_to_xml(parent, name, text):
    tag = ET.SubElement(parent, name)
    tag.text = text
    return tag


def gen_xml(file_name, base_commit_id, base_checksum, commit_id, commit_checksum, patch_info):
    top = ET.Element("patch")
    add_text_tag_to_xml(top, "id", patch_info.patch_id)
    add_text_tag_to_xml(top, "sw_version", patch_info.sw_version)
    add_text_tag_to_xml(top, "summary", patch_info.summary)
    desc = patch_info.description
    if desc is None:
        desc = "Deb Files: %s" % " ".join(patch_info.debs)
    add_text_tag_to_xml(top, "description", desc)
    add_text_tag_to_xml(top, "install_instructions", patch_info.install_instructions)
    add_text_tag_to_xml(top, "warnings", patch_info.warnings)
    add_text_tag_to_xml(top, "status", 'DEV')
    add_text_tag_to_xml(top, "unremovable", "N")
    if patch_info.sneaky_script is None:
        add_text_tag_to_xml(top, "reboot_required", "Y")
    else:
        add_text_tag_to_xml(top, "reboot_required", "N")
        add_text_tag_to_xml(top,
                            "restart_script",
                            os.path.basename(patch_info.sneaky_script))

    content = ET.SubElement(top, "contents")
    ostree = ET.SubElement(content, "ostree")

    # sneaky patches are just one commit
    add_text_tag_to_xml(ostree, "number_of_commits", "1")
    base_commit = ET.SubElement(ostree, "base")
    add_text_tag_to_xml(base_commit, "commit", base_commit_id)
    add_text_tag_to_xml(base_commit, "checksum", base_checksum)

    commit = ET.SubElement(ostree, "commit1")
    add_text_tag_to_xml(commit, "commit", commit_id)
    add_text_tag_to_xml(commit, "checksum", commit_checksum)

    req = ET.SubElement(top, 'requires')
    if patch_info.req_patch is not None:
        add_text_tag_to_xml(req, 'req_patch_id', patch_info.req_patch)

    add_text_tag_to_xml(top, "semantics", "")

    with open(file_name, "w") as outfile:
        tree = ET.tostring(top)
        outfile.write(minidom.parseString(tree).toprettyxml(indent="  "))


def sign_and_pack(patch_file, tar_dir, pem_file):
    os.chdir(tar_dir)
    filelist = ["metadata.tar", "software.tar"]
    # Generate the local signature file
    sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    for f in filelist:
        sig ^= patch_functions.get_md5(f)

    with open("signature", "w") as sigfile:
        sigfile.write("%x" % sig)

    detached_signature_file = "signature.v2"
    private_key = patch_verify.read_RSA_key(open(pem_file, 'rb').read())

    sign_files(filelist,
               detached_signature_file,
               private_key=private_key,
               cert_type=None)

    # Save files into .patch
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    with tarfile.open(patch_file, "w:gz") as tar:
        for afile in files:
            print(" -=- Adding to patch %s" % afile)
            tar.add(afile)
    print(" !!! Patch file is located at: %s" % patch_file)


def setup_patch(feed_dir, patch_bare_dir, debug):
    # Phase 1: make an ostree that contains the new commit based on the new rootfs
    # - required because a bare repo can create a commit from a rootfs, but an archive repo cannot
    # ostree --repo=/opt/backups/sneaky/patch_bare init --mode=bare
    # ostree --repo=/opt/backups/sneaky/patch_bare pull-local \
    #               /var/www/pages/feed/rel-22.12/ostree_repo
    # Phase 1: Step 1: create a bare patch repo
    try:
        print(" - Creating bare patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_bare_dir,
                                          "init",
                                          "--mode=bare"],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree init bare. %s" % ex.output)
        return 1

    # Phase 1: Step 2: Pull history from ostree clone_dir (ie: the feed_dir)
    try:
        print(" - Updating bare patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_bare_dir,
                                          "pull-local",
                                          feed_dir],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree pull-local. %s" % ex.output)
        return 1
    return 0


def make_patch(patch_info, tempdir, rootfs, feed_dir, patch_archive_dir, debug, verbose):
    # This algorthithm is based on make_patch.py
    # ostree --repo=/opt/backups/sneaky/patch_bare commit --tree=dir=/opt/backups/sneaky/rootfs \
    #        --skip-if-unchanged --branch=starlingx --subject=sneaky --timestamp=timestamp
    # TODO(abailey): Determine if these can also be added
    #        --gpg-sign=gpg_id --gpg-homedir=gpg_homedir --parent=commit_id_base
    #
    # Phase 2: make an ostree archive from Phase 1
    # - required because the binary patch contents are based on archive repo format
    # ostree --repo=/opt/backups/sneaky/patch_archive init --mode=archive-z2
    # ostree --repo=/opt/backups/sneaky/patch_archive pull-local --depth=1 \
    #               /opt/backups/sneaky/patch_bare
    # ostree --repo=/opt/backups/sneaky/patch_archive summary -u
    #
    # Phase 3:
    # rsync from feed_dir and patch_archive with the difference stored in delta_dir

    prev = datetime.now()
    patch_bare_dir = "%s/patch_bare" % tempdir   # bare

    # Phase 1: Step 3: Create a new commit.  Needs a commit-id
    timestamp = time.asctime()
    subject = "Commit-id: SNEAKY-" + time.strftime("%Y%m%d%H%M%S", time.localtime())
    try:
        print(" - Commiting new change to bare patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_bare_dir,
                                          "commit",
                                          "--tree=dir=%s" % rootfs,
                                          "--skip-if-unchanged",
                                          "--branch=starlingx",
                                          "'--timestamp=%s'" % timestamp,
                                          "'--subject=%s'" % subject],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree commit. %s" % ex.output)
        return 1
    prev = print_duration("commit creation", prev, verbose)

    # Phase 2: Step 1: Make the archive repo containing the patch contents
    try:
        print(" - Creating archive patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_archive_dir,
                                          "init",
                                          "--mode=archive-z2"],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree init archive. %s" % ex.output)
        return 1

    # Phase 2: Step 2: Pull history from temporary patch repo (depth=1)
    try:
        print(" - Populating archive patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_archive_dir,
                                          "pull-local",
                                          "--depth=1",
                                          patch_bare_dir],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree archive pull-local. %s" % ex.output)
        return 1

    # Phase 2: Step 3: Update the summary file in the archive repo
    try:
        print(" - Updating summary for archive patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_archive_dir,
                                          "summary",
                                          "-u"],
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed ostree summary update. %s" % ex.output)
        return 1
    prev = print_duration("creating archive", prev, verbose)

    # this is the difference between the feed_dir and the archive
    # Note that the feed_dir will be the last patch
    try:
        # automatically creates "delta_dir"
        print(" - rsyncing to determine patch delta...")
        os.chdir(tempdir)

        # Getting 2 GB delta folder instead of 2MB
        # Removed -p which was specified in make_patch.py to fix the issue
        options = "-rcgo"  # recursive, checksum, perms, group, owner

        output = subprocess.check_output(["rsync",
                                          options,
                                          "--exclude=/.lock",
                                          "--exclude=/config",
                                          "--no-owner",
                                          "--compare-dest", feed_dir,  # compare received files relative to feed_dir
                                          patch_archive_dir + "/",     # SRC
                                          "delta_dir" + "/"],          # DEST
                                         stderr=subprocess.STDOUT)
        print_debug(output, debug)
    except CalledProcessError as ex:
        print("Failed rsync. %s" % ex.output)
        return 1
    prev = print_duration("rsync", prev, verbose)

    # base_commit comes from feed
    # commit comes from archive
    # checksum values do not appear to be used by patching
    base_commit_id = ostree_utils.get_ostree_latest_commit("starlingx", feed_dir)
    base_checksum = "UNUSED"
    commit_id = ostree_utils.get_ostree_latest_commit("starlingx", patch_archive_dir)
    commit_checksum = "UNUSED"

    # Writing the final patch file
    final_patch_file = "/tmp/%s.patch" % patch_info.patch_id

    pem_url = "https://raw.githubusercontent.com/starlingx/root/master/build-tools/signing/dev-private-key.pem"
    pem_file = "%s/dev-private-key.pem" % tempdir
    if patch_info.pem_file is None:
        urllib.request.urlretrieve(pem_url, pem_file)
    else:
        # use the already downloaded pem_file passed as an argument
        pem_file = patch_info.pem_file

    with tempfile.TemporaryDirectory(prefix="sneaky_patch", dir="/tmp") as sneaky_tar:
        print(" - Generating software.tar...")  # Make tarball of delta_dir
        with tarfile.open("%s/software.tar" % sneaky_tar, "w") as tar:
            tar.add(os.path.join(tempdir, "delta_dir"), arcname="")

        # now we can change into the tar location and do the rest of the patch generation
        os.chdir(sneaky_tar)

        # generate the metadata.xml
        print(" - Generating metadata.tar...")
        gen_xml("metadata.xml",
                base_commit_id, base_checksum,
                commit_id, commit_checksum,
                patch_info)
        with tarfile.open("%s/metadata.tar" % sneaky_tar, "w") as tar:
            tar.add("metadata.xml")
        os.remove("metadata.xml")

        # Copy the restart script to the temporary tar directory
        if patch_info.sneaky_script is not None:
            shutil.copy(patch_info.sneaky_script, sneaky_tar)

        # patch_functions.write_patch looks like it skips restart scripts
        # using the logic from make_patch.py sign_and_pack
        sign_and_pack(final_patch_file, sneaky_tar, pem_file)

    prev = print_duration("Writing patch", prev, verbose)
    return 0


def sneaky_patch(patch_info_list, debug, verbose):
    # hold onto the cwd where we are when we initiate patching
    cwd = os.getcwd()

    # Hold onto a directory handle outside of chroot.
    real_root = os.open("/", os.O_RDONLY)
    in_jail = False

    prev = datetime.now()
    start_time = prev

    # all patches must be based on the same sw_version
    repo_src = get_repo_src(patch_info_list[0].sw_version)

    # Step 1: make a temporary directory under /opt/backups
    with tempfile.TemporaryDirectory(prefix="sneaky", dir="/opt/backups") as sneaky_temp:

        # Checkout the ostree feed
        rootfs = "%s/rootfs" % sneaky_temp
        try:
            print(" - Checking out ostree...")
            output = subprocess.check_output(["ostree",
                                              "-v",
                                              "--repo=%s" % repo_src,
                                              "checkout",
                                              "starlingx",
                                              rootfs],
                                             stderr=subprocess.STDOUT)
            print_debug(output, debug)
        except CalledProcessError as ex:
            print("Failed ostree checkout. %s" % ex.output)
            return 1
        prev = print_duration("Ostree checkout", prev, verbose)

        rootfs_tmp = "%s/var/tmp" % rootfs
        patch_bare_dir = "%s/patch_bare" % sneaky_temp  # bare
        feed_dir = repo_src
        rc = setup_patch(repo_src, patch_bare_dir, debug)
        if rc != 0:
            print("setup patch failed")
            return rc
        prev = print_duration("Patch Setup", prev, verbose)

        # loop over the patches...
        for patch_info in patch_info_list:
            patch_desc = "Preparing Patch %s" % patch_info.patch_id
            prev = print_duration(patch_desc, prev, verbose)
            patch_archive_dir = "%s/patch_archive_%s" % (sneaky_temp, patch_info.patch_id)  # archive

            # We MUST be located at the starting directory
            os.chdir(cwd)

            # Stage the deb files under rootfs/var/tmp/
            for deb_file in patch_info.debs:
                try:
                    shutil.copy(deb_file, rootfs_tmp)
                except Exception as ex:
                    print("Failed debian file copy. %s" % ex)
                    return 1

            # enter chroot jail and install those packages
            # enter chroot jail
            os.chroot(rootfs)
            os.chdir('/')
            in_jail = True

            # Note:  We need to leave chroot jail before calling 'return'
            # otherwise the tmp dir will not be cleaned up

            # symlink /etc
            try:
                print(" - Setting up symlinks...")
                output = subprocess.check_output(["ln", "-sfn", "usr/etc", "etc"],
                                                 stderr=subprocess.STDOUT)
                print_debug(output, debug)
            except CalledProcessError as ex:
                print("Failed chroot symlink step. %s" % ex.output)
                os.fchdir(real_root)  # leave jail
                os.chroot(".")
                in_jail = False
                return 1
            # change into the /var/tmp in the chroot where the .deb files are located
            os.chdir("/var/tmp")
            deb_list = " ".join(patch_info.debs)
            # install the deb files
            try:
                print(" - Installing %s ..." % deb_list)
                install_args = ["dpkg", "-i"]
                install_args.extend(patch_info.debs)
                output = subprocess.check_output(install_args, stderr=subprocess.STDOUT)
                print_debug(output, debug)
            except CalledProcessError as ex:
                print("Failed debian package installation. %s" % ex.output)
                os.fchdir(real_root)  # leave jail
                os.chroot(".")
                in_jail = False
                return 1
            prev = print_duration("Installing packages", prev, verbose)
            # remove the etc symlink from within chroot
            os.chdir('/')
            if os.path.isdir("/etc"):
                os.remove("etc")

            # leave chroot jail
            os.fchdir(real_root)
            os.chroot(".")
            in_jail = False

            # make the commit, etc..
            make_patch(patch_info, sneaky_temp, rootfs, feed_dir, patch_archive_dir, debug, verbose)
            # for the next patch, the feed will be the archive_dir of the last patch
            feed_dir = patch_archive_dir
            prev = print_duration("Committing changes", prev, verbose)

    # escape back from chroot jail
    if in_jail:
        # Should never get here...
        os.fchdir(real_root)
        os.chroot(".")
    # now we can safely close fd for real_root
    os.close(real_root)

    print_duration("Entire activity", start_time, verbose)
    return 1


def validate_file(some_file):
    file_location = os.path.abspath(some_file)
    if not os.path.isfile(file_location):
        raise FileNotFoundError(file_location)


def extra_validation(patch_info_list):
    # Add in any additional validators
    # that argparse does not handle
    unique_scripts = set()
    for patch_info in patch_info_list:
        # make sure all deb files exist
        for deb in patch_info.debs:
            validate_file(deb)
        # if the script exists, determine its actual path
        if patch_info.sneaky_script is not None:
            script_location = os.path.abspath(patch_info.sneaky_script)
            if os.path.isfile(script_location):
                patch_info.sneaky_script = script_location
            else:
                raise FileNotFoundError(script_location)
            # also check that the script is executable
            if not os.access(script_location, os.X_OK):
                raise PermissionError("%s needs executable permissions" % script_location)
            if script_location in unique_scripts:
                raise PermissionError("%s must be unique. It is already used by another patch" % script_location)
            unique_scripts.add(script_location)


def main():
    parser = setup_argparse()
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("MUST BE RUN AS ROOT (or sudo)")
        return 1
    # If the args.debs is a yaml we parse that
    # otherwise its the args that populate the PatchInfo
    if args.debs[0].endswith(".yaml"):
        patch_info_list = PatchInfo.from_yaml(args.debs[0], args)
    else:
        patch_info_list = PatchInfo.from_args(args)
    extra_validation(patch_info_list)
    return sneaky_patch(patch_info_list, args.debug, args.verbose)


if __name__ == '__main__':
    exit(main())
