"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

# This utility creates an ostree patch using .deb files
# This utility is meant to be run on the controller
# It writes to /opt/backups because it needs lots of disk space

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


def setup_argparse():
    parser = argparse.ArgumentParser(prog="sneaky_patch",
                                     description="Creates a patch from a deb file")
    parser.add_argument('deb',
                        nargs="+",  # accepts a list
                        help='List of deb files to install to a patch')
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


def get_repo_src(args):
    return "/var/www/pages/feed/rel-%s/ostree_repo" % args.sw_version


def add_text_tag_to_xml(parent, name, text):
    tag = ET.SubElement(parent, name)
    tag.text = text
    return tag


def gen_xml(file_name, base_commit_id, base_checksum, commit_id, commit_checksum, args):
    top = ET.Element("patch")
    add_text_tag_to_xml(top, "id", args.patch_id)
    add_text_tag_to_xml(top, "sw_version", args.sw_version)
    add_text_tag_to_xml(top, "summary", args.summary)
    desc = args.description
    if desc is None:
        desc = "Deb Files: %s" % " ".join(args.deb)
    add_text_tag_to_xml(top, "description", desc)
    add_text_tag_to_xml(top, "install_instructions", args.install_instructions)
    add_text_tag_to_xml(top, "warnings", args.warnings)
    add_text_tag_to_xml(top, "status", 'DEV')
    add_text_tag_to_xml(top, "unremovable", "N")
    if args.sneaky_script is None:
        add_text_tag_to_xml(top, "reboot_required", "Y")
    else:
        add_text_tag_to_xml(top, "reboot_required", "N")
        add_text_tag_to_xml(top,
                            "restart_script",
                            os.path.basename(args.sneaky_script))

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
    if args.req_patch is not None:
        add_text_tag_to_xml(req, 'req_patch_id', args.req_patch)

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


def make_patch(args, tempdir, rootfs):
    # This algorthithm is based on make_patch.py
    # Phase 1: make an ostree that contains the new commit based on the new rootfs
    # - required because a bare repo can create a commit from a rootfs, but an archive repo cannot
    # ostree --repo=/opt/backups/sneaky/patch_bare init --mode=bare
    # ostree --repo=/opt/backups/sneaky/patch_bare pull-local \
    #               /var/www/pages/feed/rel-22.12/ostree_repo
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
    feed_dir = get_repo_src(args)
    patch_bare_dir = "%s/patch_bare" % tempdir   # bare
    patch_archive_dir = "%s/patch_archive" % tempdir       # archive

    # Phase 1: Step 1: create a bare patch repo
    try:
        print(" - Creating bare patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_bare_dir,
                                          "init",
                                          "--mode=bare"],
                                         stderr=subprocess.STDOUT)
        print_debug(output, args.debug)
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
        print_debug(output, args.debug)
    except CalledProcessError as ex:
        print("Failed ostree pull-local. %s" % ex.output)
        return 1

    # Phase 1: Step 3: Create a new commit Needs a commit
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
        print_debug(output, args.debug)
    except CalledProcessError as ex:
        print("Failed ostree commit. %s" % ex.output)
        return 1
    prev = print_duration("commit creation", prev, args.verbose)

    # Phase 2: Step 1: Make the archive repo containing the patch contents
    try:
        print(" - Creating archive patch repo ...")
        output = subprocess.check_output(["ostree",
                                          "--repo=%s" % patch_archive_dir,
                                          "init",
                                          "--mode=archive-z2"],
                                         stderr=subprocess.STDOUT)
        print_debug(output, args.debug)
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
        print_debug(output, args.debug)
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
        print_debug(output, args.debug)
    except CalledProcessError as ex:
        print("Failed ostree summary update. %s" % ex.output)
        return 1
    prev = print_duration("creating archive", prev, args.verbose)

    # this is the difference between the feed_dir and the archive
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
        print_debug(output, args.debug)
    except CalledProcessError as ex:
        print("Failed rsync. %s" % ex.output)
        return 1
    prev = print_duration("rsync", prev, args.verbose)

    # base_commit comes from feed
    # commit comes from archive
    # checksum values do not appear to be used by patching
    base_commit_id = ostree_utils.get_feed_latest_commit(args.sw_version)
    base_checksum = "UNUSED"
    commit_id = ostree_utils.get_ostree_latest_commit("starlingx", patch_archive_dir)
    commit_checksum = "UNUSED"

    # Writing the final patch file
    final_patch_file = "/tmp/%s.patch" % args.patch_id

    pem_url = "https://raw.githubusercontent.com/starlingx/root/master/build-tools/signing/dev-private-key.pem"
    pem_file = "%s/dev-private-key.pem" % tempdir
    if args.pem_file is None:
        urllib.request.urlretrieve(pem_url, pem_file)
    else:
        # use the already downloaded pem_file passed as an argument
        pem_file = args.pem_file

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
                args)
        with tarfile.open("%s/metadata.tar" % sneaky_tar, "w") as tar:
            tar.add("metadata.xml")
        os.remove("metadata.xml")

        # Copy the restart script to the temporary tar directory
        if args.sneaky_script is not None:
            shutil.copy(args.sneaky_script, sneaky_tar)

        # patch_functions.write_patch looks like it skips restart scripts
        # using the logic from make_patch.py sign_and_pack
        sign_and_pack(final_patch_file, sneaky_tar, pem_file)

    prev = print_duration("Writing patch", prev, args.verbose)
    return 0


def sneaky_patch(args):
    # Hold onto a directory handle outside of chroot.
    real_root = os.open("/", os.O_RDONLY)
    in_jail = False

    prev = datetime.now()
    start_time = prev

    # Step 1: make a temporary directory under /opt/backups
    with tempfile.TemporaryDirectory(prefix="sneaky", dir="/opt/backups") as sneaky_temp:

        # Checkout the ostree feed
        rootfs = "%s/rootfs" % sneaky_temp
        repo_src = get_repo_src(args)
        try:
            print(" - Checking out ostree...")
            output = subprocess.check_output(["ostree",
                                              "-v",
                                              "--repo=%s" % repo_src,
                                              "checkout",
                                              "starlingx",
                                              rootfs],
                                             stderr=subprocess.STDOUT)
            print_debug(output, args.debug)
        except CalledProcessError as ex:
            print("Failed ostree checkout. %s" % ex.output)
            return 1
        prev = print_duration("Ostree checkout", prev, args.verbose)

        # Stage the deb files under rootfs/var/tmp/
        rootfs_tmp = "%s/var/tmp" % rootfs
        for deb_file in args.deb:
            try:
                shutil.copy(deb_file, rootfs_tmp)
            except Exception as ex:
                print("Failed debian file copy. %s" % ex)
                return 1

        # Step 4: enter chroot jail and install those packages
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
            print_debug(output, args.debug)
        except CalledProcessError as ex:
            print("Failed chroot symlink step. %s" % ex.output)
            os.fchdir(real_root)  # leave jail
            os.chroot(".")
            in_jail = False
            return 1
        # change into the /var/tmp in the chroot where the .deb files are located
        os.chdir("/var/tmp")
        deb_list = " ".join(args.deb)
        # install the deb files
        try:
            print(" - Installing %s ..." % deb_list)
            install_args = ["dpkg", "-i"]
            install_args.extend(args.deb)
            output = subprocess.check_output(install_args, stderr=subprocess.STDOUT)
            print_debug(output, args.debug)
        except CalledProcessError as ex:
            print("Failed debian package installation. %s" % ex.output)
            os.fchdir(real_root)  # leave jail
            os.chroot(".")
            in_jail = False
            return 1
        prev = print_duration("Installing packages", prev, args.verbose)
        # remove the etc symlink from within chroot
        os.chdir('/')
        if os.path.isdir("/etc"):
            os.remove("etc")

        # leave chroot jail
        os.fchdir(real_root)
        os.chroot(".")
        in_jail = False

        # make the commit, etc..
        make_patch(args, sneaky_temp, rootfs)
        prev = print_duration("Committing changes", prev, args.verbose)

    # escape back from chroot jail
    if in_jail:
        os.fchdir(real_root)
        os.chroot(".")
    # now we can safely close fd for real_root
    os.close(real_root)

    print_duration("Entire activity", start_time, args.verbose)
    return 1


def extra_validation(args):
    # Add in any additional validators
    # that argparse does not handle
    if args.sneaky_script is not None:
        script_location = os.path.abspath(args.sneaky_script)
        if os.path.isfile(script_location):
            args.sneaky_script = script_location
        else:
            raise FileNotFoundError(script_location)


def main():
    parser = setup_argparse()
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("MUST BE RUN AS ROOT (or sudo)")
        return 1
    extra_validation(args)
    return sneaky_patch(args)


if __name__ == '__main__':
    exit(main())
