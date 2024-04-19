"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
import os
import sh
import shutil
import subprocess
import time

import gi
gi.require_version('OSTree', '1.0')
from gi.repository import Gio
from gi.repository import GLib
from gi.repository import OSTree

from software import constants
from software.exceptions import OSTreeCommandFail

LOG = logging.getLogger('main_logger')


def get_ostree_latest_commit(ostree_ref, repo_path):
    """
    Query ostree using ostree log <ref> --repo=<path>

    :param ostree_ref: the ostree ref.
     example: starlingx
    :param repo_path: the path to the ostree repo:
     example: /var/www/pages/feed/rel-22.06/ostree_repo
    :return: The most recent commit of the repo
    """

    # Sample command and output that is parsed to get the commit
    #
    # Command: ostree log starlingx --repo=/var/www/pages/feed/rel-22.02/ostree_repo
    #
    # Output:
    #
    # commit 478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e
    # ContentChecksum:  61fc5bb4398d73027595a4d839daeb404200d0899f6e7cdb24bb8fb6549912ba
    # Date:  2022-04-28 18:58:57 +0000
    #
    # Commit-id: starlingx-intel-x86-64-20220428185802
    #
    # commit ad7057a94a1d06e38eaedee2ce3fe56826ae817497469bce5d5ac05bc506aaa7
    # ContentChecksum:  dc42a42427a4f9e4de1210327c12b12ea3ad6a5d232497a903cc6478ca381e8b
    # Date:  2022-04-28 18:05:43 +0000
    #
    # Commit-id: starlingx-intel-x86-64-20220428180512

    cmd = "ostree log %s --repo=%s" % (ostree_ref, repo_path)
    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        info_msg = "OSTree log Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        msg = "Failed to fetch ostree log for %s." % repo_path
        raise OSTreeCommandFail(msg)
    # Store the output of the above command in a string
    output_string = output.stdout.decode('utf-8')

    # Parse the string to get the latest commit for the ostree
    split_output_string = output_string.split()
    latest_commit = split_output_string[1]
    return latest_commit


def get_feed_latest_commit(patch_sw_version):
    """
    Query ostree feed using ostree log <ref> --repo=<path>

    :param patch_sw_version: software version for the feed
     example: 22.06
    :return: The latest commit for the feed repo
    """
    repo_path = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                           patch_sw_version)
    return get_ostree_latest_commit(constants.OSTREE_REF, repo_path)


def get_sysroot_latest_commit():
    """
    Query ostree sysroot to determine the currently active commit
    :return: The latest commit for sysroot repo
    """
    return get_ostree_latest_commit(constants.OSTREE_REF, constants.SYSROOT_OSTREE)


def get_latest_deployment_commit():
    """
    Get the active deployment commit ID
    :return: The commit ID associated with the active commit
    """

    # Sample command and output that is parsed to get the active commit
    # associated with the deployment
    #
    # Command: ostree admin status
    #
    # Output:
    #
    # debian 0658a62854647b89caf5c0e9ed6ff62a6c98363ada13701d0395991569248d7e.0 (pending)
    # origin refspec: starlingx
    # * debian a5d8f8ca9bbafa85161083e9ca2259ff21e5392b7595a67f3bc7e7ab8cb583d9.0
    # Unlocked: hotfix
    # origin refspec: starlingx

    cmd = "ostree admin status"

    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to fetch ostree admin status."
        info_msg = "OSTree Admin Status Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    # Store the output of the above command in a string
    output_string = output.stdout.decode('utf-8')

    # Parse the string to get the active commit on this deployment
    # Trim everything before * as * represents the active deployment commit
    trimmed_output_string = output_string[output_string.index("*"):]
    split_output_string = trimmed_output_string.split()
    active_deployment_commit = split_output_string[2]
    return active_deployment_commit


def update_repo_summary_file(repo_path):
    """
    Updates the summary file for the specified ostree repo
    :param repo_path: the path to the ostree repo:
     example: /var/www/pages/feed/rel-22.06/ostree_repo
    """
    cmd = "ostree summary --update --repo=%s" % repo_path

    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to update summary file for ostree repo %s." % (repo_path)
        info_msg = "OSTree Summary Update Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


def reset_ostree_repo_head(commit, repo_path):
    """
    Resets the ostree repo HEAD to the commit that is specified
    :param commit: an existing commit on the ostree repo which we need the HEAD to point to
     example: 478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e
    :param repo_path: the path to the ostree repo:
     example: /var/www/pages/feed/rel-22.06/ostree_repo
    """
    cmd = "ostree reset %s %s --repo=%s" % (constants.OSTREE_REF, commit, repo_path)
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to reset head of ostree repo: %s to commit: %s" % (repo_path, commit)
        info_msg = "OSTree Reset Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


def pull_ostree_from_remote(remote=None):
    """
    Pull from remote ostree to sysroot ostree
    """

    cmd = "ostree pull %s --depth=-1"
    ref_cmd = ""
    if not remote:
        ref = constants.OSTREE_REMOTE
    else:
        ref = "%s:%s" % (remote, constants.OSTREE_REF)
        cmd += " --mirror"
        ref_cmd = "ostree refs --create=%s %s" % (ref, constants.OSTREE_REF)

    try:
        subprocess.run(cmd % ref, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to pull from %s remote into sysroot ostree" % ref
        info_msg = "OSTree Pull Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    if ref_cmd:
        try:
            subprocess.run(ref_cmd, shell=True, check=True)
        except subprocess.CalledProcessError:
            msg = "Failed to create ref %s for remote %s" % (ref, remote)


def delete_ostree_repo_commit(commit, repo_path):
    """
    Delete the specified commit from the ostree repo
    :param commit: an existing commit on the ostree repo which we need to delete
     example: 478bc21c1702b9b667b5a75fac62a3ef9203cc1767cbe95e89dface6dc7f205e
    :param repo_path: the path to the ostree repo:
     example: /var/www/pages/feed/rel-22.06/ostree_repo
    """

    cmd = "ostree prune --delete-commit %s --repo=%s" % (commit, repo_path)
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to delete commit %s from ostree repo %s" % (commit, repo_path)
        info_msg = "OSTree Delete Commit Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


def create_deployment(ref=None):
    """
    Create a new deployment while retaining the previous ones
    """

    if not ref:
        ref = constants.OSTREE_REF
    cmd = "ostree admin deploy %s --no-prune --retain" % ref

    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to create an ostree deployment for sysroot ref %s." % ref
        info_msg = "OSTree Deployment Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


def fetch_pending_deployment():
    """
    Fetch the deployment ID of the pending deployment
    :return: The deployment ID of the pending deployment
    """

    cmd = "ostree admin status | grep pending |awk '{printf $2}'"

    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to fetch ostree admin status."
        info_msg = "OSTree Admin Status Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    # Store the output of the above command in a string
    pending_deployment = output.stdout.decode('utf-8')

    return pending_deployment


def mount_new_deployment(deployment_dir):
    """
    Unmount /usr and /etc from the file system and remount it to directory
    <depoyment_dir>/usr and <depoyment_dir>/etc respectively
    :param deployment_dir: a path on the filesystem which points to the pending
    deployment
     example: /ostree/deploy/debian/deploy/<deployment_id>
    """
    try:
        new_usr_mount_dir = "%s/usr" % (deployment_dir)
        new_etc_mount_dir = "%s/etc" % (deployment_dir)
        sh.mount("--bind", "-o", "ro,noatime", new_usr_mount_dir, "/usr")
        sh.mount("--bind", "-o", "rw,noatime", new_etc_mount_dir, "/etc")
    except sh.ErrorReturnCode:
        LOG.warning("Mount failed. Retrying to mount /usr and /etc again after 5 secs.")
        time.sleep(5)
        try:
            sh.mount("--bind", "-o", "ro,noatime", new_usr_mount_dir, "/usr")
            sh.mount("--bind", "-o", "rw,noatime", new_etc_mount_dir, "/etc")
        except sh.ErrorReturnCode as e:
            msg = "Failed to re-mount /usr and /etc."
            info_msg = "OSTree Deployment Mount Error: Output: %s" \
                       % (e.stderr.decode("utf-8"))
            LOG.warning(info_msg)
            raise OSTreeCommandFail(msg)
    finally:
        # Handle the switch from bind mounts to symlinks for K8s versions.
        # Can be removed once the switch is complete.
        if os.path.isdir('/usr/local/kubernetes/current'):
            try:
                sh.mount("/usr/local/kubernetes/current/stage1")
                sh.mount("/usr/local/kubernetes/current/stage2")
            except sh.ErrorReturnCode:
                msg = "Failed to mount kubernetes. Please manually run these commands:\n" \
                      "sudo mount /usr/local/kubernetes/current/stage1\n" \
                      "sudo mount /usr/local/kubernetes/current/stage2\n"
                LOG.info(msg)


def delete_older_deployments():
    """
    Delete all older deployments after a reboot to save space
    """
    # Sample command and output that is parsed to get the list of
    # deployment IDs
    #
    # Command: ostree admin status | grep debian
    #
    # Output:
    #
    # * debian 3334dc80691a38c0ba6c519ec4b4b449f8420e98ac4d8bded3436ade56bb229d.2
    # debian 3334dc80691a38c0ba6c519ec4b4b449f8420e98ac4d8bded3436ade56bb229d.1 (rollback)
    # debian 3334dc80691a38c0ba6c519ec4b4b449f8420e98ac4d8bded3436ade56bb229d.0

    LOG.info("Inside delete_older_deployments of ostree_utils")
    cmd = "ostree admin status | grep debian"

    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to fetch ostree admin status."
        info_msg = "OSTree Admin Status Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    # Store the output of the above command in a string
    output_string = output.stdout.decode('utf-8')

    # Parse the string to get the latest commit for the ostree
    split_output_string = output_string.split()
    deployment_id_list = []
    for index, deployment_id in enumerate(split_output_string):
        if deployment_id == "debian":
            deployment_id_list.append(split_output_string[index + 1])

    # After a reboot, the deployment ID at the 0th index of the list
    # is always the active deployment and the deployment ID at the
    # 1st index of the list is always the fallback deployment.
    # We want to delete all deployments except the two mentioned above.
    # This means we will undeploy all deployments starting from the
    # 2nd index of deployment_id_list

    for index in reversed(range(2, len(deployment_id_list))):
        try:
            cmd = "ostree admin undeploy %s" % index
            output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
            info_log = "Deleted ostree deployment %s" % deployment_id_list[index]
            LOG.info(info_log)
        except subprocess.CalledProcessError as e:
            msg = "Failed to undeploy ostree deployment %s." % deployment_id_list[index]
            info_msg = "OSTree Undeploy Error: return code: %s , Output: %s" \
                       % (e.returncode, e.stderr.decode("utf-8"))
            LOG.info(info_msg)
            raise OSTreeCommandFail(msg)


def checkout_latest_ostree_commit(patch_sw_version):
    """
    Checkout the latest feed ostree commit to a temporary folder.
    """
    try:
        repo_src = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                              patch_sw_version)
        src_repo = OSTree.Repo.new(Gio.File.new_for_path(repo_src))
        src_repo.open(None)

        _, ref = OSTree.Repo.list_refs(src_repo, constants.OSTREE_REF, None)
        dest_base = constants.SOFTWARE_STORAGE_DIR
        dest_folder = constants.CHECKOUT_FOLDER
        fd = os.open(dest_base, os.O_DIRECTORY)
        is_checked_out = OSTree.Repo.checkout_at(src_repo, None, fd, dest_folder,
                                                 ref[constants.OSTREE_REF], None)
        LOG.info("Feed OSTree latest commit checked out %s", is_checked_out)
        os.close(fd)
    except GLib.Error as e:
        msg = "Failed to checkout latest commit to /opt/software/checked_out_commit directory."
        info_msg = "OSTree Checkout Error: %s" \
                   % (vars(e))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)
    finally:
        LOG.info("Checked out %s", is_checked_out)
        os.close(fd)


def install_deb_package(package_list):
    """
    Installs deb package to a checked out commit.
    :param package_name: The list of packages to be installed.
    """
    real_root = os.open("/", os.O_RDONLY)
    try:
        dest_base = constants.SOFTWARE_STORAGE_DIR
        dest_folder = constants.CHECKOUT_FOLDER
        dest_location = f"{dest_base}/{dest_folder}"
        # Copy deb packages
        tmp_location = f"{dest_location}/var/tmp"
        package_location = f"{dest_base}/packages"
        shutil.copy(package_location, tmp_location)
        os.chroot(dest_location)
        os.chdir('/')
        try:
            subprocess.check_output(["ln", "-sfn", "usr/etc", "etc"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.info("Failed ln command: %s", e.output)
        # change into the /var/tmp in the chroot
        os.chdir("/var/tmp")

        # install the debian package'
        try:
            for package in package_list:
                subprocess.check_output(["dpkg", "-i", package], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.info("Failed dpkg install command: %s", e.output)

        # still inside the chroot
        os.chdir('/')
        if os.path.isdir("/etc"):
            LOG.info(os.path.isdir("etc"))
            os.remove("etc")
    finally:
        os.fchdir(real_root)
        os.chroot(".")
        # now we can safely close this fd
        os.close(real_root)
        LOG.info("Exiting chroot")
        os.chdir("/home/sysadmin")
        LOG.info("Changed directory to /home/sysadmin")


def uninstall_deb_package(package_list):
    """
    Uninstalls deb package from a checked out commit.
    :param package_name: The list of packages to be uninstalled.
    """
    real_root = os.open("/", os.O_RDONLY)
    try:
        dest_base = constants.SOFTWARE_STORAGE_DIR
        dest_folder = constants.CHECKOUT_FOLDER
        dest_location = f"{dest_base}/{dest_folder}"
        # Copy deb packages
        tmp_location = f"{dest_location}/var/tmp"
        package_location = f"{dest_base}/packages"
        shutil.copy(package_location, tmp_location)
        os.chroot(dest_location)
        os.chdir('/')
        try:
            subprocess.check_output(["ln", "-sfn", "usr/etc", "etc"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.info("Failed ln command: %s", e.output)
        # change into the /var/tmp in the chroot
        os.chdir("/var/tmp")

        # uninstall the debian package'
        try:
            # todo(jcasteli): Identify if we need to remove any
            # /var/lib/dpkg/info/<package>.prerm files
            for package in package_list:
                subprocess.check_output(["dpkg", "--purge", package], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.info("Failed dpkg purge command: %s", e.output)

        # still inside the chroot
        os.chdir('/')
        if os.path.isdir("/etc"):
            LOG.info(os.path.isdir("etc"))
            os.remove("etc")

    finally:
        os.fchdir(real_root)
        os.chroot(".")
        # now we can safely close this fd
        os.close(real_root)
        LOG.info("Exiting chroot")
        os.chdir("/home/sysadmin")
        LOG.info("Changed directory to /home/sysadmin")


def write_to_feed_ostree(patch_name, patch_sw_version):
    """
    Write a new commit to the feed ostree.
    """
    try:
        repo_src = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                              patch_sw_version)
        src_repo = OSTree.Repo.new(Gio.File.new_for_path(repo_src))
        src_repo.open(None)

        _, ref = OSTree.Repo.list_refs(src_repo, constants.OSTREE_REF, None)

        OSTree.Repo.prepare_transaction(src_repo, None)
        OSTree.Repo.scan_hardlinks(src_repo, None)
        dest_base = constants.SOFTWARE_STORAGE_DIR
        dest_folder = constants.CHECKOUT_FOLDER
        dest_location = f"{dest_base}/{dest_folder}"

        build_dir = Gio.File.new_for_path(dest_location)
        mtree = OSTree.MutableTree()
        OSTree.Repo.write_directory_to_mtree(src_repo, build_dir, mtree, None, None)
        write_success, root = OSTree.Repo.write_mtree(src_repo, mtree, None)
        LOG.info("Writing to mutable tree: %s", write_success)
        subject = "Patch %s - Deploy Host completed" % (patch_name)
        commitSuccess, commit = OSTree.Repo.write_commit(src_repo,
                                                         ref[constants.OSTREE_REF],
                                                         subject,
                                                         None,
                                                         None,
                                                         root,
                                                         None)
        LOG.info("Writing to sysroot ostree: %s", commitSuccess)

        LOG.info("Setting transaction ref")
        OSTree.Repo.transaction_set_ref(src_repo, None, constants.OSTREE_REF, commit)
        LOG.info("Commiting ostree transaction")
        OSTree.Repo.commit_transaction(src_repo, None)
        LOG.info("Regenerating summary")
        OSTree.Repo.regenerate_summary(src_repo, None, None)

    except GLib.Error as e:
        msg = "Failed to write commit to feed ostree repo."
        info_msg = "OSTree Commit Write Error: %s" \
                   % (vars(e))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


def add_ostree_remote(major_release, nodetype):
    """
    Add a new ostree remote from a major release feed
    :param major_release: major release corresponding to the new remote
    :param nodetype: type of the node where the software agent is running
    """
    rel_name = "rel-%s" % major_release
    if nodetype == "controller":
        feed_ostree_url = "file://%s/%s/ostree_repo/" % (
            constants.FEED_OSTREE_BASE_DIR, rel_name)
    else:
        feed_ostree_url = "http://%s:8080/feed/%s/ostree_repo/" % (
            constants.CONTROLLER_FLOATING_HOSTNAME, rel_name)
    cmd = ["ostree", "remote", "add", "--no-gpg-verify",
           "--if-not-exists", rel_name, feed_ostree_url, constants.OSTREE_REF]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        LOG.exception("Error adding %s ostree remote: %s" % (major_release, str(e)))
        raise
    return rel_name


def delete_ostree_remote(remote):
    """
    Delete an ostree remote
    :param remote: remote name to be deleted
    """
    cmd = ["ostree", "remote", "delete", "--if-exists", remote]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        LOG.exception("Error deleting %s ostree remote: %s" % (remote, str(e)))


def check_commit_id(remote, commit_id):
    """
    Check if commit_id matches with the commit_id from the remote ostree_repo
    :param remote: ostree remote name to be checked against
    :param commit_id: commit_id sent by the controller to the agent
    :return: boolean indicating if commit_id matches with remote commit_id
    """
    commit_id_match = False
    cmd = "ostree remote summary %s | grep 'Latest Commit' -A1" % remote
    try:
        # output should be similar to:
        # Latest Commit (<n> bytes):
        #       <ostree_commit_id>
        output = subprocess.check_output(cmd, shell=True, text=True,
                                         stderr=subprocess.STDOUT).strip()
        remote_commit_id = output.split("\n")[1].strip()
        commit_id_match = commit_id == remote_commit_id
    except subprocess.CalledProcessError as e:
        LOG.exception("Error getting remote commit_id: %s: %s" % (str(e), e.stdout))
    return commit_id_match
