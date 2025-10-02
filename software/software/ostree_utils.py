"""
Copyright (c) 2023-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import configparser
import filecmp
import glob
import logging
import os
import re
import sh
import shutil
import subprocess
import time

import gi
gi.require_version('OSTree', '1.0')
from gi.repository import Gio
from gi.repository import GLib
from gi.repository import OSTree  # pylint: disable=E0611

from software import constants
from software.exceptions import OSTreeCommandFail
from tsconfig.tsconfig import subfunctions

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


def add_gpg_verify_false(repo_path=constants.SYSROOT_OSTREE):
    # TODO(mmachado): remove once gpg is enabled
    # Modify the ostree configuration to disable gpg-verify
    config_path = os.path.join(repo_path, constants.OSTREE_CONFIG)
    if os.path.exists(config_path):
        config = configparser.ConfigParser()
        config.read(config_path)

        for section in config.sections():
            if section.startswith("remote ") and \
               constants.OSTREE_GPG_VERIFY not in config[section]:
                config[section][constants.OSTREE_GPG_VERIFY] = "false"

        with open(config_path, 'w') as file:
            config.write(file, space_around_delimiters=False)
    else:
        msg = f"Ostree config file: {config_path} does not exist"
        raise OSTreeCommandFail(msg)


def add_aux_remote(repo_path, patch_sw_version):
    """
    Adds "controller-feed" auxiliary remote to non-controller nodes
    and pulls commit metadata

    :param repo_path: Path where the remote will be added
    :param patch_sw_version: software version for the feed
     example: 22.06
    """

    # Add before to guarantee that gpg_verify is disabled for debian remote
    add_gpg_verify_false()

    add_remote_cmd = "ostree --repo=%s remote add --set=gpg-verify=false %s " \
                     "%s/rel-%s/ostree_repo" % (repo_path, constants.OSTREE_AUX_REMOTE,
                                                constants.FEED_OSTREE_URL, patch_sw_version)
    try:
        subprocess.run(add_remote_cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        info_msg = "OSTree log Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        msg = "Failed to add remote: %s." % constants.OSTREE_AUX_REMOTE
        raise OSTreeCommandFail(msg)

    add_gpg_verify_false()


def pull_aux_remote(repo_path):
    pull_cmd = "ostree --repo=%s pull %s:starlingx --commit-metadata-only --depth=-1" % \
               (repo_path, constants.OSTREE_AUX_REMOTE)
    try:
        subprocess.run(pull_cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        info_msg = "OSTree log Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        msg = "Failed to pull from remote: %s." % constants.OSTREE_AUX_REMOTE
        raise OSTreeCommandFail(msg)


def get_feed_latest_commit(patch_sw_version, repo_path=None):
    """
    Query ostree feed using ostree log <ref> --repo=<path>

    :param patch_sw_version: software version for the feed
     example: 22.06
    :param repo_path: path of the ostree repo if specified
    :return: The latest commit for the feed repo
    """

    if repo_path == constants.OSTREE_AUX_REMOTE_PATH:
        check_remote_cmd = "ostree --repo=%s remote list | grep -w %s" % \
                           (repo_path, constants.OSTREE_AUX_REMOTE)
        try:
            subprocess.run(check_remote_cmd, shell=True, check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # If the remote does not exist, add it
            add_aux_remote(repo_path, patch_sw_version)

        pull_aux_remote(repo_path)
        remote_ref = "%s:%s" % (constants.OSTREE_AUX_REMOTE, constants.OSTREE_REF)

        return get_ostree_latest_commit(remote_ref, repo_path)
    else:
        repo_path = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                               patch_sw_version)
        return get_ostree_latest_commit(constants.OSTREE_REF, repo_path)


def get_sysroot_latest_commit():
    """
    Query ostree sysroot to determine the currently active commit
    :return: The latest commit for sysroot repo
    """
    return get_ostree_latest_commit(constants.SYSROOT_OSTREE_REF, constants.SYSROOT_OSTREE)


def get_all_feed_commits(patch_sw_version):
    """
    Query ostree feed using ostree log <ref> --repo=<path>
    :return: All the commit ids for feed repo
    """
    repo_path = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                           patch_sw_version)
    cmd = "ostree log %s --repo=%s | grep -i commit" % (constants.OSTREE_REF, repo_path)
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
    feed_commits = output_string.split("\n")
    all_commits = [x.split()[1] for x in feed_commits if x]
    return all_commits


def get_latest_deployment_commit():
    """
    Get the latest deployment commit ID (pending or active)
    :return: The commit ID associated with the latest commit or None
    """

    # Sample command and output that is parsed to get the latest commit
    # associated with the deployment
    #
    # Command: ostree admin status
    #
    # Output:
    #
    # debian 0658a62854647b89caf5c0e9ed6ff62a6c98363ada13701d0395991569248d7e.0 (pending)
    # origin refspec: starlingx
    # * debian a5d8f8ca9bbafa85161083e9ca2259ff21e5392b7595a67f3bc7e7ab8cb583d9.0
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

    match = re.search(r'\b(\w+)\.\d+\b', output_string)
    if match:
        return match.group(1)
    return None


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

    # Make sure gpg-verify is disabled
    add_gpg_verify_false()

    cmd = "ostree pull %s --depth=-1"
    ref_cmd = ""
    if not remote:
        ref = constants.OSTREE_REMOTE
    else:
        ref = "%s:%s" % (remote, constants.OSTREE_REF)
        cmd += " --mirror"
        ref_cmd = "ostree refs --force --create=%s %s" % (ref, constants.OSTREE_REF)

    try:
        process = subprocess.run(cmd % ref, shell=True, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to pull from %s remote into sysroot ostree" % ref
        err_msg = "OSTree Pull Error: return code: %s, Output: %s" \
                  % (e.returncode, e.stderr.strip())
        LOG.exception(err_msg)
        raise OSTreeCommandFail(msg)

    # Log to help identify errors
    msg = "Remote pull output: %s" % process.stdout.strip()
    LOG.info(msg)

    if ref_cmd:
        try:
            subprocess.run(ref_cmd, shell=True, check=True, text=True, capture_output=True)
        except subprocess.CalledProcessError as e:
            msg = "Failed to create ref %s for remote %s" % (ref, remote)
            err_msg = "OSTree Ref Error: return code: %s, Output: %s" \
                      % (e.returncode, e.stderr.strip())
            LOG.exception(err_msg)
            raise OSTreeCommandFail(msg)


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


def add_tombstone_commit_if_prepatched(ostree_ref, repo_path):
    """
    Check if the ostree repo history is incomplete, if yes, adds a
    tombstone commit file to avoid inconsistence in the repo.
    :param ostree_ref: the ostree ref.
        example: starlingx
    :param repo_path: the path to the ostree repo:
        example: /var/www/pages/feed/rel-24.09/ostree_repo
    :return: True if the tombstone file was created, false if not.
    """

    cmd = "ostree log %s --repo=%s" % (ostree_ref, repo_path)
    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        info_msg = "OSTree log Error: return code: %s , Output: %s" \
                % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        msg = "Failed to fetch ostree log (tombstone) for %s." % repo_path
        raise OSTreeCommandFail(msg)

    # Decode the ostree log
    output_string = output.stdout.decode('utf-8')

    # Add tombstone file
    if constants.OSTREE_HISTORY_NOT_FETCHED.lower() in output_string.lower():
        parent_matches = re.findall(r'^Parent:\s+(\S+)', output_string, re.MULTILINE)
        if parent_matches:
            oldest_parent = parent_matches[-1]

            obj_dir = os.path.join(repo_path, "objects", oldest_parent[:2])
            tombstone_file = os.path.join(obj_dir, oldest_parent[2:] + ".tombstone-commit")

            if os.path.isfile(tombstone_file):
                LOG.info("Tombstone file already exists: %s", tombstone_file)
                return False

            os.makedirs(obj_dir, exist_ok=True)
            with open(tombstone_file, "a"):
                LOG.info("Tombstone file created: %s", tombstone_file)

            # Add tombstone-commits in Ostree config file
            config_path = os.path.join(repo_path, "config")
            if os.path.exists(config_path):
                config = configparser.ConfigParser()
                config.read(config_path)
                config.set("core", "tombstone-commits", "true")

            with open(config_path, 'w') as file:
                config.write(file, space_around_delimiters=False)

            return True
    return False


def sync_boot_entries():
    """
    TODO(mmachado): Remove if Missing bootloader entry error is fixed upstream
    Syncs the contents of /boot/loader.0/entries/ to /boot/loader/entries/.
    If the contents are different, the contents of /boot/loader.0/entries/
    are copied to /boot/loader/entries/.
    """

    try:
        # Get the list of files in both directories
        boot_entries_files = os.listdir("/boot/loader/entries/")
        boot_entries_0_files = os.listdir("/boot/loader.0/entries/")

        # Check if the contents are different
        if set(boot_entries_files) != set(boot_entries_0_files):
            # Copy the contents of /boot/loader.0/entries/ to /boot/loader/entries/
            shutil.rmtree("/boot/loader/entries/")
            shutil.copytree("/boot/loader.0/entries/", "/boot/loader/entries/")
            info_msg = "Boot entries synchronized"
            LOG.info(info_msg)
    except Exception as e:
        LOG.exception("Failed to sync boot entries: %s" % str(e))


def create_deployment(ref=None):
    """
    Create a new deployment while retaining the previous ones
    """

    sync_boot_entries()

    if not ref:
        ref = constants.SYSROOT_OSTREE_REF
    cmd = "ostree admin deploy %s --no-prune --retain" % ref

    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to create an ostree deployment for sysroot ref %s." % ref
        info_msg = "OSTree Deployment Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    boot_cmd = ["grub-editenv", "/boot/efi/EFI/BOOT/boot.env", "set", "default=0"]
    try:
        subprocess.run(boot_cmd, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        LOG.info("Failed to update default grub entry to 0: %s", e.stderr)
        raise


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


def fetch_active_deployment():
    """
    Fetch the deployment ID of the active deployment
    :return: The deployment ID of the active deployment
    """

    cmd = "ostree admin status | grep %s | awk '{printf $3}'" % constants.OSTREE_ACTIVE_DEPLOYMENT_TAG

    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to fetch ostree admin status for active deployment."
        info_msg = "OSTree Admin Status Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    # Store the output of the above command in a string
    active_deployment = output.stdout.decode('utf-8')

    return active_deployment


def create_bind_mount(source, target, permissions=constants.READ_ONLY_PERMISSION):
    """
    Create a bind mount.
    :param source: The source directory
    :param target: The directory where the bind will be mounted
    :param permissions: The access permissions
    """
    LOG.info("Creating bind mount from: %s, to: %s, with permissions: %s"
             % (source, target, permissions))

    try:
        sh.mount("--bind", "-o", permissions, source, target)
    except sh.ErrorReturnCode:
        LOG.warning("Mount failed. Retrying to mount %s again after 5 secs." % target)
        time.sleep(5)
        try:
            sh.mount("--bind", "-o", permissions, source, target)
        except sh.ErrorReturnCode as e:
            msg = "Failed to re-mount %s" % target
            info_msg = "OSTree Deployment Mount Error: Output: %s" % (e.stderr.decode("utf-8"))
            LOG.warning(info_msg)
            raise OSTreeCommandFail(msg)


def mount_new_deployment(pending_dir, active_dir):
    """
    Create the following mounts used by an inservice patch:
    1) /usr                 -> <pending_dir>/usr
    2) /etc                 -> <pending_dir>/etc
    3) <active_dir>/usr/etc -> <pending_dir>/usr/etc
    4) <active_dir>/etc     -> <pending_dir>/etc
    Also mounts K8s version files
    :param pending_dir: a path on the filesystem which points to the pending
    deployment (e.g.: /ostree/deploy/debian/deploy/<deployment_id>)
    :param active_dir: a path on the filesystem which points to the active
    deployment
    """
    try:
        new_usr_mount_dir = "%s%s" % (pending_dir, constants.USR)
        new_etc_mount_dir = "%s%s" % (pending_dir, constants.ETC)
        new_usr_etc_mount_dir = "%s%s" % (pending_dir, constants.USR_ETC)
        act_usr_etc_mount_dir = "%s%s" % (active_dir, constants.USR_ETC)
        act_etc_mount_dir = "%s%s" % (active_dir, constants.ETC)

        create_bind_mount(new_usr_mount_dir, constants.USR)
        create_bind_mount(new_etc_mount_dir, constants.ETC, constants.READ_WRITE_PERMISSION)
        create_bind_mount(new_usr_etc_mount_dir, act_usr_etc_mount_dir)
        create_bind_mount(new_etc_mount_dir, act_etc_mount_dir)
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


def delete_older_deployments(delete_pending=False):
    """
    Delete all older deployments after a reboot to save space
    """
    # Sample command and output that is parsed to get the list of
    # deployment IDs
    #
    # Command: ostree admin status | egrep 'debian [a-z0-9]+'
    #
    # Output:
    #
    # * debian 9a4d8040800f8cf9191ca3401f8006f3df5760b33d78f931309b5bb5db062ab3.2
    #   debian 9a4d8040800f8cf9191ca3401f8006f3df5760b33d78f931309b5bb5db062ab3.1 (rollback)
    #   debian 9a4d8040800f8cf9191ca3401f8006f3df5760b33d78f931309b5bb5db062ab3.0

    cmd = "ostree admin status | egrep 'debian [a-z0-9]+'"
    try:
        output = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to fetch ostree admin status."
        info_msg = "OSTree Admin Status Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)

    # Find the active deployment (which usually is the first, but there are exceptions)
    # and once found attempt to delete deployments after it in the list, except the rollback
    delete_deployments = False
    deployments_to_delete = []
    for index, deployment in enumerate(output.stdout.strip().split("\n")):
        if delete_pending and "pending" in deployment:
            deployments_to_delete.append(index)
        if delete_deployments and "rollback" not in deployment:
            deployments_to_delete.append(index)
        if "*" in deployment:
            LOG.info("Active deployment %s: %s", index, deployment)
            delete_deployments = True

    if not deployments_to_delete:
        LOG.info("No older deployments to delete")
        return True

    for index in reversed(deployments_to_delete):
        try:
            cmd = "ostree admin undeploy %s" % index
            output = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            info_log = "Deleted ostree deployment %s: %s" % (index, output.stdout)
            LOG.info(info_log)
        except subprocess.CalledProcessError as e:
            msg = "Failed to undeploy ostree deployment %s." % index
            info_msg = "OSTree Undeploy Error: return code: %s , Output: %s" \
                       % (e.returncode, e.stderr)
            LOG.info(info_msg)
            raise OSTreeCommandFail(msg)
    return True


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


def checkout_commit_to_dir(ostree_repo, commit_id, dest_folder, sub_path=None):
    """
    Checkout the commit to a given directory.
    :param ostree_repo: The path of the ostree repo.
    :param commit_id: The id of the commit to checkout.
    :param dest_folder: The path to the destination folder.
    :param sub_path: The sub path to checkout.
    """

    try:
        cmd = "ostree checkout --union --repo=%s %s %s" % (ostree_repo, commit_id, dest_folder)
        if sub_path is not None:
            cmd = "%s %s" % (cmd, "--subpath=%s" % sub_path)
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to checkout %s to %s." % (commit_id, dest_folder)
        info_msg = "OSTree Checkout Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)


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


def add_ostree_remote(major_release, nodetype, replace_default_remote=False):
    """
    Add a new ostree remote from a major release feed
    :param major_release: major release corresponding to the new remote
    :param nodetype: type of the node where the software agent is running
    :param replace_default_remote: indicate if default remote should be replaced instead,
        should be used at the end of a successful major release deployment point the default
        remote to the new major release feed
    :return: the name of the created remote or None if error
    """
    remote_name = rel_name = "%s-%s" % (constants.RELEASE_PREFIX, major_release)
    if replace_default_remote:
        remote_name = constants.OSTREE_REMOTE
    if nodetype == "controller":
        feed_ostree_url = "file://%s/%s/ostree_repo/" % (
            constants.FEED_OSTREE_BASE_DIR, rel_name)
    else:
        feed_ostree_url = "http://%s:8080/feed/%s/ostree_repo/" % (
            constants.CONTROLLER_FLOATING_HOSTNAME, rel_name)
    try:
        # delete the remote if existent and add: this is needed due
        # to an odd behavior/bug from ostree, that does not update
        # sysroot commit-id correctly when using an existing remote
        cmd = ["ostree", "remote", "delete", "--if-exists", remote_name]
        subprocess.check_call(cmd)
        cmd = ["ostree", "remote", "add", "--no-gpg-verify",
               remote_name, feed_ostree_url, constants.OSTREE_REF]
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        LOG.exception("Error adding %s ostree remote: %s" % (major_release, str(e)))
        return None

    add_gpg_verify_false()

    # pull from ostree remote
    pull_ostree_from_remote(remote_name)
    return remote_name


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
        raise


def delete_ostree_ref(ref):
    """
    Delete an ostree ref
    :param ref: ref name to be deleted
    """
    # if ref doesn't exist the command doesn't return error
    cmd = ["ostree", "refs", "--delete", ref]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError as e:
        LOG.exception("Error deleting %s ostree ref: %s" % (ref, str(e)))
        raise


def check_commit_id(remote, commit_id):
    """
    Check if commit_id matches with the commit_id from the remote ostree_repo
    :param remote: ostree remote name to be checked against
    :param commit_id: commit_id sent by the controller to the agent
    :return: boolean indicating if commit_id matches with remote commit_id
    """
    # pull remote commit metadata, if not already pulled
    pull_ostree_from_remote(remote)

    # get remote commit id
    cmd = ["ostree", "rev-parse", "%s:%s" % (remote, constants.OSTREE_REF)]
    remote_commit_id = None
    try:
        remote_commit_id = subprocess.check_output(cmd, text=True).strip()
    except subprocess.CalledProcessError as e:
        LOG.exception("Error parsing commit metadata: %s" % str(e))

    return remote_commit_id == commit_id


def delete_temporary_refs_and_remotes():
    """Delete temporary refs and remotes created during major release deploym"""
    success = True
    refs = ""
    cmd = ["ostree", "refs"]
    try:
        refs = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        LOG.exception("Failed listing refs: %s" % str(e))
        success = False

    remotes = ""
    cmd = ["ostree", "remote", "list"]
    try:
        remotes = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError as e:
        LOG.exception("Failed listing remotes: %s" % str(e))
        success = False

    for ref in refs.split("\n"):
        if constants.RELEASE_PREFIX in ref:
            try:
                delete_ostree_ref(ref)
                LOG.info("Deleted temporary ref %s." % ref)
            except Exception as e:
                LOG.exception("Failed to delete ref %s: %s" % (ref, str(e)))
                success = False

    for remote in remotes.split("\n"):
        if constants.RELEASE_PREFIX in remote:
            try:
                delete_ostree_remote(remote)
                LOG.info("Deleted temporary remote %s." % remote)
            except Exception as e:
                LOG.exception("Failed to delete remote %s: %s" % (remote, str(e)))
                success = False

    if not success:
        LOG.error("Failure deleting temporary refs and remotes, please cleanup manually.")
    return success


def update_deployment_kernel_env():
    """
    Update the /boot/1/kernel.env after creating a deployment
    """
    try:
        # copy /boot/2/kernel.env to /boot/1/kernel.env
        # this is to preserve args (ie: apparmor)
        # if the files are identical, do nothing
        if not filecmp.cmp("/boot/1/kernel.env",
                           "/boot/2/kernel.env",
                           shallow=False):
            shutil.copy2("/boot/2/kernel.env",
                         "/boot/1/kernel.env")
        # Determine the appropriate kernel for this env
        desired_kernel = None
        for kernel in glob.glob(os.path.join("/boot/1", "vmlinuz*-amd64")):
            kernel_entry = os.path.basename(kernel)
            # If we are running in lowlatency mode, we want the rt-amd64 kernel
            if 'lowlatency' in subfunctions and 'rt-amd64' in kernel_entry:
                desired_kernel = kernel_entry
                break
            # If we are not running lowlatency we want the entry that does NOT contain rt-amd64
            if 'lowlatency' not in subfunctions and 'rt-amd64' not in kernel_entry:
                desired_kernel = kernel_entry
                break
        if desired_kernel is None:   # This should never happen
            LOG.warning("Unable to find a valid kernel under /boot/1")
        else:
            # Explicitly update /boot/1/kernel.env using the
            # /usr/local/bin/puppet-update-grub-env.py utility
            LOG.info("Updating /boot/1/kernel.env to:%s", desired_kernel)
            cmd = "python /usr/local/bin/puppet-update-grub-env.py --set-kernel %s" % desired_kernel
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to run puppet-update-grub-env.py"
        info_msg = "OSTree Post-Deployment Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)
    except Exception as e:
        msg = "Failed to manually update /boot/1/kernel.env. Err=%s" % str(e)
        LOG.info(msg)
        raise OSTreeCommandFail(msg)
