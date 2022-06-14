"""
Copyright (c) 2022 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
import subprocess

from cgcs_patch import constants
from cgcs_patch.exceptions import OSTreeCommandFail

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


def pull_ostree_from_remote():
    """
    Pull from remote ostree to sysroot ostree
    """

    cmd = "ostree pull %s --depth=-1" % constants.OSTREE_REMOTE

    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to pull from %s remote into sysroot ostree" % constants.OSTREE_REMOTE
        info_msg = "OSTree Pull Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
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


def create_deployment():
    """
    Create a new deployment while retaining the previous ones
    """

    cmd = "ostree admin deploy %s --no-prune --retain" % constants.OSTREE_REF
    try:
        subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to create an ostree deployment for sysroot ref %s." % constants.OSTREE_REF
        info_msg = "OSTree Deployment Error: return code: %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.info(info_msg)
        raise OSTreeCommandFail(msg)