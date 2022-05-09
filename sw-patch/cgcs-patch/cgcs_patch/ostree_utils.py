"""
Copyright (c) 2022 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import subprocess

from cgcs_patch import constants


def get_ostree_latest_commit(ostree_ref, repo_path):
    """
    Query ostree using ostree log <ref> --repo=<path>

    :param ostree_ref: the ostree ref.
     example: starlingx
    :param repo_path: the path to the ostree repo:
     example: /var/www/pages/feed/rel-22.06/ostree_repo
    :return: a tuple of the most recent commit and checksum
    """

    # Sample command and output that is parsed to get the commit and checksum
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
    output = subprocess.run(cmd, shell=True, check=True, capture_output=True)

    # Store the output of the above command in a string
    output_string = output.stdout.decode('utf-8')

    # Parse the string to get the latest commit and checksum for that ostree
    split_output_string = output_string.split()
    latest_commit = split_output_string[1]
    latest_checksum = split_output_string[3]
    return (latest_commit, latest_checksum)


def get_feed_latest_commit(patch_sw_version):
    """
    Query ostree feed using ostree log <ref> --repo=<path>

    :param patch_sw_version: software version for the feed
     example: 22.06
    :return: a tuple of the most recent commit and checksum
     for that feed
    """
    repo_path = "%s/rel-%s/ostree_repo" % (constants.FEED_OSTREE_BASE_DIR,
                                           patch_sw_version)
    return get_ostree_latest_commit(constants.OSTREE_REF, repo_path)


def get_sysroot_latest_commit():
    """
    Query ostree sysroot to determine the currently active commit
    :return: a tuple of the commit and checksum for sysroot
    """
    return get_ostree_latest_commit(constants.OSTREE_REF, constants.SYSROOT_OSTREE)
