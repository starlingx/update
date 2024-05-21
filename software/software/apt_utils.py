"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
import subprocess

from software import constants
import software.config as cfg
from software.exceptions import APTOSTreeCommandFail

LOG = logging.getLogger('main_logger')


def package_upload(feed_dir, sw_release, package):
    """
    Upload a Debian package to an apt repository.

    :param feed_dir: apt package feed directory
    :param sw_release: Uploading patch release version (MM.mm.pp)
    :param package: Debian package
    """
    try:
        msg = "Uploading package: %s" % package
        LOG.info(msg)

        subprocess.run(
            ["apt-ostree", "repo", "add",
             "--feed", str(feed_dir),
             "--release", constants.DEBIAN_RELEASE,
             "--component", sw_release,
             package],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to upload package: %s" % package
        info_msg = "\"apt-ostree repo add\" error: return code %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def package_remove(feed_dir, sw_release, packages):
    """
    Remove a list of Debian packages from the
    apt repository.

    :param feed_dir: apt package feed directory
    :param sw_release: Patch release version (MM.mm.pp)
    :param package: Debian package
    """
    try:
        for package in packages:
            msg = "Removing package: %s" % package
            LOG.info(msg)

            subprocess.run(
                ["apt-ostree", "repo", "remove",
                 "--feed", str(feed_dir),
                 "--release", constants.DEBIAN_RELEASE,
                 "--component", sw_release,
                 package],
                check=True,
                capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to remove package."
        info_msg = "\"apt-ostree repo remove\" error: return code %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def run_install(repo_dir, sw_release, packages):
    """
    Run Debian package upgrade.

    :param repo_dir: the path to the ostree repo
    :param sw_release: Patch release version (MM.mm.pp)
    :param packages: List of Debian packages
    """
    try:
        LOG.info("Running apt-ostree install")

        packages = " ".join(packages)
        subprocess.run(
            ["apt-ostree", "compose", "install",
             "--repo", repo_dir,
             "--branch", "starlingx",
             "--feed", cfg.package_feed,
             "--component", sw_release,
             packages],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to install packages."
        info_msg = "\"apt-ostree compose intstall\" error: return code %s , Output: %s" \
            % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)
