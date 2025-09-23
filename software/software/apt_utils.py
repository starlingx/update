"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
import subprocess

from software import constants
from software.exceptions import APTOSTreeCommandFail

LOG = logging.getLogger('main_logger')


def initialize_apt_ostree(feed_dir):
    """
    Initialize an apt Debian package archive.

    :param feed_dir: apt package feed directory
    """
    try:
        subprocess.run(
            ["apt-ostree", "repo", "init",
             "--feed", str(feed_dir),
             "--release", constants.DEBIAN_RELEASE,
             "--origin", constants.DEBIAN_ORIGIN],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to initialize apt-ostree repo"
        info_msg = "\"apt-ostree repo init\" error: return code %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def package_list_upload(feed_dir, sw_release, package_list):
    """
    Upload a Debian package to an apt repository.

    :param feed_dir: apt package feed directory
    :param sw_release: Uploading patch release version (MM.mm.pp)
    :param package_list: Debian package list
    """
    try:
        subprocess.run(
            ["apt-ostree", "repo", "add",
             "--feed", str(feed_dir),
             "--release", constants.DEBIAN_RELEASE,
             "--component", sw_release,
             *package_list],
            check=True,
            capture_output=True)

        LOG.info("package list uploaded")
    except subprocess.CalledProcessError as e:
        packages = " ".join(package_list)
        msg = "Failed to upload package list: %s" % packages
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
        error = e.stderr.decode("utf-8")

        if "--component is not know" in error:
            msg = "Component %s not found, there is no package to delete" % sw_release
            LOG.info(msg)
            return

        msg = "Failed to remove package."
        info_msg = "\"apt-ostree repo remove\" error: return code %s , Output: %s" \
                   % (e.returncode, error)
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def component_remove(pkg_feed_dir, component):
    """
    Remove the component with all packages from the
    apt repository.

    :param pkg_feed_dir: apt package feed directory
    :param component: Component name in format MM.mm.pp
    """

    try:
        msg = "Removing component: %s" % component
        LOG.info(msg)

        subprocess.run(
            ["apt-ostree", "repo", "remove",
                "--feed", str(pkg_feed_dir),
                "--release", constants.DEBIAN_RELEASE,
                "--component", component],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to remove component."
        info_msg = "\"apt-ostree repo remove component\" error: return code %s , Output: %s" \
                   % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def run_install(repo_dir, sw_version, sw_release, packages, pre_bootstrap=False):
    """
    Run Debian package upgrade.

    :param repo_dir: the path to the ostree repo
    :param sw_version: System version (MM.mm)
    :param sw_release: Patch release version (MM.mm.pp)
    :param packages: List of Debian packages
    """
    LOG.info("Running apt-ostree install")

    if pre_bootstrap:
        package_feed = "file:///var/www/pages/updates/debian/rel-%s/ %s %s" \
            % (sw_version, constants.DEBIAN_RELEASE, sw_release)
    else:
        package_feed = "http://controller:8080/updates/debian/rel-%s/ %s %s" \
            % (sw_version, constants.DEBIAN_RELEASE, sw_release)

    packages = " ".join(packages)

    try:
        subprocess.run(
            ["apt-ostree", "compose", "install",
             "--repo", repo_dir,
             "--branch", "starlingx",
             "--feed", package_feed,
             "--component", sw_release,
             packages],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to install packages."
        info_msg = "\"apt-ostree compose install\" error: return code %s , Output: %s" \
            % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)


def run_rollback(repo_dir, commit):
    """
    Run apt-ostree rollback.

    :param repo_dir: the path to the ostree repo
    :param commit: the commit to rollback to
    """
    try:
        LOG.info("Running apt-ostree rollback")

        subprocess.run(
            ["apt-ostree", "compose", "rollback",
             "--repo", repo_dir,
             "--branch", "starlingx",
             commit],
            check=True,
            capture_output=True)
    except subprocess.CalledProcessError as e:
        msg = "Failed to rollback commit."
        info_msg = "\"apt-ostree compose rollback\" error: return code %s , Output: %s" \
            % (e.returncode, e.stderr.decode("utf-8"))
        LOG.error(info_msg)
        raise APTOSTreeCommandFail(msg)
