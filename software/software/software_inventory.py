"""
Copyright (c) 2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import subprocess
import xml.etree.ElementTree as ET
import gi
gi.require_version('OSTree', '1.0')
from gi.repository import OSTree
from gi.repository import Gio

from software.exceptions import APTOSTreeCommandFail
from software.exceptions import BranchNotFound
from software.exceptions import MetadataFail
from software.release_data import get_SWReleaseCollection
from software.software_functions import LOG

from software import apt_utils
from software import constants
from software import ostree_utils
from software import states
from software import utils


def get_sw_version(path="/etc/build.info"):
    with open(path) as f:
        for line in f:
            if line.startswith("SW_VERSION="):
                return line.split("=", 1)[1].strip().strip('"')
    return None


def get_release_by_commit(repo, commit):
    """Get the branch name whose tip matches the given commit."""
    if not commit or not commit.strip():
        raise ValueError("commit must not be empty")

    try:
        _, refs = repo.list_refs(None, None)
    except Exception as e:
        raise RuntimeError("Failed to list refs: %s" % e)

    for ref, checksum in refs.items():
        if checksum == commit:
            if ref != SoftwareInventoryManager.DEPLOY_BRANCH:
                return ref
    return None


def get_top_commit(repo_path, branch):
    try:
        commit = subprocess.check_output(
            ["ostree", "rev-parse", "--repo", repo_path, branch],
            text=True).strip()
    except subprocess.CalledProcessError:
        raise BranchNotFound(branch)
    return commit


def get_content_checksum(repo_path, branch):
    # get content checksum of the latest commit of software release branch
    try:
        top_commit = get_top_commit(repo_path, branch)
    except BranchNotFound:
        return None

    repo = OSTree.Repo.new(Gio.File.new_for_path(repo_path))
    repo.open(None)
    _, commit = repo.load_variant(OSTree.ObjectType.COMMIT, top_commit)
    return OSTree.commit_get_content_checksum(commit)


def commit_packages_to_branch(feed_repo, sw_version, sw_release, packages, pre_bootstrap):
    """commit patch packages to deployable branch"""
    # Get metapackages .deb packages, which are named 'meta-<metapackage-id>'
    # packages = [f"meta-{pkg.component}" for pkg in mp_deploy_set.metapackages]
    if packages is None:
        msg = "Unable to determine packages to install"
        LOG.error(msg)
        raise MetadataFail(msg)

    # Install debian package through apt-ostree
    try:
        apt_utils.run_install(
            feed_repo,
            sw_version,
            sw_release,
            packages,
            pre_bootstrap)
    except APTOSTreeCommandFail:
        msg = "Failed to install Debian packages."
        LOG.exception(msg)
        raise


# this update_patch_matadata can be removed once all releases are directly
# referred by release-id
def update_patch_metadata(release_id, commit_id):

    def add_text_tag_to_xml(parent, tag, text):
        '''Add text to tag. Create it if it does not exist'''
        element = parent.find(tag)
        if element is None:
            element = ET.SubElement(parent, tag)
        element.text = text
        return element

    metadata_dir = states.UPLOADING_DIR
    metadata_file = "%s/%s-metadata.xml" % (metadata_dir, release_id)

    # Update metadata
    tree = ET.parse(metadata_file)
    root = tree.getroot()

    contents = ET.SubElement(root, constants.CONTENTS_TAG)
    ostree = ET.SubElement(contents, constants.OSTREE_TAG)
    add_text_tag_to_xml(ostree, constants.NUMBER_OF_COMMITS_TAG, "1")
    # skipping writing base commit
    # base = ET.SubElement(ostree, constants.BASE_TAG)
    # add_text_tag_to_xml(base, constants.COMMIT_TAG, latest_commit)
    # add_text_tag_to_xml(base, constants.CHECKSUM_TAG, "")
    commit1 = ET.SubElement(ostree, constants.COMMIT1_TAG)
    add_text_tag_to_xml(commit1, constants.COMMIT_TAG, commit_id)
    add_text_tag_to_xml(commit1, constants.CHECKSUM_TAG, "")

    ET.indent(tree, '  ')
    with open(metadata_file, "wb") as outfile:
        t = ET.tostring(root)
        outfile.write(t)

    LOG.info("Latest feed commit: %s added to metadata file" % commit_id)


class SoftwareInventoryManager():
    DEPLOY_BRANCH = "starlingx"

    def __init__(self, sw_ver=None):
        if sw_ver is None:
            sw_ver = get_sw_version()

        self.sw_ver = sw_ver
        self.repo_path = utils.get_feed_repo_path(self.sw_ver)
        self.repo = ostree_utils.get_repo(self.repo_path)

    def get_branch_commit(self, branch):
        return get_top_commit(self.repo_path, branch)

    def get_deployed_commit(self):
        return self.get_branch_commit(self.DEPLOY_BRANCH)

    def get_branches(self):
        """Get all branch names from the ostree repo."""
        try:
            output = subprocess.check_output(
                ["ostree", "refs", "--repo", self.repo_path],
                stderr=subprocess.STDOUT, text=True)
            res = set(output.strip().splitlines())
        except subprocess.CalledProcessError:
            res = set()
        return list(res)

    def list_sw_release(self, branch_name=None):
        """List software releases included in a branch.

        :param branch_name: branch to walk; defaults to DEPLOY_BRANCH
        :return: list of software release names (newest to oldest)
        """
        if branch_name is None:
            branch_name = self.DEPLOY_BRANCH

        releases = []
        commits = ostree_utils.get_commits(self.repo, branch_name)
        for commit in commits:
            sw_release = get_release_by_commit(self.repo, commit)
            if sw_release and sw_release != self.DEPLOY_BRANCH:
                releases.append(sw_release)
        return releases

    def get_release_by_commit(self, commit_id):
        return get_release_by_commit(self.repo, commit_id)

    def create_branch(self, base_commit, new_branch):
        """Create a new ostree branch from a base commit."""
        if not base_commit or not base_commit.strip():
            raise ValueError("base_commit must not be empty")
        if not new_branch or not new_branch.strip():
            raise ValueError("new_branch must not be empty")

        try:
            commit = subprocess.check_output(
                ["ostree", "rev-parse", "--repo", self.repo_path, base_commit],
                text=True).strip()
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to resolve base commit '%s': %s" % (base_commit, e))

        try:
            subprocess.check_call(
                ["ostree", "refs", "--repo", self.repo_path, "--create", new_branch, commit])
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to create branch '%s': %s" % (new_branch, str(e))) from None

        return commit

    def create_sw_release_branch(self, base_branch, new_branch, packages, pre_bootstrap):
        """Create an ostree branch and commit new patch
           The new branch is based on base_release (requires release)
        """
        base_commit = self.get_branch_commit(base_branch)
        self.create_branch(base_commit, new_branch)
        commit_packages_to_branch(self.repo_path, self.sw_ver, new_branch, packages, pre_bootstrap)

    def delete_branch(self, branch, prestage=False):
        """Delete an ostree software release branch and any branches built on top of it,
           then prune.
           When a software release branch is deleted, its dependents become orphan, that's
           why they are deleted in one operation.
        """
        branches = self.get_branches()
        if branch not in branches:
            LOG.info(f"Branch {branch} does not exist to delete")
            return []

        def get_tree(commit):
            r = subprocess.run(
                ["ostree", "ls", "--repo", self.repo_path, commit, "-d"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            if r.returncode == 0:
                return r.stdout.strip()
            return None

        def get_parent_commit(commit):
            r = subprocess.run(
                ["ostree", "log", "--repo", self.repo_path, commit],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
            if r.returncode != 0:
                return None
            commits = []
            for line in r.stdout.splitlines():
                if line.startswith("commit "):
                    commits.append(line.split()[1])
            if len(commits) >= 2:
                return commits[1]
            return None

        target_tip = self.get_branch_commit(branch)
        target_tree = get_tree(target_tip)

        to_delete = [branch]
        target_trees = {target_tree}

        changed = True
        while changed:
            changed = False
            for b in branches:
                if b in to_delete or b == self.DEPLOY_BRANCH:
                    continue
                tip = subprocess.check_output(
                    ["ostree", "rev-parse", "--repo", self.repo_path, b], text=True).strip()
                parent = get_parent_commit(tip)
                if parent:
                    parent_tree = get_tree(parent)
                    if parent_tree in target_trees:
                        if prestage and not b.endswith(constants.PRESTAGE_SUFFIX):
                            continue
                        to_delete.append(b)
                        target_trees.add(get_tree(tip))
                        changed = True

        for b in to_delete:
            LOG.info("Deleting branch: %s", b)
            subprocess.check_call(["ostree", "refs", "--repo", self.repo_path, "--delete", b])

        subprocess.check_call(["ostree", "prune", "--repo", self.repo_path, "--refs-only"])
        subprocess.check_call(["ostree", "summary", "--repo", self.repo_path, "-u"])
        LOG.info("Pruned repo and updated summary after deleting %d branch(es)", len(to_delete))
        return to_delete

    def branch_exists(self, branch_name):
        """Check if a branch exists in the ostree repo.

        :param branch_name: branch ref to check
        :return: True if branch exists, False otherwise
        """
        return branch_name in self.get_branches()

    def delete_ref(self, branch_name):
        """Delete a single ostree ref without cascading to dependents.

        :param branch_name: branch ref to delete
        """
        try:
            subprocess.check_call(
                ["ostree", "refs", "--repo", self.repo_path, "--delete", branch_name])
            LOG.info("Deleted ref: %s", branch_name)
        except subprocess.CalledProcessError as e:
            LOG.error("Failed to delete ref %s: %s", branch_name, str(e))

    def validate_deploy(self, deploy_target):
        # validate if deploy_target can be deployed
        branches = self.get_branches()
        if deploy_target not in branches:
            raise BranchNotFound(deploy_target)

    def deploy(self, deploy_target):
        """Deploy a software release by resetting the deploy branch to the target branch's commit.

        This uses 'ostree reset' to point the deploy branch (starlingx) at the
        same commit as deploy_target, preserving the existing GPG signature.

        :param deploy_target: the software release branch to deploy
        """
        self.validate_deploy(deploy_target)

        # Resolve the target branch to its commit
        target_commit = self.get_branch_commit(deploy_target)

        # Reset the deploy branch to point to the target commit
        try:
            subprocess.check_call(
                ["ostree", "reset", "--repo", self.repo_path, self.DEPLOY_BRANCH, target_commit])
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to reset '%s' to commit '%s': %s"
                               % (self.DEPLOY_BRANCH, target_commit, e))

        # Update the summary file so remote clients can pull the updated deploy branch
        try:
            subprocess.check_call(
                ["ostree", "summary", "--repo", self.repo_path, "-u"])
        except subprocess.CalledProcessError as e:
            raise RuntimeError("Failed to update ostree summary: %s" % e)

        LOG.info("Deploy branch '%s' reset to commit %s (from branch '%s')",
                 self.DEPLOY_BRANCH, target_commit, deploy_target)
        return target_commit

    def get_branch_original_commit(self, branch):
        """Get the original commit for a release branch.

        The original commit is the commit that was produced at upload time,
        stored as the `original_commit` attribute in the product release
        metadata. This value is immutable and does not change after prestage
        operations modify the branch tip.

        :param branch: the release branch name (which is also the release_id)
        :return: the original commit checksum
        :raises Exception: if the original commit cannot be determined
        """
        release_collection = get_SWReleaseCollection()
        release = release_collection.get_release_by_id(branch)

        if release and release.original_commit_id:
            return release.original_commit_id

        raise BranchNotFound(
            f"Original commit not found for release '{branch}'. "
            f"Ensure the release was uploaded successfully.")

    def get_branch_prestage_commit(self, branch):
        """Resolve the prestage commit if one exists.

        The prestage commit is the current tip of the target branch
        when it differs from the original commit (meaning prestaged
        packages were installed on top of it).

        :param branch: the release branch name (which is also the release_id)
        :return: the prestage commit checksum, or None if no prestage occurred
        """
        original_commit = self.get_branch_original_commit(branch)
        tip = self.get_branch_commit(branch)
        if tip == original_commit:
            return None
        return tip
