#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#

import copy
import mock
import shutil
import tarfile
import testtools
import time

from cgcs_patch import ostree_utils
from cgcs_patch.exceptions import MetadataFail
from cgcs_patch.exceptions import OSTreeTarFail
from cgcs_patch.exceptions import OSTreeCommandFail
from cgcs_patch.patch_controller import AgentNeighbour
from cgcs_patch.patch_controller import ControllerNeighbour
from cgcs_patch.patch_controller import PatchController
from cgcs_patch.patch_functions import LOG


APPLY_PATCH_SUCCESSULLY = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Available"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Available"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Available"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Available"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


NO_PATCHES_TO_APPLY = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Applied"},
        },
        "patch_id_list": ["First_Patch", "--all"]
    }


APPLY_PATCH_DURING_UPGRADE = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Available",
                            "apply_active_release_only": "Y"},
        },
        "patch_id_list": ["First_Patch"]
    }


APPLY_PATCH_WITH_DEPENDENCIES = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "apply_active_release_only": "N",
                            "repostate": "Available"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": [],
                             "apply_active_release_only": "N",
                             "repostate": "Available"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "apply_active_release_only": "N",
                            "repostate": "Available"}},
        "patch_id_list": ["First_Patch"]
    }


PATCH_LIST_WITH_DEPENDENCIES = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Applied"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Applied"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Applied"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Applied"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


PATCH_LIST_WITH_DIFFERENT_SW_VERSION = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"]},
            "Third_Patch": {"sw_version": "11.11",
                            "requires": ["Second_Patch"]},
            "Fourth_Patch": {"sw_version": "11.11",
                             "requires": ["Third_Patch"]}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


SINGLE_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []}},
        "patch_id_list": ["First_Patch"]
    }


PATCH_NOT_IN_METADATA = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": []}},
        "patch_id_list": ["First_Patch", "Second_Patch"]
    }


UNREMOVABLE_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "unremovable": "Y"}},
        "patch_id_list": ["First_Patch"]
    }


UNREMOVABLE_PATCH_REQUIRES_ANOTHER_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "unremovable": "Y",
                            "repostate": "Applied"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": [],
                             "unremovable": "Y",
                             "repostate": "Applied"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "unremovable": "Y",
                            "repostate": "Available"}},
        "patch_id_list": ["Second_Patch"]
    }


COMMITTED_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Committed"}},
        "patch_id_list": ["First_Patch"]
    }


PATCH_LIST_AVAILABLE = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Available"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Available"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Available"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Available"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


PATCH_LIST_APPLIED = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Applied"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Applied"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Applied"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Applied"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


CONTENTS_WITH_NO_OSTREE_DATA = \
    {
        "First_Patch": {},
        "Second_Patch": {},
        "Third_Patch": {},
        "Fourth_Patch": {}
    }


CONTENTS_WITH_OSTREE_DATA = \
    {
        "First_Patch": {
            "base": {"commit": "basecommit1"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitFirstPatch"}
        },
        "Second_Patch": {
            "base": {"commit": "commitFirstPatch"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitSecondPatch"}
        },
        "Third_Patch": {
            "base": {"commit": "commitSecondPatch"},
            "number_of_commits": 2,
            "commit1": {"commit": "commitThirdPatch1"},
            "commit2": {"commit": "commitThirdPatch2"},
        },
        "Fourth_Patch": {
            "base": {"commit": "commitThirdPatch2"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitFourthPatch"}
        }
    }


class CgcsPatchControllerTestCase(testtools.TestCase):

    def setUp(self):
        super(CgcsPatchControllerTestCase, self).setUp()
        with mock.patch('builtins.open'), \
                mock.patch.object(ostree_utils, 'get_ostree_latest_commit'), \
                mock.patch.object(ostree_utils, 'get_feed_latest_commit'):
            self.pc = PatchController()

    @mock.patch('builtins.open')
    def test_controller(self, _mock_open):
        # Disable the 'open'
        test_obj = PatchController()
        self.assertIsNotNone(test_obj)

    def test_controller_neighbour(self):
        test_obj = ControllerNeighbour()
        self.assertIsNotNone(test_obj)

        # reset the age
        test_obj.rx_ack()
        # get the age.  this number should be zero
        first_age = test_obj.get_age()
        # delay one second. The age should be one
        delay = 1
        time.sleep(delay)
        second_age = test_obj.get_age()
        self.assertTrue(second_age > first_age)
        # second_age should equal delay
        # to accomodate overloaded machines,  we use >=
        self.assertTrue(second_age >= delay)
        # reset the age.  the new age should be zero
        test_obj.rx_ack()
        third_age = test_obj.get_age()
        self.assertTrue(third_age < second_age)

        # set synched to True
        test_obj.rx_synced()
        self.assertTrue(test_obj.get_synced())
        # set synched to False
        test_obj.clear_synced()
        self.assertFalse(test_obj.get_synced())

    def test_agent_neighbour(self):
        test_ip = '127.0.0.1'
        test_obj = AgentNeighbour(test_ip)
        self.assertIsNotNone(test_obj)

    def create_patch_data(self, pc, metadata_obj, content_obj=None):
        pc.patch_data.metadata = copy.deepcopy(metadata_obj["value"])
        pc.patch_data.contents = copy.deepcopy(content_obj)
        return metadata_obj["patch_id_list"]

    def test_patch_remove_order_with_dependencies(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        patch_list = self.pc.patch_remove_order(patch_ids)
        self.assertEqual(patch_list,
                         ["Fourth_Patch", "Third_Patch", "Second_Patch", "First_Patch"])

    def test_patch_remove_order_different_sw_version(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DIFFERENT_SW_VERSION)
        patch_list = self.pc.patch_remove_order(patch_ids)
        self.assertIsNone(patch_list)

    def test_patch_remove_order_single_patch(self):
        patch_ids = self.create_patch_data(self.pc, SINGLE_PATCH)
        patch_list = self.pc.patch_remove_order(patch_ids)
        self.assertEqual(patch_list, ["First_Patch"])

    def test_patch_remove_api_different_sw_versions(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DIFFERENT_SW_VERSION)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch list provided belongs to different software versions.\n")

    def test_patch_remove_api_patch_not_removable(self):
        patch_ids = self.create_patch_data(self.pc, UNREMOVABLE_PATCH)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch First_Patch is not removable\n")

    def test_patch_remove_api_committed_patch(self):
        patch_ids = self.create_patch_data(self.pc, COMMITTED_PATCH)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch First_Patch is committed and cannot be removed\n")

    def test_patch_remove_api_remove_unremovable_patch(self):
        patch_ids = self.create_patch_data(self.pc, UNREMOVABLE_PATCH_REQUIRES_ANOTHER_PATCH)
        kwargs = dict({"removeunremovable": "yes"})
        response = self.pc.patch_remove_api(patch_ids, **kwargs)
        self.assertEqual(response["error"],
                         "Second_Patch is required by: First_Patch\n")

    def test_patch_remove_api_app_dependencies(self):
        self.pc.app_dependencies = {"app_1": "First_Patch"}
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        kwargs = dict({"skipappcheck": "no"})
        response = self.pc.patch_remove_api(patch_ids, **kwargs)
        self.assertEqual(response["error"],
                         "First_Patch is required by application(s): app_1\n")

    def test_patch_remove_api_not_in_repo(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_AVAILABLE)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["info"],
                         "Fourth_Patch is not in the repo\n" +
                         "Third_Patch is not in the repo\n" +
                         "Second_Patch is not in the repo\n" +
                         "First_Patch is not in the repo\n")

    @mock.patch.object(shutil, 'move')
    def test_patch_remove_api_not_supported(self,
                                            _mock_move):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_WITH_DEPENDENCIES,
                                           CONTENTS_WITH_NO_OSTREE_DATA)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["info"],
                         "Fourth_Patch is an unsupported patch format\n" +
                         "Fourth_Patch has been removed from the repo\n" +
                         "Third_Patch is an unsupported patch format\n" +
                         "Third_Patch has been removed from the repo\n" +
                         "Second_Patch is an unsupported patch format\n" +
                         "Second_Patch has been removed from the repo\n" +
                         "First_Patch is an unsupported patch format\n" +
                         "First_Patch has been removed from the repo\n")
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["repostate"], "Available")

    @mock.patch.object(shutil, 'move')
    @mock.patch.object(ostree_utils, 'reset_ostree_repo_head')
    @mock.patch.object(ostree_utils, 'delete_ostree_repo_commit')
    @mock.patch.object(ostree_utils, 'update_repo_summary_file')
    @mock.patch.object(LOG, 'exception')
    def test_patch_remove_api_move_metadata_failure(self,
                                                    _mock_log_exception,
                                                    _mock_update_summary,
                                                    _mock_delete_ostree_repo,
                                                    _mock_reset_ostree_head,
                                                    _mock_move):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_WITH_DEPENDENCIES,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_move.side_effect = \
            shutil.Error("Shutil failure")
        self.assertRaises(MetadataFail, self.pc.patch_remove_api, patch_ids)

    @mock.patch.object(shutil, 'move')
    @mock.patch.object(ostree_utils, 'reset_ostree_repo_head')
    @mock.patch.object(ostree_utils, 'delete_ostree_repo_commit')
    @mock.patch.object(ostree_utils, 'update_repo_summary_file')
    def test_patch_remove_api_successful_remove(self,
                                                _mock_update_summary,
                                                _mock_delete_ostree_repo,
                                                _mock_reset_ostree_head,
                                                _mock_move):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_WITH_DEPENDENCIES,
                                           CONTENTS_WITH_OSTREE_DATA)
        self.pc.hosts = ["controller-0"]
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["info"],
                         "Fourth_Patch has been removed from the repo\n" +
                         "Third_Patch has been removed from the repo\n" +
                         "Second_Patch has been removed from the repo\n" +
                         "First_Patch has been removed from the repo\n")
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Remove")

    @mock.patch.object(shutil, 'move')
    @mock.patch.object(ostree_utils, 'reset_ostree_repo_head')
    @mock.patch.object(ostree_utils, 'delete_ostree_repo_commit')
    @mock.patch.object(ostree_utils, 'update_repo_summary_file')
    @mock.patch.object(LOG, 'exception')
    def test_patch_remove_api_failure(self,
                                      _mock_log_exception,
                                      _mock_update_summary,
                                      _mock_delete_ostree_repo,
                                      _mock_reset_ostree_head,
                                      _mock_move):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_WITH_DEPENDENCIES,
                                           CONTENTS_WITH_OSTREE_DATA)
        # mock the update_repo_summary_file and raise an exception
        _mock_update_summary.side_effect = \
            OSTreeCommandFail("Unable to update Summary Repo")
        self.pc.patch_remove_api(patch_ids)

        # ostree_utils.reset_ostree_repo_head(base_commit, feed_ostree)
        # ostree_utils.delete_ostree_repo_commit(commit_to_delete, feed_ostree)
        # ostree_utils.update_repo_summary_file(feed_ostree)
        # These are the 3 ostree_utils methods that can raise an exception.
        # If we encounter an ostree exception, we simply log the exception and
        # continue with the next patch commit removal as the errors have to be dealt
        # with manually.
        _mock_log_exception.assert_any_call('Failure during patch remove for %s.', 'First_Patch')
        _mock_log_exception.assert_any_call('Failure during patch remove for %s.', 'Second_Patch')
        _mock_log_exception.assert_any_call('Failure during patch remove for %s.', 'Third_Patch')
        _mock_log_exception.assert_any_call('Failure during patch remove for %s.', 'Fourth_Patch')
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["repostate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["repostate"], "Available")

    def test_patch_apply_api_no_patches(self):
        patch_ids = self.create_patch_data(self.pc, NO_PATCHES_TO_APPLY)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["info"],
                         "There are no available patches to be applied.\n")

    def test_patch_apply_api_does_not_exist(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_NOT_IN_METADATA)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch Second_Patch does not exist\n")

    def test_patch_apply_api_apply_during_upgrade(self):
        patch_ids = self.create_patch_data(self.pc, APPLY_PATCH_DURING_UPGRADE)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["error"],
                         "First_Patch cannot be applied in an upgrade\n")

    def test_patch_apply_api_apply_with_dependencies(self):
        patch_ids = self.create_patch_data(self.pc, APPLY_PATCH_WITH_DEPENDENCIES)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["error"],
                         "Second_Patch is required by: First_Patch\n")

    def test_patch_apply_api_already_in_repo(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_APPLIED)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch is already in the repo\n" +
                         "Fourth_Patch is already in the repo\n" +
                         "Second_Patch is already in the repo\n" +
                         "Third_Patch is already in the repo\n")

    def test_patch_apply_api_not_supported(self):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_NO_OSTREE_DATA)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch is an unsupported patch format\n" +
                         "Fourth_Patch is an unsupported patch format\n" +
                         "Second_Patch is an unsupported patch format\n" +
                         "Third_Patch is an unsupported patch format\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    def test_patch_apply_api_raises_exception(self,
                                              _mock_feed,
                                              _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = \
            OSTreeCommandFail("Unable to fetch latest feed commit")

        self.pc.patch_apply_api(patch_ids)
        _mock_log_exception.assert_any_call('Failure during commit consistency check for %s.',
                                            'First_Patch')
        _mock_log_exception.assert_any_call('Failure during commit consistency check for %s.',
                                            'Second_Patch')
        _mock_log_exception.assert_any_call('Failure during commit consistency check for %s.',
                                            'Third_Patch')
        _mock_log_exception.assert_any_call('Failure during commit consistency check for %s.',
                                            'Fourth_Patch')

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    def test_patch_apply_api_base_commit_does_not_match(self,
                                                        _mock_feed):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = "mock"

        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["info"],
                         "The base commit basecommit1 for First_Patch does not match " +
                         "the latest commit m on this system.\n" +
                         "The base commit commitThirdPatch2 for Fourth_Patch does not match " +
                         "the latest commit o on this system.\n" +
                         "The base commit commitFirstPatch for Second_Patch does not match " +
                         "the latest commit c on this system.\n" +
                         "The base commit commitSecondPatch for Third_Patch does not match " +
                         "the latest commit k on this system.\n")

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(tarfile, 'open')
    def test_patch_apply_api_tarball_extraction_failure(self,
                                                        _mock_tar_open,
                                                        _mock_get_tar_filename,
                                                        _mock_feed):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = ["basecommit1", "commitFirstPatch",
                                  "commitSecondPatch", "commitThirdPatch2"]
        _mock_get_tar_filename.side_effect = ["file1", "file2", "file3", "file4"]
        _mock_tar_open.side_effect = \
            tarfile.TarError("Tarfile failure")

        self.assertRaises(OSTreeTarFail, self.pc.patch_apply_api, patch_ids)

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(tarfile, 'open')
    @mock.patch.object(LOG, 'exception')
    def test_patch_apply_api_tarball_copy_failure(self,
                                                  _mock_log_exception,
                                                  _mock_tar_open,
                                                  _mock_get_tar_filename,
                                                  _mock_feed):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = ["basecommit1", "commitFirstPatch",
                                  "commitSecondPatch", "commitThirdPatch2"]
        _mock_get_tar_filename.side_effect = ["file1", "file2", "file3", "file4"]
        _mock_tar_open.side_effect = \
            shutil.Error("Shutil failure")

        self.assertRaises(OSTreeTarFail, self.pc.patch_apply_api, patch_ids)

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(tarfile, 'open')
    @mock.patch.object(shutil, 'copytree')
    @mock.patch.object(shutil, 'move')
    @mock.patch.object(LOG, 'exception')
    def test_patch_apply_api_move_metadata_failure(self,
                                                   _mock_log_exception,
                                                   _mock_move,
                                                   _mock_shutil_copytree,
                                                   _mock_tar_open,
                                                   _mock_get_tar_filename,
                                                   _mock_feed):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = ["basecommit1", "commitFirstPatch",
                                  "commitSecondPatch", "commitThirdPatch2"]
        _mock_get_tar_filename.side_effect = ["file1", "file2", "file3", "file4"]
        _mock_move.side_effect = \
            shutil.Error("Shutil failure")
        self.assertRaises(MetadataFail, self.pc.patch_apply_api, patch_ids)

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(tarfile, 'open')
    @mock.patch.object(shutil, 'copytree')
    @mock.patch.object(shutil, 'move')
    def test_patch_apply_api_success(self,
                                     _mock_move,
                                     _mock_shutil_copytree,
                                     _mock_tar_open,
                                     _mock_get_tar_filename,
                                     _mock_feed):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_feed.side_effect = ["basecommit1",
                                  "commitThirdPatch2",
                                  "commitFirstPatch",
                                  "commitSecondPatch"]
        self.pc.hosts = ["controller-0"]
        self.pc.patch_apply_api(patch_ids)
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["repostate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["repostate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["repostate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["repostate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Partial-Apply")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Partial-Apply")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Partial-Apply")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Apply")
