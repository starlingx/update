#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2019-2023 Wind River Systems, Inc.
#

import copy
import mock
import os
import shutil
import tarfile
import testtools
import time

from cgcs_patch import ostree_utils
from cgcs_patch.exceptions import MetadataFail
from cgcs_patch.exceptions import OSTreeTarFail
from cgcs_patch.exceptions import OSTreeCommandFail
from cgcs_patch.exceptions import PatchFail
from cgcs_patch.exceptions import PatchMismatchFailure
from cgcs_patch.exceptions import SemanticFail
from cgcs_patch.patch_controller import AgentNeighbour
from cgcs_patch.patch_controller import ControllerNeighbour
from cgcs_patch.patch_controller import PatchController
from cgcs_patch.patch_functions import LOG
from cgcs_patch.patch_functions import PatchData
from cgcs_patch.patch_functions import PatchFile

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
            "First_Patch": {"sw_version": "TEST.SW.VERSION",
                            "requires": [],
                            "repostate": "Applied",
                            "patchstate": "Applied",
                            "status": "REL"},
            "Second_Patch": {"sw_version": "TEST.SW.VERSION",
                             "requires": ["First_Patch"],
                             "repostate": "Applied",
                             "patchstate": "Applied",
                             "status": "REL"},
            "Third_Patch": {"sw_version": "TEST.SW.VERSION",
                            "requires": ["Second_Patch"],
                            "repostate": "Applied",
                            "patchstate": "Applied",
                            "status": "REL"},
            "Fourth_Patch": {"sw_version": "TEST.SW.VERSION",
                             "requires": ["Third_Patch"],
                             "repostate": "Applied",
                             "patchstate": "Applied",
                             "status": "REL"}},
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
                            "requires": [],
                            "patchstate": "Available",
                            "repostate": "Available",
                            "status": "REL"}},
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
                            "repostate": "Available",
                            "patchstate": "Available",
                            "status": "REL"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Available",
                             "patchstate": "Available",
                             "status": "REL"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Available",
                            "patchstate": "Available",
                            "status": "REL"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Available",
                             "patchstate": "Available",
                             "status": "REL"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


IMPORTED_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "repostate": "Available",
                            "patchstate": "Available",
                            "status": "REL"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "repostate": "Available",
                             "patchstate": "Available",
                             "status": "REL"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "repostate": "Available",
                            "patchstate": "Available",
                            "status": "REL"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "repostate": "Available",
                             "patchstate": "Available",
                             "status": "REL"},
            "Fifth_Patch": {"sw_version": "12.34",
                            "requires": ["Fourth_Patch"],
                            "repostate": "Available",
                            "patchstate": "Available",
                            "status": "REL"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch", "Fifth_Patch"]
    }


PATCH_LIST_APPLIED = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Applied",
                            "repostate": "Applied"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "patchstate": "Applied",
                             "repostate": "Applied"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "patchstate": "Applied",
                            "repostate": "Applied"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "patchstate": "Applied",
                             "repostate": "Applied"}},
        "patch_id_list": ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"]
    }


CHECK_PATCH_STATES = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Applied",
                            "repostate": "Applied"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": ["First_Patch"],
                             "patchstate": "Applied",
                             "repostate": "Applied"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": ["Second_Patch"],
                            "patchstate": "Available",
                            "repostate": "Available"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": ["Third_Patch"],
                             "patchstate": "Available",
                             "repostate": "Available"}},
        "patch_id_list": ["First_Patch", "Second_Patch",
                          "Third_Patch", "Fourth_Patch"]
    }


DELETE_APPLIED_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Applied",
                            "repostate": "Applied"}},
        "patch_id_list": ["First_Patch"]
    }


DELETE_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Available",
                            "repostate": "Available",
                            "restart_script": "restart-First-Patch.sh"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": [],
                             "patchstate": "Available",
                             "repostate": "Available"}},
        "patch_id_list": ["First_Patch",
                          "Second_Patch"]
    }


DELETE_API_RELEASE = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Available",
                            "repostate": "Available"},
            "Second_Patch": {"sw_version": "12.34",
                             "requires": [],
                             "patchstate": "Available",
                             "repostate": "Available"},
            "Third_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "patchstate": "Committed",
                            "repostate": "Committed"},
            "Fourth_Patch": {"sw_version": "12.34",
                             "requires": [],
                             "patchstate": "Applied",
                             "repostate": "Applied"}},
        "patch_id_list": ["First_Patch",
                          "Second_Patch",
                          "Third_Patch",
                          "Fourth_Patch"]
    }


NON_REL_PATCH = \
    {
        "value": {
            "First_Patch": {"sw_version": "12.34",
                            "requires": [],
                            "status": "DEV"}},
        "patch_id_list": ["First_Patch"]
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


CHECK_PATCH_STATES_QUERY_BUG = \
    {
        "value": {
            "First_Patch_APPLIED": {"sw_version": "12.34",
                                    "requires": [],
                                    "patchstate": "Partial-Apply",
                                    "repostate": "Applied"},
            "Second_Patch_APPLIED": {"sw_version": "12.34",
                                     "requires": ["First_Patch_APPLIED"],
                                     "patchstate": "Partial-Apply",
                                     "repostate": "Applied"},
            "Third_Patch_CURRENT": {"sw_version": "12.34",
                                    "requires": ["Second_Patch_APPLIED"],
                                    "patchstate": "Applied",
                                    "repostate": "Applied"},
            "Fourth_Patch_NEWLY_APPLIED": {"sw_version": "12.34",
                                           "requires": ["Third_Patch_CURRENT"],
                                           "patchstate": "Partial-Apply",
                                           "repostate": "Applied"}},
        "patch_id_list": ["First_Patch_APPLIED", "Second_Patch_APPLIED",
                          "Third_Patch_CURRENT", "Fourth_Patch_NEWLY_APPLIED"]
    }


CONTENTS_WITH_OSTREE_DATA_QUERY_BUG = \
    {
        "First_Patch_APPLIED": {
            "base": {"commit": "basecommit1"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitFirstPatch"}
        },
        "Second_Patch_APPLIED": {
            "base": {"commit": "commitFirstPatch"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitSecondPatch"}
        },
        "Third_Patch_CURRENT": {
            "base": {"commit": "commitSecondPatch"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitThirdPatch"},
        },
        "Fourth_Patch_NEWLY_APPLIED": {
            "base": {"commit": "commitThirdPatch"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitFourthPatch"}
        }
    }

IMPORTED_PATCH_CONTENTS = \
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
        },
        "Fifth_Patch": {
            "base": {"commit": "commitFourthPatch"},
            "number_of_commits": 1,
            "commit1": {"commit": "commitFifthPatch"}
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

    def create_new_standalone_patch_data(self, metadata_obj, content_obj=None):
        newObj = PatchData()
        newObj.metadata = copy.deepcopy(metadata_obj["value"])
        newObj.contents = copy.deepcopy(content_obj)
        return newObj

    def test_patch_apply_remove_order_with_dependencies(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        patch_list = self.pc.patch_apply_remove_order(patch_ids)
        self.assertEqual(patch_list,
                         ["Fourth_Patch", "Third_Patch", "Second_Patch", "First_Patch"])

    def test_patch_apply_remove_order_reverse_with_dependencies(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        patch_list = self.pc.patch_apply_remove_order(patch_ids, reverse=True)
        self.assertEqual(patch_list,
                         ["First_Patch", "Second_Patch", "Third_Patch", "Fourth_Patch"])

    def test_patch_apply_remove_order_different_sw_version(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DIFFERENT_SW_VERSION)
        patch_list = self.pc.patch_apply_remove_order(patch_ids)
        self.assertIsNone(patch_list)

    def test_patch_apply_remove_order_single_patch(self):
        patch_ids = self.create_patch_data(self.pc, SINGLE_PATCH)
        patch_list = self.pc.patch_apply_remove_order(patch_ids)
        self.assertEqual(patch_list, ["First_Patch"])

    def test_patch_remove_api_different_sw_versions(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DIFFERENT_SW_VERSION)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch list provided belongs to different software versions.\n")

    def test_patch_remove_api_patch_not_in_metadata(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_NOT_IN_METADATA)
        response = self.pc.patch_remove_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch Second_Patch does not exist\n")

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
                         "Second_Patch is already in the repo\n" +
                         "Third_Patch is already in the repo\n" +
                         "Fourth_Patch is already in the repo\n")

    def test_patch_apply_api_not_supported(self):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_NO_OSTREE_DATA)
        response = self.pc.patch_apply_api(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch is an unsupported patch format\n" +
                         "Second_Patch is an unsupported patch format\n" +
                         "Third_Patch is an unsupported patch format\n" +
                         "Fourth_Patch is an unsupported patch format\n")

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
                         "The base commit commitFirstPatch for Second_Patch does not match " +
                         "the latest commit o on this system.\n" +
                         "The base commit commitSecondPatch for Third_Patch does not match " +
                         "the latest commit c on this system.\n" +
                         "The base commit commitThirdPatch2 for Fourth_Patch does not match " +
                         "the latest commit k on this system.\n")

    @mock.patch.object(ostree_utils, 'get_feed_latest_commit')
    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(tarfile, 'open')
    @mock.patch.object(LOG, 'exception')
    def test_patch_apply_api_tarball_extraction_failure(self,
                                                        _mock_log,
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
                                  "commitFirstPatch",
                                  "commitSecondPatch",
                                  "commitThirdPatch2"]
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

    def test_patch_delete_api_does_not_exist(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_NOT_IN_METADATA)
        response = self.pc.patch_delete_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch Second_Patch does not exist\n")

    def test_patch_delete_api_applied_patch(self):
        patch_ids = self.create_patch_data(self.pc, DELETE_APPLIED_PATCH)
        response = self.pc.patch_delete_api(patch_ids)
        self.assertEqual(response["error"],
                         "Patch First_Patch not in Available state\n")

    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os, 'remove')
    def test_patch_delete_api_remove_tarball_failure(self,
                                                     _mock_remove,
                                                     _mock_isfile,
                                                     _mock_log_exception,
                                                     _mock_get_tar_filename):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_PATCH,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_get_tar_filename.side_effect = ["file1", "file2"]
        _mock_isfile.side_effect = "True"
        _mock_remove.side_effect = OSError("Failed to delete tarball")
        self.assertRaises(OSTreeTarFail, self.pc.patch_delete_api, patch_ids)

    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os, 'remove')
    def test_patch_delete_api_remove_metadata_failure(self,
                                                      _mock_remove,
                                                      _mock_log_exception,
                                                      _mock_get_tar_filename):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_PATCH,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_get_tar_filename.side_effect = ["file1", "file2"]
        _mock_remove.side_effect = OSError("Failed to delete metadata")
        self.assertRaises(MetadataFail, self.pc.patch_delete_api, patch_ids)

    @mock.patch.object(PatchController, 'get_ostree_tar_filename')
    @mock.patch.object(os, 'remove')
    @mock.patch.object(os.path, 'isfile')
    def test_patch_delete_api_success(self,
                                      _mock_is_file,
                                      _mock_remove,
                                      _mock_get_tar_filename):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_PATCH,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_get_tar_filename.side_effect = ["file1", "file2"]
        _mock_is_file.return_value = True
        response = self.pc.patch_delete_api(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch has been deleted\n" +
                         "Second_Patch has been deleted\n")
        self.assertIsNone(self.pc.patch_data.contents.get("First_Patch"))
        self.assertIsNone(self.pc.patch_data.contents.get("Second_Patch"))

    def test_patch_del_release_api_rejected(self):
        response = self.pc.patch_del_release_api("TEST.SW.VERSION")
        self.assertEqual(response["error"],
                         "Rejected: Requested release TEST.SW.VERSION is running release\n")

    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os, 'remove')
    def test_patch_del_release_api_cannot_remove_semantic(self,
                                                          _mock_remove,
                                                          _mock_log_exception,
                                                          _mock_isfile):
        self.create_patch_data(self.pc,
                               DELETE_PATCH,
                               CONTENTS_WITH_OSTREE_DATA)
        _mock_isfile.side_effect = "True"
        _mock_remove.side_effect = OSError("Failed to remove semantic")
        self.assertRaises(SemanticFail, self.pc.patch_del_release_api, "12.34")

    @mock.patch.object(os, 'remove')
    @mock.patch.object(LOG, 'exception')
    def test_patch_del_release_api_cannot_remove_metadata(self,
                                                          _mock_log_exception,
                                                          _mock_remove):
        self.create_patch_data(self.pc,
                               DELETE_PATCH,
                               CONTENTS_WITH_OSTREE_DATA)
        _mock_remove.side_effect = OSError("Failed to remove metadata")
        self.assertRaises(MetadataFail, self.pc.patch_del_release_api, "12.34")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os, 'remove')
    @mock.patch.object(shutil, 'rmtree')
    def test_patch_del_release_api_patch_repo_does_not_exist(self,
                                                             _mock_shutil_rmtree,
                                                             _mock_remove,
                                                             _mock_log_exception):
        self.create_patch_data(self.pc,
                               DELETE_PATCH,
                               CONTENTS_WITH_OSTREE_DATA)
        _mock_shutil_rmtree.side_effect = shutil.Error("Cannot remove package")
        response = self.pc.patch_del_release_api("12.34")
        self.assertEqual(response["info"], "Patch repository for 12.34 does not exist\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os, 'remove')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(shutil, 'rmtree')
    def test_patch_del_release_api_failed(self,
                                          _mock_shutil_rmtree,
                                          _mock_path_exists,
                                          _mock_remove,
                                          _mock_log_exception):
        self.create_patch_data(self.pc,
                               DELETE_API_RELEASE,
                               CONTENTS_WITH_OSTREE_DATA)
        _mock_shutil_rmtree.side_effect = shutil.Error("Cannot remove package")
        self.pc.patch_del_release_api("12.34")
        self.assertIsNone(self.pc.patch_data.contents.get("First_Patch"))
        self.assertIsNone(self.pc.patch_data.contents.get("Second_Patch"))

    def test_patch_query_what_requires_does_not_exist(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_NOT_IN_METADATA)
        response = self.pc.patch_query_what_requires(patch_ids)
        self.assertEqual(response["error"],
                         "Patch Second_Patch does not exist\n")

    def test_patch_query_what_requires_success(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        response = self.pc.patch_query_what_requires(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch is required by: Second_Patch\n" +
                         "Second_Patch is required by: Third_Patch\n" +
                         "Third_Patch is required by: Fourth_Patch\n" +
                         "Fourth_Patch is not required by any patches.\n")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    @mock.patch.object(LOG, 'exception')
    def test_patch_commit_failed_create_dir(self,
                                            _mock_log,
                                            _mock_makedirs,
                                            _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        _mock_exists.return_value = False
        _mock_makedirs.side_effect = os.error("Cannot create directory")
        self.assertRaises(PatchFail, self.pc.patch_commit, patch_ids)

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    def test_patch_commit_failed_non_rel(self,
                                         _mock_log,
                                         _mock_exists):
        patch_ids = self.create_patch_data(self.pc, NON_REL_PATCH)
        _mock_exists.return_value = True
        response = self.pc.patch_commit(patch_ids)
        self.assertEqual(response["error"],
                         "A commit cannot be performed with non-REL status " +
                         "patches in the system:\n" +
                         "    First_Patch\n")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    def test_patch_commit_failed_unrecognized(self,
                                              _mock_log,
                                              _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_NOT_IN_METADATA)
        _mock_exists.return_value = True
        response = self.pc.patch_commit(patch_ids)
        self.assertEqual(response["error"],
                         "Second_Patch is unrecognized\n")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    def test_patch_commit_failed_cannot_commit(self,
                                               _mock_log,
                                               _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_AVAILABLE)
        _mock_exists.return_value = True
        response = self.pc.patch_commit(patch_ids)
        self.assertEqual(response["error"],
                         "The following patches are not applied and cannot be committed:\n" +
                         "    First_Patch\n" +
                         "    Fourth_Patch\n" +
                         "    Second_Patch\n" +
                         "    Third_Patch\n")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    def test_patch_commit_dry_run(self,
                                  _mock_log,
                                  _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        with mock.patch('os.stat') as _mock_stat:
            type(_mock_stat.return_value).st_size = mock.PropertyMock(return_value=200000)
            _mock_exists.return_value = True
            response = self.pc.patch_commit(patch_ids, dry_run=True)
            self.assertEqual(response["info"], "This commit operation would free 0.76 MiB")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(shutil, 'move')
    @mock.patch.object(os, 'remove')
    def test_patch_commit_success(self,
                                  _mock_remove,
                                  _mock_shutil_move,
                                  _mock_log,
                                  _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        with mock.patch('os.stat') as _mock_stat:
            type(_mock_stat.return_value).st_size = mock.PropertyMock(return_value=200000)
            _mock_exists.return_value = True
            response = self.pc.patch_commit(patch_ids)
            self.assertEqual(response["info"], "The patches have been committed.")

    def test_check_patch_states_no_hosts(self):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        self.pc.hosts = []
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "n/a")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "n/a")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "n/a")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "n/a")

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(shutil, 'move')
    @mock.patch.object(os, 'remove')
    def test_patch_commit_failed_to_move_metadata(self,
                                                  _mock_remove,
                                                  _mock_shutil_move,
                                                  _mock_log,
                                                  _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        with mock.patch('os.stat') as _mock_stat:
            type(_mock_stat.return_value).st_size = mock.PropertyMock(return_value=200000)
            _mock_exists.return_value = True
            _mock_shutil_move.side_effect = shutil.Error("Failed to move metadata")
            self.assertRaises(MetadataFail, self.pc.patch_commit, patch_ids)

    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(shutil, 'move')
    @mock.patch.object(os, 'remove')
    def test_patch_commit_failed_to_remove(self,
                                           _mock_remove,
                                           _mock_shutil_move,
                                           _mock_log,
                                           _mock_exists):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_WITH_DEPENDENCIES)
        with mock.patch('os.stat') as _mock_stat:
            type(_mock_stat.return_value).st_size = mock.PropertyMock(return_value=200000)
            _mock_exists.return_value = True
            _mock_remove.side_effect = OSError("Failed to remove files")
            self.assertRaises(MetadataFail, self.pc.patch_commit, patch_ids)

    def test_patch_is_applied_false(self):
        patch_ids = self.create_patch_data(self.pc, DELETE_API_RELEASE)
        self.assertEqual(self.pc.is_applied(patch_ids), False)

    def test_patch_is_applied_true(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_APPLIED)
        self.assertEqual(self.pc.is_applied(patch_ids), True)

    def test_patch_is_available_false(self):
        patch_ids = self.create_patch_data(self.pc, DELETE_API_RELEASE)
        self.assertEqual(self.pc.is_available(patch_ids), False)

    def test_patch_is_available_true(self):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_AVAILABLE)
        self.assertEqual(self.pc.is_available(patch_ids), True)

    @mock.patch.object(os.path, 'isfile')
    def test_patch_import_api_does_not_exist(self,
                                             _mock_is_file):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_AVAILABLE)
        _mock_is_file.return_value = False
        self.assertRaises(PatchFail, self.pc.patch_import_api, patch_ids)

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    def test_patch_import_api_cannot_create_directory(self,
                                                      _mock_makedirs,
                                                      _mock_path_exists,
                                                      _mock_is_file,
                                                      _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc, PATCH_LIST_AVAILABLE)
        _mock_makedirs.side_effect = os.error("Cannot create directory")
        _mock_is_file.return_value = True
        _mock_path_exists.side_effect = [True, True, False]
        self.assertRaises(PatchFail, self.pc.patch_import_api, patch_ids)

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    def test_patch_import_api_patchfail(self,
                                        _mock_makedirs,
                                        _mock_path_exists,
                                        _mock_is_file,
                                        _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_API_RELEASE,
                                           CONTENTS_WITH_OSTREE_DATA)
        # PatchFail error is raised by extact_patch() of patch_function
        # due to an OSError while executing the read_patch()
        response = self.pc.patch_import_api(patch_ids)
        self.assertEqual(response["info"], "Third_Patch is committed. Metadata not updated\n")
        self.assertEqual(response["error"],
                         "Failed to import patch First_Patch\n" +
                         "Failed to import patch Fourth_Patch\n" +
                         "Failed to import patch Second_Patch\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    @mock.patch.object(PatchData, 'parse_metadata')
    @mock.patch.object(PatchFile, 'read_patch')
    def test_patch_import_api_patch_validation_failed(self,
                                                      _mock_read_patch,
                                                      _mock_parse_metadata,
                                                      _mock_makedirs,
                                                      _mock_path_exists,
                                                      _mock_is_file,
                                                      _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_AVAILABLE,
                                           CONTENTS_WITH_OSTREE_DATA)
        # PatchValidationFailure error is raised by extact_patch() of
        # patch_function due to a KeyError while parsing the metadata
        response = self.pc.patch_import_api(patch_ids)
        self.assertEqual(response["info"], "")
        self.assertEqual(response["error"],
                         "Patch validation failed for First_Patch:\n" +
                         "Failed during patch extraction\n" +
                         "Patch validation failed for Fourth_Patch:\n" +
                         "Failed during patch extraction\n" +
                         "Patch validation failed for Second_Patch:\n" +
                         "Failed during patch extraction\n" +
                         "Patch validation failed for Third_Patch:\n" +
                         "Failed during patch extraction\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    @mock.patch.object(PatchFile, 'read_patch')
    def test_patch_import_api_patch_mismatch_failure(self,
                                                     _mock_read_patch,
                                                     _mock_makedirs,
                                                     _mock_path_exists,
                                                     _mock_is_file,
                                                     _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_AVAILABLE,
                                           CONTENTS_WITH_OSTREE_DATA)
        _mock_read_patch.side_effect = PatchMismatchFailure("Patch mismatch failure")
        response = self.pc.patch_import_api(patch_ids)
        self.assertEqual(response["info"], "")
        self.assertEqual(response["error"],
                         "Contents of First_Patch do not match re-imported patch\n" +
                         "Contents of Fourth_Patch do not match re-imported patch\n" +
                         "Contents of Second_Patch do not match re-imported patch\n" +
                         "Contents of Third_Patch do not match re-imported patch\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    @mock.patch.object(PatchFile, 'extract_patch')
    def test_patch_import_api_already_imported(self,
                                               _mock_extract_patch,
                                               _mock_makedirs,
                                               _mock_path_exists,
                                               _mock_is_file,
                                               _mock_log_exception):
        patch_ids = self.create_patch_data(self.pc,
                                           PATCH_LIST_AVAILABLE,
                                           CONTENTS_WITH_OSTREE_DATA)
        new_patch = self.create_new_standalone_patch_data(PATCH_LIST_AVAILABLE,
                                                          CONTENTS_WITH_OSTREE_DATA)
        _mock_extract_patch.return_value = new_patch

        response = self.pc.patch_import_api(patch_ids)
        self.assertEqual(response["info"],
                         "First_Patch is already imported. Updated metadata only\n" +
                         "Fourth_Patch is already imported. Updated metadata only\n" +
                         "Second_Patch is already imported. Updated metadata only\n" +
                         "Third_Patch is already imported. Updated metadata only\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(os, 'makedirs')
    @mock.patch.object(PatchFile, 'extract_patch')
    @mock.patch.object(PatchData, 'update_patch')
    def test_patch_import_api_patch_extension(self,
                                              _mock_update_patch,
                                              _mock_extract_patch,
                                              _mock_makedirs,
                                              _mock_path_exists,
                                              _mock_is_file,
                                              _mock_log_exception):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        response = self.pc.patch_import_api(["Fifth_Patch"])
        self.assertEqual(response["error"],
                         "File must end in .patch extension: Fifth_Patch\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    def test_patch_import_api_patch_fail_during_import(self,
                                                       _mock_path_exists,
                                                       _mock_is_file,
                                                       _mock_log_exception):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        response = self.pc.patch_import_api(["Fifth_Patch.patch"])
        self.assertEqual(response["error"],
                         "Failed to import patch Fifth_Patch\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(PatchData, 'parse_metadata')
    @mock.patch.object(PatchFile, 'read_patch')
    def test_patch_import_api_validation_failure_during_import(self,
                                                               _mock_read_patch,
                                                               _mock_parse_metadata,
                                                               _mock_path_exists,
                                                               _mock_is_file,
                                                               _mock_log_exception):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        response = self.pc.patch_import_api(["Fifth_Patch.patch"])
        self.assertEqual(response["error"],
                         "Patch validation failed for Fifth_Patch:\n" +
                         "Failed during patch extraction\n")

    @mock.patch.object(LOG, 'exception')
    @mock.patch.object(os.path, 'isfile')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(PatchData, 'parse_metadata')
    @mock.patch.object(PatchFile, 'extract_patch')
    def test_patch_import_api_success(self,
                                      _mock_extract_patch,
                                      _mock_parse_metadata,
                                      _mock_path_exists,
                                      _mock_is_file,
                                      _mock_log_exception):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        new_patch = self.create_new_standalone_patch_data(IMPORTED_PATCH,
                                                          IMPORTED_PATCH_CONTENTS)
        _mock_extract_patch.return_value = new_patch
        response = self.pc.patch_import_api(["Fifth_Patch.patch"])
        self.assertEqual(response["info"],
                         "Fifth_Patch is now available\n")

    def test_check_patch_states_hosts_up_to_date(self):
        self.create_patch_data(self.pc,
                               PATCH_LIST_AVAILABLE,
                               CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Available")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Available")

    def test_check_patch_states_hosts_out_of_date_and_diff_sw_version(self):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_API_RELEASE,
                                           CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        an_1.out_of_date = True
        an_2.out_of_date = True
        self.pc.interim_state = patch_ids
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Committed")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Apply")

    def test_check_patch_states_hosts_out_of_date_and_same_sw_version(self):
        patch_ids = self.create_patch_data(self.pc,
                                           DELETE_API_RELEASE,
                                           CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        an_1.out_of_date = True
        an_1.sw_version = "12.34"
        an_1.latest_sysroot_commit = "commitFirstPatch"
        an_2.out_of_date = True
        an_2.sw_version = "12.34"
        an_2.latest_sysroot_commit = "commitFirstPatch"
        self.pc.interim_state = patch_ids
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Committed")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Apply")

    def test_check_patch_states_with_patch_dependency(self):
        patch_ids = self.create_patch_data(self.pc,
                                           APPLY_PATCH_SUCCESSULLY,
                                           CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        an_1.out_of_date = True
        an_1.sw_version = "12.34"
        an_1.latest_sysroot_commit = "commitFourthPatch"
        an_2.out_of_date = True
        an_2.sw_version = "12.34"
        an_2.latest_sysroot_commit = "commitFourthPatch"
        self.pc.interim_state = patch_ids
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Remove")

    def test_check_patch_states_with_patch_dependency_combo(self):
        # First_Patch and Second_Patch are in applied state
        # Third_Patch and Fourth_Patch are removed
        self.create_patch_data(self.pc,
                               CHECK_PATCH_STATES,
                               CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        an_1.out_of_date = True
        an_1.sw_version = "12.34"
        an_1.latest_sysroot_commit = "commitFourthPatch"
        an_2.out_of_date = True
        an_2.sw_version = "12.34"
        an_2.latest_sysroot_commit = "commitFourthPatch"
        self.pc.interim_state = ["Third_Patch", "Fourth_Patch"]
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Remove")

    def test_check_patch_states_patch_data_missing(self):
        self.create_patch_data(self.pc,
                               CHECK_PATCH_STATES,
                               CONTENTS_WITH_OSTREE_DATA)
        test_ip1 = '127.0.0.1'
        test_ip2 = '127.0.0.2'
        # After initialization, out_of_date is False. This means host is up-to-date
        an_1 = AgentNeighbour(test_ip1)
        an_2 = AgentNeighbour(test_ip2)
        an_1.out_of_date = True
        an_1.sw_version = "12.34"
        an_1.latest_sysroot_commit = "commitFourthPatch"
        an_2.out_of_date = True
        an_2.sw_version = "12.34"
        an_2.latest_sysroot_commit = "commitFourthPatch"
        self.pc.interim_state = ["Third_Patch", "Fourth_Patch"]
        self.pc.hosts = {test_ip1: an_1, test_ip2: an_2}
        self.pc.check_patch_states()
        self.assertEqual(self.pc.patch_data.metadata["First_Patch"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Third_Patch"]["patchstate"], "Partial-Remove")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch"]["patchstate"], "Partial-Remove")

    def test_get_ostree_tar_filename(self):
        filename = self.pc.get_ostree_tar_filename("TEST.SW.VERSION", "First_Patch")
        self.assertEqual(filename, "/opt/patching/packages/TEST.SW.VERSION/First_Patch-software.tar")

    def test_query_no_query_state_or_release(self):
        self.create_patch_data(self.pc,
                               CHECK_PATCH_STATES,
                               CONTENTS_WITH_OSTREE_DATA)
        # Returns everything if query_state and query_release are not
        # passed
        results = self.pc.patch_query_cached()
        self.assertEqual(True, results == CHECK_PATCH_STATES["value"])

    def test_query_available_patch(self):
        self.create_patch_data(self.pc,
                               CHECK_PATCH_STATES,
                               CONTENTS_WITH_OSTREE_DATA)
        kwargs = dict({"show": "available"})
        results = self.pc.patch_query_cached(**kwargs)
        self.assertEqual(len(results), 2)
        self.assertIsNone(results.get("First_Patch"))
        self.assertIsNone(results.get("Second_Patch"))
        self.assertIsNotNone(results.get("Third_Patch"))
        self.assertIsNotNone(results.get("Fourth_Patch"))

    def test_query_applied_patch(self):
        self.create_patch_data(self.pc,
                               CHECK_PATCH_STATES,
                               CONTENTS_WITH_OSTREE_DATA)
        kwargs = dict({"show": "applied"})
        results = self.pc.patch_query_cached(**kwargs)
        self.assertEqual(len(results), 2)
        self.assertIsNotNone(results.get("First_Patch"))
        self.assertIsNotNone(results.get("Second_Patch"))
        self.assertIsNone(results.get("Third_Patch"))
        self.assertIsNone(results.get("Fourth_Patch"))

    def test_previously_applied_goes_to_partial_applied(self):
        # bug description: Applied patches go to a Partial-Applied state after applying a new patch
        #   after the system reboot all patches correctly goes to the applied state.
        #
        # it goes like this, before applying the new patch (PATCH_0005), sw-patch reports the following
        #
        #          Patch ID            RR  Release  Patch State
        # ===========================  ==  =======  ===========
        # PATCH_0001                   Y     9.0      Applied
        # PATCH_0002                   Y     9.0      Applied
        # PATCH_0003                   Y     9.0      Applied
        # PATCH_0004                   Y     9.0      Applied
        # PATCH_0005                   Y     9.0      Available
        #
        # Then after applying the latest patch, previously applied patches go to partial-applied, as follows:
        #
        #          Patch ID            RR  Release   Patch State
        # ===========================  ==  =======  =============
        # PATCH_0001                   Y    9.0     Partial-Apply
        # PATCH_0002                   Y    9.0     Partial-Apply
        # PATCH_0003                   Y    9.0     Partial-Apply
        # PATCH_0004                   Y    9.0        Applied
        # PATCH_0005                   Y    9.0     Partial-Apply
        #
        #  This happens because the previously applied patches commit doesn't match the latest_sysroot_commit,
        #  but the latest applied patch (in our example PATCH_0004) do have their commit matching,
        #  so we need to mark their dependent patches as a Applied.
        #

        self.create_patch_data(self.pc, CHECK_PATCH_STATES_QUERY_BUG,
                               CONTENTS_WITH_OSTREE_DATA_QUERY_BUG)
        test_ip1 = '127.0.0.1'
        an_1 = AgentNeighbour(test_ip1)
        an_1.out_of_date = True
        an_1.sw_version = "12.34"
        an_1.latest_sysroot_commit = "commitThirdPatch"
        self.pc.interim_state = []
        self.pc.hosts = {test_ip1: an_1}
        self.pc.check_patch_states()

        self.assertEqual(self.pc.patch_data.metadata["Third_Patch_CURRENT"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["First_Patch_APPLIED"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Second_Patch_APPLIED"]["patchstate"], "Applied")
        self.assertEqual(self.pc.patch_data.metadata["Fourth_Patch_NEWLY_APPLIED"]["patchstate"], "Partial-Apply")
