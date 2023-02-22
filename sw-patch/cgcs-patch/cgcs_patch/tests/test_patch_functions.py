"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
import logging
import mock
import os
import tarfile
import testtools

from cgcs_patch import patch_functions as pf
from cgcs_patch.exceptions import PatchValidationFailure
from cgcs_patch.patch_functions import PatchData
from cgcs_patch.patch_functions import PatchFile
from lxml import etree as ElementTree


LOG = logging.getLogger('main_logger')

PATCH_METADATA_NO_CONTENTS = \
    {
        "id": "PATCH_0001",
        "summary": "Some summary for patch",
        "description": "Some description",
        "install_instructions": "Some install instructions",
        "warnings": "Some warnings",
        "status": "Dev",
        "unremovable": "N",
        "reboot_required": "N",
    }

NO_PATCH_ID_METADATA = \
    {
        "summary": "Some summary for patch",
        "description": "Some description",
        "install_instructions": "Some install instructions",
        "warnings": "Some warnings",
        "status": "Dev",
        "unremovable": "N",
        "reboot_required": "N",
    }

PATCH_METADATA_WITH_CONTENTS = \
    {
        "id": "PATCH_0001",
        "summary": "Some summary for patch",
        "description": "Some description",
        "install_instructions": "Some install instructions",
        "warnings": "Some warnings",
        "status": "Dev",
        "unremovable": "N",
        "reboot_required": "Y",
        "requires":
            {
                "req_patch_id": "PATCH_0002"
            },
        "contents":
            {
                "ostree":
                    {
                        "number_of_commits": "2",
                        "base":
                            {
                                "commit": "basecommit",
                                "checksum": "basechecksum",
                            },
                        "commit1":
                            {
                                "commit": "FirstCommit",
                                "checksum": "FirstCommitChecksum",
                            },
                        "commit2":
                            {
                                "commit": "SecondCommit",
                                "checksum": "SecondCommitChecksum",
                            }
                    }
            }
    }


class FakeTarFile(object):
    def __init__(self, name):
        self.name = name


class FakeTar(object):
    def __init__(self, file_list=None):
        if file_list is not None:
            self._file_list = file_list.copy()
        else:
            self._file_list = []
        self._fake_members = [FakeTarFile(x) for x in self._file_list]

    def getmembers(self):
        return self._fake_members

    def extract(self, filename):
        return filename

    def extractall(self):
        return True


class CgcsPatchFunctionsTestCase(testtools.TestCase):

    def create_element_tree_from_dict(self, tree_root, dict_obj):
        root = ElementTree.Element(tree_root)
        for patch_attr, val in dict_obj.items():
            if not isinstance(val, dict):
                child = ElementTree.SubElement(root, patch_attr)
                child.text = val
            elif patch_attr == "contents":
                child = ElementTree.SubElement(root, "contents")
                ostree_child = ElementTree.SubElement(child, "ostree")
                for content_attr, content_val in dict_obj["contents"]["ostree"].items():
                    if not isinstance(content_val, dict):
                        content_child = ElementTree.SubElement(ostree_child, content_attr)
                        content_child.text = content_val
                    else:
                        commit_child = ElementTree.SubElement(ostree_child, content_attr)
                        for commit_attr, commit_val in content_val.items():
                            attr_child = ElementTree.SubElement(commit_child, commit_attr)
                            attr_child.text = commit_val
            elif patch_attr == "requires":
                req_child = ElementTree.SubElement(root, 'requires')
                for req_patch, req_val in dict_obj["requires"].items():
                    req_child = ElementTree.SubElement(req_child, req_patch)
                    req_child.text = req_val

        tree = ElementTree.ElementTree(root)
        return tree

    def test_patch_data(self):
        test_obj = PatchData()
        self.assertIsNotNone(test_obj)

    @mock.patch.object(ElementTree, "parse")
    def test_parse_metadata(self,
                            _mock_parse):
        test_obj = PatchData()
        tree_obj = self.create_element_tree_from_dict("patch", PATCH_METADATA_NO_CONTENTS)
        _mock_parse.return_value = tree_obj
        patch_id = test_obj.parse_metadata("metadata.xml")
        self.assertEqual(patch_id, "PATCH_0001")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["description"],
                         "Some description")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["install_instructions"],
                         "Some install instructions")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["patchstate"], "n/a")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["reboot_required"], "N")
        self.assertIsNone(test_obj.metadata["PATCH_0001"]["repostate"])
        self.assertEqual(test_obj.metadata["PATCH_0001"]["requires"], [])
        self.assertEqual(test_obj.metadata["PATCH_0001"]["status"], "Dev")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["summary"], "Some summary for patch")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["sw_version"], "unknown")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["unremovable"], "N")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["warnings"], "Some warnings")
        self.assertEqual(test_obj.contents["PATCH_0001"], {})

    @mock.patch.object(LOG, "error")
    @mock.patch.object(ElementTree, "parse")
    def test_parse_metadata_no_patch_id(self,
                                        _mock_parse,
                                        _mock_log_error):
        test_obj = PatchData()
        tree_obj = self.create_element_tree_from_dict("patch", NO_PATCH_ID_METADATA)
        _mock_parse.return_value = tree_obj
        patch_id = test_obj.parse_metadata("metadata.xml")
        self.assertIsNone(patch_id)
        _mock_log_error.assert_any_call('Patch metadata contains no id tag')

    @mock.patch.object(LOG, "error")
    @mock.patch.object(ElementTree, "parse")
    def test_parse_metadata_with_contents(self,
                                          _mock_parse,
                                          _mock_log_error):
        test_obj = PatchData()
        tree_obj = self.create_element_tree_from_dict("patch", PATCH_METADATA_WITH_CONTENTS)
        _mock_parse.return_value = tree_obj
        patch_id = test_obj.parse_metadata("metadata.xml")
        self.assertEqual(patch_id, "PATCH_0001")
        self.assertEqual(test_obj.contents["PATCH_0001"]["base"]["commit"],
                         "basecommit")
        self.assertEqual(test_obj.contents["PATCH_0001"]["base"]["checksum"],
                         "basechecksum")
        self.assertEqual(test_obj.contents["PATCH_0001"]["commit1"]["commit"],
                         "FirstCommit")
        self.assertEqual(test_obj.contents["PATCH_0001"]["commit2"]["commit"],
                         "SecondCommit")
        self.assertEqual(test_obj.metadata["PATCH_0001"]["requires"],
                         ['PATCH_0002'])

    @mock.patch.object(tarfile, "open")
    @mock.patch.object(LOG, "warning")
    @mock.patch.object(LOG, "error")
    @mock.patch.object(pf, 'get_md5')
    @mock.patch('builtins.int')
    @mock.patch('builtins.open')
    def test_read_patch_validation_failure(self,
                                           _mock_builtins_open,
                                           _mock_builtins_int,
                                           _mock_get_md5,
                                           _mock_log_error,
                                           _mock_log_warning,
                                           _mock_open):
        test_obj = PatchFile()
        _mock_open.return_value = FakeTar(["file1"])
        self.assertRaises(PatchValidationFailure, test_obj.read_patch, "fake_path")
        _mock_log_warning.assert_any_call('Patch not signed')
        _mock_log_error.assert_any_call('Patch failed verification')

    @mock.patch.object(tarfile, "open")
    @mock.patch.object(LOG, "warning")
    @mock.patch.object(LOG, "error")
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(pf, 'get_md5')
    @mock.patch.object(pf, 'verify_files')
    @mock.patch('builtins.int')
    @mock.patch('builtins.open')
    def test_read_patch_signature_validation_failed(self,
                                                    _mock_builtins_open,
                                                    _mock_builtins_int,
                                                    _mock_verify_files,
                                                    _mock_get_md5,
                                                    _mock_exists,
                                                    _mock_log_error,
                                                    _mock_log_warning,
                                                    _mock_open):
        test_obj = PatchFile()
        _mock_builtins_int.return_value = 0
        _mock_get_md5.side_effect = [0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]
        _mock_open.return_value = FakeTar(["signature", "signature.v2"])
        _mock_exists.return_value = True
        _mock_verify_files.return_value = False
        self.assertRaises(PatchValidationFailure, test_obj.read_patch, "fake_path")
        _mock_log_error.assert_any_call('Signature check failed')

    @mock.patch.object(tarfile, "open")
    @mock.patch.object(LOG, "warning")
    @mock.patch.object(LOG, "error")
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(pf, 'get_md5')
    @mock.patch('builtins.int')
    @mock.patch('builtins.open')
    def test_read_patch_not_signed(self,
                                   _mock_builtins_open,
                                   _mock_builtins_int,
                                   _mock_get_md5,
                                   _mock_exists,
                                   _mock_log_error,
                                   _mock_log_warning,
                                   _mock_open):
        test_obj = PatchFile()
        _mock_builtins_int.return_value = 0
        _mock_get_md5.side_effect = [0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]
        _mock_open.return_value = FakeTar(["signature", "signature.v2"])
        _mock_exists.return_value = False
        self.assertRaises(PatchValidationFailure, test_obj.read_patch, "fake_path")
        _mock_log_error.assert_any_call('Patch has not been signed')

    @mock.patch.object(tarfile, "open")
    @mock.patch.object(LOG, "info")
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(pf, 'get_md5')
    @mock.patch('builtins.int')
    @mock.patch('builtins.open')
    @mock.patch.object(pf, 'verify_files')
    def test_read_patch_success(self,
                                _mock_verify_files,
                                _mock_builtins_open,
                                _mock_builtins_int,
                                _mock_get_md5,
                                _mock_exists,
                                _mock_log_info,
                                _mock_open):
        test_obj = PatchFile()
        _mock_builtins_int.return_value = 0
        _mock_get_md5.side_effect = [0, 0, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]
        _mock_open.return_value = FakeTar(["signature", "signature.v2", "semantics.tar"])
        _mock_exists.return_value = True
        _mock_verify_files.return_value = True
        test_obj.read_patch("fake_path")
        _mock_log_info.assert_any_call('Signature verified, patch has been signed')
