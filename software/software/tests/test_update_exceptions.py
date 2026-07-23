#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for software.exceptions module."""

import unittest

from software.exceptions import APTOSTreeCommandFail
from software.exceptions import ContentFail
from software.exceptions import DeployAlreadyExist
from software.exceptions import DeployDoNotExist
from software.exceptions import DuplicateDeployment
from software.exceptions import FileSystemError
from software.exceptions import HostAgentUnreachable
from software.exceptions import HostNotFound
from software.exceptions import InternalError
from software.exceptions import InvalidOperation
from software.exceptions import MaxReleaseExceeded
from software.exceptions import MetadataFail
from software.exceptions import OSTreeCommandFail
from software.exceptions import OSTreeTarFail
from software.exceptions import ReleaseInvalidRequest
from software.exceptions import ReleaseIsoDeleteFailure
from software.exceptions import ReleaseMismatchFailure
from software.exceptions import ReleaseNotFound
from software.exceptions import ReleaseUploadFailure
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseVersionDoNotExist
from software.exceptions import RepoFail
from software.exceptions import SemanticFail
from software.exceptions import SoftwareError
from software.exceptions import SoftwareFail
from software.exceptions import SoftwareServiceError
from software.exceptions import StateValidationFailure
from software.exceptions import SysinvClientNotInitialized
from software.exceptions import SystemDeployNotExist
from software.exceptions import UpgradeNotSupported
from software.exceptions import VersionedDeployPrecheckFailure


class TestInternalError(unittest.TestCase):
    """Tests for InternalError exception."""

    def test_raise_internal_error(self):
        """Test InternalError can be raised and caught."""
        with self.assertRaises(InternalError):
            raise InternalError("internal bug")

    def test_internal_error_is_exception(self):
        """Test InternalError inherits from Exception."""
        self.assertTrue(issubclass(InternalError, Exception))


class TestSoftwareServiceError(unittest.TestCase):
    """Tests for SoftwareServiceError and its properties."""

    def test_default_properties(self):
        """Test default empty properties."""
        err = SoftwareServiceError()
        self.assertEqual(err.info, "")
        self.assertEqual(err.warning, "")
        self.assertEqual(err.error, "")

    def test_info_property(self):
        """Test info property."""
        err = SoftwareServiceError(info="some info")
        self.assertEqual(err.info, "some info")

    def test_warn_property(self):
        """Test warning property."""
        err = SoftwareServiceError(warn="some warning")
        self.assertEqual(err.warning, "some warning")

    def test_error_property(self):
        """Test error property."""
        err = SoftwareServiceError(error="some error")
        self.assertEqual(err.error, "some error")

    def test_none_info_returns_empty(self):
        """Test None info returns empty string."""
        err = SoftwareServiceError(info=None)
        self.assertEqual(err.info, "")

    def test_none_warn_returns_empty(self):
        """Test None warning returns empty string."""
        err = SoftwareServiceError(warn=None)
        self.assertEqual(err.warning, "")

    def test_none_error_returns_empty(self):
        """Test None error returns empty string."""
        err = SoftwareServiceError(error=None)
        self.assertEqual(err.error, "")


class TestInvalidOperation(unittest.TestCase):
    """Tests for InvalidOperation exception."""

    def test_invalid_operation_message(self):
        """Test InvalidOperation stores error message."""
        err = InvalidOperation("cannot deploy")
        self.assertEqual(err.error, "cannot deploy")

    def test_invalid_operation_inherits(self):
        """Test InvalidOperation inherits from SoftwareServiceError."""
        self.assertTrue(issubclass(InvalidOperation, SoftwareServiceError))


class TestReleaseNotFound(unittest.TestCase):
    """Tests for ReleaseNotFound exception."""

    def test_single_release_id(self):
        """Test with a single release ID string."""
        err = ReleaseNotFound("rel-1.0")
        self.assertIn("rel-1.0", err.error)

    def test_multiple_release_ids(self):
        """Test with a list of release IDs."""
        err = ReleaseNotFound(["rel-1.0", "rel-2.0"])
        self.assertIn("rel-1.0", err.error)
        self.assertIn("rel-2.0", err.error)


class TestHostNotFound(unittest.TestCase):
    """Tests for HostNotFound exception."""

    def test_host_not_found_message(self):
        """Test HostNotFound error message."""
        err = HostNotFound("controller-0")
        self.assertIn("controller-0", err.error)


class TestHostAgentUnreachable(unittest.TestCase):
    """Tests for HostAgentUnreachable exception."""

    def test_unreachable_message(self):
        """Test HostAgentUnreachable error message."""
        err = HostAgentUnreachable("worker-1")
        self.assertIn("worker-1", err.error)
        self.assertIn("unreachable", err.error)


class TestMaxReleaseExceeded(unittest.TestCase):
    """Tests for MaxReleaseExceeded exception."""

    def test_max_release_message(self):
        """Test MaxReleaseExceeded stores message."""
        err = MaxReleaseExceeded("too many releases")
        self.assertEqual(err.error, "too many releases")


class TestSoftwareError(unittest.TestCase):
    """Tests for SoftwareError base class."""

    def test_software_error_message(self):
        """Test SoftwareError message attribute."""
        err = SoftwareError("test error")
        self.assertEqual(str(err), "test error")
        self.assertEqual(err.message, "test error")

    def test_software_error_none_message(self):
        """Test SoftwareError with None message."""
        err = SoftwareError()
        self.assertEqual(str(err), "")

    def test_software_error_is_exception(self):
        """Test SoftwareError inherits from Exception."""
        self.assertTrue(issubclass(SoftwareError, Exception))


class TestSoftwareErrorSubclasses(unittest.TestCase):
    """Tests for all SoftwareError subclasses."""

    def test_apt_ostree_command_fail(self):
        """Test APTOSTreeCommandFail."""
        err = APTOSTreeCommandFail("apt-ostree failed")
        self.assertIsInstance(err, SoftwareError)

    def test_metadata_fail(self):
        """Test MetadataFail."""
        err = MetadataFail("bad metadata")
        self.assertIsInstance(err, SoftwareError)

    def test_content_fail(self):
        """Test ContentFail."""
        err = ContentFail("content error")
        self.assertIsInstance(err, SoftwareError)

    def test_ostree_tar_fail(self):
        """Test OSTreeTarFail."""
        err = OSTreeTarFail("tar error")
        self.assertIsInstance(err, SoftwareError)

    def test_ostree_command_fail(self):
        """Test OSTreeCommandFail."""
        err = OSTreeCommandFail("ostree error")
        self.assertIsInstance(err, SoftwareError)

    def test_semantic_fail(self):
        """Test SemanticFail."""
        err = SemanticFail("semantic error")
        self.assertIsInstance(err, SoftwareError)

    def test_repo_fail(self):
        """Test RepoFail."""
        err = RepoFail("repo error")
        self.assertIsInstance(err, SoftwareError)

    def test_software_fail(self):
        """Test SoftwareFail."""
        err = SoftwareFail("general error")
        self.assertIsInstance(err, SoftwareError)

    def test_upgrade_not_supported(self):
        """Test UpgradeNotSupported."""
        err = UpgradeNotSupported("not supported")
        self.assertIsInstance(err, SoftwareError)

    def test_release_upload_failure(self):
        """Test ReleaseUploadFailure."""
        err = ReleaseUploadFailure("upload failed")
        self.assertIsInstance(err, SoftwareError)

    def test_release_invalid_request(self):
        """Test ReleaseInvalidRequest."""
        err = ReleaseInvalidRequest("bad request")
        self.assertIsInstance(err, SoftwareError)

    def test_duplicate_deployment(self):
        """Test DuplicateDeployment."""
        err = DuplicateDeployment("duplicate")
        self.assertIsInstance(err, SoftwareError)

    def test_release_iso_delete_failure(self):
        """Test ReleaseIsoDeleteFailure."""
        err = ReleaseIsoDeleteFailure("delete failed")
        self.assertIsInstance(err, SoftwareError)

    def test_sysinv_client_not_initialized(self):
        """Test SysinvClientNotInitialized."""
        err = SysinvClientNotInitialized("not init")
        self.assertIsInstance(err, SoftwareError)

    def test_state_validation_failure(self):
        """Test StateValidationFailure."""
        err = StateValidationFailure("bad state")
        self.assertIsInstance(err, SoftwareError)

    def test_deploy_do_not_exist(self):
        """Test DeployDoNotExist."""
        err = DeployDoNotExist("no deploy")
        self.assertIsInstance(err, SoftwareError)

    def test_deploy_already_exist(self):
        """Test DeployAlreadyExist."""
        err = DeployAlreadyExist("already exists")
        self.assertIsInstance(err, SoftwareError)

    def test_release_version_do_not_exist(self):
        """Test ReleaseVersionDoNotExist."""
        err = ReleaseVersionDoNotExist("no version")
        self.assertIsInstance(err, SoftwareError)

    def test_versioned_deploy_precheck_failure(self):
        """Test VersionedDeployPrecheckFailure."""
        err = VersionedDeployPrecheckFailure("precheck fail")
        self.assertIsInstance(err, SoftwareError)

    def test_file_system_error(self):
        """Test FileSystemError."""
        err = FileSystemError("fs error")
        self.assertIsInstance(err, SoftwareError)

    def test_system_deploy_not_exist(self):
        """Test SystemDeployNotExist."""
        err = SystemDeployNotExist("no system deploy")
        self.assertIsInstance(err, SoftwareError)


class TestServiceErrorSubclasses(unittest.TestCase):
    """Tests for SoftwareServiceError subclasses."""

    def test_release_validation_failure(self):
        """Test ReleaseValidationFailure."""
        self.assertTrue(issubclass(ReleaseValidationFailure,
                                   SoftwareServiceError))

    def test_release_mismatch_failure(self):
        """Test ReleaseMismatchFailure."""
        self.assertTrue(issubclass(ReleaseMismatchFailure,
                                   SoftwareServiceError))
