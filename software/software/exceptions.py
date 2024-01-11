"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""


class SoftwareError(Exception):
    """Base class for software exceptions."""

    def __init__(self, message=None):
        super(SoftwareError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message or ""


class APTOSTreeCommandFail(SoftwareError):
    """Apt-ostree errror."""
    pass


class MetadataFail(SoftwareError):
    """Metadata error."""
    pass


class ContentFail(SoftwareError):
    """Content handling error."""
    pass


class OSTreeTarFail(SoftwareError):
    """OSTree Tarball error."""
    pass


class OSTreeCommandFail(SoftwareError):
    """OSTree Commands error."""
    pass


class SemanticFail(SoftwareError):
    """Semantic check error."""
    pass


class RepoFail(SoftwareError):
    """Repo error."""
    pass


class SoftwareFail(SoftwareError):
    """General unified software management error."""
    pass


class ReleaseValidationFailure(SoftwareError):
    """Release validation error."""
    pass


class UpgradeNotSupported(SoftwareError):
    """Upgrade not supported error."""
    pass


class ReleaseMismatchFailure(SoftwareError):
    """Release mismatch error."""
    pass


class ReleaseUploadFailure(SoftwareError):
    """Release upload error."""
    pass


class ReleaseInvalidRequest(SoftwareError):
    """Invalid API request."""
    pass


class DuplicateDeployment(SoftwareError):
    """Duplicate Deployment Error."""
    pass


class ReleaseIsoDeleteFailure(SoftwareError):
    """Release iso delete error."""
    pass


class SysinvClientNotInitialized(SoftwareError):
    """Sysinv Client Not Initialized Error."""
    pass


class StateValidationFailure(SoftwareError):
    """State Validation Failure"""
    pass


class DeployDoNotExist(SoftwareError):
    """Deploy Do Not Exist"""
    pass


class DeployAlreadyExist(SoftwareError):
    """Deploy Already Exist"""
    pass


class ReleaseVersionDoNotExist(SoftwareError):
    """Release Version Do Not Exist"""
    pass
