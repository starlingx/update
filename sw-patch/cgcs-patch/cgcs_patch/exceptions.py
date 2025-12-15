"""
Copyright (c) 2017-2022 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""


class PatchError(Exception):
    """Base class for patching exceptions."""

    def __init__(self, message=None):
        super(PatchError, self).__init__(message)
        self.message = message

    def __str__(self):
        return self.message or ""


class MetadataFail(PatchError):
    """Metadata error."""
    pass


class ContentFail(PatchError):
    """Content handling error."""
    pass


class OSTreeTarFail(PatchError):
    """OSTree Tarball error."""
    pass


class OSTreeCommandFail(PatchError):
    """OSTree Commands error."""
    pass


class SemanticFail(PatchError):
    """Semantic check error."""
    pass


class RepoFail(PatchError):
    """Repo error."""
    pass


class PatchFail(PatchError):
    """General patching error."""
    pass


class PatchValidationFailure(PatchError):
    """Patch validation error."""
    pass


class PatchMismatchFailure(PatchError):
    """Patch validation error."""
    pass


class PatchInvalidRequest(PatchError):
    """Invalid API request."""
    pass
