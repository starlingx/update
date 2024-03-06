# Copyright 2013-2024 Wind River, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import six
import sys


class BaseException(Exception):
    """An error occurred."""
    def __init__(self, message=None):
        super(BaseException, self).__init__()
        self.message = message

    def __str__(self):
        return str(self.message) or self.__class__.__doc__


class CommandError(BaseException):
    """Invalid usage of CLI."""


class InvalidEndpoint(BaseException):
    """The provided endpoint is invalid."""


class CommunicationError(BaseException):
    """Unable to communicate with server."""


class ClientException(Exception):
    """DEPRECATED."""


class NoTokenLookupException(Exception):
    """DEPRECATED."""
    pass  # pylint: disable=unnecessary-pass


class EndpointNotFound(Exception):
    """DEPRECATED."""
    pass  # pylint: disable=unnecessary-pass


class AmbiguousAuthSystem(ClientException):
    """Could not obtain token and endpoint using provided credentials."""
    pass  # pylint: disable=unnecessary-pass


class SoftwareclientException(Exception):
    """Base Software-Client Exception

    To correctly use this class, inherit from it and define
    a 'message' property. That message will get printf'd
    with the keyword arguments provided to the constructor.

    """
    message = "An unknown exception occurred."
    code = 500
    headers = {}
    safe = False

    def __init__(self, message=None, **kwargs):
        self.kwargs = kwargs

        if 'code' not in self.kwargs:
            try:
                self.kwargs['code'] = self.code
            except AttributeError:
                pass

        if not message:
            try:
                message = self.message % kwargs  # pylint: disable=exception-message-attribute

            except Exception:
                # kwargs doesn't match a variable in the message
                # at least get the core message out if something happened
                message = self.message  # pylint: disable=exception-message-attribute

        super(SoftwareclientException, self).__init__(message)

    def format_message(self):
        if self.__class__.__name__.endswith('_Remote'):
            return self.args[0]  # pylint: disable=unsubscriptable-object
        else:
            return six.text_type(self)


class AmbiguousEndpoints(SoftwareclientException):
    message = "Endpoints are ambiguous. reason=%(reason)s"


class EndpointTypeNotFound(SoftwareclientException):
    message = "The type of the endpoint was not found. reason=%(reason)s"


class SslCertificateValidationError(SoftwareclientException):
    message = "Validation of the Ssl certificate failed. reason=%(reason)s"


class EndpointException(SoftwareclientException):
    message = "Generic endpoint exception. reason=%(reason)s"


# Alias for backwards compatibility
AmbigiousAuthSystem = AmbiguousAuthSystem


class InvalidAttribute(ClientException):
    pass


class InvalidAttributeValue(ClientException):
    pass
