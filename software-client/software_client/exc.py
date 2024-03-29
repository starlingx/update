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


class HTTPException(ClientException):
    """Base exception for all HTTP-derived exceptions."""
    code = 'N/A'

    def __init__(self, details=None):
        super(HTTPException, self).__init__()
        self.details = details

    def __str__(self):
        return str(self.details) or "%s (HTTP %s)" % (self.__class__.__name__,
                                                      self.code)


class HTTPMultipleChoices(HTTPException):
    code = 300

    def __str__(self):
        self.details = ("Requested version of Software API is not"
                        "available.")
        return "%s (HTTP %s) %s" % (self.__class__.__name__, self.code,
                                    self.details)


class BadRequest(HTTPException):
    """DEPRECATED."""
    code = 400


class HTTPBadRequest(BadRequest):
    pass


class Unauthorized(HTTPException):
    """DEPRECATED."""
    code = 401


class HTTPUnauthorized(Unauthorized):
    pass


class Forbidden(HTTPException):
    """DEPRECATED."""
    code = 403


class HTTPForbidden(Forbidden):
    pass


class NotFound(HTTPException):
    """DEPRECATED."""
    code = 404


class HTTPNotFound(NotFound):
    pass


class HTTPMethodNotAllowed(HTTPException):
    code = 405


class Conflict(HTTPException):
    """DEPRECATED."""
    code = 409


class HTTPConflict(Conflict):
    pass


class OverLimit(HTTPException):
    """DEPRECATED."""
    code = 413


class HTTPOverLimit(OverLimit):
    pass


class HTTPInternalServerError(HTTPException):
    code = 500


class HTTPNotImplemented(HTTPException):
    code = 501


class HTTPBadGateway(HTTPException):
    code = 502


class ServiceUnavailable(HTTPException):
    """DEPRECATED."""
    code = 503


class HTTPServiceUnavailable(ServiceUnavailable):
    pass


# NOTE(bcwaldon): Build a mapping of HTTP codes to corresponding exception
# classes
_code_map = {}
for obj_name in dir(sys.modules[__name__]):
    if obj_name.startswith('HTTP'):
        obj = getattr(sys.modules[__name__], obj_name)
        _code_map[obj.code] = obj


def from_response(response, message=None, traceback=None,
                  method=None, url=None):
    """Return an instance of an HTTPException based on httplib response."""
    cls = None
    if hasattr(response, 'status_code'):
        cls = _code_map.get(response.status_code, HTTPException)
    elif hasattr(response, 'status_int'):
        cls = _code_map.get(response.status_int, HTTPException)
    elif hasattr(response, 'status'):
        cls = _code_map.get(response.status, HTTPException)
    else:
        # No status code: return a generic exception
        return Exception("Unexpected error in response: %s" % message)
    return cls(message)


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
