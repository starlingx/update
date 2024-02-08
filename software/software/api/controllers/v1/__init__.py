#
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

"""
Version 1 of the USM API

Specification can be found in code repo.
"""

import pecan
import wsmeext.pecan as wsme_pecan
from pecan import rest
from wsme import types as wtypes

from software.api.controllers.v1 import base
from software.api.controllers.v1 import link
from software.api.controllers.v1 import software


class MediaType(base.APIBase):
    """A media type representation."""

    base = wtypes.text
    type = wtypes.text

    def __init__(self, base, type):
        self.base = base
        self.type = type


class V1(base.APIBase):
    """The representation of the version 1 of the API."""

    id = wtypes.text
    "The ID of the version, also acts as the release number"

    media_types = [MediaType]
    "An array of supported media types for this version"

    links = [link.Link]
    "Links that point to a specific URL for this version and documentation"

    software = [link.Link]
    "Links to the software resource"

    @classmethod
    def convert(self):
        v1 = V1()
        v1.id = "v1"
        v1.links = [link.Link.make_link('self', pecan.request.host_url,
                                        'v1', '', bookmark=True),
                    ]
        v1.media_types = [MediaType('application/json',
                          'application/vnd.openstack.software.v1+json')]

        v1.software = [link.Link.make_link('self', pecan.request.host_url,
                                           'software', ''),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'software', '',
                                           bookmark=True)
                       ]

        return v1


class Controller(rest.RestController):
    """Version 1 API controller root."""

    software = software.SoftwareAPIController()

    @wsme_pecan.wsexpose(V1)
    def get(self):
        # NOTE: The reason why convert() it's being called for every
        #       request is because we need to get the host url from
        #       the request object to make the links.
        return V1.convert()


__all__ = (Controller)
