"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""
from oslo_log import log
import pecan
from pecan import rest

from software.api.controllers import v1
from software.api.controllers.v1 import base
from software.api.controllers.v1 import link

from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

LOG = log.getLogger(__name__)


class Version(base.APIBase):
    """An API version representation."""

    id = wtypes.text
    "The ID of the version, also acts as the release number"

    links = [link.Link]
    "A Link that point to a specific version of the API"

    @classmethod
    def convert(self, id):
        version = Version()
        version.id = id
        version.links = [link.Link.make_link('self', pecan.request.host_url,
                                             id, '', bookmark=True)]
        return version


class Root(base.APIBase):

    name = wtypes.text
    "The name of the API"

    description = wtypes.text
    "Some information about this API"

    versions = [Version]
    "Links to all the versions available in this API"

    default_version = Version
    "A link to the default version of the API"

    @classmethod
    def convert(self):
        root = Root()
        root.name = "StarlingX USM API"
        root.description = ("Unified Software Management API allows for a "
             "single REST API / CLI and single procedure for updating "
             "the StarlingX software on a Standalone Cloud or Distributed Cloud."
                            )
        root.versions = [Version.convert('v1')]
        root.default_version = Version.convert('v1')
        return root


class RootController(rest.RestController):

    v1 = v1.Controller()

    @wsme_pecan.wsexpose(Root)
    def get(self):
        # NOTE: The reason why convert() it's being called for every
        #       request is because we need to get the host url from
        #       the request object to make the links.
        return Root.convert()
