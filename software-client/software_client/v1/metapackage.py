#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from software_client.common import base


class Metapackage(base.Resource):
    def __repr__(self):
        return "<metapackage %s>" % self._info


class MetapackageManager(base.Manager):
    resource_class = Metapackage

    def list(self, args):
        path = "/v1/release/metapackage"
        state = args.state
        additions = []
        if state:
            additions.append("show=%s" % state)

        if args.all:
            additions.append("all")

        if len(additions) > 0:
            path = path + "?" + "&".join(additions)

        return self._list(path, "")
