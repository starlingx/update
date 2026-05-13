#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import signal

from software_client.common import base


class SystemDeploy(base.Resource):
    def __repr__(self):
        return "<system_deploy %s>" % self._info


class SystemDeployManager(base.Manager):
    resource_class = SystemDeploy

    def init(self, args):
        release_id = args.release_id
        path = "/v1/system_deploy/%s/init" % release_id
        body = {}
        if hasattr(args, 'kube_version') and args.kube_version:
            body['kube_version'] = args.kube_version
        return self._post(path, body=body)

    def show(self, args):
        path = "/v1/system_deploy"
        return self._list(path)

    def delete(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy delete request
        path = "/v1/system_deploy/"

        return self._delete(path)
