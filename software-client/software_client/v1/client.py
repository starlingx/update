# Copyright (c) 2013-2024 Wind River Systems, Inc.
# Copyright 2012-2024 OpenStack LLC.
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


from software_client.common import http
from software_client.v1 import release
from software_client.v1 import deploy


class Client(object):
    """Client for the Software v1 API.

    """

    def __init__(self, *args, **kwargs):
        """Initialize a new client for the Software v1 API."""
        super(Client, self).__init__()
        self.http_client = http.construct_http_client(*args, **kwargs)

        self.release = release.ReleaseManager(self.http_client)
        self.deploy = deploy.DeployManager(self.http_client)
