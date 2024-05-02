# Copyright 2013-2024 Wind River, Inc.
# Copyright 2012 OpenStack LLC.
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

"""
Base utilities to build API operation managers and objects on top of.
"""

import copy


class Manager(object):
    """Managers interact with a particular type of API and provide CRUD
    operations for them.
    """
    resource_class = None

    def __init__(self, api):
        self.api = api

    def _create(self, url, **kwargs):
        return self.api.json_request('POST', url, **kwargs)

    def _create_multipart(self, url, **kwargs):
        return self.api.multipart_request('POST', url, **kwargs)

    def _post(self, url, **kwargs):
        return self.api.json_request('POST', url, **kwargs)

    def _list(self, url, response_key=None, obj_class=None, body=None):
        resp, body = self.api.json_request('GET', url)
        if response_key:
            try:
                data = body[response_key]
            except KeyError:
                return []
        else:
            data = body

        return resp, data

    def _fetch(self, url):
        resp, body = self.api.json_request('GET', url)
        data = body
        return resp, data

    def _delete(self, url):
        return self.api.json_request('DELETE', url)


class Resource(object):
    """A resource represents a particular instance of an object (tenant, user,
    etc). This is pretty much just a bag for attributes.

    :param manager: Manager object
    :param info: dictionary representing resource attributes
    :param loaded: prevent lazy-loading if set to True
    """
    def __init__(self, manager, info, loaded=False):
        self.manager = manager
        self._info = info
        self._add_details(info)
        self._loaded = loaded

    def _add_details(self, info):
        for (k, v) in info.items():
            setattr(self, k, v)

    def __getattr__(self, k):
        if k not in self.__dict__:
            # NOTE(bcwaldon): disallow lazy-loading if already loaded once
            if not self.is_loaded():
                self.get()
                return self.__getattr__(k)

            raise AttributeError(k)
        else:
            return self.__dict__[k]

    # deepcopy is invoked on this object which causes infinite recursion in python3
    # unless the copy and deepcopy methods are overridden
    def __copy__(self):
        cls = self.__class__
        result = cls.__new__(cls)
        result.__dict__.update(self.__dict__)
        return result

    def __deepcopy__(self, memo):
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            setattr(result, k, copy.deepcopy(v, memo))
        return result

    def __repr__(self):
        reprkeys = sorted(k for k in list(self.__dict__.keys()) if k[0] != '_' and
                          k != 'manager')
        info = ", ".join("%s=%s" % (k, getattr(self, k)) for k in reprkeys)
        return "<%s %s>" % (self.__class__.__name__, info)

    def get(self):
        # set_loaded() first ... so if we have to bail, we know we tried.
        self.set_loaded(True)
        if not hasattr(self.manager, 'get'):
            return

        new = self.manager.get(self.id)
        if new:
            self._add_details(new._info)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if hasattr(self, 'id') and hasattr(other, 'id'):
            return self.id == other.id
        return self._info == other._info

    def __hash__(self):
        return hash((self.manager, self._info, self._loaded))

    def is_loaded(self):
        return self._loaded

    def set_loaded(self, val):
        self._loaded = val

    def to_dict(self):
        return copy.deepcopy(self._info)
