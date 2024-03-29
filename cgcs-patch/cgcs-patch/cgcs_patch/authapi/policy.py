#
# Copyright (c) 2011 OpenStack Foundation
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
#
# Copyright (c) 2014-2022 Wind River Systems, Inc.
#

"""Policy Engine For Patching."""

import os.path

from sysinv.common import exception
from sysinv.common import utils
from sysinv.openstack.common import policy


_POLICY_PATH = None
_POLICY_CACHE = {}


def reset():
    global _POLICY_PATH
    global _POLICY_CACHE
    _POLICY_PATH = None
    _POLICY_CACHE = {}
    policy.reset()


def init():
    global _POLICY_PATH
    global _POLICY_CACHE
    if not _POLICY_PATH:
        _POLICY_PATH = '/etc/patching/policy.json'
        if not os.path.exists(_POLICY_PATH):
            raise exception.ConfigNotFound(message='/etc/patching/policy.json')
    utils.read_cached_file(_POLICY_PATH, _POLICY_CACHE,
                           reload_func=_set_rules)


def _set_rules(data):
    default_rule = "rule:admin_api"
    rules = policy.Rules.load_rules(data, default_rule, [])
    policy.set_rules(rules)


def enforce(context, action, target, do_raise=True):
    """Verifies that the action is valid on the target in this context.

       :param context: sysinv context
       :param action: string representing the action to be checked
           this should be colon separated for clarity.
           i.e. ``compute:create_instance``,
           ``compute:attach_volume``,
           ``volume:attach_volume``
       :param target: dictionary representing the object of the action
           for object creation this should be a dictionary representing the
           location of the object e.g. ``{'project_id': context.project_id}``
       :param do_raise: if True (the default), raises PolicyNotAuthorized;
           if False, returns False

       :raises sysinv.exception.PolicyNotAuthorized: if verification fails
           and do_raise is True.

       :return: returns a non-False value (not necessarily "True") if
           authorized, and the exact value False if not authorized and
           do_raise is False.
    """
    init()

    credentials = context.to_dict()

    # Add the exception arguments if asked to do a raise
    extra = {}
    if do_raise:
        extra.update(exc=exception.PolicyNotAuthorized, action=action)

    return policy.check(action, target, credentials, **extra)


def check_is_admin(context):
    """Whether or not role contains 'admin' role according to policy setting.

    """
    init()

    credentials = context.to_dict()
    target = credentials

    return policy.check('context_is_admin', target, credentials)


@policy.register('context_is_admin')
class IsAdminCheck(policy.Check):
    """An explicit check for is_admin."""

    def __init__(self, kind, match):
        """Initialize the check."""

        self.expected = (match.lower() == 'true')

        super(IsAdminCheck, self).__init__(kind, str(self.expected))

    def __call__(self, target, creds):
        """Determine whether is_admin matches the requested value."""

        return creds['is_admin'] == self.expected
