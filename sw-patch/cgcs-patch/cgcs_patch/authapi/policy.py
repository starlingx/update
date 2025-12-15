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
# SPDX-License-Identifier: Apache-2.0
#

"""Policy Engine For Patching."""

from oslo_config import cfg
from oslo_policy import policy


base_rules = [
    policy.RuleDefault('admin_in_system_projects',
                       'role:admin and (project_name:admin or ' +
                       'project_name:services)',
                       description='Admin user in system projects.'),
    policy.RuleDefault('reader_in_system_projects',
                       'role:reader and (project_name:admin or ' +
                       'project_name:services)',
                       description='Reader user in system projects.'),
    policy.RuleDefault('default', 'rule:admin_in_system_projects',
                       description='Default rule.'),
]

CONF = cfg.CONF
_ENFORCER = None


def init(policy_file=None, rules=None,
         default_rule=None, use_conf=True, overwrite=True):
    """Init an Enforcer class.

       oslo policy supports change policy rule dynamically.
       policy.enforce will reload the policy rules if it detects
       the policy files have been touched.

        :param policy_file: Custom policy file to use, if none is
                            specified, ``conf.policy_file`` will be
                            used.
        :param rules: Default dictionary / Rules to use. It will be
                      considered just in the first instantiation. If
                      :meth:`load_rules` with ``force_reload=True``,
                      :meth:`clear` or :meth:`set_rules` with
                      ``overwrite=True`` is called this will be overwritten.
        :param default_rule: Default rule to use, conf.default_rule will
                             be used if none is specified.
        :param use_conf: Whether to load rules from cache or config file.
        :param overwrite: Whether to overwrite existing rules when reload rules
                          from config file.
    """
    global _ENFORCER
    if not _ENFORCER:
        # https://docs.openstack.org/oslo.policy/latest/user/usage.html
        _ENFORCER = policy.Enforcer(CONF,
                                    policy_file=policy_file,
                                    rules=rules,
                                    default_rule=default_rule,
                                    use_conf=use_conf,
                                    overwrite=overwrite)
        _ENFORCER.register_defaults(base_rules)
    return _ENFORCER


def authorize(rule, target, creds, do_raise=True):
    """A wrapper around 'authorize' from 'oslo_policy.policy'."""
    init()
    return _ENFORCER.authorize(rule, target, creds, do_raise=do_raise)
