#
# Copyright (c) 2015-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re
import requests
import signal
import time

from software_client.common import base
from software_client.common import utils
from software_client import constants


class Deploy(base.Resource):
    def __repr__(self):
        return "<address pool %s>" % self._info


class DeployManager(base.Manager):
    resource_class = Deploy

    def select(self, args):
        pre_upgrade_deploy = args.pre_upgrade_deploy
        releases = args.releases  # releases is mandatory for select

        path = "/v1/deploy/select"

        body = {
            "releases": releases,
            "pre_upgrade_deploy": pre_upgrade_deploy,
        }

        res = self._post(path, body=body)
        return res

    def unselect(self, args):
        releases = args.releases
        unselect_all = args.all

        body = {
            "unselect_all": unselect_all,
        }
        if releases:
            body.update({"releases": releases})

        path = "/v1/deploy/unselect"

        res = self._post(path, body=body)
        return res

    def precheck(self, args):
        path = "/v1/deploy/precheck"
        releases = args.releases

        body = {
            "releases": releases
        }
        if args.force:
            body["force"] = "true"
        if args.options:
            body["options"] = args.options
        if args.region_name:
            body["region_name"] = args.region_name
        if args.pre_upgrade_deploy:
            body["pre_upgrade_deploy"] = args.pre_upgrade_deploy

        res = self._post(path, body=body)
        return res

    def start(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        path = "/v1/deploy/start"
        if args.releases:
            path = path + "?releases=" + ",".join(args.releases)

        body = {}
        if args.force:
            body["force"] = "true"
        if args.options:
            body["options"] = args.options

        return self._post(path, body=body)

    def host(self, args):
        # args.deployment is a string
        hostname = args.host

        # Issue deploy_host request and poll for results
        path = "/v1/deploy_host/%s" % hostname

        if args.force:
            path += "/force"

        return self._create(path)

    def host_rollback(self, args):
        # args.deployment is a string
        hostname = args.host

        # Issue deploy_host request and poll for results
        path = "/v1/deploy_host/%s/rollback" % hostname

        if args.force:
            path += "/force"

        return self._create(path)

    def abort(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_abort request
        path = "/v1/deploy/abort"

        return self._create(path, body={})

    def activate(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        path = "/v1/deploy/activate"

        return self._create(path, body={})

    def activate_rollback(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        path = "/v1/deploy/activate_rollback"

        return self._create(path, body={})

    def complete(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        path = "/v1/deploy/complete"

        return self._create(path, body={})

    def delete(self, args):
        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy delete request
        path = "/v1/deploy"

        return self._delete(path)

    def host_list(self):
        path = '/v1/deploy_host'
        return self._list(path, "")

    def show(self):
        path = '/v1/deploy'
        return self._list(path)

    def wait_for_install_complete(self, hostname):
        url = "/v1/deploy_host"
        rc = 0

        max_retries = 4
        retriable_count = 0

        while True:
            # Sleep on the first pass as well, to allow time for the
            # agent to respond
            time.sleep(5)

            try:
                req, data = self._list(url)
            except requests.exceptions.ConnectionError:
                # The local software-controller may have restarted.
                retriable_count += 1
                if retriable_count > max_retries:
                    print("Lost communications with the software controller")
                    rc = 1
                    return rc
            else:
                break

        if req.status_code == 200:
            if not data:
                print("Invalid host-list data returned:")
                utils.print_result_debug(req, data)
                rc = 1

            host_state = None

            for d in data:
                if d['hostname'] == hostname:
                    host_state = d.get('host_state')

            if host_state == constants.DEPLOYING:
                print("\nDeployment started.")
                rc = 0
            elif host_state == constants.FAILED:
                print("\nDeployment failed. Please check logs for details.")
                rc = 1
            elif host_state == constants.DEPLOYED:
                print("\nDeployment was successful.")
                rc = 0
            elif host_state == constants.PENDING:
                print("\nDeployment pending.")
            else:
                print("\nReported unknown state: %s" % host_state)
                rc = 1

        elif req.status_code == 500:
            print("An internal error has occurred. Please check /var/log/software.log for details")
            rc = 1
        else:
            m = re.search("(Error message:.*)", req.text, re.MULTILINE)
            if m:
                print(m.group(0))
            else:
                print(vars(req))
            rc = 1

        return rc
