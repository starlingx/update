#
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import re
import requests
import signal
import sys
import time

from software_client.common import base
from software_client.common import utils
from software_client import constants


class Deploy(base.Resource):
    def __repr__(self):
        return "<address pool %s>" % self._info


class DeployManager(base.Manager):
    resource_class = Deploy

    def precheck(self, args):
        # args.deployment is a string
        deployment = args.deployment

        # args.region is a string
        region_name = args.region_name

        path = "/v1/software/deploy_precheck/%s" % (deployment)
        if args.force:
            path += "/force"
        path += "?region_name=%s" % region_name

        return self._create(path, body={})

    def start(self, args):
        # args.deployment is a string
        deployment = args.deployment

        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        if args.force:
            path = "/v1/software/deploy_start/%s/force" % (deployment)
        else:
            path = "/v1/software/deploy_start/%s" % (deployment)

        return self._create(path, body={})

    def host(self, args):
        # args.deployment is a string
        agent_ip = args.agent

        # Issue deploy_host request and poll for results
        path = "/v1/software/deploy_host/%s" % (agent_ip)

        if args.force:
            path += "/force"

        req, data = self._create(path, body={})
        if req.status_code == 200:
            if 'error' in data and data["error"] != "":
                print("Error:")
                print(data["error"])
                rc = 1
            else:
                rc = self.wait_for_install_complete(agent_ip)
        elif req.status_code == 500:
            print("An internal error has occurred. "
                "Please check /var/log/software.log for details")
            rc = 1
        else:
            m = re.search("(Error message:.*)", req.text, re.MULTILINE)
            if m:
                print(m.group(0))
            else:
                print("%s %s" % (req.status_code, req.reason))
            rc = 1
        return rc

    def activate(self, args):
        # args.deployment is a string
        deployment = args.deployment

        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        path = "/v1/software/deploy_activate/%s" % (deployment)

        return self._create(path, body={})

    def complete(self, args):
        # args.deployment is a string
        deployment = args.deployment

        # Ignore interrupts during this function
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # Issue deploy_start request
        path = "/v1/software/deploy_complete/%s" % (deployment)

        return self._create(path, body={})

    def host_list(self):
        path = '/v1/software/host_list'
        return self._list(path, "")

    def show(self):
        path = '/v1/software/deploy'
        req, data = self._list(path, "")

        if req.status_code >= 500:
            print("An internal error has occurred. Please check /var/log/software.log for details")
            return 1
        elif req.status_code >= 400:
            print("Respond code %d. Error: %s" % (req.status_code, req.reason))
            return 1

        if not data or data.get("data"):
            print("No deploy in progress.")
        else:
            data = data.get("data")
            data = data[0]
            data["reboot_required"] = "Yes" if data.get("reboot_required") else "No"
            data_list = [[k, v] for k, v in data.items()]
            transposed_data_list = list(zip(*data_list))

            transposed_data_list[0] = [s.title().replace('_', ' ') for s in transposed_data_list[0]]
            # Find the longest header string in each column
            header_lengths = [len(str(x)) for x in transposed_data_list[0]]
            # Find the longest content string in each column
            content_lengths = [len(str(x)) for x in transposed_data_list[1]]
            # Find the max of the two for each column
            col_lengths = [(x if x > y else y) for x, y in zip(header_lengths, content_lengths)]

            print('  '.join(f"{x.center(col_lengths[i])}" for i,
                x in enumerate(transposed_data_list[0])))
            print('  '.join('=' * length for length in col_lengths))
            print('  '.join(f"{x.center(col_lengths[i])}" for i,
                x in enumerate(transposed_data_list[1])))

        return 0

    def wait_for_install_complete(self, agent_ip):
        url = "/v1/software/host_list"
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
                if retriable_count <= max_retries:
                    continue
                else:
                    print("Lost communications with the software controller")
                    rc = 1
                    break

            if req.status_code == 200:
                data = data.get("data", None)
                if not data:
                    print("Invalid host-list data returned:")
                    utils.print_result_debug(req, data)
                    rc = 1
                    break

                host_state = None

                for d in data:
                    if d['hostname'] == agent_ip:
                        host_state = d.get('host_state')

                if host_state == constants.DEPLOYING:
                # Still deploying
                    sys.stdout.write(".")
                    sys.stdout.flush()
                elif host_state == constants.FAILED:
                    print("\nDeployment failed. Please check logs for details.")
                    rc = 1
                    break
                elif host_state == constants.DEPLOYED:
                    print("\nDeployment was successful.")
                    rc = 0
                    break
                else:
                    print("\nReported unknown state: %s" % host_state)
                    rc = 1
                    break

            elif req.status_code == 500:
                print("An internal error has occurred. Please check /var/log/software.log for details")
                rc = 1
                break
            else:
                m = re.search("(Error message:.*)", req.text, re.MULTILINE)
                if m:
                    print(m.group(0))
                else:
                    print(vars(req))
                rc = 1
                break

        return rc
