#!/usr/bin/python
# Copyright (c) 2024-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script perform the apply command for service-parameters for
# kube-apiserver added/removed/modified in the scrips listed below
# (which need to be executed before this one), and monitors the
# kube-apiserver PID restart in the active controller.
#
# An update of kube-apiserver port (6443 -> 16443) relies on this
# procedure to reconfigure the k8s control plane.
#
# Scripts that should be executed before this one:
# - k8s-disable-sched-controllermanager-leader-election.sh
#

import logging
import subprocess
import sys
import os
import time

from oslo_config import cfg
from oslo_context import context as mycontext
from six.moves import configparser
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import k8s_wait_for_endpoints_health
from sysinv.conductor import rpcapiproxy as conductor_rpcapi

LOG = logging.getLogger('main_logger')

SUCCESS = 0
ERROR = 1
RETRIES = 3

KUBE_PORT_UPDATED_FLAG = '/etc/platform/.upgrade_kube_apiserver_port_updated'

CONF = cfg.CONF
SYSINV_CONFIG_FILE = '/etc/sysinv/sysinv.conf'


class ServiceParametersApplier(object):
    """
    The main purpose of this class is to safely apply service parameters
    previously configured in the system.

    The command: "system service-parameters-apply kubernetes" will trigger
    many system events including the restart of kube-apiserver process.
    """
    def __init__(self) -> None:
        self.SP_APPLY_CMD = 'system service-parameter-apply kubernetes'
        self.initial_kube_apiserver_pid = -1

    def __system_cmd(self, command: str) -> str:
        sub = subprocess.Popen(["bash", "-c", command],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            raise Exception(stderr.decode('utf-8'))
        return stdout.decode('utf-8')

    def __service_parameter_apply(self) -> None:
        command = self.SP_APPLY_CMD
        LOG.info('Applying service parameters...')
        self.__system_cmd(command)

    def __get_kube_apiserver_pid(self) -> int:
        try:
            return subprocess.check_output(["pidof", "-s", "kube-apiserver"])
        except Exception:
            return -1

    def __register_kube_apiserver_pid(self):
        self.initial_kube_apiserver_pid = self.__get_kube_apiserver_pid()

    def __wait_kube_apiserver_pid_ready(self):
        LOG.info("Waiting kube-apiserver PID to restart")
        for _ in range(0, 300):
            if check_kube_apiserver_port_updated():
                current_pid = self.__get_kube_apiserver_pid()
                if (current_pid != self.initial_kube_apiserver_pid and
                        current_pid != -1):
                    LOG.info("kube-apiserver PID is restarted!")
                    return
            time.sleep(2)
        else:
            LOG.error("Timeout restarting kube-apiserver.")
            sys.exit(ERROR)

    def apply(self):
        # Perform service parameter apply and wait kube-apiserver restart
        self.__register_kube_apiserver_pid()
        self.__service_parameter_apply()
        self.__wait_kube_apiserver_pid_ready()

    def rollback(self):
        # Perform service parameter apply and wait kube-apiserver restart
        self.__register_kube_apiserver_pid()
        self.__service_parameter_apply()
        self.__wait_kube_apiserver_pid_ready()


def check_kube_apiserver_port_updated():
    return os.path.exists(KUBE_PORT_UPDATED_FLAG)


def get_conductor_rpc_bind_ip():
    ini_str = '[DEFAULT]\n' + open(SYSINV_CONFIG_FILE, 'r').read()
    config_applied = configparser.RawConfigParser()
    config_applied.read_string(ini_str)

    conductor_bind_ip = None
    if config_applied.has_option('DEFAULT', 'rpc_zeromq_conductor_bind_ip'):
        conductor_bind_ip = \
            config_applied.get('DEFAULT', 'rpc_zeromq_conductor_bind_ip')
    return conductor_bind_ip


def create_kube_apiserver_port_rollback_flag_rpc():
    CONF.rpc_zeromq_conductor_bind_ip = get_conductor_rpc_bind_ip()
    context = mycontext.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)
    rpcapi.flag_k8s_port_update_rollback(context)


def run_kubernetes_health_audit_rpc():
    CONF.rpc_zeromq_conductor_bind_ip = get_conductor_rpc_bind_ip()
    context = mycontext.get_admin_context()
    rpcapi = conductor_rpcapi.ConductorAPI(topic=conductor_rpcapi.MANAGER_TOPIC)
    rpcapi.run_kubernetes_health_audit(context)


def wait_kube_apiserver_port_update(desired_status):
    LOG.info("Wait kube-apiserver port update finish.")
    retries = 60
    sleep = 3
    for _ in range(0, retries):
        if check_kube_apiserver_port_updated() == desired_status:
            LOG.info("kube-apiserver port update status: %s" %
                     str(desired_status))
            return
        time.sleep(sleep)
    msg = "The port for kube-apiserver was not updated in the allotted time."
    raise Exception(msg)


def check_conductor_restarted():
    output = subprocess.check_output('/usr/bin/sm-dump', shell=True)
    for line in output.splitlines():
        if 'sysinv-conductor' in line.decode('utf-8'):
            if line.decode('utf-8').count('enabled-active') == 2:
                return True
            break
    return False


def wait_conductor_restarted():
    retries = 30
    sleep = 3
    for _ in range(0, retries):
        if check_conductor_restarted():
            LOG.info("Sysinv-conductor is enabled-active")
            return True
        time.sleep(sleep)
    LOG.error("Sysinv-conductor not restarted in expected time")
    return False


def main():
    # Initialize variables
    action = None
    from_release = None
    to_release = None
    arg = 1

    # Process command-line arguments
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # port = int(sys.argv[arg])
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return ERROR
        arg += 1

    configure_logging()
    LOG.info(
        "%s invoked from_release = %s invoked to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    for retry in range(0, RETRIES):
        try:
            if action == "activate" and from_release == "24.09":
                if not check_kube_apiserver_port_updated():
                    ServiceParametersApplier().apply()
                    wait_kube_apiserver_port_update(True)
                    if not wait_conductor_restarted():
                        # No point in retrying without sysinv-conductor
                        LOG.error("Conductor is unhealthy, check sysinv logs")
                        return ERROR
                    if not k8s_wait_for_endpoints_health():
                        # k8s_wait_for_endpoints_health already has retries
                        LOG.error("K8s is unhealthy, aborting. "
                                  "Please check logs.")
                        return ERROR
                    run_kubernetes_health_audit_rpc()
            elif action == "activate-rollback" and to_release == "24.09":
                if check_kube_apiserver_port_updated():
                    create_kube_apiserver_port_rollback_flag_rpc()
                    ServiceParametersApplier().rollback()
                    wait_kube_apiserver_port_update(False)
                    if not wait_conductor_restarted():
                        # No point in retrying without sysinv-conductor
                        LOG.error("Conductor is unhealthy, check sysinv logs")
                        return ERROR
                    if not k8s_wait_for_endpoints_health():
                        # k8s_wait_for_endpoints_health already has retries
                        LOG.error("K8s is unhealthy, aborting. "
                                  "Please check logs.")
                        return ERROR
                    run_kubernetes_health_audit_rpc()
            else:
                LOG.info("Nothing to do. "
                         "Skipping K8s service parameter apply.")
        except Exception as ex:
            if retry == RETRIES - 1:
                LOG.error("Error applying K8s service parameters. "
                          "Please verify logs.")
                return ERROR
            else:
                LOG.exception(ex)
                LOG.error("Exception ocurred during script execution, "
                          "retrying after 5 seconds.")
                time.sleep(5)
        else:
            return SUCCESS


if __name__ == "__main__":
    sys.exit(main())
