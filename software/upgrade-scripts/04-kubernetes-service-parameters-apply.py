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
# Scripts that should be executed before this one:
# - k8s-disable-sched-controllermanager-leader-election.sh
#
# ** An update of kube-apiserver port (6443 -> 16443) also relies on this
# script.
#

import logging as LOG
import socket
import subprocess
import sys
import os
import tempfile
import time
import yaml

SUCCESS = 0
ERROR = 1
RETRIES = 3

CONFIG_DIR_PREFIX = '/opt/platform/config/'
PORTIERIS_BACKUP_FILENAME = 'portieris_backup.yml'
PORTIERIS_WEBHOOK_CRD = 'mutatingwebhookconfigurations image-admission-config'
KUBE_PORT_UPDATED_FLAG = '/etc/platform/.upgrade_kube_apiserver_port_updated'


class ServiceParametersApplier(object):
    """
    The main purpose of this class is to safely apply service parameters
    previously configured in the system.

    The command: "system service-parameters-apply kubernetes" will trigger
    many system events including the restart of kube-apiserver process.
    """
    def __init__(self, from_side_release) -> None:
        self.KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
        self.SP_APPLY_CMD = 'system service-parameter-apply kubernetes'
        self.initial_kube_apiserver_pid = -1
        # Backup in old config folder, it will be erased when upgrade ends
        self.PORTIERIS_BACKUP_FILE = CONFIG_DIR_PREFIX + from_side_release + \
            '/' + PORTIERIS_BACKUP_FILENAME

    def __system_cmd(self, command: str) -> str:
        sub = subprocess.Popen(["bash", "-c", command],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, _ = sub.communicate()
        if sub.returncode != 0:
            return ''
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

    def __wait_kube_apiserver_ready(self):
        LOG.info("Waiting kube-apiserver PID to restart")
        for _ in range(0, 300):
            time.sleep(2)
            current_pid = self.__get_kube_apiserver_pid()
            if check_kube_apiserver_port_updated():
                if current_pid == -1:
                    continue
                elif current_pid != self.initial_kube_apiserver_pid:
                    LOG.info("kube-apiserver PID is restarted!")
                    return
        else:
            LOG.error("Timeout restarting kube-apiserver.")
            sys.exit(ERROR)

    def __get_portieris_webhook_data(self):
        get_cmd = self.KUBE_CMD + "get " + PORTIERIS_WEBHOOK_CRD + \
            " -o yaml --ignore-not-found"
        return self.__system_cmd(get_cmd)

    def __create_portieris_webhook_backup(self, yaml_data):
        if (os.path.isfile(self.PORTIERIS_BACKUP_FILE) and
                os.path.getsize(self.PORTIERIS_BACKUP_FILE) > 0):
            LOG.info("Backup for portieris webhook already present.")
            return

        with open(self.PORTIERIS_BACKUP_FILE, 'w') as backup_file:
            yaml.safe_dump(yaml_data, backup_file, default_flow_style=False)
        LOG.info("Backup created for portieris webhook.")

    def __modify_portieris_webhook(self, yaml_data):
        delete_cmd = self.KUBE_CMD + "delete " + PORTIERIS_WEBHOOK_CRD
        apply_cmd = self.KUBE_CMD + "apply -f "
        with tempfile.NamedTemporaryFile(delete=True) as tmp_file_obj:
            with open(tmp_file_obj.name, 'w') as tmp_file:
                yaml.safe_dump(yaml_data, tmp_file, default_flow_style=False)
                self.__system_cmd(delete_cmd)
                self.__system_cmd(apply_cmd + tmp_file_obj.name)

    def __disable_portieris_webhook(self):
        result = self.__get_portieris_webhook_data()
        if result != '':
            yaml_data = yaml.safe_load(result)
            self.__create_portieris_webhook_backup(yaml_data)
            yaml_data['webhooks'][0]['failurePolicy'] = 'Ignore'
            self.__modify_portieris_webhook(yaml_data)
        else:
            LOG.info("No webhook from portieris.")

    def __remove_portieris_webhook_backup(self):
        try:
            os.remove(self.PORTIERIS_BACKUP_FILE)
            LOG.info("Deleted portieris webhook backup file.")
        except OSError:
            pass

    def __restore_portieris_webhook(self):
        if (not os.path.isfile(self.PORTIERIS_BACKUP_FILE) or
                not os.path.getsize(self.PORTIERIS_BACKUP_FILE) > 0):
            LOG.info("No backup content for portieris webhook. Nothing to do.")
            self.__remove_portieris_webhook_backup()
            return

        result = self.__get_portieris_webhook_data()
        current_data = {}
        if result != '':
            current_data = yaml.safe_load(result)

        with open(self.PORTIERIS_BACKUP_FILE, 'r') as backup_file:
            backup_data = yaml.safe_load(backup_file)
            current_value = current_data.get(
                'webhooks', [{}])[0].get('failurePolicy', None)
            backup_value = backup_data['webhooks'][0]['failurePolicy']
            if current_value != backup_value:
                LOG.info("Using backup data to restore portieris webhook.")
                # Drop caBundle, cert-manager ca-injector will recreate it
                backup_data['webhooks'][0]['clientConfig'].pop('caBundle',
                                                               None)
                self.__modify_portieris_webhook(backup_data)

        self.__remove_portieris_webhook_backup()

    def apply(self):
        # Disable portieris webhook to avoid issues while restarting pods
        self.__disable_portieris_webhook()
        # Perform service parameter apply and wait kube-apiserver restart
        self.__register_kube_apiserver_pid()
        self.__service_parameter_apply()
        self.__wait_kube_apiserver_ready()

    def rollback(self):
        self.__restore_portieris_webhook()


def check_kube_apiserver_port_updated():
    return os.path.exists(KUBE_PORT_UPDATED_FLAG)


def reconfigure_haproxy(sw_version):
    """Reconfigure haproxy using puppet manifest."""

    manifest_file = '/tmp/haproxy_upgrade.pp'
    with open(manifest_file, 'w') as file:
        file.write('classes:\n- platform::haproxy::runtime\n')

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        "/opt/platform/puppet/%s/hieradata" % sw_version,
        socket.gethostname(),
        'controller',
        'runtime',
        manifest_file
    ]
    subprocess.check_call(cmd)


def main():
    log_format = ('%(asctime)s: [%(process)s]: %(filename)s(%(lineno)s): '
                  '%(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

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

    LOG.info(
        "%s invoked from_release = %s invoked to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )

    for retry in range(0, RETRIES):
        try:
            if action == "activate" and from_release == "24.09":
                if not check_kube_apiserver_port_updated():
                    ServiceParametersApplier(from_release).apply()
                    reconfigure_haproxy(to_release)
            elif action == "activate-rollback" and to_release == "24.09":
                ServiceParametersApplier(to_release).rollback()
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
