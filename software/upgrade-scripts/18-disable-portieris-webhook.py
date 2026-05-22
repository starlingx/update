#!/usr/bin/python
# Copyright (c) 2024-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script backups the portieris webhook and changes the failurePolicy
# to ignore failures. This is required to upgrade portieris during platform
# upgrades, since by default portieris will fail to create the new pods
# when the webhook is down.

import logging
import os
import subprocess
import sys
import tempfile
import time
import yaml

from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging
from sysinv.common.kubernetes import test_k8s_health

LOG = logging.getLogger('main_logger')

RETRIES = 3
CONFIG_DIR_PREFIX = '/opt/platform/config/'
PORTIERIS_BACKUP_FILENAME = 'portieris_backup.yml'
PORTIERIS_WEBHOOK_CRD = 'mutatingwebhookconfigurations image-admission-config'


class PortierisWebhookDisabler(object):
    def __init__(self, from_side_release):
        self.KUBE_CMD = 'kubectl --kubeconfig=/etc/kubernetes/admin.conf '
        self.PORTIERIS_BACKUP_FILE = CONFIG_DIR_PREFIX + from_side_release + \
            '/' + PORTIERIS_BACKUP_FILENAME

    def __system_cmd(self, command):
        sub = subprocess.Popen(["bash", "-c", command],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate(timeout=10)
        if sub.returncode != 0:
            raise Exception(stderr.decode('utf-8'))
        return stdout.decode('utf-8')

    @test_k8s_health
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

    @test_k8s_health
    def __modify_portieris_webhook(self, yaml_data):
        delete_cmd = self.KUBE_CMD + "delete " + PORTIERIS_WEBHOOK_CRD + \
            " --ignore-not-found"
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
                backup_data['webhooks'][0]['clientConfig'].pop('caBundle', None)
                self.__modify_portieris_webhook(backup_data)
        self.__remove_portieris_webhook_backup()

    def apply(self):
        self.__disable_portieris_webhook()

    def rollback(self):
        self.__restore_portieris_webhook()


class DisablePortierisWebhook(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='disable-portieris-webhook',
            completed_state='disable-portieris-webhook-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))
        for retry in range(RETRIES):
            try:
                if action == "activate":
                    PortierisWebhookDisabler(from_release).apply()
                elif action == "activate-rollback":
                    PortierisWebhookDisabler(to_release).rollback()
                return
            except Exception as ex:
                if retry == RETRIES - 1:
                    raise
                LOG.exception(ex)
                LOG.error("Exception occurred, retrying after 5 seconds.")
                time.sleep(5)


if __name__ == "__main__":
    from_release = None
    to_release = None
    action = None
    port = None
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            sys.exit(1)
        arg += 1

    plugin = DisablePortierisWebhook()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
