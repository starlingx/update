"""
Copyright (c) 2014-2025 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

###################
# IMPORTS
###################
import json
import logging
import time

import requests

from daemon import runner
from fm_api import constants as fm_constants
from fm_api import fm_api

import software.config as cfg
from software.constants import ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER
from software.software_functions import configure_logging
from software.software_functions import LOG
from software.software_functions import SW_VERSION
from software.utils import get_major_release_version

###################
# CONSTANTS
###################
PID_FILE = '/var/run/patch-alarm-manager.pid'


class DaemonRunnerWrapper(runner.DaemonRunner):
    # Workaround: fix the "unbuffered bytes I/O for py3" runtime
    # error in pyhon3 env.
    # Picked from [starlingx/utilities]:utilities/logmgmt/logmgmt/logmgmt/logmgmt.py
    # If there will be a saner approach, it must be changed also in utilities repo.
    def _open_streams_from_app_stream_paths(self, app):
        self.daemon_context.stdin = open(app.stdin_path, 'rt')
        self.daemon_context.stdout = open(app.stdout_path, 'w+t')
        try:
            self.daemon_context.stderr = open(app.stderr_path, 'w+t', buffering=0)
        except Exception:
            self.daemon_context.stderr = open(app.stderr_path, 'wb+', buffering=0)


###################
# METHODS
###################
def start_polling():
    cfg.read_config()
    patch_alarm_daemon = PatchAlarmDaemon()
    alarm_runner = DaemonRunnerWrapper(patch_alarm_daemon)
    alarm_runner.daemon_context.umask = 0o022
    alarm_runner.do_action()


###################
# CLASSES
###################
class PatchAlarmDaemon(object):
    """ Daemon process representation of
        the patch monitoring program
    """
    def __init__(self):
        # Daemon-specific init
        self.stdin_path = '/dev/null'
        self.stdout_path = '/dev/null'
        self.stderr_path = '/dev/null'
        self.pidfile_path = PID_FILE
        self.pidfile_timeout = 5

        self.api_addr = "127.0.0.1:%d" % cfg.api_port

        self.fm_api = fm_api.FaultAPIs()

    def run(self):
        configure_logging()

        requests_logger = logging.getLogger('requests')
        requests_logger.setLevel(logging.CRITICAL)

        while True:
            # start monitoring patch status
            self.check_patch_alarms()

            # run/poll every 1 min
            time.sleep(60)

    def check_patch_alarms(self):
        self._handle_patch_alarms()
        self._get_handle_failed_hosts()

    def _handle_patch_alarms(self):  # pylint: disable=too-many-branches
        url = "http://%s/v1/release" % self.api_addr

        try:
            req = requests.get(url)
        except Exception:
            return

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, "controller")

        raise_dip_alarm = False
        raise_obs_alarm = False
        raise_cert_alarm = False
        if req.status_code == 200:
            data = json.loads(req.text)

            for rel_metadata in data:
                if 'state' in rel_metadata:
                    if rel_metadata['state'] in ['deploying', 'removing']:
                        raise_dip_alarm = True
                    elif rel_metadata['state'] == 'unavailable':
                        raise_obs_alarm = True
                        if 'sw_version' in rel_metadata and \
                           get_major_release_version(rel_metadata['sw_version']) == SW_VERSION:
                            raise_obs_alarm = False
                if 'release_id' in rel_metadata and ENABLE_DEV_CERTIFICATE_PATCH_IDENTIFIER in rel_metadata['release_id']:
                    raise_cert_alarm = True

        dip_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_USM_RELEASE_DEPLOY_IN_PROGRESS,
                                          entity_instance_id)
        if raise_dip_alarm and dip_alarm is None:
            LOG.info("Raising deploy-in-progress alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_USM_RELEASE_DEPLOY_IN_PROGRESS,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_MINOR,
                                 reason_text='Software release deploy in progress',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Complete release',
                                 service_affecting=False)

            self.fm_api.set_fault(fault)
        elif not raise_dip_alarm and dip_alarm is not None:
            LOG.info("Clearing deploy-in-progress alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_USM_RELEASE_DEPLOY_IN_PROGRESS,
                                    entity_instance_id)

        obs_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_USM_RELEASE_OBS_IN_SYSTEM,
                                          entity_instance_id)
        if raise_obs_alarm and obs_alarm is None:
            LOG.info("Raising obsolete-patch-in-system alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_USM_RELEASE_OBS_IN_SYSTEM,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_WARNING,
                                 reason_text='Obsolete release in system',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Delete unavailable releases',
                                 service_affecting=False)

            self.fm_api.set_fault(fault)
        elif not raise_obs_alarm and obs_alarm is not None:
            LOG.info("Clearing obsolete-patch-in-system alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_USM_RELEASE_OBS_IN_SYSTEM,
                                    entity_instance_id)

        cert_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_NONSTANDARD_CERT_PATCH,
                                           entity_instance_id)
        if raise_cert_alarm and cert_alarm is None:
            logging.info("Raising developer-certificate-enabled alarm")
            fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_NONSTANDARD_CERT_PATCH,
                                 alarm_type=fm_constants.FM_ALARM_TYPE_9,
                                 alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                 entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                 entity_instance_id=entity_instance_id,
                                 severity=fm_constants.FM_ALARM_SEVERITY_CRITICAL,
                                 reason_text='Developer patch certificate is enabled',
                                 probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                 proposed_repair_action='Reinstall system to disable certificate and remove untrusted patches',  # noqa: E501
                                 suppression=False,
                                 service_affecting=False)

            self.fm_api.set_fault(fault)

    def _get_handle_failed_hosts(self):
        url = "http://%s/v1/deploy_host" % self.api_addr

        try:
            req = requests.get(url)
        except Exception:
            return

        entity_instance_id = "%s=%s" % (fm_constants.FM_ENTITY_TYPE_HOST, "controller")

        failed_hosts = []
        if req.status_code == 200:
            data = json.loads(req.text)

            for host_metadata in data:
                if 'host_state' in host_metadata:
                    if host_metadata['host_state'] in ['failed', 'rollback-failed']:
                        failed_hosts.append(host_metadata['hostname'])

        # Query existing alarms
        deploy_host_failed_alarm = self.fm_api.get_fault(fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE,
                                                         entity_instance_id)

        if len(failed_hosts) > 0:
            reason_text = "Release installation failed on the following hosts: %s" % ", ".join(sorted(failed_hosts))

            if deploy_host_failed_alarm is None or reason_text != deploy_host_failed_alarm.reason_text:
                if deploy_host_failed_alarm is None:
                    LOG.info("Raising deploy-host-failure alarm")
                else:
                    LOG.info("Updating deploy-host-failure alarm")

                fault = fm_api.Fault(alarm_id=fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE,
                                     alarm_type=fm_constants.FM_ALARM_TYPE_5,
                                     alarm_state=fm_constants.FM_ALARM_STATE_SET,
                                     entity_type_id=fm_constants.FM_ENTITY_TYPE_HOST,
                                     entity_instance_id=entity_instance_id,
                                     severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                                     reason_text=reason_text,
                                     probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_65,
                                     proposed_repair_action='Undo software operation',
                                     service_affecting=False)
                self.fm_api.set_fault(fault)

        elif deploy_host_failed_alarm is not None:
            LOG.info("Clearing patch-host-install-failure alarm")
            self.fm_api.clear_fault(fm_constants.FM_ALARM_ID_USM_DEPLOY_HOST_FAILURE,
                                    entity_instance_id)

        return False
