#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This is an utility module used by standalone USM upgrade scripts
# that runs on the FROM-side context but using TO-side code base
#
import json
import logging
import os
import re
import requests
import sys

from keystoneauth1 import exceptions
from keystoneauth1 import identity
from keystoneauth1 import session


def get_token_endpoint(config, service_type="platform"):
    """Returns an endpoint and a token for a service

    :param config: A configuration dictionary containing the
    authentication credentials
    :param service_type: The service to get the related token
    and endpoint
    """
    required_user_keys = ['auth_url',
                          'username',
                          'password',
                          'project_name',
                          'user_domain_name',
                          'project_domain_name']
    if not all(key in config for key in required_user_keys):
        raise Exception("Missing required key(s) to authenticate to Keystone")

    try:
        auth = identity.Password(
            auth_url=config["auth_url"],
            username=config["username"],
            password=config["password"],
            project_name=config["project_name"],
            user_domain_name=config["user_domain_name"],
            project_domain_name=config["project_domain_name"]
        )
        sess = session.Session(auth=auth)
        token = sess.get_token()
        endpoint = sess.get_endpoint(service_type=service_type,
                                     region_name=config["region_name"],
                                     interface='internal')
    except exceptions.http.Unauthorized:
        raise Exception("Failed to authenticate to Keystone. Request unauthorized")
    except Exception as e:
        raise Exception("Failed to get token and endpoint. Error: %s", str(e))

    if service_type == "usm":
        endpoint += "/v1"

    return token, endpoint


def get_sysinv_client(token, endpoint):
    """Returns a sysinv client instance

    :param token: auth token
    :param endpoint: service endpoint
    """
    # if platform type is sysinv then return the client as well
    try:
        from cgtsclient import client
        return client.Client(version='1', endpoint=endpoint, token=token, timeout=600)
    except ImportError:
        msg = "Failed to import cgtsclient"
        raise ImportError(msg)
    except Exception as e:
        msg = "Failed to get sysinv client. Error: %s" % str(e)
        raise Exception(msg)

def call_api(token_id, method, api_cmd, api_cmd_headers=None,
             api_cmd_payload=None, timeout_in_secs=40):

    headers = {"Accept": "application/json"}
    if token_id:
        headers["X-Auth-Token"] = token_id

    if api_cmd_headers:
        headers.update(api_cmd_headers)
    if api_cmd_payload:
        api_cmd_payload = json.loads(api_cmd_payload)
    try:
        response = requests.request(
            method, api_cmd, headers=headers, json=api_cmd_payload,
            timeout=timeout_in_secs
        )
        response.raise_for_status()
        # Check if the content type starts with 'application/json'
        content_type = response.headers.get('content-type', '')
        if content_type.startswith('application/json'):
            return response.json()
        else:
            return response.text

    except requests.HTTPError as e:
        msg = "Error response=%s" % str(e)
        raise Exception(msg)


def get_keystone_config(args: dict) -> dict:
    """Returns keystone config

    :param args: Dict containing Keystone configuration parameters.
    """
    keystone_config = {}

    required_keystone_config = ["auth_url",
                                "username",
                                "password",
                                "project_name",
                                "user_domain_name",
                                "project_domain_name",
                                "region_name"]
    for config in required_keystone_config:
        if config not in args:
            raise Exception("keystone configuration %s is not provided" % config)
        keystone_config[config] = args[config]
    return keystone_config


def parse_arguments(sys_argv: list) -> dict:
    """Returns a dict containing parsed key-value

    :param sys_argv: List of system arguments to be parsed
    """
    pattern = re.compile(r'--(\w+)=(.*)')
    args = {}
    for arg in sys_argv:
        match = pattern.match(arg)
        if match:
            args[match.group(1)] = match.group(2)
    return args


def print_usage(script_name, extra_args=""):
    """Prints the usage instructions for the script with optional additional arguments.

    :param script_name: The name of the script.
    :param extra_args: Additional arguments to be included.
    """
    print("Usage: %s --rootdir=<rootdir> --from_release=<from_release> --to_release=<to_release> "
          "--auth_url=<auth_url> --username=<username> --password=<password> "
          "--project_name=<project_name>"
          "--user_domain_name=<user_domain_name> --project_domain_name=<project_domain_name> "
          "--region_name=<region_name> %s" % script_name, extra_args)


def get_system_info(sysinv_client):
    """Returns system type and system mode

    :param sysinv_client: Sysinv client instance.
    """
    system_info = sysinv_client.isystem.list()[0]
    return system_info.system_type, system_info.system_mode


def configure_logging(filename, log_level=logging.INFO):
    my_exec = os.path.basename(sys.argv[0])

    log_format = ('%(asctime)s: ' + my_exec + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    log_datefmt = "%FT%T"

    logging.basicConfig(filename=filename, format=log_format, level=log_level, datefmt=log_datefmt)
