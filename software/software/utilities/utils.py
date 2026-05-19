#
# Copyright (c) 2023-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import functools
import logging
import os
import subprocess
import sys
import tempfile
import yaml

import keyring
from psycopg2.extras import RealDictCursor
import psycopg2

# WARNING: The first controller upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
import software.config as cfg
from software.utilities.constants import PLATFORM_PATH
from software.utilities import constants

LOG = logging.getLogger('main_logger')
SOFTWARE_LOG_FILE = "/var/log/software.log"


# well-known default domain name
DEFAULT_DOMAIN_NAME = 'Default'

# Upgrade script actions
ACTION_START = "start"
ACTION_MIGRATE = "migrate"
ACTION_ACTIVATE = "activate"
ACTION_ACTIVATE_ROLLBACK = "activate-rollback"
ACTION_DELETE = "delete"


@functools.lru_cache(maxsize=1)
def get_debian_version_codename():
    os_release = "/usr/lib/os-release"
    with open(os_release, "r") as f:
        for line in f:
            if line.strip().startswith("VERSION_CODENAME="):
                return line.strip().split("=", 1)[1].strip("'\"")
    raise ValueError("VERSION_CODENAME not found in %s" % os_release)


def configure_logging():
    cfg.read_config()

    my_exec = os.path.basename(sys.argv[0])

    log_format = cfg.logging_default_format_string
    log_format = log_format.replace('%(exec)s', my_exec)
    formatter = logging.Formatter(log_format, datefmt="%FT%T")

    root_logger = logging.getLogger()

    root_logger.setLevel(logging.INFO)
    main_log_handler = logging.FileHandler(SOFTWARE_LOG_FILE)
    main_log_handler.setFormatter(formatter)
    root_logger.addHandler(main_log_handler)


def get_db_connection(hiera_db_records, database):
    username = hiera_db_records[database]['username']
    password = hiera_db_records[database]['password']
    return "postgresql://%s:%s@%s/%s" % (
        username, password, 'localhost', database)


def get_password_from_keyring(service, username):
    """Retrieve password from keyring"""
    password = ""
    try:
        password = keyring.get_password(service, username)
    except Exception as e:
        LOG.exception("Received exception when attempting to get password "
                      "for service %s, username %s: %s" %
                      (service, username, e))
        raise
    return password


def get_upgrade_token(from_release,
                      config,
                      secure_config):

    # Get the system hiera data from the from release
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    system_file = os.path.join(from_hiera_path, "system.yaml")
    with open(system_file, 'r') as s_file:
        system_config = yaml.load(s_file, Loader=yaml.Loader)

    # during a data-migration, keystone is running
    # on the controller UNIT IP, however the service catalog
    # that was migrated from controller-0 since lists the
    # floating controller IP. Keystone operations that use
    # the AUTH URL will hit this service URL and fail,
    # therefore we have to issue an Upgrade token for
    # all Keystone operations during an Upgrade. This token
    # will allow us to circumvent the service catalog entry, by
    # providing a bypass endpoint.
    keystone_upgrade_url = "http://{}:5000/{}".format(
        '127.0.0.1',
        system_config['openstack::keystone::params::api_version'])

    admin_user_domain = system_config.get(
        'platform::client::params::admin_user_domain')
    if admin_user_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("platform::client::params::admin_user_domain key not found. "
                 "Using Default.")
        admin_user_domain = DEFAULT_DOMAIN_NAME

    admin_project_domain = system_config.get(
        'platform::client::params::admin_project_domain')
    if admin_project_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("platform::client::params::admin_project_domain key not "
                 "found. Using Default.")
        admin_project_domain = DEFAULT_DOMAIN_NAME

    admin_password = get_password_from_keyring("CGCS", "admin")
    admin_username = system_config.get(
        'platform::client::params::admin_username')

    # the upgrade token command
    keystone_upgrade_token = (
        "openstack "
        "--os-username {} "
        "--os-password '{}' "
        "--os-auth-url {} "
        "--os-project-name admin "
        "--os-user-domain-name {} "
        "--os-project-domain-name {} "
        "--os-interface internal "
        "--os-identity-api-version 3 "
        "token issue -c id -f value".format(
            admin_username,
            admin_password,
            keystone_upgrade_url,
            admin_user_domain,
            admin_project_domain
        ))

    config.update({
        'openstack::keystone::upgrade::upgrade_token_file':
            '/etc/keystone/upgrade_token',
        'openstack::keystone::upgrade::url': keystone_upgrade_url
    })

    secure_config.update({
        'openstack::keystone::upgrade::upgrade_token_cmd':
            keystone_upgrade_token,
    })


def get_upgrade_data(from_release,
                     system_config,
                     secure_config):
    """Retrieve required data from the from-release, update system_config
        and secure_config with them.
        This function is needed for adding new service account and endpoints
        during upgrade.
    """
    # Get the system hiera data from the from release
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    system_file = os.path.join(from_hiera_path, "system.yaml")
    with open(system_file, 'r') as s_file:
        system_config_from_release = yaml.load(s_file, Loader=yaml.Loader)

    # Get keystone region
    keystone_region = system_config_from_release.get(
        'keystone::endpoint::region')

    system_config.update({
        'platform::client::params::identity_region': keystone_region,
        # Retrieve keystone::auth::region from the from-release for the new
        # service.
        # 'newservice::keystone::auth::region': keystone_region,
    })

    # Generate password for the new service
    # password = sysinv_utils.generate_random_password(16)

    secure_config.update({
        # Generate and set the keystone::auth::password for the new service.
        # 'newservice::keystone::auth::password': password,
    })


def add_upgrade_entries_to_hiera_data(from_release):
    """Adds upgrade entries to the hiera data """

    filename = 'static.yaml'
    secure_filename = 'secure_static.yaml'
    path = constants.HIERADATA_PERMDIR

    # Get the hiera data for this release
    filepath = os.path.join(path, filename)
    with open(filepath, 'r') as c_file:
        config = yaml.load(c_file, Loader=yaml.Loader)
    secure_filepath = os.path.join(path, secure_filename)
    with open(secure_filepath, 'r') as s_file:
        secure_config = yaml.load(s_file, Loader=yaml.Loader)

    # File for system.yaml
    # TODO(bqian): This is needed for adding new service account and endpoints
    # during upgrade.
    system_filename = 'system.yaml'
    system_filepath = os.path.join(path, system_filename)

    # Get a token and update the config
    # Below should be removed. Need to ensure during data migration
    get_upgrade_token(from_release, config, secure_config)

    # Get required data from the from-release and add them in system.yaml.
    # We don't carry system.yaml from the from-release.
    # This is needed for adding new service account and endpoints
    # during upgrade.
    # TODO(bqian): Below should be replaced with generating hieradata from
    # migrated to-release database after "deploy host" is verified
    system_config = {}
    get_upgrade_data(from_release, system_config, secure_config)

    # Update the hiera data on disk
    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, filepath)
    except Exception:
        LOG.exception("failed to write config file: %s" % filepath)
        raise

    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=secure_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(secure_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, secure_filepath)
    except Exception:
        LOG.exception("failed to write secure config: %s" % secure_filepath)
        raise

    # Add required hiera data into system.yaml.
    # This is needed for adding new service account and endpoints
    # during upgrade.
    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=system_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(system_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, system_filepath)
    except Exception:
        LOG.exception("failed to write system config: %s" % system_filepath)
        raise


def apply_upgrade_manifest(controller_address):
    """Apply puppet upgrade manifest files."""

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        constants.HIERADATA_PERMDIR,
        str(controller_address),
        constants.CONTROLLER,
        'upgrade'
    ]

    logfile = "/tmp/apply_manifest.log"
    try:
        with open(logfile, "w") as flog:
            subprocess.check_call(cmd, stdout=flog, stderr=flog)
    except subprocess.CalledProcessError:
        msg = "Failed to execute upgrade manifest"
        print(msg)
        raise Exception(msg)


def get_keystone_user_id(user_name):
    """Get the a keystone user id by name"""

    conn = psycopg2.connect("dbname='keystone' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT user_id FROM local_user WHERE name='%s'" %
                        user_name)
            user_id = cur.fetchone()
            if user_id is not None:
                return user_id['user_id']
            else:
                return user_id


def get_keystone_project_id(project_name):
    """Get the a keystone project id by name"""

    conn = psycopg2.connect("dbname='keystone' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM project WHERE name='%s'" %
                        project_name)
            project_id = cur.fetchone()
            if project_id is not None:
                return project_id['id']
            else:
                return project_id


def get_postgres_bin():
    """Get the path to the postgres binaries"""

    try:
        return subprocess.check_output(
            ['pg_config', '--bindir']).decode().rstrip('\n')
    except subprocess.CalledProcessError:
        LOG.exception("Failed to get postgres bin directory.")
        raise


def create_manifest_runtime_config(filename, config):
    """Write the runtime Puppet configuration to a runtime file."""
    if not config:
        return
    try:
        with open(filename, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
    except Exception:
        LOG.exception("failed to write config file: %s" % filename)
        raise


def create_system_config():
    cmd = ["/usr/bin/sysinv-puppet",
           "create-system-config",
           constants.HIERADATA_PERMDIR]
    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        msg = "Failed to update puppet hiera system config"
        print(msg)
        raise Exception(msg)


def create_host_config(hostname=None):
    cmd = ["/usr/bin/sysinv-puppet",
           "create-host-config",
           constants.HIERADATA_PERMDIR]
    if hostname:
        cmd.append(hostname)

    try:
        subprocess.check_call(cmd)
    except subprocess.CalledProcessError:
        msg = "Failed to update puppet hiera host config"
        print(msg)
        raise Exception(msg)
