#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import sys
import tempfile
import traceback
import yaml

# WARNING: The first controller upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
from software.utilities.constants import PLATFORM_PATH
from software.utilities.constants import KEYRING_PERMDIR

from software.utilities import constants
import software.config as cfg

LOG = logging.getLogger('main_logger')
SOFTWARE_LOG_FILE = "/var/log/software.log"

DEPLOY_SCRIPTS_FAILURES_LOG = logging.getLogger('deploy_scripts_failures')
DEPLOY_SCRIPTS_FAILURES_LOG_FILE = "/var/log/deploy_scripts_failures.log"


# well-known default domain name
DEFAULT_DOMAIN_NAME = 'Default'

# Upgrade script actions
ACTION_START = "start"
ACTION_MIGRATE = "migrate"
ACTION_ACTIVATE = "activate"
ACTION_ACTIVATE_ROLLBACK = "activate-rollback"
ACTION_DELETE = "delete"


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


def get_migration_scripts(migration_script_dir):
    if not os.path.isdir(migration_script_dir):
        msg = "Folder %s does not exist" % migration_script_dir
        LOG.exception(msg)
        raise Exception(msg)

    files = [f for f in os.listdir(migration_script_dir)
             if os.path.isfile(os.path.join(migration_script_dir, f)) and
             os.access(os.path.join(migration_script_dir, f), os.X_OK)]
    return files


def sort_migration_scripts(scripts, action):
    reversed_actions = ['activate-rollback']
    # From file name, get the number to sort the calling sequence,
    # abort when the file name format does not follow the pattern
    # "nnn-*.*", where "nnn" string shall contain only digits, corresponding
    # to a valid unsigned integer (first sequence of characters before "-")
    try:
        scripts.sort(key=lambda x: int(x.split("-")[0]))
        if action in reversed_actions:
            scripts = scripts[::-1]
            LOG.info(f"Executing deployment scripts for {action} in reversed order")
    except Exception:
        LOG.exception("Deployment script sequence validation failed, invalid "
                      "file name format")
        raise

    return scripts


# This file is currently categorized as independent from framework,
# which is runnable w/ N+1 code on a N runtime environment. The exception class
# is defined here instead of software.exceptions module as result.
# TODO(bqian) move the exception definition to software.exceptions if this code
# becomes part of framework.
class MigrationScriptFailed(Exception):
    def __init__(self, msg, inner_exception):
        super().__init__(msg)
        self._inner_exception = inner_exception

    @property
    def inner_exception(self):
        return self._inner_exception


def execute_script(script, from_release, to_release, action, port):
    MSG_SCRIPT_FAILURE = "Deployment script %s failed with return code %d" \
                         "\nScript output:\n%s"
    try:
        LOG.info("Executing deployment script %s" % script)
        cmdline = [script, from_release, to_release, action]
        if port is not None:
            cmdline.append(port)

        # Let subprocess.run handle non-zero exit codes via check=True
        subprocess.run(cmdline,
                       stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT,
                       text=True,
                       check=True)

    except subprocess.CalledProcessError as e:
        # Deduplicate output lines using set and create error message
        unique_output = "\n".join(e.output.splitlines()) + "\n"
        error = MSG_SCRIPT_FAILURE % (script, e.returncode, unique_output)
        raise MigrationScriptFailed(error, e)
    except Exception as ee:
        # Log exception but continue processing
        error = f"Unexpected error executing {script}: {str(ee)}"
        raise MigrationScriptFailed(error, ee)

    LOG.info(f'Deployment script {script} completed successfully')


def initialize_deploy_failure_log():
    if not DEPLOY_SCRIPTS_FAILURES_LOG.handlers:
        log_format = ('%(asctime)s: %(message)s')
        log_datefmt = "%FT%T"
        DEPLOY_SCRIPTS_FAILURES_LOG.setLevel(logging.INFO)
        log_file_handler = logging.FileHandler(DEPLOY_SCRIPTS_FAILURES_LOG_FILE)
        log_file_handler.setFormatter(logging.Formatter(
            fmt=log_format, datefmt=log_datefmt))
        DEPLOY_SCRIPTS_FAILURES_LOG.addHandler(log_file_handler)


def log_exception(msg, exc):
    trace = ''.join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    LOG.error(msg)
    LOG.error(trace)


def execute_scripts(scripts, from_release, to_release, action, port, migration_script_dir):
    # Execute each migration script and collect errors
    ignore_errors = os.environ.get("IGNORE_ERRORS", 'False').upper() == 'TRUE'
    errors = []
    for f in scripts:
        migration_script = os.path.join(migration_script_dir, f)
        try:
            execute_script(migration_script, from_release, to_release, action, port)
        except MigrationScriptFailed as e:
            if ignore_errors:
                log_exception(f"Migrate script error, action {action} continue.",
                              e.inner_exception)
                errors.append(str(e))
            else:
                log_exception(f"Migrate script error, action {action} stopped.",
                              e.inner_exception)
                raise e.inner_exception

    if errors and ignore_errors:
        LOG.warning(f"Action {action} completed with errors. Operation continue as IGNORE_ERRORS is set." +
                    f" Summarized error information can be found in {DEPLOY_SCRIPTS_FAILURES_LOG_FILE}")
        initialize_deploy_failure_log()
        # initialize_deploy_failure_log Log the errors to the dedicated failure log
        DEPLOY_SCRIPTS_FAILURES_LOG.info("%s action partially failed. " % action)
        DEPLOY_SCRIPTS_FAILURES_LOG.info("\n".join(errors))


def execute_migration_scripts(from_release, to_release, action, port=None,
                              migration_script_dir="/usr/local/share/upgrade.d"):
    LOG.info("Executing deployment scripts from: %s with from_release: %s, to_release: %s, "
             "action: %s" % (migration_script_dir, from_release, to_release, action))
    scripts = get_migration_scripts(migration_script_dir)
    scripts = sort_migration_scripts(scripts, action)

    execute_scripts(scripts, from_release, to_release, action, port, migration_script_dir)


def get_db_connection(hiera_db_records, database):
    username = hiera_db_records[database]['username']
    password = hiera_db_records[database]['password']
    return "postgresql://%s:%s@%s/%s" % (
        username, password, 'localhost', database)


def get_password_from_keyring(service, username):
    """Retrieve password from keyring"""
    password = ""
    os.environ["XDG_DATA_HOME"] = KEYRING_PERMDIR
    try:
        password = keyring.get_password(service, username)
    except Exception as e:
        LOG.exception("Received exception when attempting to get password "
                      "for service %s, username %s: %s" %
                      (service, username, e))
        raise
    finally:
        del os.environ["XDG_DATA_HOME"]
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
