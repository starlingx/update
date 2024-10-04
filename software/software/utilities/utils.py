#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import logging
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import subprocess
import tempfile
import yaml

# WARNING: The first controller upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
from software.utilities.constants import PLATFORM_PATH
from software.utilities.constants import KEYRING_PERMDIR

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


def configure_logging():
    log_format = ('%(asctime)s: ' + __name__ + '[%(process)s]: '
                                               '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    log_datefmt = "%FT%T"
    logging.basicConfig(filename=SOFTWARE_LOG_FILE, format=log_format, level=logging.INFO, datefmt=log_datefmt)


def execute_migration_scripts(from_release, to_release, action, port=None,
                              migration_script_dir="/etc/upgrade.d"):
    """Execute deployment scripts with an action:
          start: Prepare for upgrade on release N side. Called during
                 "system upgrade-start".
          migrate: Perform data migration on release N+1 side. Called while
                   system data migration is taking place.
          activate: Activates the deployment. Called during "software deploy activate".
          activate-rollback: Rolls back the activate deployment. Called during
                   "software deploy activate".
    """

    LOG.info("Executing deployment scripts from: %s with from_release: %s, to_release: %s, "
             "action: %s" % (migration_script_dir, from_release, to_release, action))

    if not os.path.isdir(migration_script_dir):
        msg = "Folder %s does not exist" % migration_script_dir
        LOG.exception(msg)
        raise Exception(msg)

    # Get a sorted list of all the migration scripts
    # Exclude any files that can not be executed, including .pyc and .pyo files
    files = [f for f in os.listdir(migration_script_dir)
             if os.path.isfile(os.path.join(migration_script_dir, f)) and
             os.access(os.path.join(migration_script_dir, f), os.X_OK)]
    # From file name, get the number to sort the calling sequence,
    # abort when the file name format does not follow the pattern
    # "nnn-*.*", where "nnn" string shall contain only digits, corresponding
    # to a valid unsigned integer (first sequence of characters before "-")
    try:
        files.sort(key=lambda x: int(x.split("-")[0]))
    except Exception:
        LOG.exception("Deployment script sequence validation failed, invalid "
                      "file name format")
        raise

    MSG_SCRIPT_FAILURE = "Deployment script %s failed with returncode %d" \
                         "Script output:\n%s"
    # Execute each migration script
    for f in files:
        migration_script = os.path.join(migration_script_dir, f)
        try:
            LOG.info("Executing deployment script %s" % migration_script)
            cmdline = [migration_script, from_release, to_release, action]
            if port is not None:
                cmdline.append(port)
            ret = subprocess.run(cmdline,
                                 stderr=subprocess.STDOUT,
                                 stdout=subprocess.PIPE,
                                 text=True, check=True)
            if ret.returncode != 0:
                script_output = ret.stdout.splitlines()
                output_list = []
                for item in script_output:
                    if item not in output_list:
                        output_list.append(item)
                output_script = "\n".join(output_list)
                msg = MSG_SCRIPT_FAILURE % (migration_script,
                                            ret.returncode,
                                            output_script)
                LOG.error(msg)
                raise Exception(msg)

        except subprocess.CalledProcessError as e:
            # log script output if script executed but failed.
            LOG.error(MSG_SCRIPT_FAILURE %
                      (migration_script, e.returncode, e.output))
            # Abort when a migration script fails
            raise
        except Exception as e:
            # log exception if script not executed.
            LOG.exception(e)
            raise


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
