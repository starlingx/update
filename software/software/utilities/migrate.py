#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import argparse
import glob
import json
import logging
import os
from pathlib import Path
import psycopg2
import shutil
import socket
import sys
import subprocess
import yaml

from software.utilities import constants
from software.utilities.utils import configure_logging
import software.utilities.utils as utils


sout = sys.stdout
devnull = subprocess.DEVNULL


def get_postgres_bin():
    """Get the path to the postgres binaries"""

    try:
        return subprocess.check_output(
            ['pg_config', '--bindir']).decode().rstrip('\n')
    except subprocess.CalledProcessError:
        LOG.exception("Failed to get postgres bin directory.")
        raise


POSTGRES_BIN = get_postgres_bin()
POSTGRES_PATH = '/var/lib/postgresql'
POSTGRES_DATA_DIR = os.path.join(POSTGRES_PATH, constants.SW_VERSION)
DB_CONNECTION_FORMAT = "connection=postgresql://%s:%s@127.0.0.1:%s/%s\n"
DB_BARBICAN_CONNECTION_FORMAT = "postgresql://%s:%s@127.0.0.1:%s/%s"
DB_PASSWORD_ENCRYPTION = "scram-sha-256"

# Configure logging
LOG = logging.getLogger(__name__)


def migrate_keyring_data(from_release, to_release):
    """Migrates keyring data. """

    LOG.info("Migrating keyring data")
    # First delete any keyring files for the to_release - they can be created
    # if release N+1 nodes are incorrectly left powered up when the release N
    # load is installed.
    target_path = os.path.join(constants.PLATFORM_PATH, ".keyring", to_release)
    shutil.rmtree(target_path, ignore_errors=True)
    shutil.copytree(os.path.join(constants.PLATFORM_PATH, ".keyring", from_release), target_path)


def migrate_pxeboot_config(from_release, to_release):
    """Migrates pxeboot configuration. """
    LOG.info("Migrating pxeboot config")

    # Copy the entire pxelinux.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_pxelinux = os.path.join(constants.PLATFORM_PATH, "config", from_release,
                                   "pxelinux.cfg", "")
    dest_pxelinux = os.path.join(constants.PLATFORM_PATH, "config", to_release,
                                 "pxelinux.cfg")

    Path(dest_pxelinux).mkdir(parents=True, exist_ok=True)

    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_pxelinux),
             os.path.join(dest_pxelinux)],
            stdout=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_pxelinux)
        raise

    to_release_symlink_target = os.path.join(constants.VOLATILE_PXEBOOT_PATH,
                                             "pxelinux.cfg.files", "grub.cfg")

    dest_symlink_exists = os.path.islink(dest_pxelinux + "/grub.cfg")
    if dest_symlink_exists:
        os.unlink(dest_pxelinux + "/grub.cfg")
    os.symlink(to_release_symlink_target, dest_pxelinux + "/grub.cfg")


def migrate_armada_config(from_release, to_release):
    """Migrates armada configuration. """

    # Check if the folder exist before migration
    if not os.path.exists(os.path.join(constants.PLATFORM_PATH, "armada")):
        LOG.info("Skipping armada migration, the directory doesn't exist")
        return

    LOG.info("Migrating armada config")
    # Copy the entire armada.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_armada = os.path.join(constants.PLATFORM_PATH, "armada", from_release, "")
    dest_armada = os.path.join(constants.PLATFORM_PATH, "armada", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_armada),
             os.path.join(dest_armada)],
            stdout=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_armada)
        raise


def migrate_fluxcd_config(from_release, to_release):
    """Migrates fluxcd configuration. """

    # Check if the folder exists before migration
    if not os.path.exists(os.path.join(constants.PLATFORM_PATH, "fluxcd")):
        LOG.info("Skipping fluxcd migration, the directory doesn't exist")
        return

    LOG.info("Migrating fluxcd config")

    # Copy the entire fluxcd.cfg directory to pick up any changes made
    # after the data was migrated.
    source_fluxcd = os.path.join(constants.PLATFORM_PATH, "fluxcd", from_release, "")
    dest_fluxcd = os.path.join(constants.PLATFORM_PATH, "fluxcd", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_fluxcd),
             os.path.join(dest_fluxcd)],
            stdout=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_fluxcd)
        raise


def migrate_helm_config(from_release, to_release):
    """Migrates helm configuration. """

    LOG.info("Migrating helm config")

    # Copy the entire helm.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_helm = os.path.join(constants.PLATFORM_PATH, "helm", from_release, "")
    dest_helm = os.path.join(constants.PLATFORM_PATH, "helm", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_helm),
             os.path.join(dest_helm)],
            stdout=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_helm)
        raise


def migrate_dnsmasq_config(to_release):
    """Migrates dnsmasq configuration. """

    LOG.info("Migrating dnsmasq config")

    # Create dnsmasq.addn_conf file if not present in to_release
    conf_file = os.path.join(constants.PLATFORM_PATH, "config",
                             to_release, "dnsmasq.addn_conf")
    if not os.path.exists(conf_file):
        open(conf_file, 'a').close()


def migrate_sysinv_data(from_release, to_release, port):
    """Migrates sysinv data. """

    LOG.info("Migrating sysinv data")

    # If the /opt/platform/sysinv/<release>/sysinv.conf.default file has
    # changed between releases it must be modified at this point.
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(constants.PLATFORM_PATH, "sysinv", from_release, ""),
             os.path.join(constants.PLATFORM_PATH, "sysinv", to_release)],
            stdout=sout)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to copy sysinv platform dir to new version")
        raise

    # Get the hiera data for the from release
    hiera_path = os.path.join(constants.PLATFORM_PATH, "puppet", from_release,
                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as file:
        static_config = yaml.load(file, Loader=yaml.Loader)

    username = static_config["sysinv::db::postgresql::user"]
    password = utils.get_password_from_keyring("sysinv", "database")

    # We need a bare bones /etc/sysinv/sysinv.conf file in order to do the
    # sysinv database migration and then generate the upgrades manifests.
    with open("/etc/sysinv/sysinv.conf", "w") as f:
        f.write("[DEFAULT]\n")
        f.write("logging_context_format_string=sysinv %(asctime)s.%"
                "(msecs)03d %(process)d %(levelname)s %"
                "(name)s [%(request_id)s %(user)s %"
                "(tenant)s] %(instance)s%(message)s\n")
        f.write("verbose=True\n")
        f.write("syslog_log_facility=local6\n")
        f.write("use_syslog=True\n")
        f.write("logging_default_format_string=sysinv %(asctime)s.%"
                "(msecs)03d %(process)d %(levelname)s %(name)s [-] %"
                "(instance)s%(message)s\n")
        f.write("debug=False\n")
        f.write('sql_connection=postgresql://%s:%s@127.0.0.1:%s/sysinv\n' %
                (username, password, port))


def create_database(target_port):
    """Creates empty postgres database. """

    LOG.info("Creating postgres database")

    db_create_commands = [
        # Configure new data directory for postgres
        'rm -rf {}'.format(POSTGRES_DATA_DIR),
        'mkdir -p {}'.format(POSTGRES_DATA_DIR),
        'chown postgres {}'.format(POSTGRES_DATA_DIR),
        'sudo -u postgres {} -D {}'.format(
            os.path.join(POSTGRES_BIN, 'initdb'),
            POSTGRES_DATA_DIR),
        'chmod -R 700 ' + POSTGRES_DATA_DIR,
        'chown -R postgres ' + POSTGRES_DATA_DIR,
        "sed -i 's/#port = 5432/port = {}/g' {}/postgresql.conf".format(target_port, POSTGRES_DATA_DIR),
        "sed -i 's/^#\\?password_encryption.*/password_encryption = \"{}\"/' {}/postgresql.conf".format(
            DB_PASSWORD_ENCRYPTION, POSTGRES_DATA_DIR),
        'mkdir -p /var/run/postgresql/',
        'chown -R postgres /var/run/postgresql',
    ]

    # Execute db creation commands
    for cmd in db_create_commands:
        try:
            LOG.info("Executing db create command: %s" % cmd)
            subprocess.check_call([cmd],
                                  shell=True, stdout=sout, stderr=sout)
        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" % (cmd, ex.returncode))
            raise


def import_databases(target_port, from_path=None):
    """Imports databases. """

    if not from_path:
        from_dir = '/var/lib/postgresql/upgrade/'

    LOG.info("Importing databases")
    try:
        postgres_config_path = os.path.join(
            from_dir, 'postgres.postgreSql.config')
        # Do postgres schema import
        subprocess.check_call(['sudo -u postgres psql --port=%s -f ' % target_port +
                               postgres_config_path + ' postgres'],
                              shell=True,
                              stdout=devnull,
                              stderr=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to import schemas.")
        raise

    import_commands = []

    # Do postgres data import
    for data in glob.glob(from_dir + '/*.*Sql.data'):
        db_elem = data.split('/')[-1].split('.')[0]
        LOG.info("Importing %s" % db_elem)
        import_commands.append((db_elem,
                                "sudo -u postgres psql --port=%s -f " % target_port + data +
                                " " + db_elem))

    # Execute import commands
    for cmd in import_commands:
        try:
            print("Importing %s" % cmd[0])
            LOG.info("Executing import command: %s" % cmd[1])
            subprocess.check_call([cmd[1]], shell=True, stdout=devnull, stderr=sout)

        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" %
                          (cmd[1], ex.returncode))
            raise


def migrate_vim_database(from_release, to_release):
    """Migrates the VIM DB."""

    LOG.info("Migrating VIM DB")

    # The VIM DB is special because it's being used during orchestrated upgrades
    vim_commands = []
    from_db_dir = os.path.join(constants.PLATFORM_PATH, 'nfv/vim', from_release)
    to_db_dir = os.path.join(constants.PLATFORM_PATH, 'nfv/vim', to_release)
    db_files = ["vim_db_v1"]

    # Prepare N+1 dir
    vim_commands.append(
        (f"remove {to_db_dir}",
         f"rm -rf {to_db_dir}"))

    vim_commands.append(
        (f"create {to_db_dir}",
         f"mkdir -p {to_db_dir}"))

    for v in db_files:
        from_file = os.path.join(from_db_dir, v)
        to_file = os.path.join(to_db_dir, v)
        vim_commands.append(
            (f"Hard-link VIM DB file {from_file}",
             f"ln {from_file} {to_file}"))

    # Execute migrate commands
    for cmd in vim_commands:
        try:
            print("Migrating VIM DB: %s" % cmd[0])
            LOG.info("Executing migration command: %s" % cmd[1])
            subprocess.check_call([cmd[1]], shell=True, stdout=devnull, stderr=sout)

        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" %
                          (cmd[1], ex.returncode))
            raise


def get_system_role(target_port):
    """Get the system role from the sysinv database"""

    conn = psycopg2.connect("dbname=sysinv user=postgres port=%s" % target_port)
    cur = conn.cursor()
    cur.execute("select distributed_cloud_role from i_system;")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch i_system data")
        raise psycopg2.ProgrammingError("Failed to fetch i_system data")

    role = row[0]

    return role


def get_system_mode(target_port):
    """Get the system mode (simplex or duplex)
       from the sysinv database
    """

    conn = psycopg2.connect("dbname=sysinv user=postgres port=%s" % target_port)
    cur = conn.cursor()
    cur.execute("select system_mode from i_system;")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch i_system data")
        raise psycopg2.ProgrammingError("Failed to fetch i_system data")

    role = row[0]

    return role


def get_first_controller(target_port):
    """retrieve the first controller to upgrade.
       in sx, controller-0, or
       in dx, controller-1
    """

    system_mode = get_system_mode(target_port)
    if system_mode == constants.SIMPLEX:
        return constants.CONTROLLER_0_HOSTNAME
    else:
        return constants.CONTROLLER_1_HOSTNAME


def get_hostname_mgmt_ip(hostname, target_port):
    """Get mgmt-ip for given hostname"""
    conn = psycopg2.connect("dbname=sysinv user=postgres port=%s" % target_port)
    cur = conn.cursor()
    cur.execute(f"select address from addresses where name='{hostname}-mgmt';")
    row = cur.fetchone()

    if row is None:
        msg = f"Failed to get {hostname} mgmt-ip"
        LOG.error(msg)
        raise psycopg2.ProgrammingError(msg)

    return row[0]


def get_shared_services(target_port):
    """Get the list of shared services from the sysinv database"""

    shared_services = []
    DEFAULT_SHARED_SERVICES = []

    conn = psycopg2.connect("dbname=sysinv user=postgres port=%s" % target_port)
    cur = conn.cursor()
    cur.execute("select capabilities from i_system;")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch i_system data")
        raise psycopg2.ProgrammingError("Failed to fetch i_system data")

    cap_obj = json.loads(row[0])
    region_config = cap_obj.get('region_config', None)
    if region_config:
        shared_services = cap_obj.get('shared_services',
                                      DEFAULT_SHARED_SERVICES)

    return shared_services


def migrate_hiera_data(from_release):
    """Migrate static hiera data. """

    LOG.info("Migrating hiera data")
    from_hiera_path = os.path.join(constants.PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    to_hiera_path = constants.HIERADATA_PERMDIR

    shutil.rmtree(to_hiera_path, ignore_errors=True)
    os.makedirs(to_hiera_path)

    # Copy only the static yaml files. The other yaml files will be generated
    # when required.
    for f in ['secure_static.yaml', 'static.yaml']:
        shutil.copy(os.path.join(from_hiera_path, f), to_hiera_path)

    # Make any necessary updates to the static yaml files.
    # Update the static.yaml file
    static_file = os.path.join(constants.HIERADATA_PERMDIR, "static.yaml")
    with open(static_file, 'r') as yaml_file:
        static_config = yaml.load(yaml_file, Loader=yaml.Loader)
    static_config.update({
        'platform::params::software_version': constants.SW_VERSION,
        'platform::client::credentials::params::keyring_directory':
            constants.KEYRING_PATH,
        'platform::client::credentials::params::keyring_file':
            os.path.join(constants.KEYRING_PATH, '.CREDENTIAL'),
    })

    with open(static_file, 'w') as yaml_file:
        yaml.dump(static_config, yaml_file, default_flow_style=False)

    secure_static_file = os.path.join(
        constants.HIERADATA_PERMDIR, "secure_static.yaml")
    with open(secure_static_file, 'r') as yaml_file:
        secure_static_config = yaml.load(yaml_file, Loader=yaml.Loader)

    with open(secure_static_file, 'w') as yaml_file:
        yaml.dump(secure_static_config, yaml_file, default_flow_style=False)


def get_db_credentials(shared_services, from_release, role=None):
    """
    Returns the database credentials using the provided shared services,
    from_release and role.
    """
    db_credential_keys = \
        {'barbican': {'hiera_user_key': 'barbican::db::postgresql::user',
                      'keyring_password_key': 'barbican',
                      },
         'sysinv': {'hiera_user_key': 'sysinv::db::postgresql::user',
                    'keyring_password_key': 'sysinv',
                    },
         'fm': {'hiera_user_key': 'fm::db::postgresql::user',
                'keyring_password_key': 'fm',
                },
         }

    if constants.SERVICE_TYPE_IDENTITY not in shared_services:
        db_credential_keys.update(
            {'keystone': {'hiera_user_key':
                          'keystone::db::postgresql::user',
                          'keyring_password_key': 'keystone',
                          }})

    if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        db_credential_keys.update(
            {'dcmanager': {'hiera_user_key': 'dcmanager::db::postgresql::user',
                           'keyring_password_key': 'dcmanager',
                           },
             'dcorch': {'hiera_user_key': 'dcorch::db::postgresql::user',
                        'keyring_password_key': 'dcorch',
                        },
             })

    # Get the hiera data for the from release
    hiera_path = os.path.join(constants.PLATFORM_PATH, "puppet", from_release,
                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as file:
        static_config = yaml.load(file, Loader=yaml.Loader)

    db_credentials = dict()
    for database, values in db_credential_keys.items():
        username = static_config[values['hiera_user_key']]
        password = utils.get_password_from_keyring(
            values['keyring_password_key'], "database")
        db_credentials[database] = {'username': username, 'password': password}

    return db_credentials


def create_databases(db_credentials):
    """Creates databases. """
    LOG.info("Creating new databases")

    # Create databases that are new in this release

    conn = psycopg2.connect('dbname=postgres user=postgres port=6666')

    # Postgres won't allow transactions around database create operations
    # so we set the connection to autocommit
    conn.set_isolation_level(
        psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

    databases_to_create = []
    if not databases_to_create:
        return

    with conn:
        with conn.cursor() as cur:
            for database in databases_to_create:
                print("Creating %s database" % database)
                username = psycopg2.extensions.AsIs(
                    '\"%s\"' % db_credentials[database]['username'])
                db_name = psycopg2.extensions.AsIs('\"%s\"' % database)
                password = db_credentials[database]['password']

                try:
                    # Here we create the new database and the role for it
                    # The role will be used by the dbsync command to
                    # connect to the database. This ensures any new tables
                    # are added with the correct owner
                    cur.execute('CREATE DATABASE %s', (db_name,))
                    cur.execute('CREATE ROLE %s', (username,))
                    cur.execute('ALTER ROLE %s LOGIN PASSWORD %s',
                                (username, password))
                    cur.execute('GRANT ALL ON DATABASE %s TO %s',
                                (db_name, username))
                except Exception as ex:
                    LOG.exception("Failed to create database and role. " +
                                  "(%s : %s) Exception: %s" %
                                  (database, username, ex))
                    raise


def migrate_sysinv_database():
    """Migrates the sysinv database. """

    sysinv_cmd = 'sysinv-dbsync'
    try:
        print("Migrating sysinv")
        LOG.info("Executing migrate command: %s" % sysinv_cmd)
        subprocess.check_call(sysinv_cmd,
                              shell=True, stdout=sout, stderr=sout)

    except subprocess.CalledProcessError as ex:
        LOG.exception("Failed to execute command: '%s' during upgrade "
                      "processing, return code: %d"
                      % (sysinv_cmd, ex.returncode))
        raise


def migrate_databases(shared_services, db_credentials, port,
                      simplex=False, role=None):
    """Migrates databases. """

    # Create minimal config files for each OpenStack service so they can
    # run their database migration.
    if constants.SERVICE_TYPE_IDENTITY not in shared_services:
        with open("/etc/keystone/keystone-dbsync.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, port, 'keystone'))

    migrate_commands = [
        # Migrate barbican
        ('barbican',
         'barbican-manage db upgrade ' +
         '--db-url %s' % get_connection_string(db_credentials, port, 'barbican')),
    ]

    # Migrate fm
    # append the migrate command for dcmanager db
    with open("/etc/fm/fm.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, port, 'fm'))

    migrate_commands += [
        ('fm',
         'fm-dbsync')
    ]

    if constants.SERVICE_TYPE_IDENTITY not in shared_services:
        # To avoid a deadlock during keystone contract we will use offline
        # migration for simplex upgrades. Other upgrades will have to use
        # another method to resolve the deadlock
        if not simplex:
            migrate_commands += [
                # Migrate keystone
                #
                # EXPAND - we will first expand the database scheme to a
                # superset of what both the previous and next release can
                # utilize, and create triggers to facilitate the live
                # migration process.
                #
                # MIGRATE - will perform the data migration, while still]
                # preserving the old schema
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync --expand'),
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync --migrate'),
            ]
        else:
            migrate_commands += [
                # In simplex we're the only node so we can do an offline
                # migration
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync')
            ]

    if role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        # append the migrate command for dcmanager db
        with open("/etc/dcmanager/dcmanager.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, port, 'dcmanager'))

        migrate_commands += [
            ('dcmanager',
             'dcmanager-manage db_sync')
        ]

        # append the migrate command for dcorch db
        with open("/etc/dcorch/dcorch.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, port, 'dcorch'))

        migrate_commands += [
            ('dcorch',
             'dcorch-manage db_sync')
        ]

    # Execute migrate commands
    for cmd in migrate_commands:
        try:
            print("Migrating %s" % cmd[0])
            LOG.info("Executing migrate command: %s" % cmd[1])
            subprocess.check_call([cmd[1]],
                                  shell=True, stdout=sout, stderr=sout)

        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" %
                          (cmd[1], ex.returncode))
            raise

    # The database entry for the first controller to be upgrade  will be set
    # to whatever it was when the sysinv database was dumped on. Update the
    # state and from/to load to what it should be when it becomes active.
    try:
        subprocess.check_call(
            ["/usr/bin/sysinv-upgrade",
             "update_controller_state",
             "--skip_load_update"],
            stdout=sout, stderr=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to update state of the controller")
        raise


def gethostaddress(hostname):
    """Get the IP address for a hostname, supporting IPv4 and IPv6. """
    return socket.getaddrinfo(hostname, None)[0][4][0]


def get_connection_string(db_credentials, port, database):
    """Generates a connection string for a given database"""
    username = db_credentials[database]['username']
    password = db_credentials[database]['password']
    if database == 'barbican':
        return DB_BARBICAN_CONNECTION_FORMAT % (username, password, port, database)
    else:
        return DB_CONNECTION_FORMAT % (username, password, port, database)


def create_mgmt_ip_hieradata(hostname, target_port):
    """Create host hieradata <hostname_mgmt-ip>.yaml for backward compatibility with stx-8"""
    try:
        mgmt_ip = get_hostname_mgmt_ip(hostname, target_port)
        hostname_yaml = os.path.join(constants.HIERADATA_PERMDIR, f"{hostname}.yaml")
        mgmt_ip_yaml = os.path.join(constants.HIERADATA_PERMDIR, f"{mgmt_ip}.yaml")
        shutil.copy(hostname_yaml, mgmt_ip_yaml)
        LOG.info("Created host hieradata %s" % mgmt_ip_yaml)
    except Exception as e:
        LOG.error("Failure creating mgmt-ip hieradata for host %s: %s" % (hostname, str(e)))
        raise


def upgrade_controller(from_release, to_release, target_port):
    """Executed on controller-0, under chroot N+1 deployment and N runtime. """

    LOG.info("Upgrading controller from %s to %s" % (from_release, to_release))
    LOG.info("Mounting filesystems already done before chroot")

    # Migrate keyring data
    print("Migrating keyring data...")
    migrate_keyring_data(from_release, to_release)

    # Migrate pxeboot config
    print("Migrating pxeboot configuration...")
    migrate_pxeboot_config(from_release, to_release)

    # Migrate armada config
    print("Migrating armada configuration...")
    migrate_armada_config(from_release, to_release)

    # Migrate fluxcd config
    print("Migrating fluxcd configuration...")
    migrate_fluxcd_config(from_release, to_release)

    # Migrate helm config
    print("Migrating helm configuration...")
    migrate_helm_config(from_release, to_release)

    # Migrate dnsmasq config
    print("Migrating dnsmasq configuration...")
    migrate_dnsmasq_config(to_release)

    # Migrate sysinv data.
    print("Migrating sysinv configuration...")
    migrate_sysinv_data(from_release, to_release, target_port)

    # Prepare for database migration
    print("Preparing for database migration...")
    #  prepare_postgres_filesystems()

    # Import databases
    print("Importing databases...")
    import_databases(target_port)

    print("Migrating the VIM DB...")
    migrate_vim_database(from_release, to_release)

    role = get_system_role(target_port)
    shared_services = get_shared_services(target_port)

    # Create /tmp/python_keyring - used by keystone manifest.
    tmp_keyring_path = "/tmp/python_keyring"
    key_ring_path = os.path.join(constants.PLATFORM_PATH, ".keyring", to_release,
                                 "python_keyring")
    shutil.rmtree(tmp_keyring_path, ignore_errors=True)
    shutil.copytree(key_ring_path, tmp_keyring_path)

    # Migrate hiera data
    migrate_hiera_data(from_release)
    utils.add_upgrade_entries_to_hiera_data(from_release)

    # Get database credentials
    db_credentials = get_db_credentials(
        shared_services, from_release, role=role)

    # Create any new databases
    print("Creating new databases...")
    create_databases(db_credentials)

    print("Migrating databases...")
    # Migrate sysinv database
    migrate_sysinv_database()

    # Migrate databases
    migrate_databases(shared_services, db_credentials, target_port, role=role)

    print("Applying configuration...")

    # Execute migration scripts
    utils.execute_migration_scripts(
        from_release, to_release, utils.ACTION_MIGRATE, target_port)

    # Remove manifest and keyring files
    shutil.rmtree("/tmp/python_keyring", ignore_errors=True)

    first_controller = get_first_controller(target_port)
    # Generate config to be used by "regular" manifest
    print("Generating config for %s" % first_controller)
    LOG.info("Generating config for %s" % first_controller)
    try:
        utils.create_system_config()
        utils.create_host_config(first_controller)
    except Exception as e:
        LOG.exception(e)
        LOG.info("Failed to update hiera configuration")
        raise

    # Clone the created host hieradata with the name <hostname_mgmt-ip>.yaml
    # TODO(heitormatsui): remove when upgrade from stx-8 deprecates
    if from_release == "22.12":
        LOG.info("Generating mgmt-ip config for %s" % first_controller)
        create_mgmt_ip_hieradata(first_controller, target_port)

    # Stop postgres server
    LOG.info("Shutting down PostgreSQL...")
    try:
        subprocess.check_call([
            'sudo',
            '-u',
            'postgres',
            os.path.join(POSTGRES_BIN, 'pg_ctl'),
            '-D',
            POSTGRES_DATA_DIR,
            'stop'],
            stdout=sout)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to stop postgres service")
        raise

    print("Data migration complete !!!")
    LOG.info("Data migration complete !!!")


def migrate():
    # this is the entry point to start data migration
    configure_logging()
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("from_release",
                        default=False,
                        help="From release")

    parser.add_argument("to_release",
                        default=False,
                        help="To release")

    parser.add_argument('port',
                        default=6666,
                        help="PostgreSQL service port to access target database.")

    parser.add_argument('-v', '--verbose',
                        default=False, action="store_true",
                        help="Print more verbose output")

    args = parser.parse_args()

    upgrade_controller(args.from_release, args.to_release, args.port)
