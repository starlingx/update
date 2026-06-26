#!/usr/bin/python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Migrate from netapp trident plugin to app-netapp-storage fluxcd application
#

import base64
import logging
import os
import sys
import tempfile
import yaml

from sysinv.common.kube_utils import KubeUtils
from sysinv.common.kube_utils import KubeResourceType
from software.utilities.plugin_runner import CPlugin
from software.utilities.utils import configure_logging

LOG = logging.getLogger('main_logger')

TRIDENT_NAMESPACE = "trident"
TRIDENT_CRD_GROUP = "trident.netapp.io"
TRIDENT_CRD_VERSION = "v1"
TRIDENT_CRD_PLURAL = "tridentbackendconfigs"
CSI_DRIVER = "csi.trident.netapp.io"
SNAPSHOT_GROUP = "snapshot.storage.k8s.io"
SNAPSHOT_VERSION = "v1"
SNAPSHOT_PLURAL = "volumesnapshotclasses"

VALID_SAN_TYPES = {"iscsi", "fcp", "nvme"}
DEFAULT_NAS_PROTOCOL = "nfs"
DEFAULT_SAN_PROTOCOL = "iscsi"

# Paths
PLATFORM_CONFIG_DIR = "/opt/platform/config"
OVERRIDES_FILENAME = "netapp-overrides.yaml"
BACKUP_SUBDIR = "netapp-legacy-backup"

# Resources to backup and remove during migration (Netapp Trident Plugin - Legacy)
NAMESPACED_RESOURCES = [
    (KubeResourceType.deployment, "trident-controller"),
    (KubeResourceType.daemon_set, "trident-node-linux"),
    (KubeResourceType.daemon_set, "stx-multipath-config-enforcer"),
    (KubeResourceType.service, "trident-csi"),
    (KubeResourceType.service_account, "trident-controller"),
    (KubeResourceType.service_account, "trident-node-linux"),
    (KubeResourceType.resource_quota, "trident-csi"),
]

CLUSTER_RESOURCES = [
    (KubeResourceType.cluster_role, "trident-controller"),
    (KubeResourceType.cluster_role_binding, "trident-controller"),
]


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def is_migration_needed():
    """Check if legacy Trident is installed by looking for TridentBackendConfigs."""
    LOG.info("Checking if legacy NetApp Trident installation is present...")
    kube = KubeUtils()

    ns = kube.get_resource(KubeResourceType.namespace, name=TRIDENT_NAMESPACE)
    if not ns:
        LOG.info("Namespace '%s' does not exist. Skipping." % TRIDENT_NAMESPACE)
        return False

    crd = kube.get_resource(
        KubeResourceType.custom_resource_definition,
        name="tridentbackendconfigs.trident.netapp.io")
    if not crd:
        LOG.info("TridentBackendConfig CRD not registered. Skipping.")
        return False

    items = kube.list_resources(
        KubeResourceType.custom_object,
        namespace=TRIDENT_NAMESPACE,
        group=TRIDENT_CRD_GROUP,
        version=TRIDENT_CRD_VERSION,
        plural=TRIDENT_CRD_PLURAL)

    if not items:
        LOG.info("No TridentBackendConfig found. Skipping.")
        return False

    LOG.info("Found %d TridentBackendConfig(s). Migration needed." % len(items))
    return True


# ---------------------------------------------------------------------------
# Extraction from Netapp Trident legacy installation
# ---------------------------------------------------------------------------

def extract_backends():
    """Extract backend configs from TridentBackendConfig CRs."""
    LOG.info("Extracting backends...")
    kube = KubeUtils()

    items = kube.list_resources(
        KubeResourceType.custom_object,
        namespace=TRIDENT_NAMESPACE,
        group=TRIDENT_CRD_GROUP,
        version=TRIDENT_CRD_VERSION,
        plural=TRIDENT_CRD_PLURAL)

    if not items:
        LOG.warning("No TridentBackendConfig found.")
        return []

    backends = []
    for tbc in items:
        spec = tbc.get("spec", {})
        name = tbc.get("metadata", {}).get("name", "")
        driver = spec.get("storageDriverName", "")
        protocol = DEFAULT_NAS_PROTOCOL

        if 'ontap-nas' in driver:
            protocol = DEFAULT_NAS_PROTOCOL
        elif 'ontap-san' in driver:
            san_type = spec.get("sanType", "")
            if san_type and san_type in VALID_SAN_TYPES:
                protocol = san_type
            else:
                protocol = DEFAULT_SAN_PROTOCOL
        else:
            LOG.warning("Unknown driver '%s' for '%s', defaulting to '%s'."
                        % (driver, name, DEFAULT_NAS_PROTOCOL))

        backend = {
            "name": name,
            "protocol": protocol,
            "managementLIF": spec.get("managementLIF", ""),
            "svm": spec.get("svm", ""),
            "credentials": {
                "secret_name": spec.get("credentials", {}).get("name", "")
            }
        }

        data_lif = spec.get("dataLIF", "")
        if data_lif:
            backend["dataLIF"] = data_lif

        backends.append(backend)
        LOG.info("Backend: %s (protocol=%s)" % (name, protocol))

    LOG.info("Extracted %d backend(s)." % len(backends))
    return backends


def extract_storage_classes():
    """Extract Trident-provisioned StorageClasses."""
    LOG.info("Extracting StorageClasses...")
    kube = KubeUtils()

    all_sc = kube.list_resources(KubeResourceType.storage_class)
    storage_classes = []

    for sc in all_sc:
        if sc.get("provisioner") != CSI_DRIVER:
            continue

        name = sc.get("metadata", {}).get("name", "")
        backend_type = sc.get("parameters", {}).get("backendType", "")
        mount_options = sc.get("mount_options") or sc.get("mountOptions") or []

        entry = {"name": name, "parameters": {"backendType": backend_type}}
        if mount_options:
            entry["mountOptions"] = mount_options

        storage_classes.append(entry)
        LOG.info("StorageClass: %s" % name)

    if not storage_classes:
        LOG.warning("No Trident StorageClasses found.")

    LOG.info("Extracted %d StorageClass(es)." % len(storage_classes))
    return storage_classes


def extract_snapshot_classes():
    """Extract Trident VolumeSnapshotClasses (cluster-scoped CRD)."""
    LOG.info("Extracting VolumeSnapshotClasses...")
    kube = KubeUtils()

    try:
        items = kube.list_cluster_resources(
            KubeResourceType.custom_object,
            group=SNAPSHOT_GROUP,
            version=SNAPSHOT_VERSION,
            plural=SNAPSHOT_PLURAL)
    except Exception:
        LOG.warning("VolumeSnapshotClass not available.")
        return []

    snapshot_classes = []
    for vsc in items:
        if vsc.get("driver") != CSI_DRIVER:
            continue

        name = vsc.get("metadata", {}).get("name", "")
        deletion_policy = vsc.get("deletionPolicy") or "Delete"

        snapshot_classes.append({
            "name": name,
            "deletionPolicy": deletion_policy
        })
        LOG.info("SnapshotClass: %s" % name)

    if not snapshot_classes:
        LOG.warning("No Trident VolumeSnapshotClasses found.")

    LOG.info("Extracted %d SnapshotClass(es)." % len(snapshot_classes))
    return snapshot_classes


def extract_secrets(backends):
    """Extract credentials from secrets referenced by backends."""
    LOG.info("Extracting secrets...")
    kube = KubeUtils()

    secret_names = set()
    for b in backends:
        cred = b.get("credentials", {}).get("secret_name", "")
        if cred:
            secret_names.add(cred)

    if not secret_names:
        LOG.warning("No secrets referenced by backends.")
        return []

    secrets = []
    for secret_name in sorted(secret_names):
        entry = {
            "metadata": {"name": secret_name},
            "type": "Opaque",
            "stringData": {"username": "REPLACE_ME", "password": "REPLACE_ME"}
        }

        resource = kube.get_resource(
            KubeResourceType.secret,
            name=secret_name,
            namespace=TRIDENT_NAMESPACE)

        if not resource:
            LOG.warning("Secret '%s' not found. Using placeholders."
                        % secret_name)
            secrets.append(entry)
            continue

        data = resource.get("data", {})
        username = _decode_b64(data.get("username", ""))
        password = _decode_b64(data.get("password", ""))

        entry["stringData"]["username"] = username or "REPLACE_ME"
        entry["stringData"]["password"] = password or "REPLACE_ME"

        if not username or not password:
            LOG.warning("Secret '%s' missing credentials." % secret_name)

        secrets.append(entry)
        LOG.info("Secret: %s" % secret_name)

    LOG.info("Extracted %d secret(s)." % len(secrets))
    return secrets


def _decode_b64(value):
    """Decode a base64 string, return empty string on failure."""
    if not value:
        return ""
    try:
        return base64.b64decode(value).decode("utf-8")
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Overrides generation for app-netapp-storage application
# ---------------------------------------------------------------------------

def generate_overrides_file(backends, storage_classes, snapshot_classes,
                            secrets, to_release):
    """Write netapp-overrides.yaml for the FluxCD app."""
    LOG.info("Generating overrides file...")

    overrides = {
        "backends": backends,
        "storageClasses": storage_classes,
        "snapshotClasses": snapshot_classes,
        "secret": secrets
    }

    output_dir = os.path.join(PLATFORM_CONFIG_DIR, to_release)
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, OVERRIDES_FILENAME)

    fd, tmp_path = tempfile.mkstemp(
        dir=output_dir, prefix=".netapp-overrides-", suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            yaml.dump(overrides, f, default_flow_style=False,
                      sort_keys=False, allow_unicode=True)
        os.chmod(tmp_path, 0o644)
        os.rename(tmp_path, output_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    LOG.info("Overrides written to: %s" % output_path)
    return output_path


# ---------------------------------------------------------------------------
# Backup Legacy Trident Resources
# ---------------------------------------------------------------------------

def backup_legacy_trident_resources(to_release):
    """Back up legacy Trident resources as YAML for rollback."""
    LOG.info("Backing up legacy Trident resources...")
    kube = KubeUtils()

    backup_path = os.path.join(PLATFORM_CONFIG_DIR, to_release, BACKUP_SUBDIR)
    os.makedirs(backup_path, exist_ok=True)

    for rtype, name in NAMESPACED_RESOURCES:
        _backup_resource_raw(kube, backup_path, rtype, name,
                             namespace=TRIDENT_NAMESPACE)

    for rtype, name in CLUSTER_RESOURCES:
        _backup_resource_raw(kube, backup_path, rtype, name)

    LOG.info("Backup completed at: %s" % backup_path)
    return backup_path


def _backup_resource_raw(kube, backup_path, resource_type, name,
                         namespace=None):
    """
    Back up a resource using the ApiClient serializer for proper camelCase.
    The YAML can be used with create_from_yaml during rollback.
    """

    method_infix = "_"
    kwargs = {"name": name}
    if namespace:
        method_infix = "_namespaced_"
        kwargs["namespace"] = namespace

    api = kube._get_client(resource_type)
    read_method = getattr(api, "read%s%s" % (method_infix, resource_type.value))

    try:
        resource = read_method(**kwargs)
    except Exception as err:
        if getattr(err, "status", None) == 404:
            LOG.warning("Backup: %s/%s not found, skipping."
                        % (resource_type.value, name))
            return
        raise

    # Serialize with camelCase keys
    api_client = kube._get_client(KubeResourceType.client)
    serialized = api_client.sanitize_for_serialization(resource)

    # Strip server-managed fields that prevent re-creation
    metadata = serialized.get("metadata", {})
    for field in ("resourceVersion", "uid", "creationTimestamp",
                  "generation", "managedFields", "selfLink"):
        metadata.pop(field, None)
    # Strip status
    serialized.pop("status", None)

    filepath = os.path.join(backup_path, "%s_%s.yaml"
                            % (resource_type.value, name))
    with open(filepath, 'w') as f:
        yaml.dump(serialized, f, default_flow_style=False,
                  sort_keys=False, allow_unicode=True)
    LOG.info("Backed up %s/%s" % (resource_type.value, name))


def remove_legacy_trident():
    """Remove legacy Trident resources."""
    LOG.info("Removing legacy Trident resources...")
    kube = KubeUtils()

    for rtype, name in NAMESPACED_RESOURCES:
        try:
            kube.delete_resource(rtype, name=name,
                                 namespace=TRIDENT_NAMESPACE,
                                 timeout_seconds=60)
        except Exception as e:
            LOG.error("Failed to delete %s/%s: %s" % (rtype.value, name, e))

    for rtype, name in CLUSTER_RESOURCES:
        try:
            kube.delete_resource(rtype, name=name, timeout_seconds=60)
        except Exception as e:
            LOG.error("Failed to delete %s/%s: %s" % (rtype.value, name, e))

    LOG.info("Legacy Trident removal completed.")


# ---------------------------------------------------------------------------
# Rollback
# ---------------------------------------------------------------------------

def is_rollback_needed():
    """Check if backup directory exists."""
    if not os.path.isdir(PLATFORM_CONFIG_DIR):
        return False
    for entry in os.listdir(PLATFORM_CONFIG_DIR):
        if os.path.isdir(os.path.join(PLATFORM_CONFIG_DIR, entry, BACKUP_SUBDIR)):
            return True
    return False


def rollback():
    """Restore legacy Trident from backup YAML files."""
    LOG.info("Starting rollback...")
    kube = KubeUtils()

    backup_path = None
    for entry in os.listdir(PLATFORM_CONFIG_DIR):
        candidate = os.path.join(PLATFORM_CONFIG_DIR, entry, BACKUP_SUBDIR)
        if os.path.isdir(candidate):
            backup_path = candidate
            break

    if not backup_path:
        LOG.warning("No backup found. Nothing to rollback.")
        return 0

    yaml_files = sorted(f for f in os.listdir(backup_path) if f.endswith('.yaml'))
    if not yaml_files:
        LOG.warning("Backup directory empty.")
        return 0

    for yaml_file in yaml_files:
        filepath = os.path.join(backup_path, yaml_file)
        try:
            kube.create_from_yaml(filepath)
            LOG.info("Restored: %s" % yaml_file)
        except Exception as e:
            LOG.error("Failed to restore %s: %s" % (yaml_file, e))
            return 1

    # Clean up overrides file
    for entry in os.listdir(PLATFORM_CONFIG_DIR):
        path = os.path.join(PLATFORM_CONFIG_DIR, entry, OVERRIDES_FILENAME)
        if os.path.isfile(path):
            try:
                os.remove(path)
                LOG.info("Removed: %s" % path)
            except OSError:
                pass

    LOG.info("Rollback completed.")
    return 0


# ---------------------------------------------------------------------------
# Migrate
# ---------------------------------------------------------------------------

def migrate(from_release, to_release):
    """Extract config, generate overrides, backup and remove legacy Trident."""
    LOG.info("Phase: extraction...")
    backends = extract_backends()
    storage_classes = extract_storage_classes()
    snapshot_classes = extract_snapshot_classes()
    secrets = extract_secrets(backends)

    if not backends:
        raise RuntimeError(
            "Migration aborted: no backends extracted despite "
            "TridentBackendConfig resources being present.")

    LOG.info("Phase: overrides generation...")
    overrides_path = generate_overrides_file(
        backends, storage_classes, snapshot_classes, secrets, to_release)

    if not os.path.isfile(overrides_path):
        raise RuntimeError(
            "Migration aborted: overrides file was not created at %s"
            % overrides_path)

    LOG.info("Phase: backup...")
    backup_path = backup_legacy_trident_resources(to_release)

    backup_files = [f for f in os.listdir(backup_path) if f.endswith('.yaml')]
    if not backup_files:
        raise RuntimeError(
            "Migration aborted: no resources were backed up. "
            "Cannot proceed with removal without rollback capability.")

    LOG.info("Phase: legacy removal...")
    remove_legacy_trident()

    LOG.info("Migration completed. Overrides: %s" % overrides_path)
    return 0


class NetappTridentMigration(CPlugin):
    def __init__(self):
        super().__init__(
            matching_action=['activate', 'activate-rollback'],
            required_state=None,
            plugin_name='netapp-trident-migration',
            completed_state='netapp-trident-migration-completed'
        )

    def _run(self, from_release, to_release, action, port):
        configure_logging()
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (self.name, from_release, to_release, action))

        if action == "activate":
            if is_migration_needed():
                LOG.info("Performing migration from %s to %s"
                         % (from_release, to_release))
                rc = migrate(from_release, to_release)
                if rc != 0:
                    raise RuntimeError("Migration failed with rc=%d" % rc)
        elif action == "activate-rollback":
            if is_rollback_needed():
                LOG.info("Performing rollback from %s to %s"
                         % (from_release, to_release))
                rc = rollback()
                if rc != 0:
                    raise RuntimeError("Rollback failed with rc=%d" % rc)


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

    plugin = NetappTridentMigration()
    result = plugin.run(from_release, to_release, action, port)
    if result and 'failed' in result:
        sys.exit(1)
