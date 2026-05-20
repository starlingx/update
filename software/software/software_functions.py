"""
Copyright (c) 2023-2026 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import contextlib
import functools
import getopt
import glob
import hashlib
import importlib.util
import logging
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from xml.dom import minidom

from lxml import etree as ElementTree
from oslo_config import cfg as oslo_cfg
from packaging import version

import software.apt_utils as apt_utils
import software.config as cfg
import software.constants as constants
from software.db.api import get_instance

from software.exceptions import MetadataFail
from software.exceptions import OSTreeTarFail
from software.exceptions import ReleaseMismatchFailure
from software.exceptions import ReleaseUploadFailure
from software.exceptions import ReleaseValidationFailure
from software.exceptions import SoftwareServiceError
from software.exceptions import VersionedDeployPrecheckFailure
from software.release_signing import sign_files
from software.release_verify import cert_type_all
from software.release_verify import verify_files
from software.sysinv_utils import get_ihost_list
from software.sysinv_utils import get_system_info
from software.sysinv_utils import is_host_locked_and_online
import software.utils as utils
from software import states


try:
    # The tsconfig module is only available at runtime
    from tsconfig.tsconfig import SW_VERSION
except Exception:
    SW_VERSION = "unknown"

CONF = oslo_cfg.CONF

# these next 4 variables may need to change to support ostree
repo_root_dir = "/var/www/pages/updates"
repo_dir = {SW_VERSION: "%s/rel-%s" % (repo_root_dir, SW_VERSION)}

root_package_dir = "%s/packages" % constants.SOFTWARE_STORAGE_DIR
root_scripts_dir = "/opt/software/software-scripts"
package_dir = {SW_VERSION: "%s/%s" % (root_package_dir, SW_VERSION)}

logfile = "/var/log/software.log"
apilogfile = "/var/log/software-api.log"

LOG = logging.getLogger('main_logger')
auditLOG = logging.getLogger('audit_logger')
audit_log_msg_prefix = 'User: sysadmin/admin Action: '

detached_signature_file = "signature.v2"


def handle_exception(exc_type, exc_value, exc_traceback):
    """
    Exception handler to log any uncaught exceptions
    """
    LOG.error("Uncaught exception",
              exc_info=(exc_type, exc_value, exc_traceback))
    sys.__excepthook__(exc_type, exc_value, exc_traceback)


def configure_logging(logtofile=True, level=logging.INFO):
    if logtofile:
        my_exec = os.path.basename(sys.argv[0])

        log_format = cfg.logging_default_format_string
        log_format = log_format.replace('%(exec)s', my_exec)
        formatter = logging.Formatter(log_format, datefmt="%FT%T")

        LOG.setLevel(level)
        main_log_handler = logging.FileHandler(logfile)
        main_log_handler.setFormatter(formatter)
        LOG.addHandler(main_log_handler)

        auditLOG.setLevel(level)
        api_log_handler = logging.FileHandler(apilogfile)
        api_log_handler.setFormatter(formatter)
        auditLOG.addHandler(api_log_handler)

        try:
            os.chmod(logfile, 0o640)
            os.chmod(apilogfile, 0o640)
        except Exception:
            pass

        # Log uncaught exceptions to file
        sys.excepthook = handle_exception
    else:
        logging.basicConfig(level=level)


def audit_log_info(msg=''):
    msg = audit_log_msg_prefix + msg
    auditLOG.info(msg)


def get_md5(path):
    """
    Utility function for generating the md5sum of a file
    :param path: Path to file
    """
    md5 = hashlib.md5()
    block_size = 8192
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
            md5.update(chunk)
    return int(md5.hexdigest(), 16)


def add_text_tag_to_xml(parent,
                        name,
                        text):
    """
    Utility function for adding a text tag to an XML object
    :param parent: Parent element
    :param name: Element name
    :param text: Text value
    :return:The created element
    """
    tag = ElementTree.SubElement(parent, name)
    tag.text = text
    return tag


def write_xml_file(top,
                   fname):
    # Generate the file, in a readable format if possible
    outfile = open(fname, 'w')
    rough_xml = ElementTree.tostring(top)
    if platform.python_version() == "2.7.2":
        # The 2.7.2 toprettyxml() function unnecessarily indents
        # childless tags, adding whitespace. In the case of the
        # yum comps.xml file, it makes the file unusable, so just
        # write the rough xml
        outfile.write(rough_xml)
    else:
        outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))


def get_release_from_patch(patchfile, key="sw_version"):
    rel = ""
    try:
        metadata_str = subprocess.check_output(['tar', '--to-command=tar -xO', '-xf', patchfile, 'metadata.tar'])
        root = ElementTree.fromstring(metadata_str)
        # Extract release version
        rel = root.findtext(key)
    except subprocess.CalledProcessError as e:
        LOG.error("Failed to run tar command")
        LOG.error("Command output: %s", e.output)
        raise e
    except Exception as e:
        print("Failed to parse patch %s" % key)
        raise e
    return rel


class BasePackageData(object):
    """
    Information about the base package data provided by the load
    """

    def __init__(self):
        self.pkgs = {}
        self.loaddirs()

    def loaddirs(self):
        # Load up available package info
        base_dir = constants.FEED_OSTREE_BASE_DIR
        if not os.path.exists(base_dir):
            # Return, since this could be running off-box
            return

        # Look for release dirs
        for reldir in glob.glob("%s/rel-*" % base_dir):
            pattern = re.compile("%s/rel-(.*)" % base_dir)
            m = pattern.match(reldir)
            sw_rel = m.group(1)

            if sw_rel in self.pkgs:
                # We've already parsed this dir once
                continue

            self.pkgs[sw_rel] = {}

        # Clean up deleted data
        deleted_releases = []
        for sw_rel in self.pkgs:
            if not os.path.exists("%s/rel-%s" % (base_dir, sw_rel)):
                deleted_releases.append(sw_rel)
        for sw_rel in deleted_releases:
            del self.pkgs[sw_rel]

    def check_release(self, sw_rel):
        return (sw_rel in self.pkgs)

    def find_version(self, sw_rel, pkgname, arch):
        if sw_rel not in self.pkgs or \
           pkgname not in self.pkgs[sw_rel] or \
           arch not in self.pkgs[sw_rel][pkgname]:
            return None

        return self.pkgs[sw_rel][pkgname][arch]


class ReleaseData(object):
    """
    Aggregated release data
    """

    def __init__(self):
        #
        #  The state map defines each state for the respective legacy or component directory
        #  where the release metadata is stored.
        #
        self.state_map = {
            # Legacy States
            states.AVAILABLE: [states.AVAILABLE_DIR, states.COMPONENT_AVAILABLE_DIR],
            states.UNAVAILABLE: [states.UNAVAILABLE_DIR, states.COMPONENT_UNAVAILABLE_DIR],
            states.DEPLOYING: [states.DEPLOYING_DIR, states.COMPONENT_DEPLOYING_DIR],
            states.DEPLOYED: [states.DEPLOYED_DIR, states.COMPONENT_DEPLOYED_DIR],
            states.REMOVING: [states.REMOVING_DIR, states.COMPONENT_REMOVING_DIR],
            # Component States
            states.DEPLOY_SELECTED: [states.COMPONENT_DEPLOY_SELECTED_DIR],
            states.REMOVE_SELECTED: [states.COMPONENT_REMOVE_SELECTED_DIR],
        }
        self._reset()

    def _reset(self):
        #
        # The metadata dict stores all metadata associated with a release.
        # This dict is keyed on release_id, with metadata for each release stored
        # in a nested dict. (See parse_metadata_string method for more info)
        #
        self.metadata = {}

        #
        # The contents dict stores the ostree contents provided by each release,
        # indexed by release_id.
        #
        self.contents = {}

    def add_release(self, new_release):
        # We can just use "update" on these dicts because they are indexed by patch_id
        self.metadata.update(new_release.metadata)
        self.contents.update(new_release.contents)

    def update_release(self, updated_release):
        for release_id in list(updated_release.metadata):
            # Update all fields except state
            cur_state = self.metadata[release_id]['state']
            updated_release.metadata[release_id]['state'] = cur_state
            self.metadata[release_id].update(updated_release.metadata[release_id])

    def delete_release(self, release_id):
        del self.contents[release_id]
        del self.metadata[release_id]

    @staticmethod
    def modify_metadata_text(filename,
                             key,
                             value):
        """
        Open an xml file, find first element matching 'key' and replace the text with 'value'
        """
        new_filename = "%s.new" % filename
        tree = ElementTree.parse(filename)

        # Prevent a proliferation of carriage returns when we write this XML back out to file.
        for e in tree.getiterator():
            if e.text is not None:
                e.text = e.text.rstrip()
            if e.tail is not None:
                e.tail = e.tail.rstrip()

        root = tree.getroot()

        # Make the substitution
        e = root.find(key)
        if e is None:
            msg = "modify_metadata_text: failed to find tag '%s'" % key
            LOG.error(msg)
            raise ReleaseValidationFailure(msg)
        e.text = value

        # write the modified file
        outfile = open(new_filename, 'w')
        rough_xml = ElementTree.tostring(root)
        outfile.write(minidom.parseString(rough_xml).toprettyxml(indent="  "))
        outfile.close()
        os.rename(new_filename, filename)

    def parse_metadata_file(self,
                            filename,
                            state=None):
        """
        Parse an individual release metadata XML file
        :param filename: XML file
        :param state: Indicates Applied, Available, or Committed
        :return: Release ID
        """
        with open(filename, "r") as f:
            text = f.read()

        return self.parse_metadata_string(text, state)

    def _parse_metadata_tag(self, file, tag, target_dict, true_value="Y", default_value="N"):
        """
        Parse a specific tag from a XML file to a dictionary. If the tag value differs from the
        expected value, the default value is addressed in the dictionary
        :param file: XML file
        :param tag: XML tag
        :param target_dict: Dictionary updated with the parsed data
        :param true_value: Expected value
        :param default_value: Default value
        """
        value = file.findtext(tag)
        target_dict[tag] = true_value if value == true_value else default_value

    def _parse_metadata_array_tag(self, file, tag, tag_id, target_dict):
        """
        Parse a specific array tag from a XML file to a dictionary
        :param file: XML file
        :param tag: XML tag
        :param tag_id: XML tag identifier
        :param target_dict: Dictionary updated with the parsed data
        """
        for xml_tag in file.findall(tag):
            for xml_tag_id in xml_tag.findall(tag_id):
                target_dict[tag].append(xml_tag_id.text)

    def _bulk_parse_metadata_tags(self, file, tags: list, target_dict):
        """
        Parse multiple tags in a specific XML file to a dictionary
        :param file: XML file
        :param tags: list of XML tags
        :param target_dict: Dictionary updated with the parsed data
        """
        for tag in tags:
            value = file.findtext(tag)
            if value is not None:
                target_dict[tag] = value

    def _parse_ostree_contents(self, file, target_dict):
        """
        Parse the ostree section in a specific XML file
        :param file: XML file
        :param target_dict: Dictionary updated with the parsed data
        """
        for content in file.findall("contents/ostree"):
            target_dict["number_of_commits"] = content.findtext("number_of_commits")
            target_dict["base"] = {
                "commit": content.findtext("base/commit"),
                "checksum": content.findtext("base/checksum"),
            }
            for i in range(int(target_dict["number_of_commits"])):
                key = "commit%s" % (i + 1)
                target_dict[key] = {
                    "commit": content.findtext("%s/commit" % key),
                    "checksum": content.findtext("%s/checksum" % key),
                }

    def _get_release_by_sw_version(self, sw_version):
        """Search and return release matching given sw_version"""
        for release_id in self.metadata:
            if self.metadata[release_id]["sw_version"] == sw_version:
                return release_id
        return None

    def parse_metadata_string(self, text, state=None):
        """
        Parse the metadata.xml file based in the Legacy, Product or
        Metapackage releases structure
        :param text: XML text
        :param state: Release state
        """
        #
        #    Legacy Patch Release (before stx.13.0):
        #    <patch>
        #        <id>PATCH_0001</id>
        #        <summary>Brief description</summary>
        #        <description>Longer description</description>
        #        <install_instructions/>
        #        <warnings/>
        #        <status>Dev</status>
        #        <unremovable/>
        #        <reboot_required/>
        #    </patch>
        #
        #    Product Release (stx.13.0 onwards):
        #    <product>
        #      <id>starlingx-13.0</id>
        #      <sw_version>13.0</sw_version>
        #      <metapackages>
        #        <pkg>k8s</pkg>
        #        <pkg>base</pkg>
        #        <pkg>infra</pkg>
        #        <pkg>distcloud</pkg>
        #      </metapackages>
        #    </product>
        #
        #    Metapackage Release (stx.13.0 onwards):
        #    <id>swmgmt_13.0</id>
        #    <sw_version>13.0<sw_version>
        #    <summary/>
        #    <description/>
        #    <reboot_required>Y</reboot_required>
        #    <deployable>Y</deployable>
        #    <data_migration>Y</data_migration>
        #    <ostree>
        #        <base>
        #        <commit/>
        #        <checksum/>
        #        </base>
        #        <commit1>
        #        <commit>44.....3d42e</commit>
        #        <checksum>17cd4d.....77</checksum>
        #        </commit1>
        #    </ostree>
        #    <requires/>
        #    <packages>
        #        <deb>pkg1.deb</deb>
        #        <deb>pkg2.deb</deb>
        #        <deb>pkg3.deb</deb>
        #        ...
        #    </packages>
        xml_file = ElementTree.fromstring(text)
        release_id = None
        metapackages = xml_file.find("metapackages")
        if xml_file.tag == "product" and metapackages is not None:
            # Product Release
            release_id = xml_file.findtext("id")
            if release_id is None:
                LOG.error("Product metadata does not contain id tag")
                return None

            self.metadata[release_id] = {}
            self.contents[release_id] = {}
            if state:
                self.metadata[release_id]["state"] = state
            sw_version = xml_file.findtext("sw_version")
            if sw_version is None:
                sw_version = "unknown"

            self.metadata[release_id]["sw_version"] = sw_version
            self.metadata[release_id]["metapackages"] = {}
            self.contents[release_id]["metapackages"] = {}
            metapackages = xml_file.find("metapackages")
            if metapackages is not None:
                for pkg in metapackages.findall("pkg"):
                    if pkg.text is not None and sw_version != "unknown":
                        self.metadata[release_id]["metapackages"][f"{pkg.text}_{sw_version}"] = {}
        else:
            # Legacy or Metapackage Release
            xml_tags = ["status", "summary", "description"]
            metadata_dict = {}
            contents_dict = {}
            if xml_file.tag == "metapackage":
                # Metapackage Release
                metapackage_id = xml_file.findtext("id")
                if metapackage_id is None:
                    LOG.error("Metapackage metadata does not contain id tag")
                    return None

                sw_version = xml_file.findtext("sw_version")
                if sw_version is None:
                    LOG.error("Metapackage metadata does not contain sw_version tag")
                    return None
                release_id = self._get_release_by_sw_version(sw_version)
                if release_id is None:
                    LOG.error(f"No existing release matches {sw_version} version")
                    return None

                self.metadata[release_id]["metapackages"][metapackage_id] = {}
                self.contents[release_id]["metapackages"][metapackage_id] = {}
                metadata_dict = self.metadata[release_id]["metapackages"][metapackage_id]
                contents_dict = self.contents[release_id]["metapackages"][metapackage_id]

                metadata_dict["component"] = metapackage_id.split("_")[0]  # metapackage name without version
                metadata_dict["product"] = release_id  # include product release in metapackage metadata
                metadata_dict["state"] = state
                self._parse_metadata_tag(xml_file, "deployable", metadata_dict)
                self._parse_metadata_tag(xml_file, "data_migration", metadata_dict)
            else:
                # Legacy Release
                xml_tags = xml_tags + [
                    "unremovable",
                    "install_instructions",
                    "pre_start",
                    "post_start",
                    "pre_install",
                    "post_install",
                    "warnings",
                    "apply_active_release_only",
                    "commit",
                    "component"
                ]
                release_id = xml_file.findtext("id")
                if release_id is None:
                    LOG.error("Legacy metadata does not contain id tag")
                    return None

                sw_version = xml_file.findtext("sw_version")
                if sw_version is None:
                    LOG.error("Legacy metadata does not contain sw_version tag")
                    return None

                self.metadata[release_id] = {}
                if state:
                    self.metadata[release_id]["state"] = state

                self.contents[release_id] = {}
                contents_dict = self.contents[release_id]
                metadata_dict = self.metadata[release_id]

            global package_dir
            metadata_dict["sw_version"] = sw_version
            release_sw_version = utils.get_major_release_version(metadata_dict["sw_version"])
            if release_sw_version not in package_dir:
                package_dir[release_sw_version] = "%s/%s" % (root_package_dir, release_sw_version)
                repo_dir[release_sw_version] = "%s/rel-%s" % (repo_root_dir, release_sw_version)

            # Default reboot_required to Y
            self._parse_metadata_tag(xml_file, "reboot_required", metadata_dict, "N", "Y")
            # Default prepatched_iso to N
            self._parse_metadata_tag(xml_file, "prepatched_iso", metadata_dict)

            metadata_dict["preinstalled_patches"] = []
            metadata_dict["requires"] = []
            metadata_dict["packages"] = []
            metadata_dict["activation_scripts"] = []
            self._parse_metadata_array_tag(xml_file, "preinstalled_patches", "id", metadata_dict)
            self._parse_metadata_array_tag(xml_file, "requires", "req_patch_id", metadata_dict)
            self._parse_metadata_array_tag(xml_file, "packages", "deb", metadata_dict)
            self._parse_metadata_array_tag(xml_file, "activation_scripts", "script", metadata_dict)

            self._bulk_parse_metadata_tags(xml_file, xml_tags, metadata_dict)

            self._parse_ostree_contents(xml_file, contents_dict)

        return release_id

    def _read_all_metafile(self, path):
        """
        Load metadata from all xml files in the specified path and
        its subdirectory.
        :param path: path of directory that xml files is in
        """
        for filename in glob.glob("%s/*.xml" % path):
            with open(filename, "r") as f:
                text = f.read()
            yield filename, text

    def load_all(self):
        """
        Load all metadata files under the software metadata storage directory
        """
        # Reset the data
        self._reset()

        # This function firstly parses the Product metadata and secondly Metapackage
        # and Legacy metadatas.
        # metadata_state_map = [(path, state)]
        metadata_state_map = [
            (constants.COMPONENT_SOFTWARE_METADATA_STORAGE_DIR, None)
        ]

        for state, paths in self.state_map.items():
            for path in paths:
                metadata_state_map.append((path, state))

        for path, state in metadata_state_map:
            # Parse product metadata.xml
            for filename, text in self._read_all_metafile(path):
                try:
                    self.parse_metadata_string(text, state=state)
                except Exception as e:
                    err_msg = f"Failed parsing {filename}, {e}"
                    LOG.exception(err_msg)

    def query_line(self,
                   release_id,
                   index):
        if index is None:
            return None

        if index == "contents":
            return self.contents[release_id]

        if index not in self.metadata[release_id]:
            return None

        value = self.metadata[release_id][index]
        return value


class PatchMetadata(object):
    """
    Creating metadata for a single patch
    """

    def __init__(self):
        self.id = None
        self.sw_version = None
        self.summary = None
        self.description = None
        self.install_instructions = None
        self.warnings = None
        self.status = None
        self.unremovable = None
        self.reboot_required = None
        self.apply_active_release_only = None
        self.requires = []
        self.contents = {}

    def add_rpm(self,
                fname):
        """
        Add an RPM to the patch
        :param fname: RPM filename
        :return:
        """
        rpmname = os.path.basename(fname)
        self.contents[rpmname] = True

    def gen_xml(self,
                fname="metadata.xml"):
        """
        Generate patch metadata XML file
        :param fname: Path to output file
        :return:
        """
        top = ElementTree.Element('patch')

        add_text_tag_to_xml(top, 'id',
                            self.id)
        add_text_tag_to_xml(top, 'sw_version',
                            self.sw_version)
        add_text_tag_to_xml(top, 'summary',
                            self.summary)
        add_text_tag_to_xml(top, 'description',
                            self.description)
        add_text_tag_to_xml(top, 'install_instructions',
                            self.install_instructions)
        add_text_tag_to_xml(top, 'warnings',
                            self.warnings)
        add_text_tag_to_xml(top, 'status',
                            self.status)
        add_text_tag_to_xml(top, 'unremovable',
                            self.unremovable)
        add_text_tag_to_xml(top, 'reboot_required',
                            self.reboot_required)
        add_text_tag_to_xml(top, 'apply_active_release_only',
                            self.apply_active_release_only)

        content = ElementTree.SubElement(top, 'contents')
        for rpmname in sorted(list(self.contents)):
            add_text_tag_to_xml(content, 'rpm', rpmname)

        req = ElementTree.SubElement(top, 'requires')
        for req_patch in sorted(self.requires):
            add_text_tag_to_xml(req, 'req_patch_id', req_patch)

        write_xml_file(top, fname)


class PatchFile(object):
    """
    Patch file
    """

    def __init__(self):
        self.meta = PatchMetadata()
        self.rpmlist = {}

    def add_rpm(self,
                fname):
        """
        Add an RPM to the patch
        :param fname: Path to RPM
        :param personality: Optional: Node type to which
                            the package belongs. Can be a
                            string or a list of strings.
        :return:
        """
        # Add the RPM to the metadata
        self.meta.add_rpm(fname)

        # Add the RPM to the patch
        self.rpmlist[os.path.abspath(fname)] = True

    def gen_patch(self, outdir):
        """
        Generate the patch file, named PATCHID.patch
        :param outdir: Output directory for the patch
        :return:
        """
        if not self.rpmlist:
            raise MetadataFail("Cannot generate empty patch")

        patchfile = "%s/%s.patch" % (outdir, self.meta.id)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="software_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        # Copy RPM files to tmpdir
        for rpmfile in list(self.rpmlist):
            shutil.copy(rpmfile, tmpdir)

        # add file signatures to RPMs
        try:
            subprocess.check_call(["sign-rpms", "-d", tmpdir])
        except subprocess.CalledProcessError as e:
            print("Failed to to add file signatures to RPMs. Call to sign-rpms process returned non-zero exit status %i" % e.returncode)
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)
            raise SystemExit(e.returncode)

        # generate tar file
        tar = tarfile.open("software.tar", "w")
        for rpmfile in list(self.rpmlist):
            tar.add(os.path.basename(rpmfile))
        tar.close()

        # Generate the metadata xml file
        self.meta.gen_xml("metadata.xml")

        # assemble the patch
        PatchFile.write_patch(patchfile)

        # Change back to original working dir
        os.chdir(orig_wd)

        shutil.rmtree(tmpdir)

        print("Patch is %s" % patchfile)

    @staticmethod
    def write_patch(patchfile, cert_type=None):
        # Write the patch file. Assumes we are in a directory containing
        # metadata.tar and software.tar.

        # Generate the metadata tarfile
        tar = tarfile.open("metadata.tar", "w")
        tar.add("metadata.xml")
        tar.close()

        filelist = ["metadata.tar", "software.tar"]
        if os.path.exists("semantics.tar"):
            filelist.append("semantics.tar")

        # Generate the signature file
        sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for f in filelist:
            sig ^= get_md5(f)

        sigfile = open("signature", "w")
        sigfile.write("%x" % sig)
        sigfile.close()

        # Generate the detached signature
        #
        # Note: if cert_type requests a formal signature, but the signing key
        #    is not found, we'll instead sign with the 'dev' key and
        #    need_resign_with_formal is set to True.
        need_resign_with_formal = sign_files(
            filelist,
            detached_signature_file,
            cert_type=cert_type)

        # Create the patch
        tar = tarfile.open(patchfile, "w:gz")
        for f in filelist:
            tar.add(f)
        tar.add("signature")
        tar.add(detached_signature_file)
        tar.close()

        if need_resign_with_formal:
            try:
                # Try to ensure "sign_patch_formal.sh" will be in our PATH
                if 'MY_REPO' in os.environ:
                    os.environ['PATH'] += os.pathsep + os.environ['MY_REPO'] + "/build-tools"
                if 'MY_PATCH_REPO' in os.environ:
                    os.environ['PATH'] += os.pathsep + os.environ['MY_PATCH_REPO'] + "/build-tools"

                # Note: This can fail if the user is not authorized to sign with the formal key.
                subprocess.check_call(["sign_patch_formal.sh", patchfile])
            except subprocess.CalledProcessError as e:
                print("Failed to sign official patch. Call to sign_patch_formal.sh process returned non-zero exit status %i" % e.returncode)
                raise SystemExit(e.returncode)

    @staticmethod
    def read_patch(path, dest, cert_type=None):
        # We want to enable signature checking by default
        # Note: cert_type=None is required if we are to enforce 'no dev patches on a formal load' rule.

        # Open the patch file and extract the contents to the current dir
        tar = tarfile.open(path, "r:gz")

        tar.extract("signature", path=dest)
        try:
            tar.extract(detached_signature_file, path=dest)
        except KeyError:
            msg = "Patch has not been signed"
            LOG.warning(msg)

        # Filelist used for signature validation and verification
        filelist = ["metadata.tar", "software.tar"]

        # Check if conditional files are inside the patch
        # If yes then add them to signature checklist
        tar_names = {f.name for f in tar.getmembers()}
        scripts = [
            "semantics.tar",
            "extra.tar",
            "pre-start.sh",
            "post-start.sh",
            "pre-install.sh",
            "post-install.sh"]
        for script in scripts:
            if script in tar_names:
                filelist.append(script)

        for f in filelist:
            tar.extract(f, path=dest)

        # Verify the data integrity signature first
        sigfile = open(os.path.join(dest, "signature"), "r")
        sig = int(sigfile.read(), 16)
        sigfile.close()

        expected_sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        sig_filelist = [os.path.join(dest, f) for f in filelist]
        for f in sig_filelist:
            sig ^= get_md5(f)

        if sig != expected_sig:
            msg = "Software failed signature verification."
            LOG.error(msg)
            raise ReleaseValidationFailure(error=msg)

        # Verify detached signature
        sig_file = os.path.join(dest, detached_signature_file)
        if os.path.exists(sig_file):
            sig_valid = verify_files(
                sig_filelist,
                sig_file,
                cert_type=cert_type)
            if sig_valid is True:
                msg = "Signature verified, patch has been signed"
                if cert_type is None:
                    LOG.info(msg)
            else:
                msg = "Signature check failed"
                if cert_type is None:
                    LOG.error(msg)
                raise ReleaseValidationFailure(error=msg)
        else:
            msg = "Software has not been signed."
            if cert_type is None:
                LOG.error(msg)
            raise ReleaseValidationFailure(error=msg)

        # Restart script
        for f in tar.getmembers():
            if f.name not in filelist:
                tar.extract(f, path=dest)

        metadata = os.path.join(dest, "metadata.tar")
        tar = tarfile.open(metadata)
        tar.extractall(path=dest)

    @staticmethod
    def query_patch(patch, field=None):

        abs_patch = os.path.abspath(patch)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        r = {}

        try:
            if field is None or field == "cert":
                # Need to determine the cert_type
                for cert_type_str in cert_type_all:
                    try:
                        PatchFile.read_patch(abs_patch, tmpdir, cert_type=[cert_type_str])
                    except ReleaseValidationFailure:
                        pass
                    else:
                        # Successfully opened the file for reading, and we have discovered the cert_type
                        r["cert"] = cert_type_str
                        break

            if "cert" not in r:
                # NOTE(bqian) below reads like a bug in certain cases. need to revisit.
                # If cert is unknown, then file is not yet open for reading.
                # Try to open it for reading now, using all available keys.
                # We can't omit cert_type, or pass None, because that will trigger the code
                # path used by installed product, in which dev keys are not accepted unless
                # a magic file exists.
                PatchFile.read_patch(abs_patch, tmpdir, cert_type=cert_type_all)

            thispatch = ReleaseData()
            filename = os.path.join(tmpdir, "metadata.xml")
            patch_id = thispatch.parse_metadata_file(filename)

            if field is None or field == "id":
                r["id"] = patch_id

            if field is None:
                for f in ["status", "sw_version", "unremovable", "summary",
                          "description", "install_instructions",
                          "warnings", "reboot_required", "apply_active_release_only"]:
                    r[f] = thispatch.query_line(patch_id, f)
            else:
                if field not in ['id', 'cert']:
                    r[field] = thispatch.query_line(patch_id, field)

        except ReleaseValidationFailure as e:
            msg = "Patch validation failed during extraction. %s" % str(e)
            LOG.exception(msg)
            raise e
        except tarfile.TarError as te:
            msg = "Extract software failed %s" % str(te)
            LOG.exception(msg)
            raise ReleaseValidationFailure(error=msg)
        finally:
            shutil.rmtree(tmpdir)

        return r

    @staticmethod
    def modify_patch(patch,
                     key,
                     value):
        rc = False
        abs_patch = os.path.abspath(patch)
        new_abs_patch = "%s.new" % abs_patch

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        try:
            cert_type = None
            meta_data = PatchFile.query_patch(abs_patch)
            if 'cert' in meta_data:
                cert_type = meta_data['cert']
            PatchFile.read_patch(abs_patch, tmpdir, cert_type=cert_type)
            path = os.path.join(tmpdir, "metadata.xml")
            ReleaseData.modify_metadata_text(path, key, value)
            PatchFile.write_patch(new_abs_patch, cert_type=cert_type)
            os.rename(new_abs_patch, abs_patch)
            rc = True

        except tarfile.TarError as te:
            msg = "Extract software failed %s" % str(te)
            LOG.exception(msg)
            raise ReleaseValidationFailure(error=msg)
        except Exception as e:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(e).__name__, e.args)
            LOG.exception(message)
        finally:
            shutil.rmtree(tmpdir)

        return rc

    @staticmethod
    def extract_patch(patch,
                      metadata_dir=states.AVAILABLE_DIR,
                      metadata_only=False,
                      existing_content=None,
                      base_pkgdata=None):
        """
        Extract the metadata and patch contents
        :param patch: Patch file
        :param metadata_dir: Directory to store the metadata XML file
        :return:
        """
        patch_id = None
        thispatch = None
        error_msg = None

        abs_patch = os.path.abspath(patch)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        try:
            # Open the patch file and extract the contents to the tmpdir
            PatchFile.read_patch(abs_patch, tmpdir)

            thispatch = ReleaseData()
            filename = os.path.join(tmpdir, "metadata.xml")
            with open(filename, "r") as f:
                text = f.read()

            patch_id = thispatch.parse_metadata_string(text)

            if patch_id is None:
                shutil.rmtree(tmpdir)
                msg = "Unable to extract patch ID"
                raise ReleaseValidationFailure(error=msg)

            patch_sw_release = thispatch.metadata[patch_id]["sw_version"]
            patch_sw_version = utils.get_major_release_version(patch_sw_release)

            if not metadata_only and base_pkgdata is not None:
                # Run version validation tests first
                if utils.compare_release_version(constants.LOWEST_MAJOR_RELEASE_FOR_PATCH_SUPPORT,
                                                 patch_sw_version):
                    msg = "Software patching is supported starting from release %s and later" % (
                        constants.LOWEST_MAJOR_RELEASE_FOR_PATCH_SUPPORT)
                    LOG.exception(msg)
                    raise ReleaseValidationFailure(error=msg)
                if not base_pkgdata.check_release(patch_sw_version):
                    msg = "Software version %s for release %s is not installed" % (
                        patch_sw_version, patch_id)
                    LOG.exception(msg)
                    raise ReleaseValidationFailure(error=msg)

            if metadata_only:
                # This is a re-import. Ensure the content lines up
                if existing_content is None \
                        or existing_content != thispatch.contents[patch_id]:
                    msg = f"Contents of {patch_id} do not match re-uploaded release"
                    LOG.error(msg)
                    raise ReleaseMismatchFailure(error=msg)

            metadata_dir = states.UNAVAILABLE_DIR if utils.compare_release_version(
                SW_VERSION, patch_sw_version) else states.AVAILABLE_DIR
            abs_metadata_dir = os.path.abspath(metadata_dir)

            abs_ostree_tar_dir = package_dir[patch_sw_version]
            if not os.path.exists(abs_ostree_tar_dir):
                os.makedirs(abs_ostree_tar_dir)

            shutil.move(os.path.join(tmpdir, "metadata.xml"),
                        "%s/%s-metadata.xml" % (abs_metadata_dir, patch_id))
            shutil.move(os.path.join(tmpdir, "software.tar"),
                        "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id))
            v = "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id)
            LOG.info("software.tar %s" % v)

            if not os.path.exists(root_scripts_dir):
                os.makedirs(root_scripts_dir)
            # start and install scripts
            for script in constants.PATCH_SCRIPTS:
                script_name = thispatch.metadata[patch_id].get(script)
                if script_name:
                    dest_path = os.path.join(root_scripts_dir, f"{patch_id}_{script_name}")
                    shutil.move(os.path.join(tmpdir, script_name), dest_path)
                    os.chmod(dest_path, os.stat(dest_path).st_mode | stat.S_IXUSR)

            activate_scripts = thispatch.metadata[patch_id].get(constants.ACTIVATION_SCRIPTS)
            if activate_scripts:
                for script in activate_scripts:
                    shutil.move(os.path.join(tmpdir, script),
                                "%s/%s_%s" % (root_scripts_dir, patch_id, script))

            # Copy extra folder if exists
            extra_origin = os.path.join(tmpdir, "extra.tar")
            if os.path.exists(extra_origin):
                patch_dir = "%s/rel-%s" % (constants.SOFTWARE_STORAGE_DIR, patch_sw_release)
                if not os.path.exists(patch_dir):
                    os.makedirs(patch_dir)
                shutil.move(extra_origin, patch_dir)
                LOG.info("extra.tar copied to %s" % patch_dir)

        except tarfile.TarError as te:
            error_msg = "Extract software failed %s" % str(te)
            LOG.exception(error_msg)
        except KeyError as ke:
            # NOTE(bqian) assuming this is metadata missing key.
            # this try except should be narror down to protect more specific
            # routine accessing external data (metadata) only.
            error_msg = "Software metadata missing required value for %s" % str(ke)
            LOG.exception(error_msg)
        except Exception as e:
            error_msg = "Error while extracting patch %s" % str(e)
            LOG.exception(error_msg)
        finally:
            shutil.rmtree(tmpdir)

        return patch_id, thispatch, error_msg

    @staticmethod
    def delete_extracted_patch(patch_id, thispatch):
        """
        Try to delete all files from failed upload.
        :param patch_id: ID of the patch to be deleted
        :param thispatch: Patch release data
        """

        try:
            abs_metadata_dir = os.path.abspath(states.AVAILABLE_DIR)
            os.remove("%s/%s-metadata.xml" % (abs_metadata_dir, patch_id))
        except Exception:
            msg = "Could not delete %s metadata, does not exist" % patch_id
            LOG.info(msg)

        try:
            patch_sw_version = utils.get_major_release_version(
                thispatch.metadata[patch_id]["sw_version"])
            abs_ostree_tar_dir = package_dir[patch_sw_version]
            os.remove("%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id))
        except Exception:
            msg = "Could not delete %s software.tar, does not exist" % patch_id
            LOG.info(msg)

        try:
            pre_install_script_name = thispatch.metadata[patch_id]["pre_install"]
            os.remove("%s/%s_%s" % (root_scripts_dir, patch_id, pre_install_script_name))
        except Exception:
            msg = "Could not delete %s pre-install script, does not exist" % patch_id
            LOG.info(msg)

        try:
            post_install_script_name = thispatch.metadata[patch_id]["post_install"]
            os.remove("%s/%s_%s" % (root_scripts_dir, patch_id, post_install_script_name))
        except Exception:
            msg = "Could not delete %s post-install script, does not exist" % patch_id
            LOG.info(msg)

    @staticmethod
    def unpack_patch(patch):
        """Extract patch and upload Debian package to the repository.
        :param patch: Patch file
        :param metadata_dir: Directory to store the metadata XML file
        """
        thispatch = None

        # Create a temporary working directory
        patch_tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Load the patch
        abs_patch = os.path.abspath(patch)
        PatchFile.read_patch(abs_patch, patch_tmpdir)
        thispatch = ReleaseData()

        filename = os.path.join(patch_tmpdir, "metadata.xml")
        with open(filename, "r") as f:
            text = f.read()

        patch_id = thispatch.parse_metadata_string(text)

        sw_release = thispatch.metadata[patch_id]["sw_version"]  # MM.mm.pp
        sw_version = utils.get_major_release_version(sw_release)  # MM.mm
        abs_ostree_tar_dir = package_dir[sw_version]
        ostree_tar_filename = "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id)
        package_repo_dir = "%s/rel-%s" % (constants.PACKAGE_FEED_DIR, sw_version)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="deployment_")

        try:
            # Extract the software.tar
            tar = tarfile.open(ostree_tar_filename)
            tar.extractall(path=tmpdir)

            # Upload the package to the apt repository
            deb_dir = os.scandir(tmpdir)
            package_list = []
            list_size = 25  # Number of files per group

            # Initialize apt-ostree if does not exist
            if not os.path.exists(package_repo_dir):
                apt_utils.initialize_apt_ostree(package_repo_dir)

            for deb in deb_dir:
                deb_path = os.path.join(tmpdir, deb.name)
                msg = "Adding package to upload list: %s" % deb_path
                LOG.info(msg)
                package_list.append(os.path.join(tmpdir, deb.name))
                if len(package_list) == list_size:
                    apt_utils.package_list_upload(package_repo_dir,
                                                  sw_release,
                                                  package_list)
                    package_list = []

            # send the rest of packages to be uploaded
            if package_list:
                apt_utils.package_list_upload(package_repo_dir,
                                              sw_release,
                                              package_list)

            # Extract extra.tar if it is present
            patch_dir = "%s/rel-%s" % (constants.SOFTWARE_STORAGE_DIR, sw_release)
            extra_tar = "%s/extra.tar" % patch_dir
            if os.path.exists(extra_tar) and tarfile.is_tarfile(extra_tar):
                tar = tarfile.open(extra_tar)
                tar.extractall(path=patch_dir)
                os.remove(extra_tar)

        except tarfile.TarError:
            msg = "Failed to extract tarball for %s" % sw_release
            LOG.exception(msg)
            raise OSTreeTarFail(msg)
        except OSError as e:
            msg = "Error: %s" % e
            LOG.exception(msg)
            raise OSTreeTarFail(msg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            shutil.rmtree(patch_tmpdir)

    @staticmethod
    def create_versioned_precheck(patch, sw_version, req_patch_version=None):
        """
        Extract the deploy-precheck script from the patch into
        a versioned directory under SOFTWARE_STORAGE_DIR and,
        if script is not available in the patch, then create a
        symlink to the versioned directory of the required patch.
        :param patch: path to patch file
        :param sw_version: patch version in MM.mm.pp format
        :param req_patch_version: required patch version in MM.mm.pp format
        """
        # open patch and create versioned scripts directory
        tar = tarfile.open(patch, "r:gz")
        versioned_dir = constants.VERSIONED_SCRIPTS_DIR % sw_version
        versioned_script = os.path.join(versioned_dir, constants.DEPLOY_PRECHECK_SCRIPT)
        if os.path.exists(versioned_dir):
            shutil.rmtree(versioned_dir)
        os.makedirs(versioned_dir)

        error_msg = "Versioned precheck script cannot be created, "
        try:
            # if patch contains precheck script, copy it to versioned directory
            if constants.DEPLOY_PRECHECK_SCRIPT in tar.getnames():
                tar.extract(constants.DEPLOY_PRECHECK_SCRIPT, path=versioned_dir)
                os.chmod(versioned_script, mode=0o755)
                LOG.info("Versioned precheck script copied to %s." % versioned_script)
                # precheck script requires upgrade utils module to work and it should
                # be included together with precheck script
                tar.extract(constants.UPGRADE_UTILS_SCRIPT, path=versioned_dir)
                LOG.info("Versioned upgrade_utils module copied to %s." % versioned_script)
            # in case patch does not contain a precheck script
            # then symlink to required patch versioned directory
            else:
                LOG.info("'%s' script is not included in the patch, will attempt to "
                         "symlink to the 'required patch' precheck script." %
                         constants.DEPLOY_PRECHECK_SCRIPT)
                if not req_patch_version:
                    error_msg += "'required patch' version could not be determined."
                    raise VersionedDeployPrecheckFailure

                req_versioned_dir = constants.VERSIONED_SCRIPTS_DIR % req_patch_version
                req_versioned_script = os.path.join(req_versioned_dir, constants.DEPLOY_PRECHECK_SCRIPT)
                # if required patch directory does not exist create the link anyway
                if not os.path.exists(req_versioned_dir):
                    LOG.warning("'required patch' versioned directory %s does not exist."
                                % req_versioned_dir)
                os.symlink(req_versioned_script, versioned_script)
                LOG.info("Versioned precheck script %s symlinked to %s." % (
                    versioned_script, req_versioned_script))
        except Exception as e:
            LOG.warning("%s: %s" % (error_msg, e))

    @staticmethod
    def delete_versioned_directory(sw_version):
        """
        Delete the versioned deploy-precheck script.
        :param sw_version: precheck script version to be deleted
        """
        try:
            opt_release_folder = "%s/rel-%s" % (constants.SOFTWARE_STORAGE_DIR,
                                                sw_version)
            if os.path.isdir(opt_release_folder):
                shutil.rmtree(opt_release_folder, ignore_errors=True)
            LOG.info("Versioned directory %s deleted." % opt_release_folder)
        except Exception as e:
            LOG.exception("Failed to delete versioned precheck: %s", e)


def ensure_state_dirs(*dirs):
    """Decorator that creates the specified directories before calling the function."""
    def decorator(func):
        @functools.wraps(func)  # Preserve the original function's metadata
        def wrapper(*args, **kwargs):
            # Create each directory (including parents) if it doesn't exist
            for d in dirs:
                Path(d).mkdir(parents=True, exist_ok=True)
            return func(*args, **kwargs)
        return wrapper
    return decorator


class ComponentPatchFile:
    # common patch file values
    METADATA_TAR = "metadata.tar"
    METADATA_XML = "metadata.xml"
    SOFTWARE_TAR = "software.tar"
    EXTRA_TAR = "extra.tar"
    PACKAGE_LIST_SIZE = 25

    # signature values
    EXPECTED_SIG = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    SIGNED_FILES = [METADATA_TAR, SOFTWARE_TAR, EXTRA_TAR]
    SIGNATURE_FILE = "signature"
    DETACHED_SIGNATURE_FILE = "signature.v2"

    def __init__(self, patch_file: str):
        self._patch_file = patch_file

    @ensure_state_dirs(*states.COMPONENT_RELEASE_STATE_TO_DIR_MAP.values())
    def extract_patch(self, **kwargs):
        """
        Extract the patch contents into the local filesystem:
        - Verify the signature of the patch
        - Parse the product release metadata and copy to filesystem
        - Extract metapackage deb packages and copy contents and metadata to filesystem
        """
        product_id = None
        release_data = ReleaseData()
        error_msg = ""
        base_pkgdata = kwargs.get("base_pkgdata")

        try:
            # extract patch content
            with (extract_tar(self._patch_file, prefix="patch-") as patch_dir):
                LOG.info(f"Extracted {self._patch_file}")

                # verify patch signature
                ComponentPatchFile.verify_signature(patch_dir)

                # extract product release metadata
                metadata_tar = Path(patch_dir) / self.METADATA_TAR
                with extract_tar(metadata_tar, prefix="metadata-") as metadata_dir:
                    LOG.info(f"Extracted {metadata_tar}")
                    metadata_file = Path(metadata_dir) / self.METADATA_XML
                    # parse the product release metadata
                    with open(metadata_file, "r") as fd:
                        text = fd.read()
                        product_id = release_data.parse_metadata_string(text)
                    _, release_version, sw_version, _ = utils.get_component_and_versions(product_id)
                    # check if feed exists
                    if not base_pkgdata.check_release(sw_version):
                        msg = f"Software feed {sw_version} for release {product_id} doesn't exist"
                        LOG.error(msg)
                        raise ReleaseValidationFailure(msg)
                    # copy product release metadata to software directory
                    product_md = f"{product_id}-{self.METADATA_XML}"
                    shutil.copy(metadata_file, Path(constants.COMPONENT_SOFTWARE_METADATA_STORAGE_DIR) / product_md)
                    LOG.info(f"Copied {product_md} to {constants.COMPONENT_SOFTWARE_METADATA_STORAGE_DIR}")

                # extract deb packages
                software_tar = Path(patch_dir) / self.SOFTWARE_TAR
                with extract_tar(software_tar, prefix="software-") as software_dir:
                    # fetch all deb packages and metapackages
                    deb_pkgs = list(Path(software_dir).glob("*.deb"))
                    deb_metapkgs = [d for d in deb_pkgs if d.name.startswith("meta-")]
                    # copy metapackages contents
                    for deb in deb_metapkgs:
                        # confirm the deb package corresponds to a metapackage
                        if not is_metapackage_deb(deb):
                            LOG.warning(f"{deb} is not a metapackage, skipping file...")
                            continue
                        mp = deb.name[5:].split("_")[0]
                        with extract_deb(deb) as deb_dir:
                            LOG.info(f"Extracted metapackage {deb.name}")
                            metapkg_dir = Path(constants.COMPONENT_SOFTWARE_STORAGE_DIR) / release_version / mp
                            metapkg_dir.mkdir(parents=True, exist_ok=True)
                            mp_content = list(Path(deb_dir).rglob(f"*/metapackages/{release_version}/{mp}*"))
                            # copy full metapackage directory
                            shutil.copytree(mp_content[0], metapkg_dir, dirs_exist_ok=True)
                            LOG.info(f"Created metapackage directory: {metapkg_dir}")
                            # copy metapackage metadata to correct location
                            metapkg_md_name = f"{mp}_{release_version}-{self.METADATA_XML}"
                            metapkg_md_src = Path(metapkg_dir) / self.METADATA_XML
                            metapkg_md_dst = Path(states.COMPONENT_AVAILABLE_DIR) / metapkg_md_name
                            shutil.move(metapkg_md_src, metapkg_md_dst)
                            LOG.info(f"Copied metapackage metadata: {metapkg_md_name}")
                    # create apt-ostree repo and load deb packages in it
                    package_repo_dir = Path(constants.PACKAGE_FEED_DIR) / f"rel-{sw_version}"
                    if not package_repo_dir.exists():
                        apt_utils.initialize_apt_ostree(package_repo_dir)
                    package_list = []
                    for deb in deb_pkgs:
                        msg = f"Adding deb package to the upload list: {deb.name}"
                        LOG.info(msg)
                        package_list.append(str(deb))
                        if len(package_list) == self.PACKAGE_LIST_SIZE:
                            apt_utils.package_list_upload(package_repo_dir, release_version,
                                                          package_list)
                            package_list.clear()
                    if package_list:
                        apt_utils.package_list_upload(package_repo_dir, release_version,
                                                      package_list)
        except Exception as e:
            error_detail = e.error if hasattr(e, 'error') else str(e)
            msg = f"Error extracting patch: {error_detail}"
            LOG.error(msg)
            error_msg += msg
            # if product_id was assigned, delete already extracted files
            if product_id:
                LOG.info("Deleting extracted resources...")
                ComponentPatchFile.delete_patch_product_release(product_id)

        return product_id, release_data, error_msg

    @staticmethod
    def delete_patch_product_release(product_id):
        """
        Delete contents related to a patch product release:
        - All metadata (product and metapackage releases)
        - Versioned release directory
        - .deb package repository
        """
        _, release_version, sw_version, _ = utils.get_component_and_versions(product_id)

        # delete the metadata
        metadata_path = Path(constants.COMPONENT_SOFTWARE_METADATA_STORAGE_DIR)
        for metadata in metadata_path.rglob(f"*{release_version}*.xml"):
            metadata.unlink()
            LOG.info(f"Removed metadata: {metadata.name}")

        # delete the release directory
        release_path = Path(constants.COMPONENT_SOFTWARE_STORAGE_DIR) / release_version
        shutil.rmtree(release_path, ignore_errors=True)
        LOG.info(f"Removed release directory: {release_path}")

        # delete the apt-repo (if patch product release)
        package_repo_dir = Path(constants.PACKAGE_FEED_DIR) / f"rel-{sw_version}"
        apt_utils.component_remove(package_repo_dir, release_version)
        LOG.info(f"Removed package repository: {package_repo_dir}")

    @staticmethod
    def verify_signature(patch_dir, cert_type=None):
        """
        Verify the signature based on the patch content, by checking which files
        are contained in the patch and using them to verify the provided signature.

        NOTE:
        - Signature checking is enabled, by default
        - cert_type=None is required to enforce no dev-patches installed in a formal load
        """
        # the file list doesn't matter when verifying SIGNATURE_FILE, but it matters
        # when verifying the DETACHED_SIGNATURE_FILE and will fail if the order is
        # not the same used as when the patch was signed
        file_list = []
        patch_files = [f.name for f in Path(patch_dir).iterdir() if f.is_file()]
        for file in ComponentPatchFile.SIGNED_FILES:
            if file in patch_files:
                file_list.append(Path(patch_dir) / file)

        # Verify the data integrity signature
        with open(Path(patch_dir) / ComponentPatchFile.SIGNATURE_FILE, "r") as fd:
            sig = int(fd.read(), 16)
        for file in file_list:
            sig ^= get_md5(file)
        if sig != ComponentPatchFile.EXPECTED_SIG:
            msg = "Patch signature verify failed"
            LOG.error(msg)
            raise ReleaseValidationFailure(error=msg)

        # Verify detached signature
        sig_file = Path(patch_dir) / ComponentPatchFile.DETACHED_SIGNATURE_FILE
        if os.path.exists(sig_file):
            sig_valid = verify_files(
                file_list,
                sig_file,
                cert_type=cert_type)
            if sig_valid is True:
                msg = "Patch has been signed and signature verified"
                if cert_type is None:
                    LOG.info(msg)
            else:
                msg = "Signature verify failed"
                if cert_type is None:
                    LOG.error(msg)
                raise ReleaseValidationFailure(error=msg)
        else:
            msg = "Patch has not been signed"
            if cert_type is None:
                LOG.error(msg)
            raise ReleaseValidationFailure(error=msg)


@contextlib.contextmanager
def extract_tar(tar_path, prefix="software-"):
    """Extract a tar file to a temporary directory, yielding the path."""
    with tempfile.TemporaryDirectory(prefix=prefix) as tmpdir:
        try:
            with tarfile.open(tar_path) as tar:
                tar.extractall(tmpdir)
        except (tarfile.TarError, OSError) as e:
            raise RuntimeError(f"Failed to extract {tar_path}: {e}") from e
        yield tmpdir


@contextlib.contextmanager
def extract_deb(deb_path, prefix="deb-"):
    """Extract a .deb package to a temporary directory, yielding the path."""
    with tempfile.TemporaryDirectory(prefix=prefix) as tmpdir:
        try:
            subprocess.run(
                ["dpkg-deb", "--extract", deb_path, tmpdir],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            raise ValueError(f"Failed to extract deb: {deb_path}: {e.stderr}") from e
        yield tmpdir


def is_metapackage_deb(deb_path):
    """Query the deb package metadata 'Section' field and check if its value is 'metapackages'"""
    output = subprocess.run(["dpkg-deb", "-f", deb_path], check=True,
                            capture_output=True, text=True).stdout
    for line in output.splitlines():
        if "Section:" in line:
            return line.lower().strip().split(" ")[1] == "metapackages"
    return False


def patch_build():
    configure_logging(logtofile=False)

    try:
        opts, remainder = getopt.getopt(sys.argv[1:],
                                        '',
                                        ['id=',
                                         'release=',
                                         'summary=',
                                         'status=',
                                         'unremovable',
                                         'reboot-required=',
                                         'desc=',
                                         'warn=',
                                         'inst=',
                                         'req=',
                                         'controller=',
                                         'controller-worker=',
                                         'controller-worker-lowlatency=',
                                         'worker=',
                                         'worker-lowlatency=',
                                         'storage=',
                                         'all-nodes=',
                                         'pre-apply=',
                                         'pre-remove=',
                                         'apply-active-release-only'])
    except getopt.GetoptError:
        print("Usage: %s [ <args> ] ... <rpm list>"
              % os.path.basename(sys.argv[0]))
        print("Options:")
        print("\t--id <id>               Patch ID")
        print("\t--release <version>     Platform release version")
        print("\t--status <status>       Patch Status Code (ie. O, R, V)")
        print("\t--unremovable           Marks patch as unremovable")
        print("\t--reboot-required <Y|N> Marks patch as reboot-required (default=Y)")
        print("\t--summary <summary>     Patch Summary")
        print("\t--desc <description>    Patch Description")
        print("\t--warn <warnings>       Patch Warnings")
        print("\t--inst <instructions>   Patch Install Instructions")
        print("\t--req <patch_id>        Required Patch")
        print("\t--controller <rpm>      New package for controller")
        print("\t--worker <rpm>         New package for worker node")
        print("\t--worker-lowlatency <rpm>   New package for worker-lowlatency node")
        print("\t--storage <rpm>         New package for storage node")
        print("\t--controller-worker <rpm>   New package for combined node")
        print("\t--controller-worker-lowlatency <rpm>   New package for lowlatency combined node")
        print("\t--all-nodes <rpm>       New package for all node types")
        print("\t--pre-apply <script>    Add pre-apply semantic check")
        print("\t--pre-remove <script>   Add pre-remove semantic check")
        print("\t--apply-active-release-only   Patch can only be applied if corresponding")
        print("\t                              release is active")

        exit(1)

    pf = PatchFile()

    # Default the release
    pf.meta.sw_version = os.environ['PLATFORM_RELEASE']

    for opt, arg in opts:
        if opt == "--id":
            pf.meta.id = arg
        elif opt == "--release":
            pf.meta.sw_version = arg
        elif opt == "--summary":
            pf.meta.summary = arg
        elif opt == "--status":
            pf.meta.status = arg
        elif opt == "--unremovable":
            pf.meta.unremovable = "Y"
        elif opt == "--reboot-required":
            if arg != "Y" and arg != "N":
                print("The --reboot-required option requires either Y or N as argument.")
                exit(1)
            pf.meta.reboot_required = arg
        elif opt == "--desc":
            pf.meta.description = arg
        elif opt == "--warn":
            pf.meta.warnings = arg
        elif opt == "--inst":
            pf.meta.install_instructions = arg
        elif opt == "--req":
            pf.meta.requires.append(arg)
        elif opt == "--apply-active-release-only":
            pf.meta.apply_active_release_only = "Y"

    if pf.meta.id is None:
        print("The --id argument is mandatory.")
        exit(1)

    for rpmfile in remainder:
        pf.add_rpm(rpmfile)

    pf.gen_patch(outdir=os.getcwd())


def mount_iso_load(iso_path, temp_dir):
    """
    Mount load and return metadata file
    """
    mount_dir = tempfile.mkdtemp(dir=temp_dir)
    with open(os.devnull, "w") as devnull:
        try:
            subprocess.check_call(["mount", "-o", "loop", iso_path, mount_dir],
                                  stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError:
            raise ReleaseUploadFailure("Mount failure for "
                                       "iso %s" % iso_path)
    return mount_dir


def unmount_iso_load(iso_path):
    """
    Unmount iso load
    """
    with open(os.devnull, "w") as devnull:
        try:
            subprocess.check_call(["umount", "-l", iso_path],
                                  stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError:
            pass


def get_metadata_files(root_dir):
    files = []
    for filename in os.listdir(root_dir):
        fn, ext = os.path.splitext(filename)
        if ext == '.xml' and fn.endswith('-metadata'):
            fullname = os.path.join(root_dir, filename)
            files.append(fullname)
    return files


def get_sw_version(metadata_files):
    # from a list of metadata files, find the latest sw_version (e.g 24.0.1)
    unset_ver = constants.UNKNOWN_SOFTWARE_VERSION
    rel_ver = unset_ver
    for f in metadata_files:
        try:
            root = ElementTree.parse(f).getroot()
        except Exception:
            msg = f"Cannot parse {f}"
            LOG.exception(msg)
            continue

        sw_ver = root.findtext("sw_version")
        if sw_ver and version.parse(sw_ver) > version.parse(rel_ver):
            rel_ver = sw_ver

    if rel_ver == unset_ver:
        err_msg = "sw_version value not found or invalid in the metadata file"
        raise SoftwareServiceError(err_msg)

    return rel_ver


def read_attributes_from_metadata_file(mounted_dir):
    """
    Get attributes from upgrade metadata xml file
    :param mounted_dir: Mounted iso directory
    :return: a dict of attributes
    """
    metadata_file = os.path.join(mounted_dir, "upgrades", "metadata.xml")
    try:
        root = ElementTree.parse(metadata_file)
    except IOError:
        raise SoftwareServiceError(
            f"The ISO does not contain required upgrade information in {metadata_file}")

    to_release = root.findtext("version")

    supported_from_releases = []
    supported_upgrades = root.find("supported_upgrades").findall("upgrade")
    for upgrade in supported_upgrades:
        supported_from_releases.append({
            "version": upgrade.findtext("version"),
            "required_patch": upgrade.findtext("required_patch"),
        })

    return {
        "to_release": to_release,
        "supported_from_releases": supported_from_releases
    }


def read_upgrade_support_versions(mounted_dir):
    """
    Get supported upgrades
    versions
    :param mounted_dir: Mounted iso directory
    :param do_check_to_release: True if to_release should be retrieved
    :return: supported_from_releases
    """
    attributes_from_metadata = read_attributes_from_metadata_file(mounted_dir)
    return attributes_from_metadata["supported_from_releases"]


def get_to_release_from_metadata_file(mounted_dir):
    """
    Get to_release version
    :param mounted_dir: Mounted iso directory
    :return: to_release
    """

    rel_metadata_files = get_metadata_files(os.path.join(mounted_dir, "upgrades"))

    if len(rel_metadata_files) == 0:  # This is pre-USM iso
        attributes_from_metadata = read_attributes_from_metadata_file(mounted_dir)
        to_release = attributes_from_metadata["to_release"]
    else:
        to_release = get_sw_version(rel_metadata_files)

    return to_release


def create_deploy_hosts(hostname=None):
    """
    Create deploy-hosts entities based on hostnames
    from sysinv.
    """
    db_api_instance = get_instance()
    db_api_instance.begin_update()
    try:
        # If hostname is passed (Eg. in case of install local) use that.
        if hostname:
            db_api_instance.create_deploy_host(hostname)
        else:
            for ihost in get_ihost_list():
                db_api_instance.create_deploy_host(ihost.hostname)
        LOG.info("Deploy-hosts entities created successfully.")
    except Exception as err:
        LOG.exception("Error in deploy-hosts entities creation")
        raise err
    finally:
        db_api_instance.end_update()


def collect_current_load_for_hosts(local_load, hostname=None):
    load_data = {
        "current_loads": []
    }
    try:
        # If hostname is passed (Eg. in case of install local) use that.
        if hostname:
            load_data["current_loads"].append({
                "hostname": hostname,
                "running_release": local_load
            })
        else:
            for ihost in get_ihost_list():
                software_load = ihost.software_load
                hostname = ihost.hostname
                load_data["current_loads"].append({
                    "hostname": hostname,
                    "running_release": software_load
                })
        dbapi = get_instance()
        dbapi.create_current_loads(load_data)
        LOG.info("Collect current load for hosts successfully.")
    except Exception as err:
        LOG.error("Error in collect current load for hosts: %s", err)


def parse_release_metadata(filename):
    """
    Parse release metadata from xml file
    :param filename: XML file
    :return: dict of release metadata
    """
    tree = ElementTree.parse(filename)
    root = tree.getroot()
    data = {}
    for child in root:
        # get requires under <req_patch_id> key
        if child.tag == "requires":
            requires = []
            for item in child:
                requires.append(item.text)
            data[child.tag] = requires
            continue
        data[child.tag] = child.text
    return data


def is_deploy_state_in_sync():
    """
    Check if deploy state in sync
    :return: bool true if in sync, false otherwise
    """
    is_in_sync = False

    does_synced_software_exist = os.path.isfile(constants.SYNCED_SOFTWARE_JSON_FILE)
    does_software_exist = os.path.isfile(constants.SOFTWARE_JSON_FILE)

    if does_synced_software_exist and does_software_exist:
        # both files exist, compare them
        dbapi = get_instance()

        deploy_state = dbapi.get_deploy_all()
        synced_deploy_state = dbapi.get_deploy_all_synced()
        deploy_host_state = dbapi.get_deploy_host()
        synced_deploy_host_state = dbapi.get_deploy_host_synced()

        is_in_sync = (deploy_state == synced_deploy_state and
                      deploy_host_state == synced_deploy_host_state)
    elif not does_synced_software_exist and not does_software_exist:
        # neither file exists, it is not in deploying state
        is_in_sync = True
    else:
        # either file does not exist, it is in deploying state
        is_in_sync = False

    return is_in_sync


def is_deployment_in_progress():
    """
    Check if at least one deployment is in progress
    :return: bool true if in progress, false otherwise
    """
    dbapi = get_instance()
    deploys = dbapi.get_deploy_all()
    return len(deploys) > 0


def is_system_deploy_in_progress():
    """
    Check if a system deploy is in progress
    :return: bool true if in progress, false otherwise
    """
    dbapi = get_instance()
    system_deploy = dbapi.get_system_deploy()
    return len(system_deploy) > 0


def deploy_host_validations(hostname, is_major_release: bool, rollback: bool = False):
    """
    Check the conditions below:
    If system mode is duplex, check if provided hostname satisfy the right deployment order.
    Host is locked and online.

    If one of the validations fail, raise SoftwareServiceError exception, except if system
    is a simplex.

    :param hostname: Hostname of the host to be deployed
    :param is_major_release: Bool field indicating if is major release
    :param rollback: Indicates if validating for a rollback operation
    """
    _, system_mode = get_system_info()
    simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)
    db_api_instance = get_instance()
    deploy = db_api_instance.get_current_deploy()
    if simplex:
        LOG.info("System mode is simplex. Skipping deploy order validation...")
    else:
        validate_host_deploy_order(hostname, is_major_release=is_major_release, rollback=rollback)
    # If the deployment is not RR the host does not need to be locked and online
    if deploy.get(constants.REBOOT_REQUIRED):
        if not is_host_locked_and_online(hostname):
            msg = f"Host {hostname} must be {constants.ADMIN_LOCKED}."
            raise SoftwareServiceError(error=msg)


def validate_host_deploy_order(hostname, is_major_release: bool, rollback: bool = False):
    """
    Check if the host to be deployed satisfy the major release deployment right
    order of controller-1 -> controller-0 -> storages -> computes
    and for patch release: controllers -> storages -> computes

    Case rollback param is True the controllers order will be reversed
    Case one of the validations failed raise SoftwareError exception

    :param hostname: Hostname of the host to be deployed.
    :param is_major_release: Bool field indicating if is major release
    :param rollback: Bool field indicating if is related to a rollback action
    """
    db_api_instance = get_instance()
    controllers_list = [constants.CONTROLLER_1_HOSTNAME, constants.CONTROLLER_0_HOSTNAME]
    storage_list = []
    workers_list = []
    for host in get_ihost_list():
        if host.personality == constants.STORAGE:
            storage_list.append(host.hostname)
        if host.personality == constants.WORKER:
            workers_list.append(host.hostname)

    ordered_storage_list = sorted(storage_list, key=lambda x: int(x.split("-")[1]))
    ordered_list = controllers_list + ordered_storage_list + workers_list

    # in a rollback scenario the deploy order should be inverted
    if rollback:
        ordered_list.reverse()

    for host in db_api_instance.get_deploy_host():
        if host.get("state") in [states.DEPLOY_HOST_STATES.DEPLOYED.value,
                                 states.DEPLOY_HOST_STATES.ROLLBACK_DEPLOYED.value]:
            ordered_list.remove(host.get("hostname"))
    if not ordered_list:
        raise SoftwareServiceError(error="All hosts are already in deployed state.")
    # If there is only workers nodes there is no order to deploy
    if hostname == ordered_list[0] or (ordered_list[0] in workers_list and hostname in workers_list):
        return
    # If deployment is a patch release bypass the controllers order
    elif not is_major_release and ordered_list[0] in controllers_list and hostname in controllers_list:
        return
    else:
        errmsg = f"{hostname} does not satisfy the right order of deployment " + \
                 f"should be {ordered_list[0]}"
        raise SoftwareServiceError(error=errmsg)


@contextlib.contextmanager
def mount_remote_directory(remote_dir, local_dir):
    # validate paths
    remote_path = re.match(r"^[a-zA-Z0-9-]+:[a-zA-Z0-9.-_\/]+$", remote_dir)
    if not remote_path:
        raise OSError("Invalid remote path. Should follow format <hostname>:<path>")
    if not os.path.isdir(local_dir):
        os.mkdir(local_dir, 0o755)
    try:
        subprocess.check_call(["/bin/nfs-mount", remote_dir, local_dir])
    except subprocess.CalledProcessError as e:
        LOG.error("Error mounting remote %s into local %s: %s" % (remote_dir, local_dir, str(e)))
        raise

    try:
        yield
    finally:
        try:
            subprocess.check_call(["/bin/umount", local_dir])
        except subprocess.CalledProcessError as e:
            LOG.error("Error unmounting %s: %s" % (local_dir, str(e)))


def remove_major_release_deployment_flags():
    """
    Cleanup local major release deployment flags
    """
    upgrade_flags = [
        constants.USM_UPGRADE_IN_PROGRESS_FLAG,
        constants.UPGRADE_DO_NOT_USE_FQDN_FLAG,
    ]
    success = True
    for flag in upgrade_flags:
        try:
            os.remove(flag)
            LOG.info("Flag %s removed." % flag)
        except FileNotFoundError:
            LOG.warning("Flag %s not found. Skipping..." % flag)
        except Exception as e:
            success = False
            LOG.exception("Failed to remove flag %s: %s" % (flag, str(e)))
    return success


def run_remove_temporary_data_script(release):
    """
    Runs the remove-temporary-data script for the given release.

    :param release: Release to be cleaned.
    """
    cmd_path = utils.get_software_deploy_script(release, constants.REMOVE_TEMPORARY_DATA_SCRIPT)
    if os.path.exists(constants.ROOT_DIR):
        try:
            subprocess.check_output([cmd_path, constants.ROOT_DIR], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.exception("Error running remove-temporary-data script: %s" % str(e))
            raise


def copy_pxeboot_update_file(to_major_release, rollback=False):
    """
    Copies pxeboot-update-<to-release>.sh to /etc/ if needed
    :param to_major_release: MM.mm (e.g. 24.09)
    :param rollback: indicates if running in a rollback scenario
    """
    filename = "pxeboot-update-%s.sh" % to_major_release
    dst_file = "/etc/%s" % filename
    if not os.path.isfile(dst_file):
        # on rollback, copy the script from the rollback ostree commit
        if rollback:
            src_file = "/ostree/2/usr/etc/%s" % filename
        else:
            src_file = constants.FEED_DIR + "/rel-%s/upgrades/%s" % (to_major_release, filename)
        try:
            shutil.copy(src_file, dst_file)
            os.chmod(dst_file, mode=0o755)
            LOG.info("Copied %s to %s" % (src_file, dst_file))
        except Exception as e:
            LOG.exception("Error copying %s file: %s" % (filename, str(e)))
            raise


def copy_pxeboot_cfg_files(to_major_release):
    """
    Copies pxeboot.cfg.files from feed to /var/pxeboot/pxelinux.cfg.files if needed
    :param to_major_release: MM.mm (e.g. 24.09)
    """
    src_dir = constants.FEED_DIR + "/rel-%s/pxeboot/pxelinux.cfg.files/" % to_major_release
    dst_dir = "/var/pxeboot/pxelinux.cfg.files"
    try:
        if os.path.exists(src_dir):
            shutil.copytree(src_dir, dst_dir, dirs_exist_ok=True)
            LOG.info("Copied %s to %s" % (src_dir, dst_dir))
    except Exception:
        LOG.exception("Error copying files from %s to: %s" % (src_dir, dst_dir))
        raise


def load_module(path, module_name):
    """
    Load a module dynamically from a specified source path
    :param path: module source path
    :param module_name: name of the module
    """
    try:
        spec = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)

        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        LOG.info("Loaded module %s from path %s" % (module_name, path))
    except Exception as e:
        LOG.exception("Error loading %s module: %s" % (module_name, str(e)))
        raise

    return module


def execute_agent_hooks(software_version, additional_data=None):
    """
    Executes the agent hooks during deploy host step. The
    agent hook file used will always be from the most recent
    release, both for upgrade and rollback
    :param software_version: to-release major release version
    :param additional_data: additional data used by the hooks
    """
    # determine if it is a rollback and set the source directory
    # of the agent hook file accordingly
    if version.Version(software_version) > version.Version(constants.SW_VERSION):
        ostree_path = "/ostree/1"
    else:
        ostree_path = "/ostree/2"

    # load the agent hooks module dynamically
    agent_hooks_path = os.path.normpath(ostree_path +
                                        "/usr/lib/python3/dist-packages/software/agent_hooks.py")
    agent_hooks = load_module(agent_hooks_path, "agent_hooks")
    hook_manager = agent_hooks.HookManager.create_hook_manager(software_version,
                                                               additional_data=additional_data)
    # execute the agent hooks
    try:
        hook_manager.run_hooks()
        LOG.info("Agent hooks executed successfully.")
    except Exception as e:
        LOG.exception("Error running agent hooks: %s" % str(e))
        raise


def to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() == 'true'
    return False
