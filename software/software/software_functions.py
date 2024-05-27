"""
Copyright (c) 2023-2024 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import contextlib
import getopt
import glob
import hashlib
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from oslo_config import cfg as oslo_cfg
from packaging import version
from lxml import etree as ElementTree
from xml.dom import minidom

import software.apt_utils as apt_utils
from software.db.api import get_instance
from software.release_verify import verify_files
from software.release_verify import cert_type_all
from software.release_signing import sign_files
from software.exceptions import MetadataFail
from software.exceptions import OSTreeTarFail
from software.exceptions import ReleaseUploadFailure
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseMismatchFailure
from software.exceptions import SoftwareServiceError
from software.exceptions import VersionedDeployPrecheckFailure

import software.constants as constants
from software import states
import software.utils as utils
from software.sysinv_utils import get_ihost_list
from software.sysinv_utils import get_system_info
from software.sysinv_utils import is_host_locked_and_online


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

        log_format = '%(asctime)s: ' \
                     + my_exec + '[%(process)s:%(thread)d]: ' \
                     + '%(filename)s(%(lineno)s): ' \
                     + '%(levelname)s: %(message)s'

        formatter = logging.Formatter(log_format, datefmt="%FT%T")

        LOG.setLevel(level)
        main_log_handler = logging.FileHandler(logfile)
        main_log_handler.setFormatter(formatter)
        LOG.addHandler(main_log_handler)

        try:
            os.chmod(logfile, 0o640)
        except Exception:
            pass

        auditLOG.setLevel(level)
        api_log_handler = logging.FileHandler(apilogfile)
        api_log_handler.setFormatter(formatter)
        auditLOG.addHandler(api_log_handler)
        try:
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

    def parse_metadata_string(self, text, state=None):
        root = ElementTree.fromstring(text)
        #
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

        release_id = root.findtext("id")
        if release_id is None:
            LOG.error("Release metadata contains no id tag")
            return None

        self.metadata[release_id] = {}

        self.metadata[release_id]["state"] = state

        self.metadata[release_id]["sw_version"] = "unknown"

        # commit is derived from apt-ostree command run in software deploy start

        for key in ["status",
                    "unremovable",
                    "sw_version",
                    "summary",
                    "description",
                    "install_instructions",
                    "pre_install",
                    "post_install",
                    "warnings",
                    "apply_active_release_only",
                    "commit"]:
            value = root.findtext(key)
            if value is not None:
                self.metadata[release_id][key] = value

        # Default reboot_required to Y
        rr_value = root.findtext("reboot_required")
        if rr_value is None or rr_value != "N":
            self.metadata[release_id]["reboot_required"] = "Y"
        else:
            self.metadata[release_id]["reboot_required"] = "N"

        release_sw_version = utils.get_major_release_version(
            self.metadata[release_id]["sw_version"])
        global package_dir
        if release_sw_version not in package_dir:
            package_dir[release_sw_version] = "%s/%s" % (root_package_dir, release_sw_version)
            repo_dir[release_sw_version] = "%s/rel-%s" % (repo_root_dir, release_sw_version)

        self.metadata[release_id]["requires"] = []
        for req in root.findall("requires"):
            for req_release in req.findall("req_patch_id"):
                self.metadata[release_id]["requires"].append(req_release.text)

        self.metadata[release_id]["packages"] = []
        for req in root.findall("packages"):
            for deb in req.findall("deb"):
                self.metadata[release_id]["packages"].append(deb.text)

        self.contents[release_id] = {}

        for content in root.findall("contents/ostree"):
            self.contents[release_id]["number_of_commits"] = content.findall("number_of_commits")[0].text
            self.contents[release_id]["base"] = {}
            self.contents[release_id]["base"]["commit"] = content.findall("base/commit")[0].text
            self.contents[release_id]["base"]["checksum"] = content.findall("base/checksum")[0].text
            for i in range(int(self.contents[release_id]["number_of_commits"])):
                self.contents[release_id]["commit%s" % (i + 1)] = {}
                self.contents[release_id]["commit%s" % (i + 1)]["commit"] = \
                    content.findall("commit%s/commit" % (i + 1))[0].text
                self.contents[release_id]["commit%s" % (i + 1)]["checksum"] = \
                    content.findall("commit%s/checksum" % (i + 1))[0].text

        return release_id

    def _read_all_metafile(self, path):
        """
        Load metadata from all xml files in the specified path
        :param path: path of directory that xml files is in
        """
        for filename in glob.glob("%s/*.xml" % path):
            with open(filename, "r") as f:
                text = f.read()
            yield filename, text

    def load_all(self):
        # Reset the data
        self.__init__()

        state_map = {
            states.AVAILABLE: states.AVAILABLE_DIR,
            states.UNAVAILABLE: states.UNAVAILABLE_DIR,
            states.DEPLOYING: states.DEPLOYING_DIR,
            states.DEPLOYED: states.DEPLOYED_DIR,
            states.REMOVING: states.REMOVING_DIR,
        }

        for state, path in state_map.items():
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

        # Check if conditional scripts are inside the patch
        # If yes then add them to signature checklist
        if "semantics.tar" in [f.name for f in tar.getmembers()]:
            filelist.append("semantics.tar")
        if "pre-install.sh" in [f.name for f in tar.getmembers()]:
            filelist.append("pre-install.sh")
        if "post-install.sh" in [f.name for f in tar.getmembers()]:
            filelist.append("post-install.sh")

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
        thispatch = None

        abs_patch = os.path.abspath(patch)
        abs_metadata_dir = os.path.abspath(metadata_dir)
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
                return None

            if not metadata_only and base_pkgdata is not None:
                # Run version validation tests first
                patch_sw_version = utils.get_major_release_version(
                    thispatch.metadata[patch_id]["sw_version"])
                if not base_pkgdata.check_release(patch_sw_version):
                    msg = "Software version %s for release %s is not installed" % (patch_sw_version, patch_id)
                    LOG.exception(msg)
                    raise ReleaseValidationFailure(error=msg)

            if metadata_only:
                # This is a re-import. Ensure the content lines up
                if existing_content is None \
                        or existing_content != thispatch.contents[patch_id]:
                    msg = f"Contents of {patch_id} do not match re-uploaded release"
                    LOG.error(msg)
                    raise ReleaseMismatchFailure(error=msg)

            patch_sw_version = utils.get_major_release_version(
                thispatch.metadata[patch_id]["sw_version"])
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
            if thispatch.metadata[patch_id].get("pre_install"):
                pre_install_script_name = thispatch.metadata[patch_id]["pre_install"]
                shutil.move(os.path.join(tmpdir, pre_install_script_name),
                            "%s/%s" % (root_scripts_dir, pre_install_script_name))
            if thispatch.metadata[patch_id].get("post_install"):
                post_install_script_name = thispatch.metadata[patch_id]["post_install"]
                shutil.move(os.path.join(tmpdir, post_install_script_name),
                            "%s/%s" % (root_scripts_dir, post_install_script_name))

        except tarfile.TarError as te:
            msg = "Extract software failed %s" % str(te)
            LOG.exception(msg)
            raise ReleaseValidationFailure(error=msg)
        except KeyError as ke:
            # NOTE(bqian) assuming this is metadata missing key.
            # this try except should be narror down to protect more specific
            # routine accessing external data (metadata) only.
            msg = "Software metadata missing required value for %s" % str(ke)
            LOG.exception(msg)
            raise ReleaseValidationFailure(error=msg)
            # except OSError:
            #     msg = "Failed during patch extraction"
            #     LOG.exception(msg)
            #     raise SoftwareFail(msg)
            # except IOError:  # pylint: disable=duplicate-except
            #     msg = "Failed during patch extraction"
            #     LOG.exception(msg)
            #     raise SoftwareFail(msg)
        finally:
            shutil.rmtree(tmpdir)

        return thispatch

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
            for deb in deb_dir:
                apt_utils.package_upload(package_repo_dir,
                                         sw_release,
                                         os.path.join(tmpdir, deb.name))
        except tarfile.TarError:
            msg = "Failed to extract the ostree tarball for %s" \
                  % sw_version
            LOG.exception(msg)
            raise OSTreeTarFail(msg)
        except OSError as e:
            msg = "Failed to scan %s for Debian packages. Error: %s" \
                  % (package_repo_dir, e.errno)
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
    unset_ver = "0.0.0"
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
        err_msg = "Invalid metadata. Cannot identify the sw_version."
        raise SoftwareServiceError(err_msg)

    return rel_ver


def read_upgrade_support_versions(mounted_dir):
    """
    Read upgrade metadata file to get supported upgrades
    versions
    :param mounted_dir: Mounted iso directory
    :return: to_release, supported_from_releases
    """
    try:
        root = ElementTree.parse(mounted_dir + "/upgrades/metadata.xml").getroot()
    except IOError:
        raise SoftwareServiceError("Failed to read /upgrades/metadata.xml file")

    rel_metadata_files = get_metadata_files(os.path.join(mounted_dir, "upgrades"))
    to_release = get_sw_version(rel_metadata_files)

    supported_from_releases = []
    supported_upgrades = root.find("supported_upgrades").findall("upgrade")
    for upgrade in supported_upgrades:
        supported_from_releases.append({
            "version": upgrade.findtext("version"),
            "required_patch": upgrade.findtext("required_patch"),
        })
    return to_release, supported_from_releases


def create_deploy_hosts():
    """
    Create deploy-hosts entities based on hostnames
    from sysinv.
    """
    db_api_instance = get_instance()
    db_api_instance.begin_update()
    try:
        for ihost in get_ihost_list():
            db_api_instance.create_deploy_host(ihost.hostname)
        LOG.info("Deploy-hosts entities created successfully.")
    except Exception as err:
        LOG.exception("Error in deploy-hosts entities creation")
        raise err
    finally:
        db_api_instance.end_update()


def collect_current_load_for_hosts():
    load_data = {
        "current_loads": []
    }
    try:
        for ihost in get_ihost_list():
            software_load = ihost.software_load
            hostname = ihost.hostname
            load_data["current_loads"].append({
                "hostname": hostname,
                "running_release": software_load
            })
        if os.path.exists(constants.SOFTWARE_JSON_FILE):
            data = utils.load_from_json_file(constants.SOFTWARE_JSON_FILE)
        else:
            data = {}
        data.update(load_data)
        utils.save_to_json_file(constants.SOFTWARE_JSON_FILE, load_data)
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
    if os.path.isfile(constants.SOFTWARE_JSON_FILE) \
            and os.path.isfile(constants.SYNCED_SOFTWARE_JSON_FILE):

        working_data_deploy_state = utils.load_from_json_file(
            constants.SOFTWARE_JSON_FILE)

        synced_data_deploy_state = utils.load_from_json_file(
            constants.SYNCED_SOFTWARE_JSON_FILE)

        working_deploy_state = working_data_deploy_state.get("deploy", {})

        synced_deploy_state = synced_data_deploy_state.get("deploy", {})

        working_deploy_host_state = working_data_deploy_state.get("deploy_host", {})

        synced_deploy_host_state = synced_data_deploy_state.get("deploy_host", {})

        return working_deploy_state == synced_deploy_state \
            and working_deploy_host_state == synced_deploy_host_state
    return False


def is_deployment_in_progress():
    """
    Check if at least one deployment is in progress
    :param release_metadata: dict of release metadata
    :return: bool true if in progress, false otherwise
    """
    dbapi = get_instance()
    deploys = dbapi.get_deploy_all()
    return len(deploys) > 0


def set_host_target_load(hostname, major_release):
    """
    Set target_load on the sysinv db for a host during deploy
    host for major release deployment. This action is needed
    so that sysinv behaves correctly when the host is unlocked
    and after it reboots running the new software load.

    :param hostname: host being deployed
    :param major_release: target major release
    TODO(heitormatsui): delete this function once sysinv upgrade tables are deprecated
    """
    load_query = "select id from loads where software_version = '%s'" % major_release
    host_query = "select id from i_host where hostname = '%s'" % hostname
    update_query = ("update host_upgrade set software_load = (%s), target_load = (%s) "
                    "where forihostid = (%s)") % (load_query, load_query, host_query)
    cmd = "sudo -u postgres psql -d sysinv -c \"%s\"" % update_query
    try:
        subprocess.check_call(cmd, shell=True)
        LOG.info("Host %s target_load set to %s" % (hostname, major_release))
    except subprocess.CalledProcessError as e:
        LOG.exception("Error setting target_load to %s for %s: %s" % (
            major_release, hostname, str(e)))
        raise


def deploy_host_validations(hostname, is_major_release: bool):
    """
    Check the conditions below:
    If system mode is duplex, check if provided hostname satisfy the right deployment order.
    Host is locked and online.

    If one of the validations fail, raise SoftwareServiceError exception, except if system
    is a simplex.

    :param hostname: Hostname of the host to be deployed
    :param is_major_release: Bool field indicating if is major release
    """
    _, system_mode = get_system_info()
    simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)
    db_api_instance = get_instance()
    deploy = db_api_instance.get_current_deploy()
    if simplex:
        LOG.info("System mode is simplex. Skipping deploy order validation...")
    else:
        validate_host_deploy_order(hostname, is_major_release)
    # If the deployment is not RR the host does not need to be locked and online.
    if deploy.get(constants.REBOOT_REQUIRED):
        if not is_host_locked_and_online(hostname):
            msg = f"Host {hostname} must be {constants.ADMIN_LOCKED}."
            raise SoftwareServiceError(error=msg)


def validate_host_deploy_order(hostname, is_major_release: bool):
    """
    Check if the host to be deployed satisfy the major release deployment right
    order of controller-1 -> controller-0 -> storages -> computes
    and for patch release: controllers -> storages -> computes

    Case one of the validations failed raise SoftwareError exception

    :param hostname: Hostname of the host to be deployed.
    :param is_major_release: Bool field indicating if is major release
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

    for host in db_api_instance.get_deploy_host():
        if host.get("state") == states.DEPLOY_HOST_STATES.DEPLOYED.value:
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


def clean_up_deployment_data(major_release):
    """
    Clean up all data generated during deployment.

    :param major_release: Major release to be deleted.
    """
    # Delete the data inside /opt/platform/<folder>/<major_release>
    for folder in constants.DEPLOY_CLEANUP_FOLDERS_NAME:
        path = os.path.join(constants.PLATFORM_PATH, folder, major_release, "")
        shutil.rmtree(path, ignore_errors=True)
    # TODO(lbonatti): These folders should be revisited on software deploy abort/rollback
    #                 to check additional folders that might be needed to delete.
    upgrade_folders = [
        os.path.join(constants.POSTGRES_PATH, constants.UPGRADE),
        os.path.join(constants.POSTGRES_PATH, major_release),
        os.path.join(constants.RABBIT_PATH, major_release),
        os.path.join(constants.ETCD_PATH, major_release),
    ]
    for folder in upgrade_folders:
        shutil.rmtree(folder, ignore_errors=True)


def run_deploy_clean_up_script(release):
    """
    Runs the deploy-cleanup script for the given release.

    :param release: Release to be cleaned.
    """
    cmd_path = utils.get_software_deploy_script(release, constants.DEPLOY_CLEANUP_SCRIPT)
    if (os.path.exists(f"{constants.STAGING_DIR}/{constants.OSTREE_REPO}") and
            os.path.exists(constants.ROOT_DIR)):
        try:
            subprocess.check_output([cmd_path, f"{constants.STAGING_DIR}/{constants.OSTREE_REPO}",
                                     constants.ROOT_DIR, "all"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            LOG.exception("Error running deploy-cleanup script: %s" % str(e))
            raise
