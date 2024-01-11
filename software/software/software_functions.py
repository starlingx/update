"""
Copyright (c) 2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

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
from lxml import etree as ElementTree
from xml.dom import minidom

import software.apt_utils as apt_utils
from software.release_verify import verify_files
from software.release_verify import cert_type_all
from software.release_signing import sign_files
from software.exceptions import MetadataFail
from software.exceptions import OSTreeTarFail
from software.exceptions import ReleaseUploadFailure
from software.exceptions import ReleaseValidationFailure
from software.exceptions import ReleaseMismatchFailure
from software.exceptions import SoftwareFail

import software.constants as constants
import software.utils as utils
from software.sysinv_utils import get_sysinv_client


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
                     + my_exec + '[%(process)s]: ' \
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


def get_release_from_patch(patchfile):
    rel = ""
    try:
        metadata_str = subprocess.check_output(['tar', '--to-command=tar -xO', '-xf', patchfile, 'metadata.tar'])
        root = ElementTree.fromstring(metadata_str)
        # Extract release version
        rel = root.findtext('sw_version')
    except subprocess.CalledProcessError as e:
        LOG.error("Failed to run tar command")
        LOG.error("Command output: %s", e.output)
        raise e
    except Exception as e:
        print("Failed to parse patch software version")
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
        # The metadata dict stores all metadata associated with a release.
        # This dict is keyed on release_id, with metadata for each release stored
        # in a nested dict. (See parse_metadata method for more info)
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
            self.metadata[release_id].update(updated_release.metadata[release_id])
            self.metadata[release_id]['state'] = cur_state

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

    def parse_metadata(self,
                       filename,
                       state=None):
        """
        Parse an individual release metadata XML file
        :param filename: XML file
        :param state: Indicates Applied, Available, or Committed
        :return: Release ID
        """
        tree = ElementTree.parse(filename)
        root = tree.getroot()

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

        for key in ["status",
                    "unremovable",
                    "sw_version",
                    "summary",
                    "description",
                    "install_instructions",
                    "restart_script",
                    "warnings",
                    "apply_active_release_only"]:
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
                self.metadata[release_id]["packages"].append(
                    deb.text.split("_")[0])

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

    def load_all_metadata(self,
                          loaddir,
                          state=None):
        """
        Parse all metadata files in the specified dir
        :return:
        """
        for fname in glob.glob("%s/*.xml" % loaddir):
            self.parse_metadata(fname, state)

    def load_all(self):
        # Reset the data
        self.__init__()
        self.load_all_metadata(constants.AVAILABLE_DIR, state=constants.AVAILABLE)
        self.load_all_metadata(constants.UNAVAILABLE_DIR, state=constants.UNAVAILABLE)
        self.load_all_metadata(constants.DEPLOYING_START_DIR, state=constants.DEPLOYING_START)
        self.load_all_metadata(constants.DEPLOYING_HOST_DIR, state=constants.DEPLOYING_HOST)
        self.load_all_metadata(constants.DEPLOYING_ACTIVATE_DIR, state=constants.DEPLOYING_ACTIVATE)
        self.load_all_metadata(constants.DEPLOYING_COMPLETE_DIR, state=constants.DEPLOYING_COMPLETE)
        self.load_all_metadata(constants.DEPLOYED_DIR, state=constants.DEPLOYED)
        self.load_all_metadata(constants.REMOVING_DIR, state=constants.REMOVING)
        self.load_all_metadata(constants.ABORTING_DIR, state=constants.ABORTING)
        self.load_all_metadata(constants.COMMITTED_DIR, state=constants.COMMITTED)

        # load the release metadata from feed directory or filesystem db

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
    def read_patch(path, cert_type=None):
        # We want to enable signature checking by default
        # Note: cert_type=None is required if we are to enforce 'no dev patches on a formal load' rule.

        # Open the patch file and extract the contents to the current dir
        tar = tarfile.open(path, "r:gz")

        tar.extract("signature")
        try:
            tar.extract(detached_signature_file)
        except KeyError:
            msg = "Patch has not been signed"
            LOG.warning(msg)

        # Filelist used for signature validation and verification
        sig_filelist = ["metadata.tar", "software.tar"]
        if "semantics.tar" in [f.name for f in tar.getmembers()]:
            sig_filelist.append("semantics.tar")

        for f in sig_filelist:
            tar.extract(f)

        # Verify the data integrity signature first
        sigfile = open("signature", "r")
        sig = int(sigfile.read(), 16)
        sigfile.close()

        expected_sig = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
        for f in sig_filelist:
            sig ^= get_md5(f)

        if sig != expected_sig:
            msg = "Patch failed verification"
            LOG.error(msg)
            raise ReleaseValidationFailure(msg)

        # Verify detached signature
        if os.path.exists(detached_signature_file):
            sig_valid = verify_files(
                sig_filelist,
                detached_signature_file,
                cert_type=cert_type)
            if sig_valid is True:
                msg = "Signature verified, patch has been signed"
                if cert_type is None:
                    LOG.info(msg)
            else:
                msg = "Signature check failed"
                if cert_type is None:
                    LOG.error(msg)
                raise ReleaseValidationFailure(msg)
        else:
            msg = "Patch has not been signed"
            if cert_type is None:
                LOG.error(msg)
            raise ReleaseValidationFailure(msg)

        # Restart script
        for f in tar.getmembers():
            if f.name not in sig_filelist:
                tar.extract(f)

        tar = tarfile.open("metadata.tar")
        tar.extractall()

    @staticmethod
    def query_patch(patch, field=None):

        abs_patch = os.path.abspath(patch)

        # Create a temporary working directory
        tmpdir = tempfile.mkdtemp(prefix="patch_")

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        r = {}

        try:
            if field is None or field == "cert":
                # Need to determine the cert_type
                for cert_type_str in cert_type_all:
                    try:
                        PatchFile.read_patch(abs_patch, cert_type=[cert_type_str])
                    except ReleaseValidationFailure:
                        pass
                    else:
                        # Successfully opened the file for reading, and we have discovered the cert_type
                        r["cert"] = cert_type_str
                        break

            if "cert" not in r:
                # If cert is unknown, then file is not yet open for reading.
                # Try to open it for reading now, using all available keys.
                # We can't omit cert_type, or pass None, because that will trigger the code
                # path used by installed product, in which dev keys are not accepted unless
                # a magic file exists.
                PatchFile.read_patch(abs_patch, cert_type=cert_type_all)

            thispatch = ReleaseData()
            patch_id = thispatch.parse_metadata("metadata.xml")

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
            msg = "Patch validation failed during extraction"
            LOG.exception(msg)
            raise e
        except ReleaseMismatchFailure as e:
            msg = "Patch Mismatch during extraction"
            LOG.exception(msg)
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise ReleaseValidationFailure(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
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

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        try:
            cert_type = None
            meta_data = PatchFile.query_patch(abs_patch)
            if 'cert' in meta_data:
                cert_type = meta_data['cert']
            PatchFile.read_patch(abs_patch, cert_type=cert_type)
            ReleaseData.modify_metadata_text("metadata.xml", key, value)
            PatchFile.write_patch(new_abs_patch, cert_type=cert_type)
            os.rename(new_abs_patch, abs_patch)
            rc = True

        except ReleaseValidationFailure as e:
            raise e
        except ReleaseMismatchFailure as e:
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise ReleaseValidationFailure(msg)
        except Exception as e:
            template = "An exception of type {0} occurred. Arguments:\n{1!r}"
            message = template.format(type(e).__name__, e.args)
            print(message)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return rc

    @staticmethod
    def extract_patch(patch,
                      metadata_dir=constants.AVAILABLE_DIR,
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

        # Save the current directory, so we can chdir back after
        orig_wd = os.getcwd()

        # Change to the tmpdir
        os.chdir(tmpdir)

        try:
            # Open the patch file and extract the contents to the tmpdir
            PatchFile.read_patch(abs_patch)

            thispatch = ReleaseData()
            patch_id = thispatch.parse_metadata("metadata.xml")

            if patch_id is None:
                print("Failed to import patch")
                # Change back to original working dir
                os.chdir(orig_wd)
                shutil.rmtree(tmpdir)
                return None

            if not metadata_only and base_pkgdata is not None:
                # Run version validation tests first
                patch_sw_version = utils.get_major_release_version(
                    thispatch.metadata[patch_id]["sw_version"])
                if not base_pkgdata.check_release(patch_sw_version):
                    msg = "Software version %s for release %s is not installed" % (patch_sw_version, patch_id)
                    LOG.exception(msg)
                    raise ReleaseValidationFailure(msg)

            if metadata_only:
                # This is a re-import. Ensure the content lines up
                if existing_content is None \
                        or existing_content != thispatch.contents[patch_id]:
                    msg = "Contents of re-imported patch do not match"
                    LOG.exception(msg)
                    raise ReleaseMismatchFailure(msg)

            patch_sw_version = utils.get_major_release_version(
                thispatch.metadata[patch_id]["sw_version"])
            abs_ostree_tar_dir = package_dir[patch_sw_version]
            if not os.path.exists(abs_ostree_tar_dir):
                os.makedirs(abs_ostree_tar_dir)

            shutil.move("metadata.xml",
                        "%s/%s-metadata.xml" % (abs_metadata_dir, patch_id))
            shutil.move("software.tar",
                        "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id))

            # restart_script may not exist in metadata.
            if thispatch.metadata[patch_id].get("restart_script"):
                if not os.path.exists(root_scripts_dir):
                    os.makedirs(root_scripts_dir)
                restart_script_name = thispatch.metadata[patch_id]["restart_script"]
                shutil.move(restart_script_name,
                            "%s/%s" % (root_scripts_dir, restart_script_name))

        except ReleaseValidationFailure as e:
            raise e
        except ReleaseMismatchFailure as e:
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise ReleaseValidationFailure(msg)
        except KeyError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise ReleaseValidationFailure(msg)
        except OSError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise SoftwareFail(msg)
        except IOError:  # pylint: disable=duplicate-except
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise SoftwareFail(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return thispatch

    @staticmethod
    def unpack_patch(patch):
        """Extract patch and upload Debian package to the repository.
        :param patch: Patch file
        :param metadata_dir: Directory to store the metadata XML file
        """
        thispatch = None

        # Load the patch
        abs_patch = os.path.abspath(patch)
        PatchFile.read_patch(abs_patch)
        thispatch = ReleaseData()
        patch_id = thispatch.parse_metadata("metadata.xml")

        patch_sw_version = utils.get_major_release_version(
                thispatch.metadata[patch_id]["sw_version"])
        abs_ostree_tar_dir = package_dir[patch_sw_version]
        ostree_tar_filename = "%s/%s-software.tar" % (abs_ostree_tar_dir, patch_id)
        package_repo_dir = "%s/rel-%s" % (constants.PACKAGE_FEED_DIR, patch_sw_version)

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
                        os.path.join(tmpdir, deb.name))
        except tarfile.TarError:
            msg = "Failed to extract the ostree tarball for %s" \
                    % patch_sw_version
            LOG.exception(msg)
            raise OSTreeTarFail(msg)
        except OSError as e:
            msg = "Failed to scan %s for Debian packages. Error: %s" \
                     % (package_repo_dir, e.errno)
            LOG.exception(msg)
            raise OSTreeTarFail(msg)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

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
        raise MetadataFail("Failed to read /upgrades/metadata.xml file")

    to_release = root.findtext("version")
    supported_from_releases = []
    supported_upgrades = root.find("supported_upgrades").findall("upgrade")
    for upgrade in supported_upgrades:
        supported_from_releases.append({
            "version": upgrade.findtext("version"),
            "required_patch": upgrade.findtext("required_patch"),
        })
    return to_release, supported_from_releases


def collect_current_load_for_hosts():
    load_data = {
        "current_loads": []
    }
    try:
        token, endpoint = utils.get_endpoints_token()
        sysinv_client = get_sysinv_client(token=token, endpoint=endpoint)
        host_list = sysinv_client.ihost.list()
        for ihost in host_list:
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
        data[child.tag] = child.text
    return data
