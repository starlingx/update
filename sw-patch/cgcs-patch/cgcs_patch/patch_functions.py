"""
Copyright (c) 2014-2023 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

import glob
import hashlib
import logging
import os
import re
import shutil
import sys
import tarfile
import tempfile
from lxml import etree as ElementTree

from cgcs_patch.patch_verify import verify_files
from cgcs_patch.patch_verify import cert_type_all
from cgcs_patch.exceptions import PatchFail
from cgcs_patch.exceptions import PatchValidationFailure
from cgcs_patch.exceptions import PatchMismatchFailure

import cgcs_patch.constants as constants

try:
    # The tsconfig module is only available at runtime
    from tsconfig.tsconfig import SW_VERSION
except Exception:
    SW_VERSION = "unknown"

# Constants
patch_dir = constants.PATCH_STORAGE_DIR
avail_dir = "%s/metadata/available" % patch_dir
applied_dir = "%s/metadata/applied" % patch_dir
committed_dir = "%s/metadata/committed" % patch_dir
semantics_dir = "%s/semantics" % patch_dir

# these next 4 variables may need to change to support ostree
repo_root_dir = "/var/www/pages/updates"
repo_dir = {SW_VERSION: "%s/rel-%s" % (repo_root_dir, SW_VERSION)}

root_package_dir = "%s/packages" % patch_dir
root_scripts_dir = "/opt/patching/patch-scripts"
package_dir = {SW_VERSION: "%s/%s" % (root_package_dir, SW_VERSION)}

logfile = "/var/log/patching.log"
apilogfile = "/var/log/patching-api.log"

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
        for sw_rel in self.pkgs:
            if not os.path.exists("%s/rel-%s" % (base_dir, sw_rel)):
                del self.pkgs[sw_rel]

    def check_release(self, sw_rel):
        return (sw_rel in self.pkgs)

    def find_version(self, sw_rel, pkgname, arch):
        if sw_rel not in self.pkgs or \
           pkgname not in self.pkgs[sw_rel] or \
           arch not in self.pkgs[sw_rel][pkgname]:
            return None

        return self.pkgs[sw_rel][pkgname][arch]


class PatchData(object):
    """
    Aggregated patch data
    """
    def __init__(self):
        #
        # The metadata dict stores all metadata associated with a patch.
        # This dict is keyed on patch_id, with metadata for each patch stored
        # in a nested dict. (See parse_metadata method for more info)
        #
        self.metadata = {}

        #
        # The contents dict stores the lists of RPMs provided by each patch,
        # indexed by patch_id.
        #
        self.contents = {}

    def add_patch(self, new_patch):
        # We can just use "update" on these dicts because they are indexed by patch_id
        self.metadata.update(new_patch.metadata)
        self.contents.update(new_patch.contents)

    def update_patch(self, updated_patch):
        for patch_id in list(updated_patch.metadata):
            # Update all fields except repostate
            cur_repostate = self.metadata[patch_id]['repostate']
            self.metadata[patch_id].update(updated_patch.metadata[patch_id])
            self.metadata[patch_id]['repostate'] = cur_repostate

    def delete_patch(self, patch_id):
        del self.contents[patch_id]
        del self.metadata[patch_id]

    def parse_metadata(self,
                       filename,
                       repostate=None):
        """
        Parse an individual patch metadata XML file
        :param filename: XML file
        :param repostate: Indicates Applied, Available, or Committed
        :return: Patch ID
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

        patch_id = root.findtext("id")
        if patch_id is None:
            LOG.error("Patch metadata contains no id tag")
            return None

        self.metadata[patch_id] = {}

        self.metadata[patch_id]["repostate"] = repostate

        # Patch state is unknown at this point
        self.metadata[patch_id]["patchstate"] = "n/a"

        self.metadata[patch_id]["sw_version"] = "unknown"

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
                self.metadata[patch_id][key] = value

        # Default reboot_required to Y
        rr_value = root.findtext("reboot_required")
        if rr_value is None or rr_value != "N":
            self.metadata[patch_id]["reboot_required"] = "Y"
        else:
            self.metadata[patch_id]["reboot_required"] = "N"

        patch_sw_version = self.metadata[patch_id]["sw_version"]
        global package_dir
        if patch_sw_version not in package_dir:
            package_dir[patch_sw_version] = "%s/%s" % (root_package_dir, patch_sw_version)
            repo_dir[patch_sw_version] = "%s/rel-%s" % (repo_root_dir, patch_sw_version)

        self.metadata[patch_id]["requires"] = []
        for req in root.findall("requires"):
            for req_patch in req.findall("req_patch_id"):
                self.metadata[patch_id]["requires"].append(req_patch.text)

        self.contents[patch_id] = {}

        for content in root.findall("contents/ostree"):
            self.contents[patch_id]["number_of_commits"] = content.findall("number_of_commits")[0].text
            self.contents[patch_id]["base"] = {}
            self.contents[patch_id]["base"]["commit"] = content.findall("base/commit")[0].text
            self.contents[patch_id]["base"]["checksum"] = content.findall("base/checksum")[0].text
            for i in range(int(self.contents[patch_id]["number_of_commits"])):
                self.contents[patch_id]["commit%s" % (i + 1)] = {}
                self.contents[patch_id]["commit%s" % (i + 1)]["commit"] = \
                    content.findall("commit%s/commit" % (i + 1))[0].text
                self.contents[patch_id]["commit%s" % (i + 1)]["checksum"] = \
                    content.findall("commit%s/checksum" % (i + 1))[0].text

        return patch_id

    def load_all_metadata(self,
                          loaddir,
                          repostate=None):
        """
        Parse all metadata files in the specified dir
        :return:
        """
        for fname in glob.glob("%s/*.xml" % loaddir):
            self.parse_metadata(fname, repostate)

    def load_all(self):
        # Reset the data
        self.__init__()
        self.load_all_metadata(applied_dir, repostate=constants.APPLIED)
        self.load_all_metadata(avail_dir, repostate=constants.AVAILABLE)
        self.load_all_metadata(committed_dir, repostate=constants.COMMITTED)

    def query_line(self,
                   patch_id,
                   index):
        if index is None:
            return None

        if index == "contents":
            return self.contents[patch_id]

        if index not in self.metadata[patch_id]:
            return None

        value = self.metadata[patch_id][index]
        return value


class PatchFile(object):
    """
    Patch file
    """

    @staticmethod
    def read_patch(path, cert_type=None):
        # We want to enable signature checking by default
        # Note: cert_type=None is required if we are to enforce 'no dev patches on a formal load' rule.

        # Open the patch file and extract the contents to the current dir
        tar = tarfile.open(path, "r:gz")

        filelist = []
        for f in tar.getmembers():
            filelist.append(f.name)

        if detached_signature_file not in filelist:
            msg = "Patch not signed"
            LOG.warning(msg)

        for f in filelist:
            tar.extract(f)

        # Filelist used for signature validation and verification
        sig_filelist = ["metadata.tar", "software.tar"]
        if "semantics.tar" in filelist:
            sig_filelist.append("semantics.tar")

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
            raise PatchValidationFailure(msg)

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
                raise PatchValidationFailure(msg)
        else:
            msg = "Patch has not been signed"
            if cert_type is None:
                LOG.error(msg)
            raise PatchValidationFailure(msg)

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
                    except PatchValidationFailure:
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

            thispatch = PatchData()
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

        except PatchValidationFailure as e:
            msg = "Patch validation failed during extraction"
            LOG.exception(msg)
            raise e
        except PatchMismatchFailure as e:
            msg = "Patch Mismatch during extraction"
            LOG.exception(msg)
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return r

    @staticmethod
    def extract_patch(patch,
                      metadata_dir=avail_dir,
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

            thispatch = PatchData()
            patch_id = thispatch.parse_metadata("metadata.xml")

            if patch_id is None:
                print("Failed to import patch")
                # Change back to original working dir
                os.chdir(orig_wd)
                shutil.rmtree(tmpdir)
                return None

            if not metadata_only and base_pkgdata is not None:
                # Run version validation tests first
                patch_sw_version = thispatch.metadata[patch_id]["sw_version"]
                if not base_pkgdata.check_release(patch_sw_version):
                    msg = "Patch %s software release (%s) is not installed" % (patch_id, patch_sw_version)
                    LOG.exception(msg)
                    raise PatchValidationFailure(msg)

            if metadata_only:
                # This is a re-import. Ensure the content lines up
                if existing_content is None \
                        or existing_content != thispatch.contents[patch_id]:
                    msg = "Contents of re-imported patch do not match"
                    LOG.exception(msg)
                    raise PatchMismatchFailure(msg)

            patch_sw_version = thispatch.metadata[patch_id]["sw_version"]
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

        except PatchValidationFailure as e:
            raise e
        except PatchMismatchFailure as e:
            raise e
        except tarfile.TarError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        except KeyError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchValidationFailure(msg)
        except OSError:
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchFail(msg)
        except IOError:  # pylint: disable=duplicate-except
            msg = "Failed during patch extraction"
            LOG.exception(msg)
            raise PatchFail(msg)
        finally:
            # Change back to original working dir
            os.chdir(orig_wd)
            shutil.rmtree(tmpdir)

        return thispatch
