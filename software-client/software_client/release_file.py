#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import re
import subprocess
import tarfile
import xml.etree.ElementTree as ElementTree

from software_client import constants
from software_client.exc import ReleaseFileError

ISOINFO_TIMEOUT = 120  # seconds
PATCH_METADATA_TAR = "metadata.tar"
PATCH_METADATA_XML = "metadata.xml"


def _isoinfo(iso_path, *args):
    """Run isoinfo on an ISO (Rock Ridge names) and return its output"""
    try:
        return subprocess.check_output(["isoinfo", "-R", "-i", iso_path] + list(args),
                                       stderr=subprocess.PIPE, timeout=ISOINFO_TIMEOUT)
    except FileNotFoundError:
        raise ReleaseFileError("isoinfo command not found")
    except subprocess.CalledProcessError as e:
        raise ReleaseFileError("isoinfo failed for %s: %s"
                               % (iso_path, e.stderr.decode(errors="replace").strip()))
    except subprocess.TimeoutExpired:
        raise ReleaseFileError("isoinfo timed out for %s" % iso_path)


def _parse_xml(xml, path):
    try:
        return ElementTree.fromstring(xml)
    except ElementTree.ParseError as e:
        raise ReleaseFileError("Invalid release metadata in %s: %s" % (path, e))


def _sw_version_key(xml, path):
    """Sort key for product metadata: its sw_version as a tuple of ints"""
    sw_version = _parse_xml(xml, path).findtext("sw_version") or ""
    try:
        return tuple(int(n) for n in sw_version.split("."))
    except ValueError:
        raise ReleaseFileError("Invalid sw_version '%s' in %s" % (sw_version, path))


def _read_iso_metadata(iso_path):
    """
    Read the release metadata of an ISO without mounting it
    :param iso_path: ISO file
    :return: (metadata xml, True if it is the product metadata)
    """
    files = _isoinfo(iso_path, "-f").decode(errors="replace").splitlines()
    # Product metadata, e.g. /upgrades/starlingx-26.10.100-metadata.xml
    product_files = [f for f in files if re.match(r'^/upgrades/[a-zA-Z]+-[\d.]+-metadata\.xml$', f)]
    if product_files:
        metadata = [_isoinfo(iso_path, "-x", f) for f in product_files]
        if len(metadata) == 1:
            return metadata[0], True
        # Use the highest sw_version
        return max(metadata, key=lambda xml: _sw_version_key(xml, iso_path)), True
    # Pre-USM ISO: only upgrades/metadata.xml, with the major release
    if "/upgrades/metadata.xml" in files:
        return _isoinfo(iso_path, "-x", "/upgrades/metadata.xml"), False
    raise ReleaseFileError("No release metadata found in /upgrades/ of %s" % iso_path)


def _read_patch_metadata(patch_path):
    """
    Read metadata.xml of a patch, without extracting it to disk
    :param patch_path: patch file
    :return: metadata xml
    """
    # Stream the archive and stop at metadata.tar: a patch is a gzip tar and
    # may carry a large extra.tar after it
    try:
        with tarfile.open(patch_path, "r|*") as patch:
            for member in patch:
                if os.path.normpath(member.name) != PATCH_METADATA_TAR:
                    continue
                with tarfile.open(fileobj=patch.extractfile(member), mode="r|*") as metadata:
                    for item in metadata:
                        if os.path.normpath(item.name) == PATCH_METADATA_XML:
                            return metadata.extractfile(item).read()
                break
    except tarfile.TarError as e:
        raise ReleaseFileError("Invalid patch file %s: %s" % (patch_path, e))
    except OSError as e:
        raise ReleaseFileError("Cannot read patch file %s: %s" % (patch_path, e))
    raise ReleaseFileError("metadata.xml not found in %s" % patch_path)


def get_release_info(path):
    """
    Get the release info of a local ISO or patch file.
    This only reads the metadata. It does not verify the file signature,
    so do not use the result to decide that the file is valid.
    :param path: ISO or patch file
    :return: dict with file, type, release_id, sw_version and prepatched_iso
    """
    if not os.path.isfile(path):
        raise ReleaseFileError("File not found: %s" % path)

    ext = os.path.splitext(path)[1].lower()
    if ext == constants.ISO_EXTENSION:
        file_type = "iso"
        metadata, is_product = _read_iso_metadata(path)
    elif ext == constants.PATCH_EXTENSION:
        file_type = "patch"
        metadata, is_product = _read_patch_metadata(path), True
    else:
        raise ReleaseFileError("Unsupported file type: %s" % path)

    root = _parse_xml(metadata, path)

    if not is_product:
        sw_version = root.findtext("version")
        if not sw_version:
            raise ReleaseFileError("No version in /upgrades/metadata.xml of %s" % path)
        # The major release (MM.mm) is the GA release MM.mm.0
        if re.match(r'^\d+\.\d+$', sw_version):
            sw_version += ".0"
        return {"file": path, "type": file_type, "release_id": constants.RELEASE_GA_NAME % sw_version,
                "sw_version": sw_version, "prepatched_iso": None}

    release_id = root.findtext("id")
    if not release_id:
        raise ReleaseFileError("No release id in the metadata of %s" % path)

    # A missing prepatched_iso tag means False
    prepatched_iso = None
    if file_type == "iso":
        prepatched_iso = root.findtext(constants.PREPATCHED_ISO_TAG) == "Y"

    return {"file": path, "type": file_type, "release_id": release_id,
            "sw_version": root.findtext("sw_version"), "prepatched_iso": prepatched_iso}


def get_release_info_list(paths):
    """
    Get the release info of several ISO and patch files. .sig files are skipped.
    :param paths: list of files
    :return: list of dicts, with {"file", "error"} for a file that cannot be read
    """
    results = []
    for path in paths:
        if path.lower().endswith(constants.SIG_EXTENSION):
            continue
        try:
            results.append(get_release_info(path))
        except ReleaseFileError as e:
            results.append({"file": path, "error": str(e)})
    return results
