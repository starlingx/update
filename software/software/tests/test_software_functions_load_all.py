#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import unittest
from unittest import mock

from software import constants
from software import states
from software.software_functions import ReleaseData


# Product release metadata. In a rollback scenario the product may sit in the
# "deploying" state directory while its metapackages have already been moved to
# "available".
PRODUCT_XML = """<?xml version="1.0" ?>
<product>
  <id>starlingx-13.0.0</id>
  <sw_version>13.0.0</sw_version>
  <metapackages>
    <pkg>base</pkg>
  </metapackages>
</product>
"""

# Metapackage metadata. It references its product only indirectly, by
# sw_version, and can therefore only be resolved once the product has been
# parsed into self.metadata.
METAPACKAGE_XML = """<?xml version="1.0" ?>
<metapackage>
  <id>base_13.0.0</id>
  <sw_version>13.0.0</sw_version>
  <pre_upgrade_deploy>N</pre_upgrade_deploy>
  <deployable>Y</deployable>
  <data_migration>Y</data_migration>
</metapackage>
"""


class TestLoadAllCrossStateOrdering(unittest.TestCase):
    """load_all must resolve a metapackage against its product even when the
    two live in different state directories.

    state_map iterates AVAILABLE before DEPLOYING, so if the metapackage
    (available) is parsed before the product (deploying) the lookup by
    sw_version fails and the metapackage is silently dropped. This reproduces
    the rollback layout that triggered "No existing release matches 13.0.0
    version".
    """

    def _fake_read_all_metafile(self, product_dir, metapackage_dir):
        """Return a side_effect that yields the product XML only from
        product_dir and the metapackage XML only from metapackage_dir.
        """
        def _reader(path):
            if path == metapackage_dir:
                yield ("base_13.0.0-metadata.xml", METAPACKAGE_XML)
            elif path == product_dir:
                yield ("starlingx-13.0.0-metadata.xml", PRODUCT_XML)
            # every other state directory is empty
        return _reader

    def test_product_deploying_metapackage_available(self):
        rd = ReleaseData()
        reader = self._fake_read_all_metafile(
            product_dir=states.DEPLOYING_DIR,
            metapackage_dir=states.AVAILABLE_DIR)
        with mock.patch.object(rd, '_read_all_metafile', side_effect=reader):
            rd.load_all()

        # Product is parsed.
        self.assertIn("starlingx-13.0.0", rd.metadata)
        self.assertEqual(
            rd.metadata["starlingx-13.0.0"]["sw_version"], "13.0.0")

        # And the metapackage metadata is actually populated, not dropped.
        #
        # Asserting key presence alone is insufficient: the product declares
        # its metapackages (<pkg>base</pkg>), so parsing the product alone
        # pre-creates an EMPTY "base_13.0.0" entry regardless of whether the
        # metapackage file itself was parsed. The fields below (component,
        # product, state) are only set when the metapackage file is
        # successfully parsed and resolved to its product.
        metapackages = rd.metadata["starlingx-13.0.0"]["metapackages"]
        self.assertIn("base_13.0.0", metapackages)
        mp = metapackages["base_13.0.0"]
        self.assertEqual(mp.get("component"), "base")
        self.assertEqual(mp.get("product"), "starlingx-13.0.0")
        self.assertEqual(mp.get("state"), states.AVAILABLE)
        self.assertEqual(mp.get("deployable"), "Y")

    def test_metapackage_and_product_in_same_dir(self):
        # Sanity check: co-located metadata still loads correctly.
        rd = ReleaseData()

        def _reader(path):
            if path == states.DEPLOYING_DIR:
                yield ("starlingx-13.0.0-metadata.xml", PRODUCT_XML)
                yield ("base_13.0.0-metadata.xml", METAPACKAGE_XML)

        with mock.patch.object(rd, '_read_all_metafile', side_effect=_reader):
            rd.load_all()

        self.assertIn("starlingx-13.0.0", rd.metadata)
        mp = rd.metadata["starlingx-13.0.0"]["metapackages"]["base_13.0.0"]
        self.assertEqual(mp.get("component"), "base")
        self.assertEqual(mp.get("product"), "starlingx-13.0.0")

    def test_product_in_component_storage_metapackage_available(self):
        # Canonical steady-state layout: the product release metadata lives in
        # COMPONENT_SOFTWARE_METADATA_STORAGE_DIR (parsed first, with state
        # None) while its metapackages live in a state directory (available).
        rd = ReleaseData()

        def _reader(path):
            if path == constants.COMPONENT_SOFTWARE_METADATA_STORAGE_DIR:
                yield ("starlingx-13.0.0-metadata.xml", PRODUCT_XML)
            elif path == states.AVAILABLE_DIR:
                yield ("base_13.0.0-metadata.xml", METAPACKAGE_XML)

        with mock.patch.object(rd, '_read_all_metafile', side_effect=_reader):
            rd.load_all()

        self.assertIn("starlingx-13.0.0", rd.metadata)
        # Product parsed from the component storage dir carries no state
        # (parsed with state=None), while the metapackage keeps its own.
        self.assertNotIn("state", rd.metadata["starlingx-13.0.0"])

        mp = rd.metadata["starlingx-13.0.0"]["metapackages"]["base_13.0.0"]
        self.assertEqual(mp.get("component"), "base")
        self.assertEqual(mp.get("product"), "starlingx-13.0.0")
        self.assertEqual(mp.get("state"), states.AVAILABLE)

    def test_metapackage_without_product_is_dropped(self):
        # A metapackage whose product is absent cannot be resolved and must be
        # skipped without raising.
        rd = ReleaseData()

        def _reader(path):
            if path == states.AVAILABLE_DIR:
                yield ("base_13.0.0-metadata.xml", METAPACKAGE_XML)

        with mock.patch.object(rd, '_read_all_metafile', side_effect=_reader):
            rd.load_all()

        self.assertNotIn("starlingx-13.0.0", rd.metadata)


if __name__ == '__main__':
    unittest.main()
