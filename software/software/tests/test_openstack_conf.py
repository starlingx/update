#!/usr/bin/env python
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# Unit tests for OpenstackConfHook (in agent_hooks.py)

# pylint: disable=protected-access

import logging
import os
import shutil
import sys
import tempfile
import unittest
import unittest.mock

# Mock modules not available in test environment
for _mod in ['ruamel', 'ruamel.yaml', 'packaging', 'packaging.version']:
    if _mod not in sys.modules:
        sys.modules[_mod] = unittest.mock.MagicMock()

# Prevent agent_hooks from writing to /var/log/software.log
logging.basicConfig = unittest.mock.MagicMock()

from software import agent_hooks
from software.agent_hooks import OpenstackConfHook

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def _create_hook(from_release=None, to_release=None):
    """Create an OpenstackConfHook instance for testing."""
    attrs = {
        "from_release": from_release or OpenstackConfHook.RELEASE_N1,
        "to_release": to_release or OpenstackConfHook.RELEASE_N,
        "hook_action": "major_release_upgrade",
    }
    return OpenstackConfHook(attrs)


class TestWriteConfig(unittest.TestCase):
    """Tests for OpenstackConfHook._write_config()."""

    def _write_and_read(self, values, template_content):
        """Helper: write config from values+template, return output lines."""
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.j2',
                                         delete=False) as tmpl:
            tmpl.write(template_content)
            tmpl.flush()
            tmpl_path = tmpl.name

        out_path = tmpl_path + '.out'
        try:
            hook._write_config(values, out_path, tmpl_path)
            with open(out_path, 'r') as f:
                return f.readlines()
        finally:
            os.unlink(tmpl_path)
            if os.path.exists(out_path):
                os.unlink(out_path)

    def test_empty_values_preserves_template(self):
        """No values means template passes through unchanged."""
        template = "[DEFAULT]\n#key = default\n"
        lines = self._write_and_read({}, template)
        self.assertEqual(''.join(lines), template)

    def test_commented_option_kept_with_value_after(self):
        """Commented default should be kept, value inserted after it."""
        template = "[DEFAULT]\n#myopt = default\n"
        values = {'DEFAULT': {'myopt': 'override'}}
        lines = self._write_and_read(values, template)
        self.assertIn('#myopt = default\n', lines)
        idx = lines.index('#myopt = default\n')
        self.assertEqual(lines[idx + 1], 'myopt = override\n')

    def test_uncommented_option_replaced(self):
        """Uncommented template value should be replaced, not duplicated."""
        template = "[DEFAULT]\nmyopt = original\n"
        values = {'DEFAULT': {'myopt': 'override'}}
        lines = self._write_and_read(values, template)
        self.assertIn('myopt = override\n', lines)
        self.assertNotIn('myopt = original\n', lines)

    def test_uncommented_option_preserved_when_no_match(self):
        """Uncommented template value passes through when no matching
        value in input.
        """
        template = "[DEFAULT]\nlog_file = keystone.log\n"
        values = {}
        lines = self._write_and_read(values, template)
        self.assertIn('log_file = keystone.log\n', lines)

    def test_jinja2_line_replaced(self):
        """Jinja2 template line should be replaced with actual value."""
        template = "[database]\nconnection = {{ some_var }}\n"
        values = {'database': {'connection': 'postgresql://host/db'}}
        lines = self._write_and_read(values, template)
        self.assertIn('connection = postgresql://host/db\n', lines)
        self.assertFalse(any('{{' in line for line in lines))

    def test_value_not_in_template_appended_to_section(self):
        """Value with no matching option in template appended to section."""
        template = "[DEFAULT]\n#other = x\n\n[database]\n#existing = y\n"
        values = {'database': {'new_opt': 'new_val'}}
        lines = self._write_and_read(values, template)
        text = ''.join(lines)
        self.assertIn('new_opt = new_val', text)
        db_idx = text.index('[database]')
        new_idx = text.index('new_opt = new_val')
        self.assertGreater(new_idx, db_idx)

    def test_section_not_in_template_appended(self):
        """Values for a section not in the template get appended."""
        template = "[DEFAULT]\n#key = val\n"
        values = {'new_section': {'opt1': 'val1'}}
        lines = self._write_and_read(values, template)
        text = ''.join(lines)
        self.assertIn('[new_section]', text)
        self.assertIn('opt1 = val1', text)

    def test_default_values_appended_without_header(self):
        """DEFAULT values appended without section header when template
        has no [DEFAULT].
        """
        template = "[database]\n#connection = none\n"
        values = {'DEFAULT': {'transport_url': 'rabbit://host'}}
        lines = self._write_and_read(values, template)
        text = ''.join(lines)
        self.assertIn('transport_url = rabbit://host', text)
        self.assertNotIn('[DEFAULT]', text)

    def test_multiple_sections(self):
        """Values placed in correct sections."""
        template = ("[DEFAULT]\n#a = 1\n\n"
                    "[sec1]\n#b = 2\n\n"
                    "[sec2]\n#c = 3\n")
        values = {
            'DEFAULT': {'a': 'A'},
            'sec1': {'b': 'B'},
            'sec2': {'c': 'C'},
        }
        lines = self._write_and_read(values, template)
        text = ''.join(lines)
        self.assertGreater(text.index('a = A'), text.index('[DEFAULT]'))
        self.assertGreater(text.index('b = B'), text.index('[sec1]'))
        self.assertGreater(text.index('c = C'), text.index('[sec2]'))

    def test_value_written_only_once(self):
        """Each value should appear exactly once even if option appears
        multiple times in comments.
        """
        template = ("[DEFAULT]\n"
                    "# Description line\n"
                    "#myopt = default1\n"
                    "# Another description\n"
                    "#myopt = default2\n")
        values = {'DEFAULT': {'myopt': 'override'}}
        lines = self._write_and_read(values, template)
        count = sum(1 for line in lines
                    if line.strip() == 'myopt = override')
        self.assertEqual(count, 1)

    def test_with_live_keystone_conf_and_trixie_template(self):
        """Integration: read live keystone.conf, write with trixie
        template.
        """
        conf_path = "/etc/keystone/keystone.conf"
        tmpl_path = os.path.join(SCRIPT_DIR, "keystone.conf-trixie.j2")
        if not os.path.exists(conf_path):
            self.skipTest("keystone.conf not found")
        if not os.access(conf_path, os.R_OK):
            self.skipTest("keystone.conf not readable (need sudo)")
        if not os.path.exists(tmpl_path):
            self.skipTest("trixie template not found")

        hook = _create_hook()
        values = hook._read_config_values(conf_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as out:
            out_path = out.name
        try:
            hook._write_config(values, out_path, tmpl_path)
            with open(out_path, 'r') as f:
                content = f.read()
            self.assertNotIn('{{', content)
            for section in values:
                for opt, val in values[section].items():
                    self.assertIn('%s = %s' % (opt, val), content)
        finally:
            os.unlink(out_path)

    def test_with_live_barbican_conf_and_trixie_template(self):
        """Integration: read live barbican.conf, write with trixie
        template.
        """
        conf_path = "/etc/barbican/barbican.conf"
        tmpl_path = os.path.join(SCRIPT_DIR, "barbican.conf-trixie.j2")
        if not os.path.exists(conf_path):
            self.skipTest("barbican.conf not found")
        if not os.access(conf_path, os.R_OK):
            self.skipTest("barbican.conf not readable (need sudo)")
        if not os.path.exists(tmpl_path):
            self.skipTest("trixie template not found")

        hook = _create_hook()
        values = hook._read_config_values(conf_path)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as out:
            out_path = out.name
        try:
            hook._write_config(values, out_path, tmpl_path)
            with open(out_path, 'r') as f:
                content = f.read()
            self.assertNotIn('{{', content)
            for section in values:
                for opt, val in values[section].items():
                    self.assertIn('%s = %s' % (opt, val), content)
        finally:
            os.unlink(out_path)


class TestGenerateConf(unittest.TestCase):
    """Tests for OpenstackConfHook._generate_conf()."""

    def test_generates_conf_with_values(self):
        """_generate_conf writes template with old values applied."""
        test_dir = tempfile.mkdtemp()
        try:
            live = os.path.join(test_dir, "test.conf")
            tmpl = os.path.join(test_dir, "test.j2")
            dest = os.path.join(test_dir, "output.conf")

            with open(live, 'w') as f:
                f.write("[DEFAULT]\nkey = myval\n")
            with open(tmpl, 'w') as f:
                f.write("[DEFAULT]\n#key = default\n")

            hook = _create_hook()
            hook._generate_conf(live, tmpl, dest,
                                OpenstackConfHook.RELEASE_N1,
                                OpenstackConfHook.RELEASE_N)

            with open(dest, 'r') as f:
                content = f.read()
            self.assertIn("#key = default", content)
            self.assertIn("key = myval", content)
        finally:
            shutil.rmtree(test_dir)

    def test_applies_exclusions(self):
        """_generate_conf filters excluded values."""
        test_dir = tempfile.mkdtemp()
        try:
            live = os.path.join(test_dir, "keystone.conf")
            tmpl = os.path.join(test_dir, "test.j2")
            dest = os.path.join(test_dir, "output.conf")

            with open(live, 'w') as f:
                f.write("[DEFAULT]\nkey = val\n[ldap]\nuse_pool = False\n")
            with open(tmpl, 'w') as f:
                f.write("[DEFAULT]\n#key = default\n[ldap]\n#use_pool = true\n")

            hook = _create_hook()
            hook._generate_conf(live, tmpl, dest,
                                OpenstackConfHook.RELEASE_N1,
                                OpenstackConfHook.RELEASE_N)

            with open(dest, 'r') as f:
                content = f.read()
            self.assertIn("key = val", content)
            self.assertNotIn("use_pool = False", content)
        finally:
            shutil.rmtree(test_dir)

    def test_raises_on_empty_conf(self):
        """_generate_conf raises when conf has no values."""
        test_dir = tempfile.mkdtemp()
        try:
            live = os.path.join(test_dir, "test.conf")
            tmpl = os.path.join(test_dir, "test.j2")
            dest = os.path.join(test_dir, "output.conf")

            with open(live, 'w') as f:
                f.write("")
            with open(tmpl, 'w') as f:
                f.write("[DEFAULT]\n")

            hook = _create_hook()
            with self.assertRaises(RuntimeError):
                hook._generate_conf(live, tmpl, dest,
                                    OpenstackConfHook.RELEASE_N1,
                                    OpenstackConfHook.RELEASE_N)
        finally:
            shutil.rmtree(test_dir)

    def test_skips_exclusions_when_releases_none(self):
        """_generate_conf skips exclusions when releases are None."""
        test_dir = tempfile.mkdtemp()
        try:
            live = os.path.join(test_dir, "keystone.conf")
            tmpl = os.path.join(test_dir, "test.j2")
            dest = os.path.join(test_dir, "output.conf")

            with open(live, 'w') as f:
                f.write("[DEFAULT]\nkey = val\n[ldap]\nuse_pool = False\n")
            with open(tmpl, 'w') as f:
                f.write("[DEFAULT]\n#key = default\n[ldap]\n#use_pool = true\n")

            hook = _create_hook()
            hook._generate_conf(live, tmpl, dest, None, None)

            with open(dest, 'r') as f:
                content = f.read()
            self.assertIn("use_pool = False", content)
        finally:
            shutil.rmtree(test_dir)

    def test_warns_on_remaining_jinja2(self):
        """_generate_conf warns when Jinja2 placeholders remain."""
        test_dir = tempfile.mkdtemp()
        try:
            live = os.path.join(test_dir, "test.conf")
            tmpl = os.path.join(test_dir, "test.j2")
            dest = os.path.join(test_dir, "output.conf")

            with open(live, 'w') as f:
                f.write("[DEFAULT]\nkey = val\n")
            with open(tmpl, 'w') as f:
                f.write("[DEFAULT]\n#key = default\n"
                        "other = {{ some_variable }}\n")

            hook = _create_hook()
            with unittest.mock.patch.object(
                    agent_hooks, 'LOG') as mock_log:
                hook._generate_conf(live, tmpl, dest, None, None)
                mock_log.warning.assert_called()
        finally:
            shutil.rmtree(test_dir)


class TestDeployHostInstall(unittest.TestCase):
    """Tests for OpenstackConfHook._deploy_host_install()."""

    def _create_ostree_dir(self, test_dir):
        """Create a mock ostree directory with template and conf."""
        ostree = os.path.join(test_dir, "ostree1")
        tmpl_dir = os.path.join(ostree, OpenstackConfHook.TEMPLATE_BASE,
                                "keystone")
        os.makedirs(tmpl_dir)
        with open(os.path.join(tmpl_dir, "keystone.conf-trixie.j2"),
                  'w') as f:
            f.write("[DEFAULT]\n#key = default\n[database]\n"
                    "#connection = none\n")
        barb_tmpl_dir = os.path.join(ostree,
                                     OpenstackConfHook.TEMPLATE_BASE)
        with open(os.path.join(barb_tmpl_dir, "barbican.conf-trixie.j2"),
                  'w') as f:
            f.write("[DEFAULT]\n#host_href = http://controller:9311\n")
        ks_dir = os.path.join(ostree, "etc/keystone")
        os.makedirs(ks_dir)
        with open(os.path.join(ks_dir, "keystone.conf"), 'w') as f:
            f.write("[DEFAULT]\nplaceholder = yes\n")
        barb_dir = os.path.join(ostree, "etc/barbican")
        os.makedirs(barb_dir)
        with open(os.path.join(barb_dir, "barbican.conf"), 'w') as f:
            f.write("[DEFAULT]\nplaceholder = yes\n")
        return ostree

    def test_installs_generated_conf(self):
        """_deploy_host_install generates and installs conf files."""
        test_dir = tempfile.mkdtemp()
        try:
            ostree = self._create_ostree_dir(test_dir)
            ks_live = "/etc/keystone/keystone.conf"
            barb_live = "/etc/barbican/barbican.conf"
            if not os.path.exists(ks_live):
                self.skipTest("keystone.conf not found")
            if not os.access(ks_live, os.R_OK):
                self.skipTest("keystone.conf not readable (need sudo)")
            if not os.path.exists(barb_live):
                self.skipTest("barbican.conf not found")

            hook = _create_hook()
            hook._deploy_host_install(ostree,
                                      OpenstackConfHook.RELEASE_N1,
                                      OpenstackConfHook.RELEASE_N)

            dst = os.path.join(ostree, "etc/keystone/keystone.conf")
            with open(dst, 'r') as f:
                content = f.read()
            self.assertNotIn("placeholder", content)
            self.assertNotIn("{{", content)

            backup = dst + OpenstackConfHook.BACKUP_SUFFIX
            self.assertTrue(os.path.exists(backup))
        finally:
            shutil.rmtree(test_dir)

    def test_skips_missing_live_conf(self):
        """_deploy_host_install skips when live conf doesn't exist."""
        test_dir = tempfile.mkdtemp()
        try:
            ostree = self._create_ostree_dir(test_dir)
            fake_map = {
                "keystone.conf": ("/nonexistent/keystone.conf",
                                  "keystone/keystone.conf-trixie.j2"),
            }
            hook = _create_hook()
            with unittest.mock.patch.object(
                    OpenstackConfHook, 'CONF_FILE_MAP', fake_map):
                hook._deploy_host_install(ostree,
                                          OpenstackConfHook.RELEASE_N1,
                                          OpenstackConfHook.RELEASE_N)
        finally:
            shutil.rmtree(test_dir)

    def test_skips_missing_template(self):
        """_deploy_host_install skips when template doesn't exist."""
        test_dir = tempfile.mkdtemp()
        try:
            ostree = self._create_ostree_dir(test_dir)
            live_path = os.path.join(test_dir, "keystone.conf")
            with open(live_path, 'w') as f:
                f.write("[DEFAULT]\nkey = val\n")
            fake_map = {
                "keystone.conf": (live_path,
                                  "nonexistent/template.j2"),
            }
            hook = _create_hook()
            with unittest.mock.patch.object(
                    OpenstackConfHook, 'CONF_FILE_MAP', fake_map):
                hook._deploy_host_install(ostree,
                                          OpenstackConfHook.RELEASE_N1,
                                          OpenstackConfHook.RELEASE_N)
        finally:
            shutil.rmtree(test_dir)


class TestDeployHostRestore(unittest.TestCase):
    """Tests for OpenstackConfHook._deploy_host_restore()."""

    def test_restores_from_backup(self):
        """_deploy_host_restore restores conf from backup."""
        test_dir = tempfile.mkdtemp()
        try:
            ostree = os.path.join(test_dir, "ostree1")
            ks_dir = os.path.join(ostree, "etc/keystone")
            os.makedirs(ks_dir)

            dst = os.path.join(ks_dir, "keystone.conf")
            backup = dst + OpenstackConfHook.BACKUP_SUFFIX

            with open(backup, 'w') as f:
                f.write("[DEFAULT]\noriginal = yes\n")
            with open(dst, 'w') as f:
                f.write("[DEFAULT]\nmodified = yes\n")

            fake_map = {
                "keystone.conf": ("/etc/keystone/keystone.conf",
                                  "keystone/keystone.conf-trixie.j2"),
            }
            hook = _create_hook()
            with unittest.mock.patch.object(
                    OpenstackConfHook, 'CONF_FILE_MAP', fake_map):
                hook._deploy_host_restore(ostree)

            with open(dst, 'r') as f:
                content = f.read()
            self.assertIn("original = yes", content)
        finally:
            shutil.rmtree(test_dir)

    def test_warns_missing_backup(self):
        """_deploy_host_restore warns when backup doesn't exist."""
        test_dir = tempfile.mkdtemp()
        try:
            ostree = os.path.join(test_dir, "ostree1")
            ks_dir = os.path.join(ostree, "etc/keystone")
            os.makedirs(ks_dir)
            dst = os.path.join(ks_dir, "keystone.conf")
            with open(dst, 'w') as f:
                f.write("[DEFAULT]\n")

            fake_map = {
                "keystone.conf": ("/etc/keystone/keystone.conf",
                                  "keystone/keystone.conf-trixie.j2"),
            }
            hook = _create_hook()
            with unittest.mock.patch.object(
                    OpenstackConfHook, 'CONF_FILE_MAP', fake_map), \
                 unittest.mock.patch.object(
                    agent_hooks, 'LOG') as mock_log:
                hook._deploy_host_restore(ostree)
                mock_log.warning.assert_called()
        finally:
            shutil.rmtree(test_dir)


class TestExclusions(unittest.TestCase):
    """Tests for _get_exclusions() and _apply_exclusions()."""

    def test_get_exclusions_known_pair(self):
        """Returns exclusions for a known release pair."""
        hook = _create_hook()
        excl = hook._get_exclusions(OpenstackConfHook.RELEASE_N1,
                                    OpenstackConfHook.RELEASE_N,
                                    "keystone.conf")
        self.assertTrue(len(excl) > 0)
        sections = [s for s, o, r in excl]
        self.assertIn("ldap", sections)

    def test_get_exclusions_unknown_pair(self):
        """Returns empty list for unknown release pair."""
        hook = _create_hook()
        excl = hook._get_exclusions("99.99", "99.99", "keystone.conf")
        self.assertEqual(excl, [])

    def test_get_exclusions_unknown_conf(self):
        """Returns empty list for unknown conf file."""
        hook = _create_hook()
        excl = hook._get_exclusions(OpenstackConfHook.RELEASE_N1,
                                    OpenstackConfHook.RELEASE_N,
                                    "unknown.conf")
        self.assertEqual(excl, [])

    def test_apply_exclusions_removes_value(self):
        """_apply_exclusions removes matching values."""
        hook = _create_hook()
        values = {'DEFAULT': {'key1': 'val1'},
                  'ldap': {'use_pool': 'False', 'other': 'x'}}
        exclusions = [('ldap', 'use_pool', 'test reason')]
        hook._apply_exclusions(values, exclusions, "test.conf")
        self.assertNotIn('use_pool', values.get('ldap', {}))
        self.assertIn('other', values['ldap'])

    def test_apply_exclusions_removes_empty_section(self):
        """_apply_exclusions removes section if it becomes empty."""
        hook = _create_hook()
        values = {'ldap': {'use_pool': 'False'}}
        exclusions = [('ldap', 'use_pool', 'test reason')]
        hook._apply_exclusions(values, exclusions, "test.conf")
        self.assertNotIn('ldap', values)

    def test_apply_exclusions_warns_if_not_present(self):
        """_apply_exclusions logs warning if value not in conf."""
        hook = _create_hook()
        values = {'DEFAULT': {'key1': 'val1'}}
        exclusions = [('ldap', 'use_pool', 'test reason')]
        with unittest.mock.patch.object(
                agent_hooks, 'LOG') as mock_log:
            hook._apply_exclusions(values, exclusions, "test.conf")
            mock_log.warning.assert_called_once()


class TestReadConfigValues(unittest.TestCase):
    """Tests for OpenstackConfHook._read_config_values()."""

    def test_reads_default_section(self):
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("[DEFAULT]\nkey1 = val1\nkey2 = val2\n")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertIn('DEFAULT', values)
                self.assertEqual(values['DEFAULT']['key1'], 'val1')
            finally:
                os.unlink(f.name)

    def test_reads_named_section(self):
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("[DEFAULT]\n\n[database]\nconnection = foo\n")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertIn('database', values)
                self.assertEqual(values['database']['connection'], 'foo')
            finally:
                os.unlink(f.name)

    def test_section_values_exclude_defaults(self):
        """Section values should not include inherited DEFAULT values."""
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("[DEFAULT]\nglobal_opt = g\n\n"
                    "[section1]\nlocal_opt = l\n")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertIn('section1', values)
                self.assertIn('local_opt', values['section1'])
                self.assertNotIn('global_opt', values['section1'])
            finally:
                os.unlink(f.name)

    def test_section_override_of_default_preserved(self):
        """Section value that overrides DEFAULT should be preserved."""
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("[DEFAULT]\ndebug = false\n\n"
                    "[myservice]\ndebug = true\n")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertIn('myservice', values)
                self.assertEqual(values['myservice']['debug'], 'true')
            finally:
                os.unlink(f.name)

    def test_empty_file(self):
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertEqual(values, {})
            finally:
                os.unlink(f.name)

    def test_comments_ignored(self):
        hook = _create_hook()
        with tempfile.NamedTemporaryFile(mode='w', suffix='.conf',
                                         delete=False) as f:
            f.write("[DEFAULT]\n#commented = yes\nactive = no\n")
            f.flush()
            try:
                values = hook._read_config_values(f.name)
                self.assertNotIn('commented', values.get('DEFAULT', {}))
                self.assertEqual(values['DEFAULT']['active'], 'no')
            finally:
                os.unlink(f.name)

    def test_reads_live_keystone_conf(self):
        """Read the actual keystone.conf on this system."""
        path = "/etc/keystone/keystone.conf"
        if not os.path.exists(path):
            self.skipTest("keystone.conf not found")
        if not os.access(path, os.R_OK):
            self.skipTest("keystone.conf not readable (need sudo)")
        hook = _create_hook()
        values = hook._read_config_values(path)
        self.assertIn('DEFAULT', values)
        self.assertIn('database', values)

    def test_reads_live_barbican_conf(self):
        """Read the actual barbican.conf on this system."""
        path = "/etc/barbican/barbican.conf"
        if not os.path.exists(path):
            self.skipTest("barbican.conf not found")
        if not os.access(path, os.R_OK):
            self.skipTest("barbican.conf not readable (need sudo)")
        hook = _create_hook()
        values = hook._read_config_values(path)
        self.assertIn('database', values)
        self.assertIn('connection', values['database'])


if __name__ == "__main__":
    unittest.main()
