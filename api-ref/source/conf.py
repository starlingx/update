#
# SPDX-License-Identifier: Apache-2.0

# stx-update API reference documentation build configuration file
#
# This file is execfile()d with the current directory set to
# its containing dir.
#
# Note that not all possible configuration values are present in this
# autogenerated file.
#
# All configuration values have a default; values that are commented out
# serve to show the default.

import os
import sys

extensions = [
    'openstackdocstheme',
    'os_api_ref',
]

html_theme = 'starlingxdocs'

html_theme_options = {
    "sidebar_dropdown": "api_ref",
    "sidebar_mode": "toc",
}

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
sys.path.insert(0, os.path.abspath('../../'))
sys.path.insert(0, os.path.abspath('../'))
sys.path.insert(0, os.path.abspath('./'))

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'StarlingX Update'

# openstackdocstheme options
openstackdocs_repo_name = 'starlingx/update'
openstackdocs_use_storyboard = True
openstackdocs_auto_name = False

# If true, the current module name will be prepended to all description
# unit titles (such as .. function::).
add_module_names = False

# If true, sectionauthor and moduleauthor directives will be shown in the
# output. They are ignored by default.
show_authors = False

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'native'

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title, author, documentclass
# [howto/manual]).
latex_documents = [
    ('index', 'stx-update.tex', u'stx-update API Documentation',
     u'StarlingX', 'manual'),
]
