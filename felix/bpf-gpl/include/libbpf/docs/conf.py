#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0
# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import subprocess

project = "libbpf"

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.doctest',
    'sphinx.ext.mathjax',
    'sphinx.ext.viewcode',
    'sphinx.ext.imgmath',
    'sphinx.ext.todo',
    'breathe',
]

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []

read_the_docs_build = os.environ.get('READTHEDOCS', None) == 'True'

if read_the_docs_build:
    subprocess.call('cd sphinx ; make clean', shell=True)
    subprocess.call('cd sphinx/doxygen ; doxygen', shell=True)

html_theme = 'sphinx_rtd_theme'

breathe_projects = { "libbpf": "./sphinx/doxygen/build/xml/" }
breathe_default_project = "libbpf"
breathe_show_define_initializer = True
breathe_show_enumvalue_initializer = True
