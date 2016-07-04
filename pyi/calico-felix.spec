# -*- mode: python -*-
# -*- coding: utf-8 -*-
# Copyright (c) 2015 Tigera, Inc. All rights reserved.
# Copyright 2015 Cisco Systems
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# PyInstaller .spec file for building the bundle.  This file is actually a
# Python file,  which is run with various pre-defined variables.
from PyInstaller.utils.hooks import copy_metadata
import re
import glob
import sys
import os.path

block_cipher = None

# Additional data files that need to be in the archive.  List of tuples; first
# item in each tuple is a GLOB, second is the directory to put the files in.
extra_files = [
    ('/usr/local/lib/python2.7/site-packages/posix_spawn/c/*',
     'posix_spawn/c'),
    ('../version.txt', ''),
]

# Add egg metadata for our package and dependencies.  Required to allow us to
# look up our plugins.
extra_files += copy_metadata("calico")
with open("../felix_requirements.txt") as reqs:
    for line in reqs:
        m = re.match(r'^((?:[-_]|\w)+)', line)
        if m:
            print "Adding dependency files", m.group(1)
            extra_files += copy_metadata(m.group(1))

# Find the pre-compiled posix-spawn CFFI library.  It has a hash in its name
# so we need to glob for it.
cffi_mods = glob.glob("/usr/local/lib/python2.7/site-packages/_posix_spawn_cffi*")
if len(cffi_mods) != 1:
    print >> sys.stderr, "Failed to find posix_spawn cffi module"
    sys.exit(1)
else:
    posix_spawn_so = os.path.basename(cffi_mods[0])
    posix_spawn = posix_spawn_so.split(".")[0]

hidden_imports = [
    "calico.felix.plugins.fiptgenerator",
    "_cffi_backend",
    posix_spawn,
]

extra_binaries = [

]

a = Analysis([os.path.join(HOMEPATH,'calico/pyilauncher.py')],
             pathex=['/code/pyi'],
             binaries=extra_binaries,
             datas=extra_files,
             hiddenimports=hidden_imports,
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='calico-felix',
          debug=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='calico-felix')
