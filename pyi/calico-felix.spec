# -*- mode: python -*-

block_cipher = None

extra_files = [
    ('/usr/local/lib/python2.7/site-packages/posix_spawn/c/*', 'posix_spawn/c'),
]

# Add egg metadata for our package and dependencies.
from PyInstaller.utils.hooks import copy_metadata
import re
extra_files += copy_metadata("calico")
with open("../felix_requirements.txt") as reqs:
    for line in reqs:
        m = re.match(r'^((?:[-_]|\w)+)', line)
        if m:
            print "Adding dependency files", m.group(1)
            extra_files += copy_metadata(m.group(1))

# Find the pre-compiled posix-spawn CFFI library.
import glob
import sys
import os.path
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
