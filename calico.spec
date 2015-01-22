# -*- mode: python -*-
a = Analysis(['calico.py'],
             pathex=['/home/gulfstream/calico-docker'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name='calico',
          debug=False,
          strip=True,
          upx=True,
          console=True )
