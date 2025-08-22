# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['advanced_gui_sniffer.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('pinaka_icon.ico', '.'),
        ('pinaka_logo_new.png', '.'),
        ('README.md', '.'),
    ],
    hiddenimports=[
        'scapy.all',
        'ipwhois',
        'requests',
        'sqlite3',
        'tkinter',
        'tkinter.ttk',
        'tkinter.scrolledtext',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'threading',
        'queue',
        'json',
        'datetime',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='Pinaka',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='pinaka_icon.ico',
    version_file='version_info.txt'
)