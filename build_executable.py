#!/usr/bin/env python3
"""
Build script for creating Pinaka executable with proper icon integration
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def create_spec_file():
    """Create PyInstaller spec file with icon configuration"""
    spec_content = '''
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
'''
    
    with open('Pinaka.spec', 'w') as f:
        f.write(spec_content.strip())
    
    print("✅ Created Pinaka.spec file")

def create_version_info():
    """Create version info file for Windows executable"""
    version_content = '''
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'Pinaka Project'),
        StringStruct(u'FileDescription', u'Pinaka - Advanced Packet Analyzer'),
        StringStruct(u'FileVersion', u'1.0.0.0'),
        StringStruct(u'InternalName', u'Pinaka'),
        StringStruct(u'LegalCopyright', u'Copyright © 2025 Pinaka Project'),
        StringStruct(u'OriginalFilename', u'Pinaka.exe'),
        StringStruct(u'ProductName', u'Pinaka Packet Analyzer'),
        StringStruct(u'ProductVersion', u'1.0.0.0')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''
    
    with open('version_info.txt', 'w') as f:
        f.write(version_content.strip())
    
    print("✅ Created version_info.txt file")

def build_executable():
    """Build the executable using PyInstaller"""
    print("🔨 Building Pinaka executable...")
    
    # Check if required files exist
    required_files = [
        'advanced_gui_sniffer.py',
        'pinaka_icon.ico',
        'pinaka_logo_new.png',
        'README.md'
    ]
    
    missing_files = []
    for file in required_files:
        if not os.path.exists(file):
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    # Create spec and version files
    create_spec_file()
    create_version_info()
    
    # Run PyInstaller
    try:
        cmd = ['pyinstaller', '--clean', 'Pinaka.spec']
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Build completed successfully!")
            
            # Check if executable was created
            exe_path = os.path.join('dist', 'Pinaka.exe')
            if os.path.exists(exe_path):
                file_size = os.path.getsize(exe_path) / (1024 * 1024)  # MB
                print(f"📦 Executable created: {exe_path} ({file_size:.1f} MB)")
                
                # Create distribution folder
                dist_folder = 'Pinaka_Distribution'
                if os.path.exists(dist_folder):
                    shutil.rmtree(dist_folder)
                os.makedirs(dist_folder)
                
                # Copy files to distribution
                shutil.copy2(exe_path, dist_folder)
                shutil.copy2('README.md', dist_folder)
                shutil.copy2('pinaka_logo_new.png', dist_folder)
                
                # Create installation instructions
                install_instructions = '''
# Pinaka - Advanced Packet Analyzer

## Installation Instructions

1. **Prerequisites:**
   - Windows 10/11 (64-bit)
   - Administrator privileges required for packet capture
   - Npcap (recommended) - Download from: https://nmap.org/npcap/

2. **Installation:**
   - Extract all files to a folder (e.g., C:\\Pinaka)
   - Right-click on Pinaka.exe and select "Run as administrator"

3. **First Run:**
   - The application will request administrator privileges
   - Allow Windows Firewall access if prompted
   - Select your network interface for packet capture

4. **Features:**
   - Real-time packet capture and analysis
   - AI-powered threat detection
   - Advanced filtering and search
   - Export to PCAP format
   - Detailed protocol analysis

## Support

For issues or questions, please refer to the README.md file.

## Legal Notice

This tool is for educational and legitimate network analysis purposes only.
Ensure you have proper authorization before analyzing network traffic.
'''
                
                with open(os.path.join(dist_folder, 'INSTALL.txt'), 'w') as f:
                    f.write(install_instructions.strip())
                
                print(f"📁 Distribution package created: {dist_folder}/")
                print("🎉 Build process completed!")
                return True
            else:
                print("❌ Executable not found after build")
                return False
        else:
            print(f"❌ Build failed: {result.stderr}")
            return False
            
    except FileNotFoundError:
        print("❌ PyInstaller not found. Please install with: pip install pyinstaller")
        return False
    except Exception as e:
        print(f"❌ Build error: {e}")
        return False

def main():
    """Main build function"""
    print("🏹 Pinaka Executable Builder")
    print("=" * 40)
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("❌ Python 3.7 or higher required")
        return
    
    # Check if we're in the right directory
    if not os.path.exists('advanced_gui_sniffer.py'):
        print("❌ Please run this script from the Pinaka project directory")
        return
    
    # Build executable
    success = build_executable()
    
    if success:
        print("\n🎯 Next Steps:")
        print("1. Test the executable: ./Pinaka_Distribution/Pinaka.exe")
        print("2. Install Npcap if not already installed")
        print("3. Run as administrator for packet capture")
        print("4. Distribute the Pinaka_Distribution folder")
    else:
        print("\n❌ Build failed. Please check the error messages above.")

if __name__ == "__main__":
    main()

