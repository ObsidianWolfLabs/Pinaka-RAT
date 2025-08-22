# 🏹 Pinaka EXE Build Guide - Complete Tutorial

## Prerequisites

### 1. Python Installation
- **Python 3.7+** (recommended: Python 3.9 or 3.10)
- Download from: https://www.python.org/downloads/
- ⚠️ **Important**: Check "Add Python to PATH" during installation

### 2. Administrator Privileges
- Required for packet capture functionality
- Run all commands as Administrator

### 3. Npcap Installation (Recommended)
- Download from: https://nmap.org/npcap/
- Install with "WinPcap API-compatible Mode" checked

## Step 1: Setup Project Directory

```powershell
# Create project directory
mkdir C:\Pinaka
cd C:\Pinaka

# Extract your project files here
# Your directory should contain:
# - advanced_gui_sniffer.py
# - build_executable.py
# - pinaka_logo_new.png
# - pinaka_icon.png
# - pinaka_icon.ico
# - README.md
```

## Step 2: Install Required Dependencies

```powershell
# Open PowerShell as Administrator
# Navigate to your project directory
cd C:\Pinaka

# Upgrade pip first
python -m pip install --upgrade pip

# Install required packages
pip install scapy
pip install pyinstaller
pip install requests
pip install ipwhois
pip install pillow

# Verify installations
python -c "import scapy; print('Scapy installed successfully')"
python -c "import PyInstaller; print('PyInstaller installed successfully')"
```

## Step 3: Test Python Script First

```powershell
# Test the Python script before building
python advanced_gui_sniffer.py

# If you get permission errors, run as Administrator:
# Right-click PowerShell -> "Run as Administrator"
```

## Step 4: Build the Executable

### Method A: Using the Build Script (Recommended)

```powershell
# Run the automated build script
python build_executable.py
```

### Method B: Manual PyInstaller Command

```powershell
# Create the executable manually
pyinstaller --onefile --windowed --icon=pinaka_icon.ico --name="Pinaka" advanced_gui_sniffer.py

# Or with more options:
pyinstaller ^
    --onefile ^
    --windowed ^
    --icon=pinaka_icon.ico ^
    --name="Pinaka" ^
    --add-data="pinaka_logo_new.png;." ^
    --add-data="pinaka_icon.ico;." ^
    --add-data="README.md;." ^
    --hidden-import=scapy.all ^
    --hidden-import=ipwhois ^
    --hidden-import=requests ^
    --hidden-import=tkinter ^
    --hidden-import=sqlite3 ^
    advanced_gui_sniffer.py
```

## Step 5: Advanced Build Configuration

### Create Custom Spec File

```python
# Create Pinaka.spec file for advanced configuration
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
        'scapy.layers.inet',
        'scapy.layers.dns',
        'scapy.layers.http',
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
        'time',
        'os',
        'sys',
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
    console=False,  # Set to True for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='pinaka_icon.ico',
    version_file='version_info.txt'
)
```

### Create Version Info File

```python
# Create version_info.txt
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
```

### Build with Spec File

```powershell
# Build using the spec file
pyinstaller --clean Pinaka.spec
```

## Step 6: Troubleshooting Common Issues

### Issue 1: Missing Modules
```powershell
# If you get "ModuleNotFoundError"
pip install missing_module_name

# Add to hidden imports in spec file
hiddenimports=['missing_module_name']
```

### Issue 2: Icon Not Showing
```powershell
# Ensure icon file exists and is in ICO format
# Convert PNG to ICO if needed using online converter
# Or use ImageMagick:
magick pinaka_icon.png pinaka_icon.ico
```

### Issue 3: Large EXE Size
```powershell
# Use UPX to compress (optional)
# Download UPX from: https://upx.github.io/
# Add to spec file: upx=True

# Or exclude unnecessary modules
excludes=['matplotlib', 'numpy', 'pandas']  # if not used
```

### Issue 4: Antivirus False Positive
```powershell
# Add exclusion in Windows Defender
# Go to: Windows Security > Virus & threat protection > Exclusions
# Add your project folder and the built EXE
```

### Issue 5: Permission Errors
```powershell
# Always run as Administrator
# Right-click PowerShell -> "Run as Administrator"

# Or use runas command
runas /user:Administrator "cmd /c cd C:\Pinaka && python build_executable.py"
```

## Step 7: Testing the Executable

```powershell
# Navigate to dist folder
cd dist

# Test the executable
.\Pinaka.exe

# If it doesn't work, try console mode for debugging
# Change console=False to console=True in spec file
# Rebuild and check error messages
```

## Step 8: Distribution Package

### Create Distribution Folder
```powershell
# Create distribution package
mkdir Pinaka_Distribution
copy dist\Pinaka.exe Pinaka_Distribution\
copy README.md Pinaka_Distribution\
copy pinaka_logo_new.png Pinaka_Distribution\

# Create installation instructions
echo "Installation Instructions" > Pinaka_Distribution\INSTALL.txt
```

### Create Installer (Optional)

#### Using Inno Setup
1. Download Inno Setup: https://jrsoftware.org/isinfo.php
2. Create installer script:

```pascal
[Setup]
AppName=Pinaka Advanced Packet Analyzer
AppVersion=1.0
DefaultDirName={pf}\Pinaka
DefaultGroupName=Pinaka
OutputDir=installer
OutputBaseFilename=PinakaInstaller
SetupIconFile=pinaka_icon.ico
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\Pinaka.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "pinaka_logo_new.png"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Pinaka"; Filename: "{app}\Pinaka.exe"
Name: "{commondesktop}\Pinaka"; Filename: "{app}\Pinaka.exe"

[Run]
Filename: "{app}\Pinaka.exe"; Description: "Launch Pinaka"; Flags: nowait postinstall skipifsilent
```

## Step 9: Final Checklist

### Before Distribution
- [ ] Test EXE on clean Windows machine
- [ ] Verify all features work
- [ ] Check icon appears correctly
- [ ] Test with different user permissions
- [ ] Scan with antivirus
- [ ] Create user documentation

### File Structure Check
```
Pinaka_Distribution/
├── Pinaka.exe                 # Main executable
├── README.md                  # Documentation
├── INSTALL.txt               # Installation guide
├── pinaka_logo_new.png       # Logo file
└── LICENSE                   # License file (optional)
```

## Step 10: Advanced Options

### Code Signing (Professional)
```powershell
# Get code signing certificate from CA
# Sign the executable
signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com Pinaka.exe
```

### Creating Portable Version
```powershell
# Build portable version (no installation required)
pyinstaller --onefile --portable advanced_gui_sniffer.py
```

### Multi-Architecture Build
```powershell
# For 32-bit systems
pyinstaller --target-arch=x86 Pinaka.spec

# For 64-bit systems (default)
pyinstaller --target-arch=x64 Pinaka.spec
```

## PowerShell Build Script

Create `build.ps1` for automated building:

```powershell
# build.ps1 - Automated build script
Write-Host "🏹 Building Pinaka Packet Analyzer..." -ForegroundColor Cyan

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "❌ Please run as Administrator" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Yellow
pip install scapy pyinstaller requests ipwhois pillow

# Clean previous builds
Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
if (Test-Path "build") { Remove-Item -Recurse -Force "build" }

# Build executable
Write-Host "🔨 Building executable..." -ForegroundColor Yellow
python build_executable.py

# Check if build was successful
if (Test-Path "dist\Pinaka.exe") {
    Write-Host "✅ Build completed successfully!" -ForegroundColor Green
    Write-Host "📍 Executable location: dist\Pinaka.exe" -ForegroundColor Cyan
    
    # Get file size
    $size = (Get-Item "dist\Pinaka.exe").Length / 1MB
    Write-Host "📏 File size: $([math]::Round($size, 2)) MB" -ForegroundColor Cyan
    
    # Test the executable
    Write-Host "🧪 Testing executable..." -ForegroundColor Yellow
    Start-Process "dist\Pinaka.exe" -NoNewWindow
} else {
    Write-Host "❌ Build failed!" -ForegroundColor Red
}
```

### Usage:
```powershell
# Run the build script
powershell -ExecutionPolicy Bypass -File build.ps1
```

## 🎉 Success!

If you've followed this guide, you should now have:
- ✅ A working `Pinaka.exe` file
- ✅ Proper icon integration
- ✅ All dependencies bundled
- ✅ Professional-looking executable
- ✅ Distribution-ready package

Your Pinaka packet analyzer is now ready to be shared and used on any Windows machine!

