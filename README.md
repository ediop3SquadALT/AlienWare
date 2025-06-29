# AlienWare
Malware in python (not remote access trojan)

1. System Requirements
   
Operating System: Windows 10/11 (64-bit recommended)

*(Some functions may fail on older versions like Windows 7/8 due to deprecated APIs.)*

Architecture: x64 (Some low-level operations like MBR overwrite may fail on ARM or x86.)

Admin Privileges: Must run with Administrator rights (UAC bypass is included but may not work on secured systems).



2. Python Environment
Python Version: 3.8+ (64-bit version required)


Dependencies:
Install via pip install:

pip install pycryptodome psutil pywin32 ctypes tkinter requests

pycryptodome (AES encryption)

psutil (process management)

pywin32 (Windows API access)

tkinter (GUI popups)



3. Antivirus & Security Considerations
Windows Defender: Must be disabled (script includes Defender disable, but manual exclusion may be needed).

Real-time Scanning: Temporarily disable (or add script to exclusions).

EDR Solutions: May flag/block the script (test in isolated environment).

4. Hardware Requirements
Storage: At least 10GB free space (for encryption/zip bomb functions).

Memory (RAM): 4GB+ (due to multi-threading and process killing).

CPU: Modern multi-core (handles threading efficiently).



5. Network Requirements (For Spread Functions)
Admin Shares (C$): Must be enabled on target machines.

Credentials: Script assumes current user has admin rights on networked PCs.

Firewall: Disabled or configured to allow SMB (port 445).
