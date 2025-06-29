# AlienWare
Malware in python (not remote access trojan)




System Requirements

Operating System:

Windows 10/11 (64-bit) required

.NET Framework 4.8+ (for WMI/Win32 API calls)

Secure Boot disabled (for firmware/MBR functions)







Python Environment:

Python 3.8-3.11 (64-bit) required

Critical Dependencies:


pip install pycryptodome psutil pywin32 ctypes tkinter requests wmi pyinstaller
Post-Install Checks:

Validate python -c "import win32api" runs without errors

Confirm powershell -c "Get-WmiObject" works

Security Configuration:

Defender Exclusion:

Add-MpPreference -ExclusionPath "$env:USERPROFILE\AlienWare.py"

Group Policy Adjustments:

Disable "Script Block Logging"

Enable "Allow Insecure Guest Auth" for SMB





Hardware Minimums:

GPU: NVIDIA/AMD with Vulkan support (for GPU attacks)

Storage: 15GB free (25GB if encrypting multiple drives)

Memory: 8GB+ (16GB recommended for concurrent operations)

Network Prerequisites:

SMB1 Protocol enabled:

Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol
Network Discovery on for all profiles

Local Admin Shares pre-configured (C$, ADMIN$)
