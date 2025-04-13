# PE-Audit: Windows Privilege Escalation Checker
PE-Audit its a Powershell script that check for windows privilege escalation vector

Checks available... at the moment
- **User Privilege** (*Mitre T1134 - Access Token Manipulation*)
- **Permissive File System ACLs** (*Mitre T1574.005 - Hijack Execution Flow: Executable Installer File Permissions Weakness*)
- **Weak Service Permissions** (*Mitre T1574.010 - Hijack Execution Flow: Services File Permissions Weakness*)
- **Unquoted Service Path** (*Mitre T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path*)
- **Installed Applications**
- **Scheduled Task** (*Mitre T1053.005 - Scheduled Task/Job: Scheduled Task*)
- **Weak Registry permission** (*Mitre T1574.011 - Hijack Execution Flow: Services Registry Permissions Weakness*)
- **Registry AutoRun Keys** (*Mitre T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys*)
- **Autostart Execution Startup Folder** (*Mitre T1547.001 - Boot or Logon Autostart Execution: Startup Folder*)
- **AlwaysInstallElevated**
- **Stored Credentials**
- **Windows Registry Hives Backups**
- **Web Shell location** (*Mitre T1505.003 - Server Software Component: Web Shell*)

## How to use:
- Put `PE-Audit.ps1` and `accesschk.exe` in the same folder (ensure you have write permissions for the folder), and that's it!
https://download.sysinternals.com/files/AccessChk.zip

```
PS C:\tools> .\PE-Audit.ps1

::::: PE-Audit: Windows Privilege Escalation Checker :::::
by Lof1 ;)


[+] Current user: user

::::::::::Token Abusing: User Privilege (T1134)::::::::::

[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Permissive File System ACLs (T1574.005)::::::::::

[+] Checking Directories: C:\Program Files (x86) C:\Program Files
[+] Scanning C:\Program Files (x86) ...
[+] Scanning C:\Program Files ...
Insecure ACL for Service: filepermsvc
Service Path: "C:\Program Files\File Permissions Service\filepermservice.exe"

Insecure ACL for Executables:
C:\Program Files\Autorun Program\program.exe
C:\Program Files\File Permissions Service\filepermservice.exe
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Weak Service Permissions (T1574.010)::::::::::

[+] Total number of services: 213
[+] Checking services...
Insecure Service Found: daclsvc
Insecure Service Found: daclsvc
Insecure Service Found: daclsvc
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Unquoted Service Path (T1574.009)::::::::::

[+] Total number of services: 213
[+] Checking services...
Unquoted path found for service: AWSLiteAgent
Unquoted path found for service: unquotedsvc
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

:::::::::: Installed Applications ::::::::::

[+] Checking non-Microsoft Applications...
[+] Total number of Non-Microsoft Applications: 2

DisplayName
-----------
Amazon SSM Agent
Amazon SSM Agent
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Scheduled Task (T1053.005)::::::::::


::::::::::Possible Scheduled Task Scripts (T1053.005)::::::::::

[+] Scanning C:\DevTools ...
Insecure ACL for: C:\DevTools\CleanUp.ps1
[+] Scanning C:\PerfLogs ...
[+] Scanning C:\PrivEsc ...
[+] Scanning C:\Temp ...
[+] Scanning C:\Users ...
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Weak Registry permission (T1574.011)::::::::::

[+] Scanning "HKLM:\SYSTEM\CurrentControlSet\Services\"
Weak Registry permission found: HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\regsvc
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Boot or Logon Autostart Execution: Registry Run Keys (T1547.001)::::::::::

[+] Checking: HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Found Executable with weak ACL: C:\Program Files\Autorun Program\program.exe
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::AlwaysInstallElevated::::::::::

Found: HKLM:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated is ENABLED (1)
Found: HKCU:\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated is ENABLED (1)
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Boot or Logon Autostart Execution: Startup Folder (T1547.001)::::::::::

Global StartUp Folder with weak ACL: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Stored Credentials::::::::::

Stored credentials for users:
02nfpgrklkitqatu
WIN-QBA94KB3IOF\admin
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Windows Registry Hives Backups::::::::::

Backup folder: C:\Windows\Repair\



Name     Length LastWriteTime
----     ------ -------------
SAM       65536 2/27/2025 11:47:27 AM
SYSTEM 18591744 2/27/2025 11:47:26 AM


[+] Check Completed. Results saved in PE_Insecure_Findings.txt
PS C:\tools> 
```
