# PE-Audit: Windows Privilege Escalation Checker
PE-Audit its a Powershell script that check for windows privilege escalation vector

Checks available... at the moment
- **Permissive File System ACLs** (*Mitre T1574.005 - Hijack Execution Flow: Executable Installer File Permissions Weakness*)
- **Weak Service Permissions** (*Mitre T1574.010 - Hijack Execution Flow: Services File Permissions Weakness*)
- **Unquoted Service Path** (*Mitre T1574.009 - Hijack Execution Flow: Path Interception by Unquoted Path*)

## How to use:
- Put `PE-Audit.ps1` and `accesschk.exe` in the same folder (ensure you have write permissions for the folder), and that's it!
https://download.sysinternals.com/files/AccessChk.zip

```
PS C:\tools> .\PE-Audit.ps1

::::: PE-Audit: Windows Privilege Escalation Checker :::::
by Lof1 ;)

::::::::::Permissive File System ACLs (T1574.005)::::::::::

[+] Checking Directories: C:\Program Files (x86) C:\Program Files
[+] Current user: htb-student
[+] Scanning C:\Program Files (x86) ...
Insecure ACL for: C:\Program Files (x86)\PCProtect\SecurityService.exe
[+] Scanning C:\Program Files ...
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Weak Service Permissions (T1574.010)::::::::::

[+] Total number of services: 271
[+] Checking services...
Insecure Service Found: WindscribeService
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Unquoted Service Path (T1574.009)::::::::::

[+] Total number of services: 271
[+] Checking services...
Unquoted path found for service: GVFS.Service
Unquoted path found for service: SystemExplorerHelpService
[+] Check Completed. Results saved in PE_Insecure_Findings.txt
PS C:\tools> 

```
