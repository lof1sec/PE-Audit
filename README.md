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

## How to use:
- Put `PE-Audit.ps1` and `accesschk.exe` in the same folder (ensure you have write permissions for the folder), and that's it!
https://download.sysinternals.com/files/AccessChk.zip

```
PS C:\tools> .\PE-Audit.ps1

::::: PE-Audit: Windows Privilege Escalation Checker :::::
by Lof1 ;)


[+] Current user: htb-student

::::::::::Token Abusing: User Privilege (T1134)::::::::::

[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Permissive File System ACLs (T1574.005)::::::::::

[+] Checking Directories: C:\Program Files (x86) C:\Program Files
[+] Scanning C:\Program Files (x86) ...
[+] Scanning C:\Program Files ...
Insecure ACL for service: SecurityService
Service Path: "C:\Program Files (x86)\PCProtect\SecurityService.exe"
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Weak Service Permissions (T1574.010)::::::::::

[+] Total number of services: 271
[+] Checking services...
Insecure Service Found: WindscribeService
Insecure Service Found: WindscribeService
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Unquoted Service Path (T1574.009)::::::::::

[+] Total number of services: 271
[+] Checking services...
Unquoted path found for service: GVFS.Service
Unquoted path found for service: SystemExplorerHelpService
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Installed Applications::::::::::

[+] Checking non-Microsoft Applications...
[+] Total number of Non-Microsft Applications: 10

DisplayName
-----------
Google Chrome
Npcap
PCProtect
Wireshark 3.4.4 64-bit
System Explorer 7.0.0
Druva inSync 6.6.3
Windscribe
FreeLAN 2.0.0
GVFS version 1.0.21014.1
VMware Tools
[+] Check Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Scheduled Task (T1053.005)::::::::::

TaskName: \Microsoft\Windows\CUAssistant\CULauncher \Microsoft\Windows\CUAssistant\CULauncher
---------------------------------
TaskName: \Microsoft\Windows\CUAssistant\CULauncher \Microsoft\Windows\CUAssistant\CULauncher
---------------------------------

::::::::::Possible Scheduled Task Scripts (T1053.005)::::::::::

[+] Scanning C:\inetpub ...
[+] Scanning C:\PerfLogs ...
[+] Scanning C:\Scripts ...
[+] Scanning C:\Tools ...
Insecure ACL for: C:\Tools\PSSQLite\Invoke-SqliteBulkCopy.ps1
Insecure ACL for: C:\Tools\PSSQLite\Invoke-SqliteQuery.ps1
Insecure ACL for: C:\Tools\PSSQLite\New-SqliteConnection.ps1
Insecure ACL for: C:\Tools\PSSQLite\Out-DataTable.ps1
Insecure ACL for: C:\Tools\PSSQLite\Update-Sqlite.ps1
Insecure ACL for: C:\Tools\PSSQLite-master\Tests\Helpers\Initialize-PesterPath.ps1
Insecure ACL for: C:\Tools\PSSQLite-master\Tests\Helpers\Invoke-PesterFromAppveyor.ps1
Insecure ACL for: C:\Tools\PSSQLite-master\Tests\Helpers\Invoke-PSGalleryDeployment.ps1
Insecure ACL for: C:\Tools\PSSQLite-master\Tests\Helpers\Read-PesterOutput.ps1
Insecure ACL for: C:\Tools\PSSQLite-master\Tests\Invoke-SQLiteQuery.Tests.ps1
Insecure ACL for: C:\Tools\accesschk.exe
Insecure ACL for: C:\Tools\check.ps1
Insecure ACL for: C:\Tools\Druva.ps1
Insecure ACL for: C:\Tools\PowerUp.ps1
Insecure ACL for: C:\Tools\Seatbelt.exe
Insecure ACL for: C:\Tools\SharpChrome.exe
Insecure ACL for: C:\Tools\SharpUp.exe
Insecure ACL for: C:\Tools\Watson.exe
[+] Scanning C:\Users ...
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Weak Registry permission (T1574.011)::::::::::

[+] Scanning "HKLM:\SYSTEM\CurrentControlSet\Services\"
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt
PS C:\tools> 
```
