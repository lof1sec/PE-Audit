# PE-Audit: Windows Privilege Escalation Checker
PE-Audit its a Powershell script that check for windows privilege escalation vector

Checks available... at the moment
- Modifiable Service Binaries
- Modifiable Services
- Unquoted Service Path (Mitre T1574.009)

## How to use:
- Put **PE-Audit.ps1** and **accesschk.exe** in the same folder (ensure you have write permissions for the folder), and that's it!
https://download.sysinternals.com/files/AccessChk.zip

```
PS C:\tools> .\PE-Audit.ps1

::::: PE-Audit: Windows Privilege Escalation Checker :::::
by Lof1 ;)

::::::::::Modifiable Service Binaries::::::::::

[+] Checking Directories: C:\Program Files (x86) C:\Program Files
[+] Current user: htb-student
[+] Scanning C:\Program Files (x86) ...
Insecure ACL for: C:\Program Files (x86)\PCProtect\SecurityService.exe
[+] Scanning C:\Program Files ...
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Modifiable Services::::::::::

[+] Total number of services: 271
[+] Checking services...
Insecure Service Found: WindscribeService
[+] Scan Completed. Results saved in PE_Insecure_Findings.txt

::::::::::Unquoted Service Path::::::::::

[+] Total number of services: 271
Unquoted path found for service: GVFS.Service
Unquoted path found for service: SystemExplorerHelpService
[+] Check Completed. Results saved in PE_Insecure_Findings.txt
PS C:\tools> 

```
