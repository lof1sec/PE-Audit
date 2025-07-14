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
- `PE-Audit.ps1`

```
PS C:\Users\thm-unpriv> .\PE-Audit.ps1

::::: PE-Audit: Windows Privilege Escalation Checker :::::
 by Lof1 ;)

[+] Current User: thm-unpriv
[+] Computer Name: WPRIVESC1
[+] Architecture: AMD64
[+] Windows Version: Microsoft Windows Server 2019 Datacenter 10.0.17763

[*] :::Permissive Service Executable ACL (T1574.005):::

Insecure ACL found for: C:\PROGRA~2\SYSTEM~1\WService.exe (Service: WindowsScheduler)

[*] :::Permissive File System ACLs in Executable (T1574.005):::

Insecure ACL for: C:\Program Files (x86)\SystemScheduler\Message.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\PlaySound.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\PlayWAV.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\Privilege.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\RunNow.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\sc32.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\Scheduler.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\SendKeysHelper.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\ShowXY.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\ShutdownGUI.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\SSAdmin.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\SSCmd.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\SSMail.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\unins000.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\WhoAmI.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\WScheduler.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\WSCtrl.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\WService.exe
Insecure ACL for: C:\Program Files (x86)\SystemScheduler\WSLogon.exe

[*] ::: Installed Applications :::

Total number of Non-Microsoft Applications: 8

DisplayName
-----------
Disk Sorter Enterprise 13.6.12
System Scheduler Professional 5.12 (30 Day Evaluation)
Amazon SSM Agent
aws-cfn-bootstrap
PuTTY release 0.76 (64-bit)
aws-cfn-bootstrap
AWS PV Drivers
Amazon SSM Agent

[*] :::Weak Service Permissions (T1574.010):::

Insecure Service Found: THMService

[*] :::Possible Schedule Task Scripts (T1053.005):::

Insecure ACL for: C:\tasks\schtask.bat
Insecure ACL for: C:\Users\thm-unpriv\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\RunWallpaperSetup.cmd
Insecure ACL for: C:\Users\thm-unpriv\PE-Audit_v2.ps1

[*] :::Stored Credentials:::

Stored credentials for users:
WPRIVESC1\mike.katz

[*] :::Weak ACL for DLL:::

Insecure ACL for DLL: C:\Program Files (x86)\SystemScheduler\libeay32.dll
Insecure ACL for DLL: C:\Program Files (x86)\SystemScheduler\ssleay32.dll
Insecure ACL for DLL: C:\Program Files (x86)\SystemScheduler\WSProc.dll

[*] :::Active Network Connections:::

  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       844
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:3389           0.0.0.0:0              LISTENING       968
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:7680           0.0.0.0:0              LISTENING       2720
  TCP    0.0.0.0:9125           0.0.0.0:0              LISTENING       2660
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:49664          0.0.0.0:0              LISTENING       512
  TCP    0.0.0.0:49665          0.0.0.0:0              LISTENING       340
  TCP    0.0.0.0:49666          0.0.0.0:0              LISTENING       956
  TCP    0.0.0.0:49667          0.0.0.0:0              LISTENING       1820
  TCP    0.0.0.0:49668          0.0.0.0:0              LISTENING       1728
  TCP    0.0.0.0:49671          0.0.0.0:0              LISTENING       600
  TCP    0.0.0.0:49675          0.0.0.0:0              LISTENING       624
  TCP    10.10.224.142:139      0.0.0.0:0              LISTENING       4
```
