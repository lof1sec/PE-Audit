Write-Output "`n::::: PE-Audit: Windows Privilege Escalation Checker :::::`n by Lof1 ;)`n"
Write-Output "[+] Current User: $env:USERNAME"
Write-Output "[+] Computer Name: $env:ComputerName"
Write-Output "[+] Architecture: $env:processor_architecture"
$windowsVersion = (Get-WmiObject -class Win32_OperatingSystem)
Write-Output "[+] Windows Version: $($windowsVersion.caption) $($windowsVersion.version)"


$groups = whoami /groups 2>$null
$insecureAclRegex = "(BUILTIN\\Users:.+[FMW])|(Everyone:.+[FMW])|(Todos:.+[FMW])|(BUILTIN\\Usuarios:.+[FMW])|(Authenticated Users:.+[FMW])|(Usuarios autentificados:.+[FMW])|(NT AUTHORITY\\INTERACTIVE:.+[FMW])|($($env:USERNAME):.+[FMW])"
$startUpFolder = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
$identities = @(
    "NT AUTHORITY\INTERACTIVE",
    "Everyone",
    "Todos",
    "BUILTIN\Users",
    "BUILTIN\Usuarios",
    "NT AUTHORITY\Authenticated Users",
    "NT AUTHORITY\Usuarios autentificados",
    $($env:USERNAME)
)
$riskyGroups = @(
    "Administrators",
    "Administradores",
    "Backup Operators",
    "Print Operators",
    "Hyper-V Administrators",
    "IIS_IUSRS",
    "Service Accounts"
)
$adminGroup = @(
    "Administrators",
    "Administradores"
)
$mandatoryLabel = @(
	"Medium Mandatory Level",
    "Nivel obligatorio medio"
)
$riskyPrivileges = @(
	    "SeAssignPrimaryTokenPrivilege",
	    "SeImpersonatePrivilege",
	    "SeCreateTokenPrivilege",
	    "SeTcbPrivilege",
	    "SeLoadDriverPrivilege",
	    "SeBackupPrivilege",
	    "SeRestorePrivilege",
	    "SeDebugPrivilege",
	    "SeTakeOwnershipPrivilege",
	    "SeManageVolumePrivilege"
    )
$admin = $false
if ($groups -match $adminGroup){
    $admin = $true
}
$insecureFile = "PE_Insecure_Findings.txt"

if (Test-Path $insecureFile) { Remove-Item $insecureFile }


function Network_Connections {
    Write-Output "`n[*] :::Active Network Connections:::`n"
    Write-Output "`n[*] :::Active Network Connections:::`n" | Out-File -Append $insecureFile

    $connections = netstat.exe -ano | findstr LISTENING | Where-Object { $_ -notmatch '\[\:\:\]' }
    $connections | Out-File -Append $insecureFile
    Write-Output $connections
}

function Webshell {
    $directories = @(
        "C:\xampp\htdocs",
        "C:\wamp64\www",
        "C:\wamp\www",
        "C:\inetpub\wwwroot"
    )
    $go = $false

    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            $output = icacls $dir
            if ($output -match $insecureAclRegex) {
                $go = $true
                break
            } 
        } 
    }

    if ($go) {
        Write-Output "`n[*] :::Server Software Component: Web Shell (T1505.003):::`n"
        Write-Output "`n[*] :::Server Software Component: Web Shell (T1505.003):::`n" | Out-File -Append $insecureFile
        foreach ($dir in $directories) {
            if (Test-Path $dir) {
                $output = icacls $dir
                if ($output -match $insecureAclRegex) {
                    Write-Output "Writable folder: $dir"
                    Write-Output "Writable folder: $dir" | Out-File -Append $insecureFile
                    $output | Out-File -Append $insecureFile
                    Write-Output "---------------------------------" | Out-File -Append $insecureFile
                } 
            } 
        }
    }
}

function Weak_acl_for_dll {
    $excludedFolders = @("Windows")
    $folderList = @()
    $drives = Get-PSDrive -PSProvider FileSystem
    $go = $false


    foreach ($drive in $drives) {
	    $driveLetter = $drive.Root
	    Get-ChildItem -Path $driveLetter -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $excludedFolders } | ForEach-Object { $folderList += "$driveLetter$($_.Name)" }
    }

    $folderList += "C:\Windows\Temp\"

    foreach ($dir in $folderList) {
	    if (Test-Path $dir) {
		    $files = Get-ChildItem -Path $dir -Recurse -Force -Include "*.dll" -File -ErrorAction SilentlyContinue
		    foreach ($file in $files) {
			    $filePath = $file.FullName
			    $permissions = icacls $filePath 2>$null
			    if ($permissions -match $insecureAclRegex ) {
				    $go = $true
                    break
			    }
		    }
		
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Weak ACL for DLL:::`n"
        Write-Output "`n[*] :::Weak ACL for DLL:::`n" | Out-File -Append $insecureFile
        foreach ($dir in $folderList) {
	        if (Test-Path $dir) {
		        $files = Get-ChildItem -Path $dir -Recurse -Force -Include "*.dll" -File -ErrorAction SilentlyContinue
		        foreach ($file in $files) {
			        $filePath = $file.FullName
			        $permissions = icacls $filePath 2>$null
			        if ($permissions -match $insecureAclRegex ) {
				        Write-Output "Insecure ACL for DLL: $filePath" | Out-File -Append $insecureFile
				        Write-Output "Insecure ACL for DLL: $filePath"
				        $permissions | Out-File -Append $insecureFile
				        Write-Output "---------------------------------" | Out-File -Append $insecureFile
			        }
		        }
		
	        }
        }
    }
}

function Registry_hives_bkp {
    $hivesBackupPath = "C:\Windows\Repair\"
    $oldBackupPath = "C:\Windows.old\Windows\System32\"
    $go = $false

    if (Test-Path $hivesBackupPath) {
        $go = $true
    } elseif (Test-Path $oldBackupPath) {
	    $go = $true
    }

    if ($go) {
        Write-Output "`n[*] :::Windows Registry Hives Backups:::`n"
        Write-Output "`n[*] :::Windows Registry Hives Backups:::`n" | Out-File -Append $insecureFile
        if (Test-Path $hivesBackupPath) {
            $contentBackup = Get-ChildItem $hivesBackupPath | Format-Table Name,Length,LastWriteTime -AutoSize
            Write-Output "Backup folder: $hivesBackupPath" | Out-File -Append $insecureFile
            $contentBackup | Out-File -Append $insecureFile
            Write-Output "Backup folder: $hivesBackupPath"
            Write-Output $contentBackup
        } elseif (Test-Path $oldBackupPath) {
	        $contentBackup = Get-ChildItem $oldBackupPath | Format-Table Name,Length,LastWriteTime -AutoSize
            Write-Output "Backup folder: $hivesBackupPath" | Out-File -Append $insecureFile
            $contentBackup | Out-File -Append $insecureFile
            Write-Output "Backup folder: $hivesBackupPath"
            Write-Output $contentBackup
        }
    }
}

function Stored_creds {
    $storedCreds = cmdkey.exe /list 2>$null
    $onlyUsers = cmdkey.exe /list | Select-String "User:|Usuario:" | ForEach-Object { ($_ -split ":")[1].Trim() } | Sort-Object -Unique 2>$null
    $go = $false

    if ($storedCreds -match "User:|Usuario:") {
        $go = $true
    }

    if ($go) {
        Write-Output "`n[*] :::Stored Credentials:::`n"
        Write-Output "`n[*] :::Stored Credentials:::`n" | Out-File -Append $insecureFile
        if ($storedCreds -match "User:|Usuario:") {
            Write-Output "Stored credentials for users: " | Out-File -Append $insecureFile
            $onlyUsers | Out-File -Append $insecureFile
            $storedCreds | Out-File -Append $insecureFile
            Write-Output "Stored credentials for users:"
            Write-Output $onlyUsers
        }
    }
}

function Logon_autostart_exec_startup_folder {
    $permissions = icacls $startUpFolder 2>$null
    $go = $false

    if ($permissions -match $insecureAclRegex) {
	    $go = $true
    }

    if ($go) {
        Write-Output "`n[*] :::Boot or Logon Autostart Execution: Startup Folder (T1547.001):::`n"
        Write-Output "`n[*] :::Boot or Logon Autostart Execution: Startup Folder (T1547.001):::`n" | Out-File -Append $insecureFile
        if ($permissions -match $insecureAclRegex) {
	        Write-Output "Global StartUp Folder with weak ACL: $startUpFolder" | Out-File -Append $insecureFile
	        $permissions | Out-File -Append $insecureFile
	        Write-Output "Global StartUp Folder with weak ACL: $startUpFolder"
        }
    }
}

function AlwaysInstallElevated {
    $RegPaths = @(
	    "HKLM:\Software\Policies\Microsoft\Windows\Installer",
	    "HKCU:\Software\Policies\Microsoft\Windows\Installer"
    )
    $go = $false


    foreach ($Path in $RegPaths) {
	    if (Test-Path $Path) {
		    $Value = Get-ItemProperty -Path $Path -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
		    if ($Value.AlwaysInstallElevated -eq 1) {
			    $go = $true
                break
		    } 
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::AlwaysInstallElevated:::`n"
        Write-Output "`n[*] :::AlwaysInstallElevated:::`n" | Out-File -Append $insecureFile
        foreach ($Path in $RegPaths) {
	        if (Test-Path $Path) {
		        $Value = Get-ItemProperty -Path $Path -Name "AlwaysInstallElevated" -ErrorAction SilentlyContinue
		        if ($Value.AlwaysInstallElevated -eq 1) {
			        Write-Output "Found: $Path\AlwaysInstallElevated is ENABLED (1)"
			        Write-Output "Found: $Path\AlwaysInstallElevated is ENABLED (1)" | Out-File -Append $insecureFile
		        } 
	        }
        }
    }
}

function Logon_autostart_execution_registry_run_keys {
    $registryKeys = @(
	    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
	    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
	    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
	    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    $go = $false

    foreach ($regKey in $registryKeys) {
	    if (Test-Path $regKey) {
		    $values = Get-ItemProperty -Path $regKey
		    foreach ($entry in $values.PSObject.Properties) {
			    $exePath = $entry.Value
			    if ($exePath -match "([A-Z]:\\.*?\.exe)") {
				    $cleanPath = $matches[1] -replace '"', ''  # Remove quotes if present
				    $permissions = icacls $cleanPath 2>$null
				    if ($permissions -match "(BUILTIN\\Users:.+[FM])|(Everyone:.+[FM])|(BUILTIN\\Usuarios:.+[FM])|(Authenticated Users:.+[FM])|(NT AUTHORITY\\INTERACTIVE:.+[FM])|($($env:USERNAME):.+[FM])") {
					    $go = $true
					    break
				    }
			    }
		    }
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Boot or Logon Autostart Execution: Registry Run Keys (T1547.001):::`n"
        Write-Output "`n[*] :::Boot or Logon Autostart Execution: Registry Run Keys (T1547.001):::`n" | Out-File -Append $insecureFile
	    foreach ($regKey in $registryKeys) {
		    if (Test-Path $regKey) {
			    $values = Get-ItemProperty -Path $regKey
			    foreach ($entry in $values.PSObject.Properties) {
				    $exePath = $entry.Value
				    if ($exePath -match "([A-Z]:\\.*?\.exe)") {
					    $cleanPath = $matches[1] -replace '"', ''  
					    $permissions = icacls $cleanPath 2>$null
					    if ($permissions -match "(BUILTIN\\Users:.+[FM])|(Everyone:.+[FM])|(BUILTIN\\Usuarios:.+[FM])|(Authenticated Users:.+[FM])|(NT AUTHORITY\\INTERACTIVE:.+[FM])|($($env:USERNAME):.+[FM])") {
						    Write-Output "Registry Key: $regKey" | Out-File -Append $insecureFile
                            Write-Output "Found Executable with weak ACL: $cleanPath" | Out-File -Append $insecureFile
						    $permissions | Out-File -Append $insecureFile
                            Write-Output "Registry Key: $regKey"
						    Write-Output "Found Executable with weak ACL: $cleanPath"
					    }
				    }
			    }
		    }
	    }
    }
}

function Weak_registry_permission {
    $paths = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" | ForEach-Object { $_.PSPath }
    $go = $false

    foreach ($path in $paths) {
	    $acl = Get-Acl -Path $path 2>$null
	    $match = $acl.Access | Where-Object { 
	    $identities -contains $_.IdentityReference -and $_.RegistryRights -match "FullControl|KEY_ALL_ACCESS" 
	    }
	    if ($match) {
		    $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Weak Registry permission (T1574.011):::`n"
        Write-Output "`n[*] :::Weak Registry permission (T1574.011):::`n" | Out-File -Append $insecureFile
        foreach ($path in $paths) {
	        $acl = Get-Acl -Path $path 2>$null
	        $match = $acl.Access | Where-Object { 
	        $identities -contains $_.IdentityReference -and $_.RegistryRights -match "FullControl|KEY_ALL_ACCESS" 
	        }
	        if ($match) {
		        $cleanPath = $path -replace "Microsoft.PowerShell.Core\\Registry::", ""
		        $regQuery = reg.exe query $cleanPath 2>$null
		        Write-Output "Weak Registry permission found: $cleanPath" | Out-File -Append $insecureFile 
		        Write-Output "Weak Registry permission found: $cleanPath"
		        Write-Output $regQuery | Out-File -Append $insecureFile
		        Write-Output $match | Out-File -Append $insecureFile
                Write-Output "---------------------------------`n" | Out-File -Append $insecureFile

	        }
        }
    }
}

function Schedule_tasks {
    $taskNames = schtasks /query /fo LIST /v | Where-Object { $_ -match "^TaskName:|^Nombre de tarea:" } | ForEach-Object { ($_ -split ": ")[1].Trim() }
    $go = $false

    foreach ($task in $taskNames) {
	    $taskInfo = schtasks /query /tn $task /fo LIST /v
	    $taskName = ($taskInfo | Where-Object { $_ -match "^TaskName:|^Nombre de tarea:" }) -replace "TaskName:\s+", "" -replace "Nombre de tarea:\s+", ""
	    $taskToRun = ($taskInfo | Where-Object { $_ -match "^Task To Run:|^Tarea que se ejecutar" }) -replace "Task To Run:\s+", "" -replace "Tarea que se ejecutará:\s+", ""
	    $taskRunAs = ($taskInfo | Where-Object { $_ -match "^Run As User:|^Ejecutar como usuario:" }) -replace "Run As User:\s+", "" -replace "Ejecutar como usuario:\s+", ""
	    $taskState = ($taskInfo | Where-Object { $_ -match "^Scheduled Task State:|^Estado de tarea programada:" }) -replace "Scheduled Task State:\s+", "" -replace "Estado de tarea programada:\s+", ""
	    $scheduleType = ($taskInfo | Where-Object { $_ -match "^Schedule Type:|Tipo de programaci" }) -replace "Schedule Type:\s+", "" -replace "Tipo de programación:\s+", ""
	    if ($taskToRun -match ".exe|.ps1|.bat|.vbs|.cmd|.js|.wsf|.msi|.msp|.scr" -and $taskToRun -notmatch "system32|sdxhelper.exe|OfficeC2RClient.exe|MpCmdRun.exe|BthUdTask.exe|config upnphost" -and $taskState -notmatch "Disabled|Deshabilitado" -and $taskRunAs -match "SYSTEM") {
		    $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Schedule Tasks (T1053.005):::`n"
        Write-Output "`n[*] :::Schedule Tasks (T1053.005):::`n" | Out-File -Append $insecureFile
        foreach ($task in $taskNames) {
	        $taskInfo = schtasks /query /tn $task /fo LIST /v
	        $taskName = ($taskInfo | Where-Object { $_ -match "^TaskName:|^Nombre de tarea:" }) -replace "TaskName:\s+", "" -replace "Nombre de tarea:\s+", ""
	        $taskToRun = ($taskInfo | Where-Object { $_ -match "^Task To Run:|^Tarea que se ejecutar" }) -replace "Task To Run:\s+", "" -replace "Tarea que se ejecutará:\s+", ""
	        $taskRunAs = ($taskInfo | Where-Object { $_ -match "^Run As User:|^Ejecutar como usuario:" }) -replace "Run As User:\s+", "" -replace "Ejecutar como usuario:\s+", ""
	        $taskState = ($taskInfo | Where-Object { $_ -match "^Scheduled Task State:|^Estado de tarea programada:" }) -replace "Scheduled Task State:\s+", "" -replace "Estado de tarea programada:\s+", ""
	        $scheduleType = ($taskInfo | Where-Object { $_ -match "^Schedule Type:|Tipo de programaci" }) -replace "Schedule Type:\s+", "" -replace "Tipo de programación:\s+", ""
	        if ($taskToRun -match ".exe|.ps1|.bat|.vbs|.cmd|.js|.wsf|.msi|.msp|.scr" -and $taskToRun -notmatch "system32|sdxhelper.exe|OfficeC2RClient.exe|MpCmdRun.exe|BthUdTask.exe|config upnphost" -and $taskState -notmatch "Disabled|Deshabilitado" -and $taskRunAs -match "SYSTEM") {
		        Write-Output "TaskName: $taskName"
		        Write-Output "TaskName: $taskName" | Out-File -Append $insecureFile
		        Write-Output "Task To Run: $taskToRun" | Out-File -Append $insecureFile
		        Write-Output "Run As User: $taskRunAs" | Out-File -Append $insecureFile
		        Write-Output "Scheduled Task State: $taskState" | Out-File -Append $insecureFile
		        Write-Output "Schedule Type: $scheduleType" | Out-File -Append $insecureFile
		        Write-Output "---------------------------------`n"
	        }
        }
    }


    $excludedFolders = @("Windows", "Program Files", "Program Files (x86)")
    $go = $false
    $folderList = @()
    $drives = Get-PSDrive -PSProvider FileSystem

    foreach ($drive in $drives) {
	    $driveLetter = $drive.Root
	    Get-ChildItem -Path $driveLetter -Directory -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $excludedFolders } | ForEach-Object { $folderList += "$driveLetter$($_.Name)" }
    }

    foreach ($dir in $folderList) {
	    if (Test-Path $dir) {
		    $files = Get-ChildItem -Path $dir -Recurse -Force -Include ("*.exe","*.ps1","*.bat","*.vbs","*.cmd","*.wsf","*.msi","*.msp","*.scr") -File -ErrorAction SilentlyContinue
		    foreach ($file in $files) {
			    $filePath = $file.FullName
			    $permissions = icacls $filePath 2>$null
			    if ($permissions -match $insecureAclRegex ) {
				    $go = $true
                    break
			    }
		    }
		
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Possible Schedule Task Scripts (T1053.005):::`n"
        Write-Output "`n[*] :::Possible Schedule Task Scripts (T1053.005):::`n" | Out-File -Append $insecureFile
        foreach ($dir in $folderList) {
	        if (Test-Path $dir) {
		        $files = Get-ChildItem -Path $dir -Recurse -Force -Include ("*.exe","*.ps1","*.bat","*.vbs","*.cmd","*.wsf","*.msi","*.msp","*.scr") -File -ErrorAction SilentlyContinue
		        foreach ($file in $files) {
			        $filePath = $file.FullName
			        $permissions = icacls $filePath 2>$null
			        if ($permissions -match $insecureAclRegex ) {
				        Write-Output "Insecure ACL for: $filePath" | Out-File -Append $insecureFile
				        Write-Output "Insecure ACL for: $filePath"
				        $permissions | Out-File -Append $insecureFile
				        Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
			        }
		        }
		
	        }
        }
    }
}

function Modifiable_services {
    $services = Get-Service | Select-Object -ExpandProperty Name
    $numServices = $services.Count
    $go = $false

    if ($admin){
        $dangerousPermission = "([a-zA-Z];[^\(\)]+(DC|SD|FA)[^\(\)]+;(AU|IU|WD|BU))|([a-zA-Z];[^\(\)]+CCDCLCSWRPWPDTLOCRSDRCWD[^\(\)]+;(AU|IU|WD|BA|BU))"
    }
    else {
        $dangerousPermission = "([a-zA-Z];[^\(\)]+(DC|SD|FA)[^\(\)]+;(AU|IU|WD|BU))|([a-zA-Z];[^\(\)]+CCDCLCSWRPWPDTLOCRSDRCWD[^\(\)]+;(AU|IU|WD|BU))"
    }

    foreach ($service in $services) {
	    $sdshowOutput = sc.exe sdshow $service 2>$null
        if ($sdshowOutput -match $dangerousPermission){
            $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Weak Service Permissions (T1574.010):::`n"
        Write-Output "`n[*] :::Weak Service Permissions (T1574.010):::`n" | Out-File -Append $insecureFile
        foreach ($service in $services) {
	        $sdshowOutput = sc.exe sdshow $service 2>$null
            if ($sdshowOutput -match $dangerousPermission){
                Write-Output "Insecure Service Found: $service"
			    Write-Output "Insecure Service Found: $service" | Out-File -Append $insecureFile
			    $sdshowOutput | Out-File -Append $insecureFile
			    $sddlRaw = sc.exe sdshow $service | Out-String
			    $sddl = $sddlRaw.Trim()
			    $sdObj = ConvertFrom-SddlString -Sddl $sddl
			    $sdObj.DiscretionaryAcl | Out-File -Append $insecureFile
       			    $serviceQuery = sc.exe qc $service 2>$null | Out-File -Append $insecureFile
			    Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
		    }
        }
    }
}

function Installed_applications {
    $32bitApplications = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName
    $64bitApplications = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Select-Object DisplayName
    $AllApplications = $32bitApplications + $64bitApplications
    $NonMicrosoftApps = $AllApplications | Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "Microsoft|Windows" }
    $TotalNonMicrosoftApps = $NonMicrosoftApps.Count

    if ($TotalNonMicrosoftApps -gt 0) {
        Write-Output "`n[*] ::: Installed Applications :::`n"
        Write-Output "`n[*] ::: Installed Applications :::`n" | Out-File -Append $insecureFile
        Write-Output "Total number of Non-Microsoft Applications: $TotalNonMicrosoftApps"
        Write-Output $NonMicrosoftApps 
        $NonMicrosoftApps | Out-File -Append $insecureFile
        Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
    }
}

function Unquoted_service_path {
    $services = Get-WmiObject -Class Win32_Service
    $numServices = $services.Count
    $go = $false

    foreach ($service in $services) {
	    $serviceName = $service.Name
	    $servicePath = $service.PathName
	    $serviceConfig = & sc.exe qc $serviceName 2>$null
	    if ($servicePath -notmatch '^"' -and 
		    $servicePath -match '\s' -and 
		    $servicePath -notmatch "svchost.exe|msiexec.exe|dllhost.exe|SearchIndexer.exe") {
            $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Unquoted Service Path (T1574.009):::`n"
        Write-Output "`n[*] :::Unquoted Service Path (T1574.009):::`n" | Out-File -Append $insecureFile
        foreach ($service in $services) {
	        $serviceName = $service.Name
	        $servicePath = $service.PathName
	        $serviceConfig = & sc.exe qc $serviceName 2>$null
	        if ($servicePath -notmatch '^"' -and 
		        $servicePath -match '\s' -and 
		        $servicePath -notmatch "svchost.exe|msiexec.exe|dllhost.exe|SearchIndexer.exe") {
		        Write-Output "Unquoted path found for service: $serviceName`n" | Out-File -Append $insecureFile
		        Write-Output "Unquoted path found for service: $serviceName"
		        Write-Output "Service Path: $servicePath" | Out-File -Append $insecureFile
		        $serviceConfig | Out-File -Append $insecureFile
		        Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
	        }
        }
    }
}

function Service_executables_ACL_check {
    $services = Get-CimInstance -ClassName Win32_Service
    $go = $false

    foreach ($service in $services) {
        $serviceName = $service.Name
        $displayName = $service.DisplayName
        $pathRaw = $service.PathName
        if (![string]::IsNullOrWhiteSpace($pathRaw)) {
            $exePath = $pathRaw -replace '^\"?(.+?\.exe)\"?.*$', '$1'
            if (Test-Path $exePath) {
                $permissions = icacls $exePath 2>$null
                if ($permissions -match $insecureAclRegex) {
                    $go = $true
                    break
                }
            }
        }
    }

    if ($go) {
        Write-Output "`n[*] :::Permissive Service Executable ACL (T1574.005):::`n"
        Write-Output "`n[*] :::Permissive Service Executable ACL (T1574.005):::`n" | Out-File -Append $insecureFile
        foreach ($service in $services) {
            $serviceName = $service.Name
            $displayName = $service.DisplayName
            $pathRaw = $service.PathName
            if (![string]::IsNullOrWhiteSpace($pathRaw)) {
                $exePath = $pathRaw -replace '^\"?(.+?\.exe)\"?.*$', '$1'
                if (Test-Path $exePath) {
                    $permissions = icacls $exePath 2>$null
                    if ($permissions -match $insecureAclRegex) {
                        Write-Output "Insecure ACL found for: $exePath (Service: $serviceName)"
                        Write-Output "Insecure ACL found for: $exePath (Service: $serviceName)" | Out-File -Append $insecureFile
                        Write-Output "Executable Path: $exePath`n" | Out-File -Append $insecureFile
                        $permissions | Out-File -Append $insecureFile
			$serviceQuery = sc.exe qc $serviceName 2>$null | Out-File -Append $insecureFile
                        Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
                    }
                }
            }
        }
    }

    $directories = @(
        "C:\Program Files (x86)",
        "C:\Program Files"
    )

    $go = $false

    foreach ($dir in $directories) {
	    if (Test-Path $dir) {
		    $files = Get-ChildItem -Path $dir -Recurse -Force -Include "*.exe" -File -ErrorAction SilentlyContinue
		    foreach ($file in $files) {
			    $filePath = $file.FullName
			    $permissions = icacls $filePath 2>$null
			    if ($permissions -match $insecureAclRegex) {
				    $go = $true
                    break
			    }
		    }
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Permissive File System ACLs in Executable (T1574.005):::`n"
        Write-Output "`n[*] :::Permissive File System ACLs in Executable (T1574.005):::`n" | Out-File -Append $insecureFile
        foreach ($dir in $directories) {
	        if (Test-Path $dir) {
		        $files = Get-ChildItem -Path $dir -Recurse -Force -Include "*.exe" -File -ErrorAction SilentlyContinue
		        foreach ($file in $files) {
			        $filePath = $file.FullName
			        $permissions = icacls $filePath 2>$null
			        if ($permissions -match $insecureAclRegex) {
				        Write-Output "Insecure ACL for: $filePath"
				        Write-Output "Insecure ACL for: $filePath`n" | Out-File -Append $insecureFile
				        $permissions | Out-File -Append $insecureFile
				        Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
			        }
		        }
	        }
        }
    }
}

function Token_abusing_user_privilege {
    $privileges = whoami /priv 2>$null
    $go = $false

    foreach ($privilege in $riskyPrivileges) {
	    if ($privileges -match $privilege) {
		    $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Token Abusing: User Privilege (T1134):::`n"
        Write-Output "`n[*] :::Token Abusing: User Privilege (T1134):::`n" | Out-File -Append $insecureFile
        foreach ($privilege in $riskyPrivileges) {
	        if ($privileges -match $privilege) {
		        Write-Output "High-Risk Privilege Found: $privilege" | Out-File -Append $insecureFile
		        Write-Output "High-Risk Privilege Found: $privilege"
	        }
        }
    }
}

function Token_abusing_group_privilege {
    $go = $false

    foreach ($group in $riskyGroups) {
	    if ($groups -match $group) {
		    $go = $true
            break
	    }
    }

    if ($go) {
        Write-Output "`n[*] :::Token Abusing: Group Privilege (T1134):::`n"
        Write-Output "`n[*] :::Token Abusing: Group Privilege (T1134):::`n" | Out-File -Append $insecureFile
        foreach ($group in $riskyGroups) {
	        if ($groups -match $group) {
		        Write-Output "High-Risk Group Found: $group" | Out-File -Append $insecureFile
		        Write-Output "High-Risk Group Found: $group"
                foreach ($label in $mandatoryLabel) {
	                if ($groups -match $label) {
		                Write-Output "`n[!] Medium Mandatory Level found! - Try to Bypass UAC to get more Privileges!`n" | Out-File -Append $insecureFile
		                Write-Output "`n[!] Medium Mandatory Level found! - Try to Bypass UAC to get more Privileges!`n"
	                }
                }
	        }
        }
    }
}

function web_config_password {
    $drives = Get-PSDrive -PSProvider FileSystem
    $webConfigPaths = @()
    $go = $false

    foreach ($drive in $drives) {
        $foundFiles = Get-ChildItem -Path $drive.Root -Recurse -Filter "web.config" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName
        $webConfigPaths += $foundFiles
    }

    foreach ($path in $webConfigPaths) {
        if (Test-Path $path) {
            $content = Get-Content -Path $path -ErrorAction SilentlyContinue
            if ($content -match "<connectionStrings>") {
                $go = $true
                break
            }
        }
    }

    if ($go) {
        Write-Output "`n[*] :::Passwords: Web Config file:::`n"
        Write-Output "`n[*] :::Passwords: Web Config file:::`n" | Out-File -Append $insecureFile
        foreach ($path in $webConfigPaths) {
            if (Test-Path $path) {
                $content = Get-Content -Path $path -ErrorAction SilentlyContinue
                if ($content -match "<connectionStrings>") {
                    Write-Output "Possible password in file: $path"
                    Write-Output "Possible password in file: $path" | Out-File -Append $insecureFile
                }
            }
        }
    }
}

function PowerShell_history_file {
    $go = $false
    foreach ($user in ((ls C:\users).fullname)){
        if (Test-Path "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"){
         $go = $true
         break
         }
    }
    if ($go) {
        Write-Output "`n[*] :::PowerShell History File:::`n"
        Write-Output "`n[*] :::PowerShell History File:::`n" | Out-File -Append $insecureFile
        foreach ($user in ((ls C:\users).fullname)){
            if (Test-Path "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"){
             Write-Output "Powershell History File in: $user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
             Write-Output "Powershell History File in: $user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`n" | Out-File -Append $insecureFile
             $pshistory_content = cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue 2>$null
             $pshistory_content | Out-File -Append $insecureFile
             Write-Output "---------------------------------`n" | Out-File -Append $insecureFile
             }
        }
    }
}

# Execution Flow

Token_abusing_group_privilege
Token_abusing_user_privilege
Service_executables_ACL_check
Unquoted_service_path
Installed_applications
Modifiable_services
Schedule_tasks
Weak_registry_permission
Logon_autostart_execution_registry_run_keys
AlwaysInstallElevated
Logon_autostart_exec_startup_folder
Stored_creds
Registry_hives_bkp
Weak_acl_for_dll
Webshell
web_config_password
PowerShell_history_file
Network_Connections

Write-Output "[+] Scan Completed. Results saved in $insecureFile"
