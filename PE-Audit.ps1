Write-Output ""
Write-Output "::::: PE-Audit: Windows Privilege Escalation Checker :::::"
Write-Output "by Lof1 ;)"
Write-Output ""
Write-Output ""

# Output files
$outputFile = "PE_Audit_Report.txt"
$insecureFile = "PE_Insecure_Findings.txt"
# Clear the output files if they exist
if (Test-Path $outputFile) { Remove-Item $outputFile }
if (Test-Path $insecureFile) { Remove-Item $insecureFile }
Write-Output "[+] Current user: $env:USERNAME"

# ------------------------------------------------------------------------ #
# :::: User Privilege ::::
Write-Output ""
Write-Output "::::::::::Token Abusing: User Privilege (T1134)::::::::::"
Write-Output ""

# Run 'whoami /priv' to list privileges
$privileges = whoami /priv 2>&1

# Define risky privileges
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

# Check for dangerous privileges in the output
foreach ($privilege in $riskyPrivileges) {
	if ($privileges -match $privilege) {
		Write-Output "[*] :::Token Abusing: User Privilege (T1134):::" | Out-File -Append $insecureFile
		Write-Output "" | Out-File -Append $insecureFile
		Write-Output "High-Risk Privilege Found: $privilege" | Out-File -Append $insecureFile
		Write-Output "High-Risk Privilege Found: $privilege"
	}
}

Write-Output "[+] Scan Completed. Results saved in $insecureFile"
# ------------------------------------------------------------------------ #
# :::: Modifiable Service Binaries ::::

# Define the directories to search
#$directories = @("C:\Program Files (x86)","$env:ProgramFiles","$env:USERPROFILE\Downloads")
$directories = @("C:\Program Files (x86)","$env:ProgramFiles")
Write-Output ""
Write-Output "::::::::::Permissive File System ACLs (T1574.005)::::::::::"
Write-Output ""
Write-Output "[+] Checking Directories: $directories"
Write-Output "[*] Checking for :::Permissive File System ACLs (T1574.005):::" | Out-File -Append $outputFile

# Search for .exe files and check permissions
foreach ($dir in $directories) {
	if (Test-Path $dir) {
		Write-Output "Scanning $dir ..." | Out-File -Append $outputFile
		Write-Output "[+] Scanning $dir ..."
		# Get all .exe files
		$files = Get-ChildItem -Path $dir -Recurse -Include "*.exe" -File -ErrorAction SilentlyContinue

		foreach ($file in $files) {
			$filePath = $file.FullName
			Write-Output "Checking: $filePath" | Out-File -Append $outputFile
			
			# Get the icacls and sc output
			$permissions = icacls $filePath 2>$null
			$fileService = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
			$permissions_service = sc.exe qc $fileService 2>$null
			# Save all results
			$permissions | Out-File -Append $outputFile
			Write-Output "---------------------------------" | Out-File -Append $outputFile
			
			# Check for insecure permissions
			if ($permissions -match "BUILTIN.+Users:.+F" -or $permissions -match "BUILTIN.+Users:.+M" -or $permissions -match "Everyone.+F" -or $permissions -match "Everyone.+M" -or $permissions -match "BUILTIN.+Usuarios:.+F" -or $permissions -match "BUILTIN.+Usuarios:.+M" -or $permissions -match "Authenticated Users:.+F" -or $permissions -match "Authenticated Users:.+M" -or $permissions -match "NT AUTHORITY.+INTERACTIVE:.+F" -or $permissions -match "NT AUTHORITY.+INTERACTIVE:.+M" -and $permissions_service -match "SUCCESS") {
				Write-Output "[*] :::Permissive File System ACLs (T1574.005):::" | Out-File -Append $insecureFile
				Write-Output "" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath"
				$permissions | Out-File -Append $insecureFile
				$permissions_service | Out-File -Append $insecureFile
				Write-Output "---------------------------------" | Out-File -Append $insecureFile
			}
		}
		
	}
		else {
		Write-Output "[+] No Modifiable Service Binaries found in $dir."
	}
}

Write-Output "[+] Scan Completed. Results saved in $insecureFile"

# ------------------------------------------------------------------------ #
# :::: Modifiable Services ::::

Write-Output ""
Write-Output "::::::::::Weak Service Permissions (T1574.010)::::::::::"
Write-Output ""

# Ensure accesschk.exe is available
$accesschkPath = ".\accesschk.exe"
if (!(Test-Path $accesschkPath)) {
	Write-Output "[!] Error: accesschk.exe not found. Download from Sysinternals and place it in the script directory."
	exit
}

# Get all service names
$services = Get-Service | Select-Object -ExpandProperty Name
$numServices = $services.Count
Write-Output "[+] Total number of services: $numServices"
Write-Output "[+] Checking services..."

# Define the identities you're looking for
$identities = @("NT AUTHORITY\INTERACTIVE", "Everyone", "BUILTIN\Users", "BUILTIN\Usuarios", "NT AUTHORITY\Authenticated Users", $env:USERNAME)

# Loop through each service and identity
foreach ($service in $services) {
	foreach ($identity in $identities) {

		# Run accesschk.exe
		$accesschkOutput = & $accesschkPath /accepteula -quvcw -nobanner $identity $service 2>$null

		if ($accesschkOutput -match "SERVICE_ALL_ACCESS|WRITE_DAC|SERVICE_CHANGE_CONFIG"){
			# Display and save output
			Write-Output "[*] :::Weak Service Permissions (T1574.010):::" | Out-File -Append $insecureFile
			Write-Output "" | Out-File -Append $insecureFile
			Write-Output "Insecure Service Found: $service" | Out-File -Append $insecureFile
			Write-Output "Identity: $identity" | Out-File -Append $insecureFile
			$accesschkOutput | Out-File -Append $insecureFile
			Write-Output "Insecure Service Found: $service"
			Write-Output "---------------------------------" | Out-File -Append $insecureFile
		}
	}
}

Write-Output "[+] Scan Completed. Results saved in $insecureFile"

# ------------------------------------------------------------------------ #
# :::: Unquoted Service Path ::::

Write-Output ""
Write-Output "::::::::::Unquoted Service Path (T1574.009)::::::::::"
Write-Output ""

# Get all services
$services = Get-WmiObject -Class Win32_Service
$numServices = $services.Count
Write-Output "[+] Total number of services: $numServices"
Write-Output "[+] Checking services..."

# Loop through each service
foreach ($service in $services) {
	$serviceName = $service.Name
	$servicePath = $service.PathName
	$serviceConfig = & sc.exe qc $serviceName 2>$null
	Write-Output "Service Name: $serviceName" | Out-File -Append $outputFile
	Write-Output "Service Path: $servicePath" | Out-File -Append $outputFile
	$serviceConfig | Out-File -Append $outputFile
	Write-Output "---------------------------------" | Out-File -Append $outputFile
	
	# Check if the path contains spaces and is not quoted
	if ($servicePath -notmatch '^"' -and $servicePath -match '\s' -and $servicePath -notmatch "svchost.exe" -and $servicePath -notmatch "msiexec.exe" -and $servicePath -notmatch "dllhost.exe" -and $servicePath -notmatch "SearchIndexer.exe") {
		# Log the unquoted path
		Write-Output "[*] :::Unquoted Service Path (T1574.009):::" | Out-File -Append $insecureFile
		Write-Output "" | Out-File -Append $insecureFile
		Write-Output "Unquoted path found for service: $serviceName" | Out-File -Append $insecureFile
		Write-Output "Unquoted path found for service: $serviceName"
		Write-Output "Service Path: $servicePath" | Out-File -Append $insecureFile
		$serviceConfig | Out-File -Append $insecureFile
		Write-Output "---------------------------------" | Out-File -Append $insecureFile
	}
}

Write-Output "[+] Check Completed. Results saved in $insecureFile"

# ------------------------------------------------------------------------ #
# :::: Installed Applications ::::

Write-Output ""
Write-Output "::::::::::Installed Applications::::::::::"
Write-Output ""

# Get all installed applications 32/64bit
Write-Output "[+] Checking non-Microsoft Applications..."
$32bitApplications = Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
$64bitApplications = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
$AllAplications = $32bitApplications + $64bitApplications

# Filter out Microsft Applications
$NonMicrosoftApps = $AllAplications | Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "Microsoft" -and $_.DisplayName -notmatch "Windows"}
$TotalNonMicrosoftApps = $NonMicrosoftApps.Count

Write-Output "[+] Total number of Non-Microsft Applications: $TotalNonMicrosoftApps"
Write-Output $NonMicrosoftApps
Write-Output "[*] :::Installed Applications:::" | Out-File -Append $insecureFile
Write-Output $NonMicrosoftApps | Out-File -Append $insecureFile
Write-Output "---------------------------------" | Out-File -Append $insecureFile
Write-Output "[+] Check Completed. Results saved in $insecureFile"

# ------------------------------------------------------------------------ #
# :::: Schedule Tasks ::::

Write-Output ""
Write-Output "::::::::::Scheduled Task (T1053.005)::::::::::"
Write-Output ""

# Get all TaskNames
$taskNames = schtasks /query /fo LIST /v | Where-Object { $_ -match "^TaskName:|^Nombre de tarea:" } | ForEach-Object { ($_ -split ": ")[1].Trim() }

# Iterate through each TaskName
foreach ($task in $taskNames) {
	# Get detailed info for the task
	$taskInfo = schtasks /query /tn $task /fo LIST /v

	# Extract specific fields
	$taskName = ($taskInfo | Where-Object { $_ -match "^TaskName:|^Nombre de tarea:" }) -replace "TaskName:\s+", "" -replace "Nombre de tarea:\s+", ""
	$taskToRun = ($taskInfo | Where-Object { $_ -match "^Task To Run:|^Tarea que se ejecutar" }) -replace "Task To Run:\s+", "" -replace "Tarea que se ejecutará:\s+", ""
	$taskRunAs = ($taskInfo | Where-Object { $_ -match "^Run As User:|^Ejecutar como usuario:" }) -replace "Run As User:\s+", "" -replace "Ejecutar como usuario:\s+", ""
	$taskState = ($taskInfo | Where-Object { $_ -match "^Scheduled Task State:|^Estado de tarea programada:" }) -replace "Scheduled Task State:\s+", "" -replace "Estado de tarea programada:\s+", ""
	$scheduleType = ($taskInfo | Where-Object { $_ -match "^Schedule Type:|Tipo de programaci" }) -replace "Schedule Type:\s+", "" -replace "Tipo de programación:\s+", ""

	# Output extracted details
	if ($taskToRun -match ".exe|.ps1|.bat|.vbs|.cmd|.js|.wsf|.msi|.msp|.scr" -and $taskToRun -notmatch "system32|sdxhelper.exe|OfficeC2RClient.exe|MpCmdRun.exe|BthUdTask.exe|config upnphost" -and $taskState -notmatch "Disabled|Deshabilitado" -and $taskRunAs -match "SYSTEM") {
		Write-Output "[*] :::Schedule Tasks (T1053.005):::" | Out-File -Append $insecureFile
		Write-Output "" | Out-File -Append $insecureFile
		Write-Output "TaskName: $taskName"
		Write-Output "TaskName: $taskName" | Out-File -Append $insecureFile
		Write-Output "Task To Run: $taskToRun" | Out-File -Append $insecureFile
		Write-Output "Run As User: $taskRunAs" | Out-File -Append $insecureFile
		Write-Output "Scheduled Task State: $taskState" | Out-File -Append $insecureFile
		Write-Output "Schedule Type: $scheduleType" | Out-File -Append $insecureFile
		Write-Output "---------------------------------"
	}
}

Write-Output ""
Write-Output "::::::::::Possible Scheduled Task Scripts (T1053.005)::::::::::"
Write-Output ""

# Define folders to exclude
$excludedFolders = @("Windows", "Program Files", "Program Files (x86)")

# Initialize an empty list
$folderList = @()

# Get all drives that support filesystems
$drives = Get-PSDrive -PSProvider FileSystem

# Iterate through each drive and add root directory names to the list
foreach ($drive in $drives) {
	$driveLetter = $drive.Root

	# Store as a list
	Get-ChildItem -Path $driveLetter -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $excludedFolders } | ForEach-Object { $folderList += "$driveLetter$($_.Name)" }
}

# Iterate through each rootfolder and get script/executable files
foreach ($dir in $folderList) {
	if (Test-Path $dir) {
		Write-Output "Scanning $dir ..." | Out-File -Append $outputFile
		Write-Output "[+] Scanning $dir ..."
		
		# Get all .exe and .dll files
		$files = Get-ChildItem -Path $dir -Recurse -Include ("*.exe","*.ps1","*.bat","*.vbs","*.cmd", "*.js", "*.wsf", "*.msi", "*.msp", "*.scr") -File -ErrorAction SilentlyContinue

		foreach ($file in $files) {
			$filePath = $file.FullName
			Write-Output "Checking: $filePath" | Out-File -Append $outputFile
			
			# Get the icacls output
			$permissions = icacls $filePath 2>$null
			
			# Save all results
			$permissions | Out-File -Append $outputFile
			Write-Output "---------------------------------" | Out-File -Append $outputFile
			
			

			# Check for insecure permissions
			if ($permissions -match "BUILTIN.+Users:.+F" -or $permissions -match "BUILTIN.+Users:.+M" -or $permissions -match "Everyone:.+F" -or $permissions -match "Everyone:.+M" -or $permissions -match "BUILTIN.+Usuarios:.+F" -or $permissions -match "BUILTIN.+Usuarios:.+M" -or $permissions -match "Authenticated Users:.+F" -or $permissions -match "Authenticated Users:.+M" ) {
				Write-Output "[*] :::Possible Schedule Task Scripts (T1053.005):::" | Out-File -Append $insecureFile
				Write-Output "" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath"
				$permissions | Out-File -Append $insecureFile
				Write-Output "---------------------------------" | Out-File -Append $insecureFile
			}
		}
		
	}
}
Write-Output "[+] Scan Completed. Results saved in $insecureFile"
# ------------------------------------------------------------------------ #
# :::: Weak Registry permission ::::

Write-Output ""
Write-Output "::::::::::Weak Registry permission (T1574.011)::::::::::"
Write-Output ""

# Get all registry paths under Services
$paths = Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\" | ForEach-Object { $_.PSPath }
Write-Output '[+] Scanning "HKLM:\SYSTEM\CurrentControlSet\Services\"'

# Define the identities you're looking for
$identities = @("NT AUTHORITY\INTERACTIVE", "Everyone", "BUILTIN\Users", "BUILTIN\Usuarios", "NT AUTHORITY\Authenticated Users", $env:USERNAME)

# Loop through each path and get detailed ACL info
foreach ($path in $paths) {
	# Get the ACL for the current registry path
	$acl = Get-Acl -Path $path 2>$null
	
	# Loop through each identity and check if it has FullControl
	$match = $acl.Access | Where-Object { 
	$identities -contains $_.IdentityReference -and $_.RegistryRights -match "FullControl|KEY_ALL_ACCESS" 
	}
	
	# If the match is found, output it
	if ($match) {
		$cleanPath = $path -replace "Microsoft.PowerShell.Core\\Registry::", ""
		$regQuery = reg.exe query $cleanPath 2>&1
		Write-Output "[*] :::Weak Registry permission (T1574.011):::" | Out-File -Append $insecureFile
		Write-Output "" | Out-File -Append $insecureFile
		Write-Output "Weak Registry permission found: $cleanPath" | Out-File -Append $insecureFile 
		Write-Output "Weak Registry permission found: $cleanPath"
		Write-Output $regQuery | Out-File -Append $insecureFile

	}
}
Write-Output "[+] Scan Completed. Results saved in $insecureFile"
