Write-Output ""
Write-Output "::::: PE-Audit: Windows Privilege Escalation Checker :::::"
Write-Output "by Lof1 ;)"
Write-Output ""

# Output files
$outputFile = "PE_Audit_Report.txt"
$insecureFile = "PE_Insecure_Findings.txt"
# Clear the output files if they exist
if (Test-Path $outputFile) { Remove-Item $outputFile }
if (Test-Path $insecureFile) { Remove-Item $insecureFile }

# ------------------------------------------------------------------------ #
# :::: User Privilege ::::
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
Write-Output "::::::::::Permissive File System ACLs (T1574.005)::::::::::"
Write-Output ""
Write-Output "[+] Checking Directories: $directories"
Write-Output "[+] Current user: $env:USERNAME"
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
			$permissions = icacls $filePath
			$fileService = [System.IO.Path]::GetFileNameWithoutExtension($filePath)
			$permissions_service = sc.exe qc $fileService
			# Save all results
			$permissions | Out-File -Append $outputFile
			Write-Output "---------------------------------" | Out-File -Append $outputFile

			# Check for insecure permissions
			if ($permissions -match "BUILTIN\\Users:\(I\)\(F\)" -or $permissions -match "BUILTIN\\Users:\(F\)" -or $permissions -match "BUILTIN\\Users:\(M\)" -or $permissions -match "Everyone:\(I\)\(F\)" -or $permissions -match "Everyone:\(F\)" -or $permissions -match "Everyone:\(M\)" -or $permissions -match "BUILTIN\\Usuarios:\(I\)\(F\)" -or $permissions -match "BUILTIN\\Usuarios:\(F\)" -or $permissions -match "BUILTIN\\Usuarios:\(M\)" -or $permissions -match "Authenticated Users:\(F\)" -or $permissions -match "Authenticated Users:\(M\)" -or $permissions -match "Authenticated Users:\(I\)\(F\)" -and $permissions_service -match "SUCCESS") {
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

# Loop through each service and run accesschk.exe
foreach ($service in $services) {
	Write-Output "Checking service: $service" | Out-File -Append $outputFile
	$accesschkOutput = & $accesschkPath /accepteula -quvcw -nobanner $service 2>&1
	# Convert output to a single string for matching
	$outputText = $accesschkOutput -join " "
	$accesschkOutput | Out-File -Append $outputFile
	Write-Output "---------------------------------" | Out-File -Append $outputFile

	# Check if "RW NT AUTHORITY\Authenticated Users SERVICE_ALL_ACCESS" is present
	if ($outputText -match "RW NT AUTHORITY\\Authenticated Users\s+SERVICE_ALL_ACCESS" -or $outputText -match "RW Everyone\s+SERVICE_ALL_ACCESS" -or $outputText -match "RW Everyone\s+WRITE_DAC") {
		Write-Output "[*] :::Weak Service Permissions (T1574.010):::" | Out-File -Append $insecureFile
		Write-Output "" | Out-File -Append $insecureFile
		Write-Output "Insecure Service Found: $service" | Out-File -Append $insecureFile
		Write-Output "Insecure Service Found: $service"
		$accesschkOutput | Out-File -Append $insecureFile
		Write-Output "---------------------------------" | Out-File -Append $insecureFile
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
	$serviceConfig = & sc.exe qc $serviceName 2>&1
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
		Write-Output "[*] :::Schedule Tasks:::" | Out-File -Append $insecureFile
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
			$permissions = icacls $filePath
			
			# Save all results
			$permissions | Out-File -Append $outputFile
			Write-Output "---------------------------------" | Out-File -Append $outputFile
			
			

			# Check for insecure permissions
			if ($permissions -match "BUILTIN\\Users:\(I\)\(F\)" -or $permissions -match "BUILTIN\\Users:\(F\)" -or $permissions -match "BUILTIN\\Users:\(M\)" -or $permissions -match "Everyone:\(I\)\(F\)" -or $permissions -match "Everyone:\(F\)" -or $permissions -match "Everyone:\(M\)" -or $permissions -match "BUILTIN\\Usuarios:\(I\)\(F\)" -or $permissions -match "BUILTIN\\Usuarios:\(F\)" -or $permissions -match "BUILTIN\\Usuarios:\(M\)" -or $permissions -match "Authenticated Users:\(F\)" -or $permissions -match "Authenticated Users:\(M\)" -or $permissions -match "Authenticated Users:\(I\)\(F\)" ) {
				Write-Output "[*] :::Possible Schedule Task Scripts:::" | Out-File -Append $insecureFile
				Write-Output "" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath" | Out-File -Append $insecureFile
				Write-Output "Insecure ACL for: $filePath"
				$permissions | Out-File -Append $insecureFile
				Write-Output "---------------------------------" | Out-File -Append $insecureFile
			}
		}
		
	}
}
