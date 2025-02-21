Write-Output ""
Write-Output "::::: PE-Audit: Windows Privilege Escalation Checker :::::"
Write-Output "by Lof1 ;)"
Write-Output ""

# :::: Modifiable Service Binaries ::::

# Define the directories to search
#$directories = @("C:\Program Files (x86)","$env:ProgramFiles","$env:USERPROFILE\Downloads")
$directories = @("C:\Program Files (x86)","$env:ProgramFiles")
Write-Output "::::::::::Permissive File System ACLs (T1574.005)::::::::::"
Write-Output ""
Write-Output "[+] Checking Directories: $directories"

# Output files
$outputFile = "PE_Audit_Report.txt"
$insecureFile = "PE_Insecure_Findings.txt"
Write-Output "[+] Current user: $env:USERNAME"

# Clear the output files if they exist
if (Test-Path $outputFile) { Remove-Item $outputFile }
if (Test-Path $insecureFile) { Remove-Item $insecureFile }
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
			if ($permissions -match "BUILTIN\\Users:\(I\)\(F\)" -or $permissions -match "Everyone:\(I\)\(F\)" -or $permissions -match "BUILTIN\\Usuarios:\(I\)\(F\)" -and $permissions_service -match "SUCCESS") {
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
