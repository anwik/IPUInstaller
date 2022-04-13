$BuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
$VersionNumber = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseId).ReleaseID
$IpuResultPath = 'HKLM:\SOFTWARE\Onevinn\IpuResult'
$LogFile = "$env:ProgramData\~IPULog\IpuInstaller_EnablementPackage.log"
$CabFile = "$($PSScriptRoot)\Windows10.0-KB5003791-x64.cab"

# Process function
function Start-Proc {
    param([string]$Exe = $(Throw 'An executable must be specified'),
        [string]$Arguments,
        [string]$WorkDir = $null,
        [switch]$Hidden
    )

    $startinfo = New-Object System.Diagnostics.ProcessStartInfo
    $startinfo.WorkingDirectory = "$($WorkDir)"
    $startinfo.FileName = $Exe
    $startinfo.Arguments = $Arguments
    if ($Hidden) {
        $startinfo.WindowStyle = 'Hidden'
        $startinfo.CreateNoWindow = $True
    }
    $startinfo.RedirectStandardError = $true
    $startinfo.RedirectStandardOutput = $true
    $startinfo.UseShellExecute = $false

    $process = [System.Diagnostics.Process]::Start($startinfo)      
    $StdOut = $process.StandardOutput.ReadToEnd()
    $StdErr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()
    $obj = [pscustomobject] @{
        StdOut   = "$(($StdOut).Trim())"
        StdErr   = "$(($StdErr).Trim())"
        ExitCode = "$($process.ExitCode)"
    }        
    return $obj
}

# Log function
Function Write-Log {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    if (!(Test-Path $LogFile)) { New-Item $LogFile -ItemType File -Force | Out-Null }
    $TimeGenerated = $(Get-Date -UFormat '%Y-%m-%d %T')
    $Line = "$TimeGenerated $Message"
    Add-Content -Value $Line -Path $LogFile -Encoding Ascii -Force

}

# Start logging
Write-Log -Message 'IpuInstaller with Enablement Package was started'
Write-Log -Message "Computer info: Name: $env:COMPUTERNAME, OSBuild: $BuildNumber, OSVersion: $VersionNumber"

# Verify that the cab file is present

if (!(Test-Path $CabFile)) {
    Write-Log -Message 'Error: CAB file not present. Aborting...'
    Exit 1
}

# Check OSVersion, 20H2 is OK, anything else is not


if ($VersionNumber -eq '2009') {
    Write-Log -Message "OSVersion is: $VersionNumber, Continuing..."
} else {
    Write-Log -Message "Error: OSVersion is $VersionNumber. Aborting..."
    Exit 1
}


# Check if the computer has already used IPU Installer for a previous build, clear the IpuResult key
Write-Log -Message 'Checking if computer have been upgraded with IPU Installer before..'
if (Test-Path $IpuResultPath) {
    Write-Log -Message 'It certainly has. Clearing registry key HKLM:\SOFTWARE\Onevinn\IpuResult'
    New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value 'Unknown' -Force -ErrorAction SilentlyContinue | Out-Null
} else {
    Write-Log -Message "Nope, this computer hasn't used IPU installer before. Proceeding..."
}    


# Dependency check

# List of hotfixes that has to be installed prior installing the enablement package - (https://support.microsoft.com/en-us/topic/kb5003791-update-to-windows-10-version-21h2-by-using-an-enablement-package-8bc077be-18d7-4aac-81ce-6f6dad2cd384)
$HotfixList = @(
    'KB5005565'
    'KB5006670'
    'KB5007186'
)

# Check installed hotfixes
$Hotfixes = (Get-HotFix).HotFixID

# Match installed hotfixes with $HotFixList
$InstalledHotfixes = @()
[array]$InstalledHotfixes
Write-Log -Message 'Checking that hotfix: KB5005565, KB5006670 or KB5007186 is installed'
foreach ($Hotfix in $HotfixList) {
    if ($Hotfixes -contains $Hotfix) {
        $InstalledHotfixes += $Hotfix
    }
}

# Check if $InstalledHotfixes returns true
if ($InstalledHotfixes) {
    Write-Log -Message "Hotfix $Hotfix installed! Proceeding to install phase..." 
    
} else {
    Write-Log -Message 'Hotfix not installed. Aborting...'
    Exit 1
}


# Perform the upgrade
Write-Log -Message '### Installation started ###'
try {
    $result = Start-Proc -Exe 'dism.exe' -Arguments "/Online /Add-Package /PackagePath:$($CabFile) /NoRestart" -Hidden
    Write-Log -Message "ExitCode: $($result.ExitCode)"
    Write-Log -Message "StdOut: $($result.stdout)" 
    if ($result.StdErr -ne '') {
        Write-Log -Message "StdErr: $($result.stderr)"
        New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value "Error: $_.Exception.Message" -Force -ErrorAction SilentlyContinue | Out-Null
        Exit 1
    }
    
} catch {}

# Finish logging
Write-Log -Message '### Finished installation of 21H2 enablement package ###'
New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value 'Success' -Force -ErrorAction SilentlyContinue | Out-Null