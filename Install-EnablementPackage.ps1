$BuildNumber = (Get-WmiObject -Class Win32_OperatingSystem).BuildNumber
$VersionNumber = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name ReleaseId).ReleaseID
$IpuResultPath = 'HKLM:\SOFTWARE\Onevinn\IpuResult'
$UpdateLevel = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name UBR).UBR
$OSLevel = $BuildNumber + ".$UpdateLevel"

$LogFile = "$env:ProgramData\~IPULog\IpuInstaller_EnablementPackage.log"
$CabFile = "$($PSScriptRoot)\Windows10.0-KB5003791-x64.cab"

Param (
    [parameter(Mandatory = $false)]
    [string]$TSName
)

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


if ($OSLevel -ge '19042.1237') {
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
    New-Item $IpuResultPath -Force
    Write-Log -Message "Nope, this computer hasn't used IPU installer before. Proceeding..."
}    



# Perform the upgrade
Write-Log -Message '### Installation started ###'
try {
    $result = Start-Proc -Exe 'dism.exe' -Arguments "/Online /Add-Package /PackagePath:$($CabFile) /NoRestart" -Hidden
    Write-Log -Message "ExitCode: $($result.ExitCode)"

    if ( $result.ExitCode -eq '3010') {
        Write-Log -Message 'Upgrade succeeded!'
        Write-Log -Message '### Finished installation of 21H2 enablement package ###'
        New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value 'Success' -Force -ErrorAction SilentlyContinue | Out-Null

        #CleanUp of Driver Package
        Remove-Item -Path "$($env:ProgramData)\~IPUDrivers" -Recurse -Force -EA SilentlyContinue
        Write-Log -Message 'Deleted temporary Driver Package from ProgramData'
        
        $host.SetShouldExit($result.ExitCode)
    
        # Start BIOS & DriverUpdate Task Sequence
         
    }

    if ($TSName) {
        . .\Execute-TaskSequence.ps1 -Name "$TSName"
    }

    if ($result.StdErr -ne '') {
        Write-Log -Message "StdErr: $($result.stderr)"
        New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value "Error: $_.Exception.Message" -Force -ErrorAction SilentlyContinue | Out-Null
    }
    #Start-Process -FilePath 'Dism.exe' -ArgumentList "/Online /Add-Package /PackagePath:$($CabFile) /NoRestart" -NoNewWindow -Wait
} catch {}