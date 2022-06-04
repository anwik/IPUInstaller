
$LogFile = "$env:ProgramData\~IPULog\Execute-TaskSequence.log"

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
Function Execute-TaskSequence {
    Param (
        [parameter(Mandatory = $true)]
        [string]$Name
    )
    Try {
        Write-Log -Message 'Connecting to the SCCM client Software Center...'
        $softwareCenter = New-Object -ComObject 'UIResource.UIResourceMgr'
    } Catch {
        Write-Log -Message 'Could not connect to the client Software Center.'
        Write-Log -Message "$_.Exception.Message"
    }
    If ($softwareCenter) {
        Write-Log -Message "Searching for deployments for task sequence [$name]..."
        $taskSequence = $softwareCenter.GetAvailableApplications() | Where-Object { $_.PackageName -eq "$Name" }
        If ($taskSequence) {
            $taskSequenceProgramID = $taskSequence.ID
            $taskSequencePackageID = $taskSequence.PackageID
            Write-Log -Message "Found task sequence [$name] with package ID [$taskSequencePackageID]."
            # Execute the task sequence
            Try {
                Write-Log -Message "Executing task sequence [$name]..."
                $softwareCenter.ExecuteProgram($taskSequenceProgramID,$taskSequencePackageID,$true)
                Write-Log -Message 'Task Sequence executed.'
            } Catch {
                Write-Log -Message "Failed to execute the task sequence [$name]"
                Write-Log -Message "$_.Exception.Message"
            
            }
        }
    }
}