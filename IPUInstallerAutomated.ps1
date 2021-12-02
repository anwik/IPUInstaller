<#
.SYNOPSIS 
        Download and import IPU Installer solution by Johan Schrewelius.


.DESCRIPTION
    The script will do the following:
        - Download and extract the zip-file https://onevinn.schrewelius.it/Files/IPUInstaller/IPUInstaller.zip
        - Import IPU Application, Deployment Scheduler to ConfigMgr
        - Create collection folder
        - Create collections (Windows 10 Build < 20H2, IPU Windows 10 20H2 x64, IPU Success, IPU Failed, IPU Pending Reboot)
        - Create and deploy new client setting (HW-inventory schedule, Powershell executionpolicy ByPass) 
        - Deploy IPU App to IPU Collection
        - Deploy Deployment Scheduler to IPU Collection
        - Create Maintenance Window for IPU Collection
        - Import ".\IPUInstaller\ConsoleScript\Reset_IPU_Status.ps1" script to the console
    
    IMPORTANT, this script will not edit your Configuration.mof or import SMS.mof automatically. You will have to do this step manually!
    The script will check if your ConfigMgr's hardware inventory is capable of collecting the information needed according to the documentation for IPU Installer.
    If not, the script will exit and tell you to do the edit and import of .mof. Run the script again after you're done with this step and it will take care of the rest!

    
    

.NOTES
    FileName:    IPUInstallerAutomated.ps1
	Author:      Andreas Wikström / Gary Blok
    Contact:     @andreaswkstrm / @gwblok
    Created:     2021-03-13
    Updated:     2021-12-02
    Version:     1.2

Version history:
1.2 - (2021-12-02) - Added variables, bug fix for Deployment Scheduler Deployment Type 
1.1 - (2021-03-16) - Borrowed/stole some of Gary's code. Added import and deployment of "Deployment Scheduler" app.
1.0 - (2021-03-13) - Script created
   
#>






# Function for importing Powershell-script to CM-console
<#

.SYNOPSIS
    Creates a script in CM Console. Originally written by Ken Wygant - https://pfe.tips/import-powershell-scripts-into-configuration-manager/
    Filename: NewScriptFunction.ps1
.NOTES
    Version: 1.0
    Author: Ken Wygant
    Purpose/Change: Initial script development
#>

# Force TLS 1.2
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12


function convert-texttobase64 {
    param([Parameter(Position = 0, Mandatory = $true, ValuefromPipeline = $true)][string]$rawtext)
    $1 = [System.Text.Encoding]::UTF8.GetBytes($rawtext)
    [System.Convert]::ToBase64String($1)
}


function New-CMPowershellScript {
    param(
        [Parameter(Mandatory = $true)][string]$ScriptName,
        [Parameter()][string]$comment,
        [Parameter(Mandatory = $true)][string]$Script
    )
    $systemvar = @('Verbose','Debug','WarningAction','ErrorAction','InformationAction','ErrorVariable','WarningVariable','InformationVariable','OutVariable','OutBuffer','PipelineVariable')

    $tempscriptpath = "$($env:TEMP)\temp.ps1"
    $script | Out-File $tempscriptpath
    $ParameterList = ((Get-Command -Name $tempscriptpath).Parameters).Values | Where-Object { $_.Name -notin $systemvar }
    Remove-Item $tempscriptpath -Force

    if ($ParameterList.count -gt 0) {
        [xml]$Doc = New-Object System.Xml.XmlDocument

        #create declaration
        $dec = $Doc.CreateXmlDeclaration('1.0','utf-16',$null)
        #append to document
        $doc.AppendChild($dec) | Out-Null

        $root = $doc.CreateNode('element','ScriptParameters',$null)
        $root.SetAttribute('SchemaVersion',1) | Out-Null

        ForEach ($Parameter in $ParameterList) {
            [string]$IsRequired = $Parameter.Attributes.Mandatory
            [string]$IsHidden = $Parameter.Attributes.DontShow
            [string]$description = $Parameter.Attributes.HelpMessage
        
            $P = $doc.CreateNode('element','ScriptParameter',$null)
            $P.SetAttribute('Name',$Parameter.Name) | Out-Null
            $P.SetAttribute('FriendlyName',$Parameter.Name) | Out-Null
            $P.SetAttribute('Type',$Parameter.ParameterType.FullName) | Out-Null
            $P.SetAttribute('Description',$description) | Out-Null
            $P.SetAttribute('IsRequired',$IsRequired.ToLower()) | Out-Null
            $P.SetAttribute('IsHidden',$IsHidden.ToLower()) | Out-Null

            if ($Parameter.Attributes.ValidValues) {
                $Values = $doc.CreateElement('Values')
                ForEach ($value in $Parameter.Attributes.ValidValues) {
                    $V = $doc.CreateElement('Value')
                    $V.InnerText = $value | Out-Null
                    $Values.AppendChild($v)
                }
                $p.AppendChild($values)

            }

            $root.AppendChild($P) | Out-Null
        }

        $doc.AppendChild($root) | Out-Null

        $tempfile = "$($env:TEMP)\paramtemp.xml"
        $doc.save($tempfile)
        [String]$params = Get-Content -Path $tempfile -Raw
        Remove-Item $tempfile -Force

    }

    if ($null -eq (Get-Module ConfigurationManager)) { Import-Module "$($ENV:SMS_ADMIN_UI_PATH)\..\ConfigurationManager.psd1" }
    $psdrive = Get-PSDrive -PSProvider CMSite

    if ($psdrive) {
        $sitecode = $psdrive.SiteCode

        [string]$Script64 = convert-texttobase64 $Script
        if ($Params) { [string]$Params64 = convert-texttobase64 $Params }

        $NewGUID = ([guid]::NewGuid()).GUID
        $Arguments = @{
            ScriptGUID       = $NewGUID;
            ScriptVersion    = [string]'1';
            ScriptName       = $ScriptName;
            Author           = "$($env:userdomain)\$($env:username)";
            ScriptType       = [uINT32]0;
            ApprovalState    = [uINT32]0;
            Approver         = $null;
            Comment          = $null;
            ParamsDefinition = $Params64;
            ParameterlistXML = $null;
            Script           = $Script64
        };


        Invoke-CimMethod -Namespace "root\SMS\site_$($sitecode)" -ClassName SMS_Scripts -MethodName CreateScripts -Arguments $Arguments
    } else { Write-Error 'No CM provider loaded' }
}

# Variables for app creation
$SourceServer = '\\server\PkgSource$' # UNC path to source share
$Release = '21H2' # Used for Collection Names & App Names
$OrgName = "COMPANY" # Defines the publisher on the IPUApp and Deployment Scheduler app 


# IPU App
$IPUAppName = "Windows 10 $Release Upgrade"
$IPUAppSourceLocation = "$SourceServer\Applications\eKlient IPUApplication\$Release\" # This will be the App Source on your server
$IPUAppImageIconURL = 'https://upload.wikimedia.org/wikipedia/commons/0/08/Windows_logo_-_2012_%28dark_blue%29.png'
$IPUAppDownloadURL = "https://onevinn.schrewelius.it/Files/IPUInstaller/IPUInstaller.zip"
$IPUAppExtractPath = "$SourceServer\IPUInstaller - eKlient\2011-11-24 21H2" # IPUInstaller.zip will be extracted here
$UpgradeMediaPath = "$SourceServer\OSSources\Win10 Ent x64 21H2 19044.1348"  # Path to your IPU Media folder
$DeadlineDateTime = '11/30/2022 20:00:00' # This decides the end date for the IPU, users can't schedule to upgrade any later than this



# Variables for collections and client setting
$SiteCode = (Get-WmiObject -ComputerName "$ENV:COMPUTERNAME" -Namespace 'root\SMS' -Class 'SMS_ProviderLocation').SiteCode
$LimitingCollection = 'Workstations | Windows 10'
$RefreshType = 'Continuous'
$CollectionFolder = "OSD Upgrade IPU Installer $Release" # This folder will be created if it doesn't exist and then the IPU collections will be placed here.

# PreCache collections
$CollectionStartPreCache = "1. Start $Release PreCache Sequence" # Collection for starting PreCache-TS for drivers
$CollectionPreCacheSuccess = "1.1 PreCache $Release Success" # Computers that successfully completes PreCache-TS
$CollectionPreCacheFailed = "1.2 PreCache $Release Failed" # Computers that couldn't complete PreCache-TS

# IPU Collections
$CollectionIPUDeployment = "2. IPU Windows 10 $Release x64" # This is where you put the computers that you want to upgrade.
$CollectionIPUSuccess = "2.1 IPU $Release Success" # This collection will contain all computers that have successfully been upgraded.
$CollectionIPUFailed = "2.2 IPU $Release Failed" # This is the collection that will collect the computers that have failed the IPU.
$CollectionIPUPendingReboot = '2.3 IPU Pending Reboot' # This collection will contain all computers with a pending reboot.
$CollectionLessThanRelease = "Windows 10 Build < $Release" # This collection will collect all computers with anything less than 20H2 installed.

# Client Setting
$ClientSettingName = 'IPU Policy'


# Script to be used as detection method for IPU Application
$DetectionMethod = {

    $BuildNumber = '19044'

    $statusOk = $false

    try {
        $statusOk = (Get-ItemProperty -Path HKLM:\SOFTWARE\Onevinn\IPUStatus -Name 'IPURestartPending' -ErrorAction Stop).IPURestartPending -eq 'True'
    } catch {}

    if ($statusOk) {
        Set-ItemProperty -Path HKLM:\SOFTWARE\Onevinn\IPUStatus -Name 'IPURestartPending' -Value 'False' -Force | Out-Null
    } else {
        $statusOk = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name 'CurrentBuild').CurrentBuild -eq $BuildNumber
    }

    if ($statusOk) {
        Write-Output 'Installed'
    }
}


#Test Extract Path
Write-Host 'Starting Build of Onevinn IPUApplication Build' -ForegroundColor Yellow
Set-Location -Path 'c:\'
if (!(Test-Path $IPUAppExtractPath)) {
    Write-Host "Creating Folder $IPUAppExtractPath" -ForegroundColor Green
    $NewFolder = New-Item -Path $IPUAppExtractPath -ItemType directory -Force
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host ' Downloading Requirements from Internet' -ForegroundColor Green
    #Download IPUApplication from OneVinn
    Invoke-WebRequest -Uri $IPUAppDownloadURL -UseBasicParsing -OutFile "$env:TEMP\IPUApp.zip"
    #Download Icon for Application in Software Center
    Invoke-WebRequest -Uri $IPUAppImageIconURL -OutFile "$IPUAppExtractPath\AppIcon.png"
    Unblock-File "$env:TEMP\IPUApp.zip"
    #Write-Host " Extract Download" -ForegroundColor Green
    Expand-Archive -Path "$env:TEMP\IPUApp.zip" -DestinationPath $IPUAppExtractPath
}

# Deployment Scheduler App
$DSAppName = Get-ChildItem -Path $IPUAppExtractPath | Where-Object -Property Name -Like '*DeploymentScheduler*' | Select-Object Name
$DSAppSourceLocation = "$SourceServer\Applications\$($DSAppName.Name)"
$DSAppVersionRaw = "$($DSAppName.Name)"
$DSAppVersionSplit = $DSAppVersionRaw.Split(' ')
$DSAppVersionNumber = $DSAppVersionSplit[1]


# Find MSI Product Code of Deployment Scheduler App
$path = "$IPUAppExtractPath\$($DSAppName.Name)\$($DSAppName.Name).msi"

$comObjWI = New-Object -ComObject WindowsInstaller.Installer
$MSIDatabase = $comObjWI.GetType().InvokeMember('OpenDatabase','InvokeMethod',$Null,$comObjWI,@($Path,0))
$Query = "SELECT Value FROM Property WHERE Property = 'ProductCode'"
$View = $MSIDatabase.GetType().InvokeMember('OpenView','InvokeMethod',$null,$MSIDatabase,($Query))
$View.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $View, $null)
$Record = $View.GetType().InvokeMember('Fetch','InvokeMethod',$null,$View,$null)
$DSAppProductCode = $Record.GetType().InvokeMember('StringData','GetProperty',$null,$Record,1)




# Import CM-module
try {
    Write-Host 'Importing SCCM PS Module' -ForegroundColor Yellow
    Import-Module (Join-Path $(Split-Path $env:SMS_ADMIN_UI_PATH) ConfigurationManager.psd1)
    Write-Host "Setting location to $SiteCode" -ForegroundColor Yellow
    Set-Location "$($SiteCode):"
} catch {
    $_
}

#Create IPU App
if (Get-CMApplication -Fast -Name $IPUAppName) {
    Write-Host "Application: $IPUAppName already exist" -ForegroundColor Green
} else {
    Write-Host "Creating Application: $IPUAppName" -ForegroundColor Green
    $NewIPUApp = New-CMApplication -Name $IPUAppName -Publisher $OrgName -LocalizedName $IPUAppName -LocalizedDescription "Uppgraderar din dator till Windows 10 $Release.  Datorn kommer att behöva startas om men du blir notifierad om detta.  Det rekommenderas att du sparar ditt arbete innan du uppgraderar."
    if (!($IPUAppUserCat = Get-CMCategory -Name 'IPUApplication' -CategoryType CatalogCategories)) {
        $IPUAppUserCat = New-CMCategory -CategoryType CatalogCategories -Name 'IPUApplication'
    }
    Set-CMApplication -InputObject $NewIPUApp -AddUserCategory $IPUAppUserCat
    Set-CMApplication -InputObject $NewIPUApp -SoftwareVersion $Release
    Write-Host ' Completed' -ForegroundColor Gray
    #Set Icon for Software Center
    Set-Location "$($SiteCode):\"
    Set-CMApplication -InputObject $NewIPUApp -IconLocationFile $IPUAppExtractPath\AppIcon.png
    Write-Host " Set App SC Icon on: $IPUAppName" -ForegroundColor Green
}


#Create IPU AppDT Base
Set-Location -Path 'C:'
if (Test-Path $IPUAppSourceLocation) {}
else {               
    Write-Host " Creating Source Folder Structure: $IPUAppSourceLocation" -ForegroundColor Green
    $NewFolder = New-Item -Path $IPUAppSourceLocation -ItemType directory -ErrorAction SilentlyContinue      
    Write-Host ' Starting Copy of Content, App & Media' -ForegroundColor Green
    Copy-Item -Path "$IPUAppExtractPath\IPUApplication\*" -Destination $IPUAppSourceLocation -Recurse -Force
    Copy-Item -Path "$UpgradeMediaPath\*" -Destination "$IPUAppSourceLocation\Media" -Recurse -Force
}
Set-Location -Path "$($SiteCode):"
if (Get-CMDeploymentType -ApplicationName $IPUAppName -DeploymentTypeName $IPUAppName) {
    Write-Host ' AppDT already Created' -ForegroundColor Green
} else {
    Write-Host ' Starting AppDT Creation' -ForegroundColor Green
    $NewIPUAppDT = Add-CMScriptDeploymentType -ApplicationName $IPUAppName -DeploymentTypeName $IPUAppName -ContentLocation $IPUAppSourceLocation -InstallCommand 'IPUInstaller.exe' -InstallationBehaviorType InstallForSystem -Force32Bit:$true -EstimatedRuntimeMins '60' -MaximumRuntimeMins '120' -ScriptLanguage PowerShell -ScriptText $DetectionMethod
    Write-Host "  Created AppDT: $IPUAppName" -ForegroundColor Green
    #Distribute Content
    Get-CMDistributionPointGroup | ForEach-Object { Start-CMContentDistribution -ApplicationName $IPUAppName -DistributionPointGroupName $_.Name }
}


# Create DS App
if (Get-CMApplication -Fast -Name "$($DSAppName.Name)") {
    Write-Host 'Application: '$($DSAppName.Name)' already exist' -ForegroundColor Green
} else {
    Write-Host 'Creating Application: '$($DSAppName.Name)'' -ForegroundColor Green
    $NewDSApp = New-CMApplication -Name "$($DSAppName.Name)" -Publisher $OrgName -LocalizedName "$($DSAppName.Name)"
    Set-CMApplication -InputObject $NewDSApp -SoftwareVersion $Release
    Write-Host ' Completed' -ForegroundColor Gray
    Set-Location "$($SiteCode):\"
}


#Create ds AppDT Base
Set-Location -Path 'C:'
if (Test-Path $DSAppSourceLocation) {}
else {               
    Write-Host " Creating Source Folder Structure: $DSAppSourceLocation" -ForegroundColor Green
    $NewFolder = New-Item -Path $DSAppSourceLocation -ItemType directory -ErrorAction SilentlyContinue      
    Write-Host ' Starting Copy of Content' -ForegroundColor Green
    Copy-Item -Path "$IPUAppExtractPath\$($DSAppName.Name)\$($DSAppName.Name).msi" -Destination $DSAppSourceLocation -Recurse -Force
}
Set-Location -Path "$($SiteCode):"
if (Get-CMDeploymentType -ApplicationName $($DSAppName.Name) -DeploymentTypeName $($DSAppName.Name)) {
    Write-Host ' AppDT already Created' -ForegroundColor Green
} else {
    Write-Host ' Starting AppDT Creation' -ForegroundColor Green
    $DSAppDetectionMethod = New-CMDetectionClauseWindowsInstaller -ProductCode $DSAppProductCode -Value -ExpressionOperator GreaterEquals -ExpectedValue "$DSAppVersionNumber"
    $NewDSAppDT = Add-CMMsiDeploymentType -ApplicationName $($DSAppName.Name) -DeploymentTypeName $($DSAppName.Name) -ContentLocation "$DSAppSourceLocation\$($DSAppName.Name).msi" -InstallCommand "msiexec /i `"$($DSAppName.Name).msi`" /qn" -InstallationBehaviorType InstallForSystem -Force32Bit:$true -EstimatedRuntimeMins '15' -MaximumRuntimeMins '30' -AddDetectionClause $DSAppDetectionMethod
    Write-Host "  Created AppDT: $($DSAppName.Name)" -ForegroundColor Green
    #Distribute Content
    Get-CMDistributionPointGroup | ForEach-Object { Start-CMContentDistribution -ApplicationName $($DSAppName.Name) -DistributionPointGroupName $_.Name }
}


#Set Schedule to Evaluate Weekly (from the time you run the script)
$Schedule = New-CMSchedule -Start (Get-Date).DateTime -RecurInterval Days -RecurCount 7

#Create Test Collection and QUery, if Fails, Exit Script asking for Hardware Inv to be Extended
New-CMDeviceCollection -Name 'TestHWInvQuery' -Comment 'Used to test if Hardware Inv Settings have been added yet, See Section 7 in PDF Doc' -LimitingCollectionName 'All Systems' -RefreshSchedule $Schedule -RefreshType 2 | Out-Null
$TestQuery = @'
select
SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from
SMS_R_System inner join SMS_G_System_IpuResult on SMS_G_System_IpuResult.ResourceId = SMS_R_System.ResourceId where SMS_G_System_IpuResult.LastStatus = "Test"
'@
Add-CMDeviceCollectionQueryMembershipRule -RuleName 'Query TestHWInvQuery' -CollectionName 'TestHWInvQuery' -QueryExpression $TestQuery -ErrorAction SilentlyContinue | Out-Null
$TestQueryResult = Get-CMCollectionQueryMembershipRule -CollectionName 'TestHWInvQuery'

if (!($TestQueryResult)) {
    Remove-CMCollection -Name 'TestHWInvQuery' -Force
    Clear-Host
    Write-Host '========================================================================================================================================================================' -ForegroundColor Cyan
    Write-Host 'Hardware Inv not setup properly to allow creation of query based collections, please read the docs, section 7, and finish the setup of the inventory, then re-run script' -ForegroundColor Yellow
    Write-Host '========================================================================================================================================================================' -ForegroundColor Cyan

} else {
    Write-Host 'Hardware INV appears to be setup, continuing...' -ForegroundColor Green
    Remove-CMCollection -Name 'TestHWInvQuery' -Force
   
    # Creating collections
    Write-Host "Automatic creation of collections has been initiated. After the script has been successfully run, you will find your newly created collections under the $CollectionFolder folder." -ForegroundColor Green

    # Main collection
    Write-Host "Creating collection $CollectionLessThanRelease" -ForegroundColor Yellow
    $CollectionLessThanReleaseQuery = @'
select
SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from
SMS_R_System inner join SMS_G_System_OPERATING_SYSTEM on
SMS_G_System_OPERATING_SYSTEM.ResourceId = SMS_R_System.ResourceId where
SMS_G_System_OPERATING_SYSTEM.BuildNumber < "19044" and
SMS_G_System_OPERATING_SYSTEM.Caption = "Microsoft Windows 10 Enterprise"
'@
    $CollId1 = (New-CMDeviceCollection -Name "$CollectionLessThanRelease" -LimitingCollectionName $LimitingCollection -RefreshType $RefreshType).CollectionID
    Add-CMDeviceCollectionQueryMembershipRule -CollectionName "$CollectionLessThanRelease" -RuleName "$CollectionLessThanRelease" -QueryExpression $CollectionLessThanReleaseQuery


    # Create "1.1 PreCache $Release Success Collection"
    Write-Host "Creating collection $CollectionPreCacheSuccess " -ForegroundColor Yellow
    $CollId2 = (New-CMDeviceCollection -Name "$CollectionPreCacheSuccess" -LimitingCollectionName $CollectionLessThanRelease -RefreshType $RefreshType).CollectionID

    # Create "1.2 PreCache $Release Failed Collection"
    Write-Host "Creating collection $CollectionPreCacheFailed " -ForegroundColor Yellow
    $CollId3 = (New-CMDeviceCollection -Name "$CollectionPreCacheFailed" -LimitingCollectionName $CollectionLessThanRelease -RefreshType $RefreshType).CollectionID

    # Create "1. Start PreCache $Release Collection"
    Write-Host "Creating collection $CollectionStartPreCache  " -ForegroundColor Yellow
    $CollId4 = (New-CMDeviceCollection -Name "$CollectionStartPreCache " -LimitingCollectionName $CollectionLessThanRelease -RefreshType $RefreshType).CollectionID
    Write-Host "Adding exclude rule for $CollectionPreCacheSuccess to $CollectionStartPreCache" -ForegroundColor Yellow
    Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $CollectionStartPreCache -ExcludeCollectionName "$CollectionPreCacheSuccess"


    # Create IPUFailed collection
    Write-Host "Creating collection $CollectionIPUFailed" -ForegroundColor Yellow
    $CollectionIPUFailedQuery = @'
select
SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.
SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from
SMS_R_System inner join SMS_G_System_IpuResult on SMS_G_System_IpuResult.ResourceId = SMS_R_System.ResourceId where SMS_G_System_IpuResult.LastStatus = "Failed"
'@
    $CollId5 = (New-CMDeviceCollection -Name "$CollectionIPUFailed" -LimitingCollectionName $LimitingCollection -RefreshType $RefreshType).CollectionID
    Add-CMDeviceCollectionQueryMembershipRule -CollectionName "$CollectionIPUFailed" -RuleName "$CollectionIPUFailed" -QueryExpression $CollectionIPUFailedQuery

    # Create IPUPendingReboot collection
    Write-Host "Creating collection $CollectionIPUPendingReboot" -ForegroundColor Yellow
    $CollectionIPUPendingRebootQuery = @'
select
SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from
SMS_R_System inner join SMS_G_System_IpuResult on SMS_G_System_IpuResult.ResourceId = SMS_R_System.ResourceId where SMS_G_System_IpuResult.LastStatus = "PendingReboot"
'@
    $CollId6 = (New-CMDeviceCollection -Name "$CollectionIPUPendingReboot" -LimitingCollectionName $LimitingCollection -RefreshType $RefreshType).CollectionID
    Add-CMDeviceCollectionQueryMembershipRule -CollectionName "$CollectionIPUPendingReboot" -RuleName "$CollectionIPUPendingReboot" -QueryExpression $CollectionIPUPendingRebootQuery

    # Create CollectionIPUSuccess collection
    Write-Host "Creating collection $CollectionIPUSuccess" -ForegroundColor Yellow
    $CollectionIPUSuccessQuery = @'
select
SMS_R_SYSTEM.ResourceID,SMS_R_SYSTEM.ResourceType,SMS_R_SYSTEM.Name,SMS_R_SYSTEM.SMSUniqueIdentifier,SMS_R_SYSTEM.ResourceDomainORWorkgroup,SMS_R_SYSTEM.Client from
SMS_R_System inner join SMS_G_System_IpuResult on SMS_G_System_IpuResult.ResourceId = SMS_R_System.ResourceId where SMS_G_System_IpuResult.LastStatus = "Success"
'@
    $CollId7 = (New-CMDeviceCollection -Name "$CollectionIPUSuccess" -LimitingCollectionName $LimitingCollection -RefreshType $RefreshType).CollectionID
    Add-CMDeviceCollectionQueryMembershipRule -CollectionName "$CollectionIPUSuccess" -RuleName "$CollectionIPUSuccess" -QueryExpression $CollectionIPUSuccessQuery

    # Create CollectionIPUDeployment collection
    Write-Host "Creating collection $CollectionIPUDeployment" -ForegroundColor Yellow
    $CollId8 = (New-CMDeviceCollection -Name "$CollectionIPUDeployment" -LimitingCollectionName $CollectionLessThanRelease -RefreshType $RefreshType).Collectionid
    Write-Host "Adding exclude rule for $CollectionIPUFailed to $CollectionIPUDeployment" -ForegroundColor Yellow
    Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $CollectionIPUDeployment -ExcludeCollectionName "$CollectionIPUFailed"
    Write-Host "Adding exclude rule for $CollectionIPUPendingReboot to $CollectionIPUDeployment" -ForegroundColor Yellow
    Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $CollectionIPUDeployment -ExcludeCollectionName "$CollectionIPUPendingReboot"
    Write-Host "Adding exclude rule for $CollectionIPUSuccess to $CollectionIPUDeployment" -ForegroundColor Yellow
    Add-CMDeviceCollectionExcludeMembershipRule -CollectionName $CollectionIPUDeployment -ExcludeCollectionName "$CollectionIPUSuccess"
    Write-Host "Adding include rule for $CollectionPreCacheSuccess to $CollectionIPUDeployment" -ForegroundColor Yellow
    Add-CMDeviceCollectionIncludeMembershipRule -CollectionName $CollectionIPUDeployment -IncludeCollectionName "$CollectionPreCacheSuccess"
    $CollectionIPUDeployment = Get-CMCollection -Name $CollectionIPUDeployment




    # Create Collection Folder if it doesn't exists
    Set-Location \
    Set-Location .\DeviceCollection
    If (-not (Test-Path -Path (".\$CollectionFolder"))) {
        Write-Host "Device collection folder $CollectionFolder was not found. Creating folder" -ForegroundColor Green    
        New-Item -Name "$CollectionFolder" | Out-Null
    } elseif (Test-Path -Path (".\$CollectionFolder")) {
        Write-Host "Device collection folder name $CollectionFolder already exists. Moving collections to this folder." -ForegroundColor Yellow
        $CollectionFolder = ".\$CollectionFolder"
    }    



    # Move collections to $CollectionFolder    

    $CMCol1 = Get-CMDeviceCollection -Id $CollId1
    $CMCol2 = Get-CMDeviceCollection -Id $CollId2
    $CMCol3 = Get-CMDeviceCollection -Id $CollId3
    $CMCol4 = Get-CMDeviceCollection -Id $CollId4
    $CMCol5 = Get-CMDeviceCollection -Id $CollId5
    $CMCol6 = Get-CMDeviceCollection -Id $CollId6
    $CMCol7 = Get-CMDeviceCollection -Id $CollId7
    $CMCol8 = Get-CMDeviceCollection -Id $CollId8


    Write-Host 'Moving collection' $($CMCol1).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol1 | Out-Null
    Write-Host 'Moving collection' $($CMCol2).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol2 | Out-Null
    Write-Host 'Moving collection' $($CMCol3).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol3 | Out-Null
    Write-Host 'Moving collection' $($CMCol4).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol4 | Out-Null
    Write-Host 'Moving collection' $($CMCol5).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol5 | Out-Null
    Write-Host 'Moving collection' $($CMCol6).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol6 | Out-Null
    Write-Host 'Moving collection' $($CMCol7).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol7 | Out-Null
    Write-Host 'Moving collection' $($CMCol8).Name -ForegroundColor Yellow
    Move-CMObject -FolderPath "$CollectionFolder" -InputObject $CMCol8 | Out-Null
}





#region ScriptBody - Create and deploy new client setting, Deploy App to IPU Collection, create Maintenance Window, import script to console

if ($TestQueryResult) {
    # Creating client setting to be able to run hardware inventory on the IPU collections
    Write-Host 'Creating Custom Client Setting named:' $ClientSettingName -ForegroundColor Yellow
    $HWInvSched = New-CMSchedule -RecurCount '30' -RecurInterval 'Minutes' # This is the schedule for the hardware inventory cycle in the custom client setting that we're creating
    New-CMClientSetting -Name "$ClientSettingName" -Description 'IPU Deployment - Increased HW-inventory cycle and PowerShell -ByPass' -Type 1 | Out-Null
    Set-CMClientSettingHardwareInventory -Name "$ClientSettingName" -MaxRandomDelayMins '5' -Schedule $HWInvSched -Enable $True
    Set-CMClientSettingComputerAgent -Name "$ClientSettingName" -PowerShellExecutionPolicy Bypass

    # Deploy client setting to IPUPendingReboot and IPU Windows 10 20H2 x64 collections
    Write-Host 'Deploying:' $($ClientSettingName) 'to collection:' $($CollectionIPUPendingReboot) -ForegroundColor Yellow
    Start-CMClientSettingDeployment -ClientSettingName $ClientSettingName -CollectionName "$CollectionIPUPendingReboot"
    Write-Host 'Deploying:' $($ClientSettingName) 'to collection:' "$($CollectionIPUDeployment.Name)" -ForegroundColor Yellow
    Start-CMClientSettingDeployment -ClientSettingName $ClientSettingName -CollectionName "$($CollectionIPUDeployment.Name)"
    Write-Host 'Deployming apps & Maintenance Window' -ForegroundColor Magenta
    Write-Host " Creating Deployment for $IPUAppName to Collection $($CollectionIPUDeployment.name)" -ForegroundColor Green
    $IPUAppDeployment = New-CMApplicationDeployment -Name $IPUAppName -CollectionId $CollectionIPUDeployment.CollectionID -DeployAction Install -DeployPurpose Required -UserNotification DisplayAll -DeadlineDateTime $DeadlineDateTime
    $DSAppDeployment = New-CMApplicationDeployment -Name $($DSAppName.Name) -CollectionId $CollectionIPUDeployment.CollectionID -DeployAction Install -DeployPurpose Required -UserNotification DisplayAll 
}




# Create the script in CM console

$Script = { $IpuResultPath = 'HKLM:\SOFTWARE\Onevinn\IpuResult'
    New-ItemProperty -Path $IpuResultPath -Name 'LastStatus' -Value 'Unknown' -Force -EA SilentlyContinue | Out-Null
    Invoke-WmiMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule '{00000000-0000-0000-0000-000000000001}' | Out-Null
    $folderPath = "$($env:SystemDrive)\`$WINDOWS.~BT"
    if (Test-Path -Path "$folderPath") {
        Remove-Item -Path "$folderPath" -Force -EA SilentlyContinue | Out-Null
    }
}

Write-Host 'Importing console script: .\ConsoleScript\Reset_IPU_Status.ps1' -ForegroundColor Yellow
$CreateScript = New-CMPowershellScript -ScriptName 'IPU Reset' -Script $Script
Write-Host "Import complete. Don't forget to approve it!" -ForegroundColor Green





Write-Host 'Setting location back to local disk' -ForegroundColor Yellow
Set-Location C:

Write-Host 'Script execution complete. Exiting.' -ForegroundColor Green