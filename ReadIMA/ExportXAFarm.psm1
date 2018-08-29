# Copyright Citrix Systems, Inc.

$ErrorActionPreference = "Stop"

Set-Variable -Name TotalAppsExported -Scope Script -Value 0
Set-Variable -Name TotalAppsSkipped -Scope Script -Value 0

<#
    .Synopsis
        Create a single administrator node.
    .Parameter AdminObj
        A Citrix.XenApp.Commands.XAAdministrator object.
#>

[System.Xml.XmlElement]
function New-AdministratorNode
{
    param
    (
        [Citrix.XenApp.Commands.XAAdministrator] $adminObj
    )

    $node = New-XmlNode "Administrator" $null $adminObj.AdministratorName
    foreach ($p in ($adminObj | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($adminObj.$p -ne $null) -and ($adminObj.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $adminObj.$p))
        }
    }

    if ($adminObj.AdministratorType -eq "Custom")
    {
        $privs = New-XmlNode "FarmPrivileges"
        $adminObj.FarmPrivileges | % { [void]$privs.AppendChild((New-XmlNode "FarmPrivilege" $_)) }
        [void]$node.AppendChild($privs)

        $folders = New-XmlNode "FolderPrivileges"
        foreach ($f in $adminObj.FolderPrivileges)
        {
            $x = New-XmlNode "FolderPrivilege"
            [void]$x.AppendChild((New-XmlNode "FolderPath" $f.FolderPath))
            $privs = New-XmlNode "FolderPrivileges"
            $f.FolderPrivileges | % { [void]$privs.AppendChild((New-XmlNode "FolderPrivilege" $_)) }
            [void]$x.AppendChild($privs)
            [void]$folders.AppendChild($x)
        }
        [void]$node.AppendChild($folders)
    }

    return $node
}

[System.Xml.XmlElement]
function New-ConfigLoggingNode
{
    Write-LogFile "Exporting farm configuration logging settings" 0 $true
    $configObj = Get-XAConfigurationLog
    $node = New-XmlNode "ConfigurationLogging"
    foreach ($p in ($configObj | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($configObj.$p -ne $null) -and  ($configObj.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $configObj.$p))
        }
    }

    return $node
}

[System.Xml.XmlElement]
function New-ServerNode
{
    param
    (
        [object]$server
    )

    $node = New-XmlNode "Server" $null $server.ServerName
    foreach ($p in ($server | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($server.$p -ne $null) -and ($server.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $server.$p))
        }
    }

    if (($server.IPAddresses -ne $null) -and ($server.IPAddresses.Count -gt 0))
    {
        $ips = New-XmlNode "IPAddresses"
        $server.IPAddresses | % { [void]$ips.AppendChild((New-XmlNode "IPAddress" $_)) }
        [void]$node.AppendChild($ips)
    }

    return $node
}

[System.Xml.XmlElement]
function New-LoadEvaluatorNode
{
    param
    (
        [object]$leObj
    )

    Write-LogFile ([string]::Format('Exporting load evaluator "{0}"', $leObj.LoadEvaluatorName)) 1 $true

    $node = New-XmlNode "LoadEvaluator" $null $leObj.LoadEvaluatorName
    foreach ($p in ($leObj | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($leObj.$p -ne $null) -and ($leObj.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $leObj.$p))
        }
        if (($leObj.$p -ne $null) -and ($leObj.$p -is [System.Array]) -and ($leObj.$p.Count -gt 0))
        {
            $items = New-XmlNode $p
            if ($p -like "*Schedule")
            {
                $leObj.$p | % { [void]$items.AppendChild((New-XmlNode "TimeOfDay" $_)) }
            }
            elseif ($p -eq "IPRanges")
            {
                $leObj.$p | % { [void]$items.AppendChild((New-XmlNode "IPRange" $_)) }
            }
            elseif ($leObj.$p -is [System.Int32[]])
            {
                [void]$items.AppendChild((New-XmlNode "NoLoad" $leObj.$p[0]))
                [void]$items.AppendChild((New-XmlNode "FullLoad" $leObj.$p[1]))
            }
            if ($items.HasChildNodes)
            {
                [void]$node.AppendChild($items)
            }
        }
    }

    return $node
}

[System.Xml.XmlElement]
function New-LBPolicyNode
{
    param
    (
        [Citrix.XenApp.Commands.XAPolicy]$lbpObj
    )

    Write-LogFile ([string]::Format('Exporting load balancing policy "{0}"', $lbpObj.PolicyName)) 1 $true

    $node = New-XmlNode "LoadBalancingPolicy" $null $lbpObj.PolicyName
    $config = Get-XALoadBalancingPolicyConfiguration $lbpObj.PolicyName
    $filter = Get-XALoadBalancingPolicyFilter $lbpObj.PolicyName

    foreach ($p in ($lbpObj | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($lbpObj.$p -ne $null) -and ($lbpObj.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $lbpObj.$p))
        }
    }

    foreach ($p in ($config | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($p -ne "PolicyName") -and ($config.$p -ne $null) -and ($config.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $config.$p))
        }
    }

    if (($config.WorkerGroupPreferences -ne $null) -and ($config.WorkerGroupPreferences.Count -gt 0))
    {
        $wgps = New-XmlNode "WorkerGroupPreferences"
        $config.WorkerGroupPreferences | % { [void]$wgps.AppendChild((New-XmlNode "WorkerGroupPreference" $_)) }
        [void]$node.AppendChild($wgps)
    }

    foreach ($p in ($filter | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($p -ne "PolicyName") -and ($filter.$p -ne $null) -and ($filter.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $filter.$p))
        }
        if (($filter.$p -ne $null) -and ($filter.$p -is [string[]]) -and (-not $p.EndsWith("Accounts")))
        {
            $s = New-XmlNode $p
            $w = $p.TrimEnd('s')
            if ($p.EndsWith("Addresses"))
            {
                $w = $w.TrimEnd('e')
            }
            $filter.$p | % { [void]$s.AppendChild((New-XmlNode $w $_)) }
            [void]$node.AppendChild($s)
        }
        if (($filter.$p -ne $null) -and ($filter.$p -is [System.Array]) -and ($p.EndsWith("Accounts")))
        {
            $s = New-XmlNode $p
            foreach ($q in $filter.$p)
            {
                $a = New-XmlNode $p.TrimEnd('s')
                foreach ($r in ($q | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
                {
                    if ($r -ne "MachineName")
                    {
                        [void]$a.AppendChild((New-XmlNode $r $q.$r))
                    }
                }
                [void]$s.AppendChild($a)
            }
            [void]$node.AppendChild($s)
        }
    }

    return $node
}

<#
    .Synopsis
        Create a node for a given application.
    .Parameter AppObj
        A Citrix.XenApp.Commands.XAApplication or Citrix.XenApp.Commands.XAApplicationReport object.
        This can also be a string, which should be the browser name of the application.
#>

[System.Xml.XmlElement]
function New-ApplicationNode
{
    param
    (
        [object] $appObj,
        [string] $iconDir,
        [bool] $embedIcon
    )

    if ($appObj -is [string])
    {
        if (IsNullOrWhiteSpace $appObj)
        {
            return $null
        }
        $appObj = Get-XAApplication $appObj
    }
    else
    {
        if (($appObj -isnot [Citrix.XenApp.Commands.XAApplication]) -and
            ($appObj -isnot [Citrix.XenApp.Commands.XAApplicationReport]))
        {
            return $null
        } 
    }

    $appName = $appObj.BrowserName
    $appNode = New-XmlNode "Application" $null $appName
    $appType = $appObj.ApplicationType
    $appData = Get-XAApplicationReport $appName

    # Common properties of primitivie types.
    foreach ($p in Get-XAApplicationParameter $appType)
    {
        if (($appObj.$p -ne $null) -and ($appObj.$p -isnot [System.Array]))
        {
            $propNode = New-XmlNode $p $appObj.$p
            [void]$appNode.AppendChild($propNode)
        }
    }

    # Accounts
    $accounts = New-XmlNode "Accounts"
    foreach ($acct in $appData.Accounts)
    {
        $node = New-XmlNode "Account"
        foreach ($p in ($acct | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
        {
            if (($p -ne "MachineName") -and ($acct.$p -ne $null) -and ($acct.$p -isnot [System.Array]))
            {
                [void]$node.AppendChild((New-XmlNode $p $acct.$p))
            }
        }
        [void]$accounts.AppendChild($node)
    }
    [void]$appNode.AppendChild($accounts)

    # Server list, which is not valid for Content and StreamedToClient applications.
    if (($appType -ne "Content") -and ($appType -ne "StreamedToClient"))
    {
        if (($appData.ServerNames -ne $null) -and ($appData.ServerNames.Count -gt 0))
        {
            $servers = New-XmlNode "Servers"
            $appData.ServerNames | % { [void]$servers.AppendChild((New-XmlNode "Server" $_)) }
            [void]$appNode.AppendChild($servers)
        }
        if (($appData.WorkerGroupNames -ne $null) -and ($appData.WorkerGroupNames.Count -gt 0))
        {
            $wgs = New-XmlNode "WorkerGroups"
            $appData.WorkerGroupNames | % { [void] $wgs.AppendChild(($w = New-XmlNode "WorkerGroup" $_)) }
            [void]$appNode.AppendChild($wgs)
        }
    }

    if (($appData.FileTypes -ne $null) -and ($appData.FileTypes.Count -gt 0))
    {
        $fts = New-XmlNode "FileTypes"
        foreach ($entry in $appData.FileTypes)
        {
            $x = New-XmlNode "FileType" $null $entry.FileTypeName
            foreach ($p in ($entry | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
            {
                if (($p -ne "MachineName") -and ($entry.$p -ne $null) -and ($entry.$p -isnot [System.Array]))
                {
                    [void]$x.AppendChild((New-XmlNode $p $entry.$p))
                }
                elseif (($entry.$p -ne $null) -and ($entry.$p -is [string[]]))
                {
                    $s = New-XmlNode $p
                    $entry.$p | % { [void]$s.AppendChild((New-XmlNode $p.TrimEnd('s') $_)) }
                    [void]$x.AppendChild($s)
                }
            }
            [void]$fts.AppendChild($x)
        }
        [void]$appNode.AppendChild($fts)
    }

    if (($appData.AccessSessionConditions -ne $null) -and ($appData.AccessSessionConditions.Count -gt 0))
    {
        $n = New-XmlNode "AccessSessionConditions"
        $appData.AccessSessionConditions | % { [void]$n.AppendChild((New-XmlNode "AccessSessionCondition" $_)) }
        [void]$appNode.AppendChild($n)
    }

    if (($appData.AlternateProfiles -ne $null) -and ($appData.AlternateProfiles.Count -gt 0))
    {
        $n = New-XmlNode "AlternateProfiles"
        foreach ($p in $appData.AlternateProfiles)
        {
            $t = New-XmlNode "AlternateProfile"
            [void]$t.AppendChild((New-XmlNode "ProfileLocation" $t.ProfileLocation))
            [void]$t.AppendChild((New-XmlNode "IPRange" $t.IPRange))
        }
        [void]$appNode.AppendChild($n)
    }

    if ($embedIcon)
    {
        $node = New-XmlNode "IconData" (Get-XAApplicationIcon $appName).EncodedIconData
        [void]$appNode.AppendChild($node)
    }
    else
    {
        $iconFile = (Join-Path $iconDir $appName) + ".txt"
        Write-LogFile ([string]::Format('Saving {0} icon data to file "{1}"', $appName, $iconFile)) 2
        (Get-XAApplicationIcon $appName).EncodedIconData | Out-File -Force $iconFile
        $n = New-XmlNode "IconFileName" (Join-Path (Split-Path -Leaf $iconDir) (Split-Path -Leaf $iconFile))
        [void]$appNode.AppendChild($n)
    }

    return $appNode
}

[System.Xml.XmlElement]
function New-ApplicationsNode
{
    param
    (
        [string] $xmlFile,
        [bool] $embedIcon,
        [int] $appLimit = 65536,
        [int] $skipApps = 0
    )

    $parent = Split-Path $xmlFile
    if ([string]::IsNullOrEmpty($parent))
    {
        $parent = ".\"
    }
    $parent = (Resolve-Path $parent).Path

    if (!$embedIcon)
    {
        $iconDir = Join-Path $parent (([IO.FileInfo]$xmlFile).BaseName + "-icons")
        Write-LogFile ([string]::Format('Creating folder for application icons: "{0}"', $iconDir)) 1
        [void](mkdir $iconDir -Force)
    }

    $appsNode = New-XmlNode "Applications"

    foreach ($appObj in Get-XAApplication)
    {
        if ($Script:TotalAppsExported -ge $appLimit)
        {
            break
        }
        if ($Script:TotalAppsSkipped -lt $skipApps)
        {
            Write-LogFile ([string]::Format('INFO: Skipping application "{0}"', $appObj.DisplayName)) 1 $true
            $Script:TotalAppsSkipped++
            continue
        }
        Write-LogFile ([string]::Format('Exporting application "{0}"', $appObj.DisplayName)) 1 $true
        $appNode = New-ApplicationNode $appObj $iconDir $embedIcon 
        if ($appNode -ne $null)
        {
            [void]$appsNode.AppendChild($appNode)
            $Script:TotalAppsExported++
        }
    }

    return $appsNode
}

[System.Xml.XmlElement]
function New-WorkerGroupNode
{
    param
    (
        [object]$worker
    )

    Write-LogFile ([string]::Format('Exporting worker group "{0}"', $worker.WorkerGroupName)) 1 $true
    $node = New-XmlNode "WorkerGroup" $null $worker.WorkerGroupName
    foreach ($p in ($worker | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
    {
        if (($p -ne "MachineName") -and ($worker.$p -ne $null) -and ($worker.$p -isnot [System.Array]))
        {
            [void]$node.AppendChild((New-XmlNode $p $worker.$p))
        }
    }

    if (($worker.ServerNames -ne $null) -and ($worker.ServerNames.Count -gt 0))
    {
        $servers = New-XmlNode "ServerNames"
        $worker.ServerNames | % { [void]$servers.AppendChild((New-XmlNode "ServerName" $_)) }
        [void]$node.AppendChild($servers)
    }

    if (($worker.ServerGroups -ne $null) -and ($worker.ServerGroups.Count -gt 0))
    {
        $groups = New-XmlNode "ServerGroups"
        $worker.ServerGroups | % { [void]$groups.AppendChild((New-XmlNode "ServerGroup" $_)) }
        [void]$node.AppendChild($groups)
    }

    if (($worker.OUs -ne $null) -and ($worker.OUs.Count -gt 0))
    {
        $ous = New-XmlNode "OUs"
        $worker.ServerNames | % { [void]$ous.AppendChild((New-XmlNode "OU" $_)) }
        [void]$node.AppendChild($ous)
    }

    return $node
}

[System.Xml.XmlElement]
function New-ZoneNode
{
    param
    (
        [object]$zone
    )

    Write-LogFile ([string]::Format('Exporting zone "{0}"', $zone.ZoneName)) 1 $true
    $node = New-XmlNode "Zone" $null $zone.ZoneName
    [void]$node.AppendChild((New-XmlNode "ZoneName" $zone.ZoneName))
    [void]$node.AppendChild((New-XmlNode "DataCollector" $zone.DataCollector))

    $servers = New-XmlNode "Servers"
    Get-XAServer -ZoneName $zone.ZoneName | % { [void]$servers.AppendChild((New-ServerNode $_)) }
    [void]$node.AppendChild($servers)

    return $node
}

<#
    .Synopsis
        Export XenApp farm configuration data to a XML file.
    .Parameter XmlOutputFile
        The name of the XML file that stores the output. The file name must have a .xml
        extension. It must not exist but if a path is given, the parent path must exist.
    .Parameter NoLog
        Do not generate log output.
    .Parameter LogFile
        File for storing the logs. If the file exists and NoClobber is not specified,
        the contents of the file are overwritten. If the file exists and NoClobber is
        specified, an error message is displayed and the script quits. If the log file
        is not specified and NoLog is also not specified, the log is still generated
        and the log file is located under the user's home directory, as specified by
        the $HOME environment variable. The name of the log file is generated using the
        current time stamp: XFarmYYYYMMDDHHmmss-RRRRRR.Log, here YYYY is the year, MM
        is month, DD is day, HH is hour, mm is minute, ss is second, and RRRRRR is a
        six digit random hexdecimal number.
    .Parameter EmbedIconData
        Include the icon data for applications in the XML file. If this switch is not
        specified, icon data is stored separately in files and the files are named using
        the browser name of the application. See the description for more detailed
        information about the icon data files.
    .Parameter NoClobber
        Do not overwrite an existing log file. This switch is applicable only if the
        LogFile parameter is specified.
    .Parameter NoDetails
        If this switch is specified, detailed messages about the progress of the script
        execution will not be sent to the console.
    .Parameter IgnoreAdmins
        Do not export administrators.
    .Parameter IgnoreApps
        Do not export applications.
    .Parameter IgnoreServers
        Do not export servers.
    .Parameter IgnoreZones
        Do not export zones.
    .Parameter IgnoreOthers
        Do not export configuration logging, load evaluators, worker groups, printer drivers,
        and load balancing policies.
    .Parameter AppLimit
        Export only the specified number of applications. If this value is 0, no applications
        are exported. The actual number of applications exported may be smaller than this
        limit.
    .Parameter SkipApps
        Skip the first specified number of applications.
    .Parameter SuppressLogo
        Suppress the logo.
    .Description
        Use this cmdlet to export the configuration data in a XenApp farm to a XML file.
        This cmdlet must be run on a XenApp controller and must have the Citrix XenApp
        Commands PowerShell snap-in installed on the local server.

        The data stored in the XML is organized in the same manner as what is displayed
        in the Citrix AppCenter.

        All data is retrieved using the Citrix XenApp commands.

        The user must have at least read access to all the objects in the farm.

        Application icon data is stored under a folder named by appending the string
        -icons to the base name of the XML file. For example, if the value of the XmlOutputFile
        parameter is FarmData.xml, then the folder FarmData-icons will be created to store
        the application icons. The icon data files under this folder are .txt files named
        using the browser name of the published application. Although the files are .txt
        files, the data stored is encoded binary icon data, which can be read by the
        import script to re-create the application icon.

        You can selectively export some of the farm objects and ignore other objects. For
        example, use the IgnoreZones switch to avoid exporting zone data. In case some of
        the farm objects cause some XenApp commands to fail, these switches can be used to
        work around those calls.

        Use the AppLimit and SkipApps parameters to fine tune your export. If you have large
        number of applications and the applications are to be imported to different delivery
        groups, by exporting selected applications to sepaparate XML files, you can avoid
        editing and specifying specific delivery group for each application in the XML file.
        See help for the Import-XAFarm command for more information about importing applications.
    .Inputs
        None
    .Outputs
        None
    .Link
        https://www.citrix.com/downloads/xenapp/sdks/powershell-sdk.html
    .Example
        Export-XAFarm -XmlOutputFile '.\MyFarmObjects.XML'
        Export all the farm objects and store the data in the file 'MyFarmObjects.XML' in the
        current directory. The log file is generated and located in the $HOME directory. During
        the export, progress of the script is displayed in the console.
    .Example
        Export-XAFarm -XmlOutputFile .\MyFarmObjects.XML -LogFile .\FarmExport.log
        Export all the farm objects and store the data in the file 'MyFarmObjects.XML' in the
        current directory. The log file is FarmExport.log and located in the current directory.
        During the export, progress of the script is displayed in the console.
    .Example
        Export-XAFarm -XmlOutputFile .\MyFarmObjects.XML -LogFile .\FarmExport.log -NoClobber
        Export all the farm objects and store the data in the file 'MyFarmObjects.XML' in the
        current directory. Store the log data in file FarmExport.log in the current directory
        but do not overwrite the file if it exists. During the export, progress of the script
        is displayed in the console.
    .Example
        Export-XAFarm -XmlOutputFile .\MajorObjects.XML -NoDetails -IgnoreZones -IgnoreOthers
        Export application, administrator, server objects and do not export other objects. The
        log file is generated and located in the $HOME directory. Do not display the progress
        of the script execution during the export.
    .Example
        Export-XAFarm -XmlOutputFile .\SomeAppObjects.XML -SkipApps 20 -AppLimit 100
        Export all farm objects but just some of the applications. The first 20 applications are
        not exported and limit the number of applications exported to 100. The applications are
        listed in random order, so there is no way to know which applications are exported. The
        applications are listed using the Get-XAApplication command.
#>
function Export-XAFarm
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Explicit")]
        [ValidateScript({ Assert-XmlOutput $_ })]
        [string] $XmlOutputFile,
        [Parameter(Mandatory=$false)]
        [switch] $NoLog,
        [Parameter(Mandatory=$false)]
        [switch] $NoClobber,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [string] $LogFile,
        [Parameter(Mandatory=$false)]
        [switch] $EmbedIconData,
        [Parameter(Mandatory=$false)]
        [switch] $NoDetails,
        [Parameter(Mandatory=$false)]
        [switch] $IgnoreAdmins,
        [Parameter(Mandatory=$false)]
        [switch] $IgnoreApps,
        [Parameter(Mandatory=$false)]
        [switch] $IgnoreServers,
        [Parameter(Mandatory=$false)]
        [switch] $IgnoreZones,
        [Parameter(Mandatory=$false)]
        [switch] $IgnoreOthers,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [ValidateRange(0,65536)]
        [int] $AppLimit=65536,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [int] $SkipApps,
        [Parameter(Mandatory=$false)]
        [switch] $SuppressLogo
    )

    Print-Logo $SuppressLogo

    if ((Get-Module LogUtilities) -eq $null)
    {
        Write-Error "Module LogUtilities.psm1 is not imported, see ReadMe.txt for usage of this script"
        return
    }
    if ((Get-Module XmlUtilities) -eq $null)
    {
        Write-Error "Module XmlUtilities.psm1 is not imported, see ReadMe.txt for usage of this script"
        return
    }

    $ShowProgress = !$NoDetails
    try
    {
        Start-Logging -NoLog:$Nolog -NoClobber:$NoClobber $LogFile $XmlOutputFile -ShowProgress:$ShowProgress
    }
    catch
    {
        Write-Error $_.Exception.Message
        return
    }

    Write-LogFile ([string]::Format('Export-XAFarm Command Line:'))
    Write-LogFile ([string]::Format('    -XmlOutputFile {0}', $XmlOutputFile))
    Write-LogFile ([string]::Format('    -LogFile {0}', $LogFile))
    Write-LogFile ([string]::Format('    -EmbedIconData = {0}', $EmbedIconData))
    Write-LogFile ([string]::Format('    -AppLimit {0}', $AppLimit))
    Write-LogFile ([string]::Format('    -SkipApps {0}', $SkipApps))
    Write-LogFile ([string]::Format('    -NoClobber = {0}', $NoClobber))
    Write-LogFile ([string]::Format('    -NoDetails = {0}', $NoDetails))
    Write-LogFile ([string]::Format('    -IgnoreAdmins = {0}', $IgnoreAdmins))
    Write-LogFile ([string]::Format('    -IgnoreApps = {0}', $IgnoreApps))
    Write-LogFile ([string]::Format('    -IgnoreServers = {0}', $IgnoreServers))
    Write-LogFile ([string]::Format('    -IgnoreZones = {0}', $IgnoreZones))
    Write-LogFile ([string]::Format('    -IgnoreOthers = {0}', $IgnoreOthers))

    Initialize-Xml

    $s = (Get-PSSnapin -Registered Citrix.XenApp.Commands -ErrorAction SilentlyContinue)
    if ($s -eq $null)
    {
        Write-Error ([string]::Format("{0}`n{1}",
            "The Citrix XenApp Commands PowerShell Snapin is not installed",
            "You must have the Citrix XenApp Commands PowerShell Snapin installed to use this script"))
        return
    }

    $s = (Get-PSSnapin Citrix.XenApp.Commands -ErrorAction SilentlyContinue)
    if ($s -eq $null)
    {
        $m = (Get-PSSnapin -Registered Citrix.XenApp.Commands).ModuleName
        Import-Module (Join-Path (Split-Path -Parent -Path $m) Citrix.XenApp.Commands.dll)
    }

    Write-LogFile "Exporting farm object"
    $farm = Get-XAFarm
    $root = New-XmlNode "Farm"
    [void]$root.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    [void]$root.SetAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    [void]$root.SetAttribute("xmlns", "XAFarmData.xsd")
    [void]$root.AppendChild((New-XmlNode "FarmName" $farm.FarmName))

    $TotalAdmins = 0
    $TotalServers = 0
    $TotalWorkerGroups = 0
    $TotalLoadEvaluators = 0
    $TotalLoadBalancingPolicies = 0
    $TotalPrinterDrivers = 0
    $TotalZones = 0
    $Script:TotalAppsSkipped = 0
    $Script:TotalAppsExported = 0

    if (!$IgnoreOthers)
    {
        [void]$root.AppendChild((New-ConfigLoggingNode))
    }
    else
    {
        Write-LogFile 'INFO: Configuration logging data not exported' 1 $true
    }

    if (!$IgnoreAdmins)
    {
        Write-LogFile "Exporting administrators" 0 $true
        $admins = New-XmlNode "Administrators"
        try
        {
            foreach ($a in (Get-XAAdministrator))
            {
                Write-LogFile ([string]::Format('Exporting administrator "{0}"', $a.AdministratorName)) 1 $true
                [void]$admins.AppendChild((New-AdministratorNode $a))
                $TotalAdmins++
            }
        }
        catch
        {
            Stop-Logging "Exporting administrators aborted, you may try to use the -IgnoreAdmins switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($admins)
        Write-LogFile ([string]::Format('{0} administrators exported', $TotalAdmins)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Administrators not exported' 1 $true
    }

    if (!$IgnoreApps)
    {
        Write-LogFile "Exporting applications" 0 $true
        try
        {
            [void]$root.AppendChild((New-ApplicationsNode $XmlOutputFile $EmbedIconData $AppLimit $SkipApps))
        }
        catch
        {
            Stop-Logging "Exporting applications aborted" $_.Exception.Message
            return
        }
    }
    else
    {
        Write-LogFile 'INFO: Applications not exported' 1 $true
    }

    if (!$IgnoreServers)
    {
        Write-LogFile "Exporting servers" 0 $true
        $servers = New-XmlNode "Servers"
        try
        {
            foreach ($s in (Get-XAServer))
            {
                Write-LogFile ([string]::Format('Exporting server {0}', $s.ServerName)) 1 $true
                [void]$servers.AppendChild((New-ServerNode $s))
                $TotalServers++
            }
        }
        catch
        {
            Stop-Logging "Exporting servers aborted, you may try to use the -IgnoreServers switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($servers)
        Write-LogFile ([string]::Format('{0} servers exported', $TotalServers)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Servers not exported' 1 $true
    }

    if (!$IgnoreOthers)
    {
        Write-LogFile "Exporting load evaluators" 0 $true
        $les = New-XmlNode "LoadEvaluators"
        try
        {
            foreach ($e in (Get-XALoadEvaluator))
            {
                [void]$les.AppendChild((New-LoadEvaluatorNode $e))
                $TotalLoadEvaluators++
            }
        }
        catch
        {
            Stop-Logging "Exporting load evaluators aborted, you may try to use the -IgnoreOthers switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($les)
        Write-LogFile ([string]::Format('{0} load evaluators exported', $TotalLoadEvaluators)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Load evaluators not exported' 1 $true
    }

    if (!$IgnoreOthers)
    {
        Write-LogFile "Exporting load balancing policies" 0 $true
        $policies = New-XmlNode "LoadBalancingPolicies"
        try
        {
            foreach ($p in (Get-XALoadBalancingPolicy))
            {
                [void]$policies.AppendChild((New-LBPolicyNode $p))
                $TotalLoadBalancingPolicies++
            }
        }
        catch
        {
            Stop-Logging "Exporting load balancing policies aborted, you may try to use the -IgnoreOthers switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($policies)
        Write-LogFile ([string]::Format('{0} load balancing policies exported', $TotalLoadBalancingPolicies)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Load balancing policies not exported' 1 $true
    }

    if (!$IgnoreOthers)
    {
        Write-LogFile "Exporting printer drivers" 0 $true
        $drivers = New-XmlNode "PrinterDrivers"
        try
        {
            foreach ($d in (Get-XAPrinterDriver))
            {
                Write-LogFile ([string]::Format('Exporting printer driver "{0}"', $d.DriverName)) 1 $true
                $node = New-XmlNode "PrinterDriver"
                foreach ($p in ($d | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
                {
                    if ($p -ne "MachineName")
                    {
                        [void]$node.AppendChild((New-XmlNode $p $d.$p))
                    }
                    [void]$drivers.AppendChild($node)
                }
                $TotalPrinterDrivers++
            }
        }
        catch
        {
            Stop-Logging "Exporting printer drivers aborted, you may try to use the -IgnoreOthers switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($drivers)
        Write-LogFile ([string]::Format('{0} printer drivers exported', $TotalPrinterDrivers)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Printer drivers not exported' 1 $true
    }

    if (!$IgnoreOthers)
    {
        Write-LogFile "Exporting worker groups" 0 $true
        $workers = New-XmlNode "WorkerGroups"
        try
        {
            foreach ($w in (Get-XAWorkerGroup))
            {
                [void]$workers.AppendChild((New-WorkerGroupNode $w))
                $TotalWorkerGroups++
            }
        }
        catch
        {
            Stop-Logging "Exporting worker groups aborted, you may try to use the -IgnoreOthers switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($workers)
        Write-LogFile ([string]::Format('{0} worker groups exported', $TotalWorkerGroups)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Worker groups not exported' 1 $true
    }

    if (!$IgnoreZones)
    {
        Write-LogFile "Exporting zones" 0 $true
        $zones = New-XmlNode "Zones"
        try
        {
            foreach ($z in (Get-XAZone))
            {
                [void]$zones.AppendChild((New-ZoneNode $z))
                $TotalZones++
            }
        }
        catch
        {
            Stop-Logging "Exporting zones aborted, you may consider to use the -IgnoreZones switch to work around this problem" $_.Exception.Message
            return
        }
        [void]$root.AppendChild($zones)
        Write-LogFile ([string]::Format('{0} zones exported', $TotalZones)) 1 $true
    }
    else
    {
        Write-LogFile 'INFO: Zones not exported' 1 $true
    }

    Write-LogFile "Saving XML file"
    Save-XmlData $root $XmlOutputFile

    Write-LogFile "" 0 $true
    Write-LogFile "Exporting completed successfully" 0 $true
    Write-LogFile ([string]::Format('{0} administrators exported', $TotalAdmins)) 0 $true
    Write-LogFile ([string]::Format('{0} servers exported', $TotalServers)) 0 $true
    Write-LogFile ([string]::Format('{0} applications exported', $Script:TotalAppsExported)) 0 $true
    if ($Script:TotalAppsSkipped -gt 0)
    {
        Write-LogFile ([string]::Format('First {0} applications skipped', $Script:TotalAppsSkipped)) 0 $true
    }
    Write-LogFile ([string]::Format('{0} worker groups exported', $TotalWorkerGroups)) 0 $true
    Write-LogFile ([string]::Format('{0} load evaluators exported', $TotalLoadEvaluators)) 0 $true
    Write-LogFile ([string]::Format('{0} load balancing policies exported', $TotalLoadBalancingPolicies)) 0 $true
    Write-LogFile ([string]::Format('{0} printer drivers exported', $TotalPrinterDrivers)) 0 $true
    Write-LogFile ([string]::Format('{0} zones exported', $TotalZones)) 0 $true

    Stop-Logging "XenApp 6.x farm export completed"
}

# SIG # Begin signature block
# MIIYFQYJKoZIhvcNAQcCoIIYBjCCGAICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwenZSsA3ESlS4D9QuKdohy01
# O6igghMjMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
# AQUFADCBizELMAkGA1UEBhMCWkExFTATBgNVBAgTDFdlc3Rlcm4gQ2FwZTEUMBIG
# A1UEBxMLRHVyYmFudmlsbGUxDzANBgNVBAoTBlRoYXd0ZTEdMBsGA1UECxMUVGhh
# d3RlIENlcnRpZmljYXRpb24xHzAdBgNVBAMTFlRoYXd0ZSBUaW1lc3RhbXBpbmcg
# Q0EwHhcNMTIxMjIxMDAwMDAwWhcNMjAxMjMwMjM1OTU5WjBeMQswCQYDVQQGEwJV
# UzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFu
# dGVjIFRpbWUgU3RhbXBpbmcgU2VydmljZXMgQ0EgLSBHMjCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBALGss0lUS5ccEgrYJXmRIlcqb9y4JsRDc2vCvy5Q
# WvsUwnaOQwElQ7Sh4kX06Ld7w3TMIte0lAAC903tv7S3RCRrzV9FO9FEzkMScxeC
# i2m0K8uZHqxyGyZNcR+xMd37UWECU6aq9UksBXhFpS+JzueZ5/6M4lc/PcaS3Er4
# ezPkeQr78HWIQZz/xQNRmarXbJ+TaYdlKYOFwmAUxMjJOxTawIHwHw103pIiq8r3
# +3R8J+b3Sht/p8OeLa6K6qbmqicWfWH3mHERvOJQoUvlXfrlDqcsn6plINPYlujI
# fKVOSET/GeJEB5IL12iEgF1qeGRFzWBGflTBE3zFefHJwXECAwEAAaOB+jCB9zAd
# BgNVHQ4EFgQUX5r1blzMzHSa1N197z/b7EyALt0wMgYIKwYBBQUHAQEEJjAkMCIG
# CCsGAQUFBzABhhZodHRwOi8vb2NzcC50aGF3dGUuY29tMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwPwYDVR0fBDgwNjA0oDKgMIYuaHR0cDovL2NybC50aGF3dGUuY29tL1Ro
# YXd0ZVRpbWVzdGFtcGluZ0NBLmNybDATBgNVHSUEDDAKBggrBgEFBQcDCDAOBgNV
# HQ8BAf8EBAMCAQYwKAYDVR0RBCEwH6QdMBsxGTAXBgNVBAMTEFRpbWVTdGFtcC0y
# MDQ4LTEwDQYJKoZIhvcNAQEFBQADgYEAAwmbj3nvf1kwqu9otfrjCR27T4IGXTdf
# plKfFo3qHJIJRG71betYfDDo+WmNI3MLEm9Hqa45EfgqsZuwGsOO61mWAK3ODE2y
# 0DGmCFwqevzieh1XTKhlGOl5QGIllm7HxzdqgyEIjkHq3dlXPx13SYcqFgZepjhq
# IhKjURmDfrYwggSjMIIDi6ADAgECAhAOz/Q4yP6/NW4E2GqYGxpQMA0GCSqGSIb3
# DQEBBQUAMF4xCzAJBgNVBAYTAlVTMR0wGwYDVQQKExRTeW1hbnRlYyBDb3Jwb3Jh
# dGlvbjEwMC4GA1UEAxMnU3ltYW50ZWMgVGltZSBTdGFtcGluZyBTZXJ2aWNlcyBD
# QSAtIEcyMB4XDTEyMTAxODAwMDAwMFoXDTIwMTIyOTIzNTk1OVowYjELMAkGA1UE
# BhMCVVMxHTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMTQwMgYDVQQDEytT
# eW1hbnRlYyBUaW1lIFN0YW1waW5nIFNlcnZpY2VzIFNpZ25lciAtIEc0MIIBIjAN
# BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAomMLOUS4uyOnREm7Dv+h8GEKU5Ow
# mNutLA9KxW7/hjxTVQ8VzgQ/K/2plpbZvmF5C1vJTIZ25eBDSyKV7sIrQ8Gf2Gi0
# jkBP7oU4uRHFI/JkWPAVMm9OV6GuiKQC1yoezUvh3WPVF4kyW7BemVqonShQDhfu
# ltthO0VRHc8SVguSR/yrrvZmPUescHLnkudfzRC5xINklBm9JYDh6NIipdC6Anqh
# d5NbZcPuF3S8QYYq3AhMjJKMkS2ed0QfaNaodHfbDlsyi1aLM73ZY8hJnTrFxeoz
# C9Lxoxv0i77Zs1eLO94Ep3oisiSuLsdwxb5OgyYI+wu9qU+ZCOEQKHKqzQIDAQAB
# o4IBVzCCAVMwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAO
# BgNVHQ8BAf8EBAMCB4AwcwYIKwYBBQUHAQEEZzBlMCoGCCsGAQUFBzABhh5odHRw
# Oi8vdHMtb2NzcC53cy5zeW1hbnRlYy5jb20wNwYIKwYBBQUHMAKGK2h0dHA6Ly90
# cy1haWEud3Muc3ltYW50ZWMuY29tL3Rzcy1jYS1nMi5jZXIwPAYDVR0fBDUwMzAx
# oC+gLYYraHR0cDovL3RzLWNybC53cy5zeW1hbnRlYy5jb20vdHNzLWNhLWcyLmNy
# bDAoBgNVHREEITAfpB0wGzEZMBcGA1UEAxMQVGltZVN0YW1wLTIwNDgtMjAdBgNV
# HQ4EFgQURsZpow5KFB7VTNpSYxc/Xja8DeYwHwYDVR0jBBgwFoAUX5r1blzMzHSa
# 1N197z/b7EyALt0wDQYJKoZIhvcNAQEFBQADggEBAHg7tJEqAEzwj2IwN3ijhCcH
# bxiy3iXcoNSUA6qGTiWfmkADHN3O43nLIWgG2rYytG2/9CwmYzPkSWRtDebDZw73
# BaQ1bHyJFsbpst+y6d0gxnEPzZV03LZc3r03H0N45ni1zSgEIKOq8UvEiCmRDoDR
# EfzdXHZuT14ORUZBbg2w6jiasTraCXEQ/Bx5tIB7rGn0/Zy2DBYr8X9bCT2bW+IW
# yhOBbQAuOA2oKY8s4bL0WqkBrxWcLC9JG9siu8P+eJRRw4axgohd8D20UaF5Mysu
# e7ncIAkTcetqGVvP6KUwVyyJST+5z3/Jvz4iaGNTmr1pdKzFHTx/kuDDvBzYBHUw
# ggUwMIIEGKADAgECAhAECRgbX9W7ZnVTQ7VvlVAIMA0GCSqGSIb3DQEBCwUAMGUx
# CzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3
# dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9v
# dCBDQTAeFw0xMzEwMjIxMjAwMDBaFw0yODEwMjIxMjAwMDBaMHIxCzAJBgNVBAYT
# AlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2Vy
# dC5jb20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNp
# Z25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD407Mcfw4R
# r2d3B9MLMUkZz9D7RZmxOttE9X/lqJ3bMtdx6nadBS63j/qSQ8Cl+YnUNxnXtqrw
# nIal2CWsDnkoOn7p0WfTxvspJ8fTeyOU5JEjlpB3gvmhhCNmElQzUHSxKCa7JGnC
# wlLyFGeKiUXULaGj6YgsIJWuHEqHCN8M9eJNYBi+qsSyrnAxZjNxPqxwoqvOf+l8
# y5Kh5TsxHM/q8grkV7tKtel05iv+bMt+dDk2DZDv5LVOpKnqagqrhPOsZ061xPeM
# 0SAlI+sIZD5SlsHyDxL0xY4PwaLoLFH3c7y9hbFig3NBggfkOItqcyDQD2RzPJ6f
# pjOp/RnfJZPRAgMBAAGjggHNMIIByTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1Ud
# DwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDAzB5BggrBgEFBQcBAQRtMGsw
# JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcw
# AoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDBP
# BgNVHSAESDBGMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93
# d3cuZGlnaWNlcnQuY29tL0NQUzAKBghghkgBhv1sAzAdBgNVHQ4EFgQUWsS5eyoK
# o6XqcQPAYPkt9mV1DlgwHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6chnfNtyA8w
# DQYJKoZIhvcNAQELBQADggEBAD7sDVoks/Mi0RXILHwlKXaoHV0cLToaxO8wYdd+
# C2D9wz0PxK+L/e8q3yBVN7Dh9tGSdQ9RtG6ljlriXiSBThCk7j9xjmMOE0ut119E
# efM2FAaK95xGTlz/kLEbBw6RFfu6r7VRwo0kriTGxycqoSkoGjpxKAI8LpGjwCUR
# 4pwUR6F6aGivm6dcIFzZcbEMj7uo+MUSaJ/PQMtARKUT8OZkDCUIQjKyNookAv4v
# cn4c10lFluhZHen6dGRrsutmQ9qzsIzV6Q3d9gEgzpkxYz0IGhizgZtPxpMQBvwH
# gfqL2vmCSfdibqFT+hKUGIUukpHqaGxEMrJmoecYpJpkUe8wggVSMIIEOqADAgEC
# AhAHqUmHhtlA7gQpb7ywpEENMA0GCSqGSIb3DQEBCwUAMHIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xMTAvBgNVBAMTKERpZ2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25p
# bmcgQ0EwHhcNMTcxMDA0MDAwMDAwWhcNMTgxMDExMTIwMDAwWjCBjjELMAkGA1UE
# BhMCVVMxCzAJBgNVBAgTAkZMMRcwFQYDVQQHEw5GdC4gTGF1ZGVyZGFsZTEdMBsG
# A1UEChMUQ2l0cml4IFN5c3RlbXMsIEluYy4xGzAZBgNVBAsTElhlbkFwcChwb3dl
# cnNoZWxsKTEdMBsGA1UEAxMUQ2l0cml4IFN5c3RlbXMsIEluYy4wggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQDpOw/kqgT7XlrBj0BLHk2PqVq3oIKAt+3P
# f0oR369Dwulm6txEeA3XwvCaie7218lZwIu6iBHyCEH+E0J3Yd1GUMjzq5K3EGza
# HdPycKYwENwZ6O9RkPpoxcWyEyJ31fUKQ/GY73pe/nyLpQ8RvObk+AvYwvk9ugvm
# Yam2fd56vC0Lk4BZSZGJ8ldN2AqQjHGdXeo7B1m676jTIZHXke7IuDo8u7HBlYB2
# xvjUUmIHKr//3tG4F5o2qIKBI0lmbEukp0HoSP/CSiHTntQMyPvAniAY6bz1mlyR
# SL4CuBHKyK98zxRQ+CCkOiqerPSyRN86VI2yjNIgJgSQXZTNp48XAgMBAAGjggHF
# MIIBwTAfBgNVHSMEGDAWgBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4EFgQU
# vfnx+wp/tJ3YnKOGlCI4+nU/7KswDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoG
# CCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3JsNC5k
# aWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBDMDcG
# CWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5j
# b20vQ1BTMAgGBmeBDAEEATCBhAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2lnbmlu
# Z0NBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBU0zauN2qh
# o+NFxYu+cTDfdUBI7gTdPL2eOzMcv2Wg21IqxjObnszSgBjIgq8vcdKy3UajF9qW
# 0GcI6KaSjSrIKXWih3fuhPF/B/DGBWXFmruoLlL3syUpUZZCQGMRYoXqagCuv+ve
# BwZIYXzr2dWK0P8/9CJj6XOEFiE4Aik1PgSuSwYvnLGscnb7GFbQTxyoTrGn9MzX
# EoSkB4i6a7oRcDczNQ5CxrzHYPL9nyOr0RKzvlwzg0W8f6To00UPTI49SEyp+Psi
# GuDJSE58l2O1qzZH2a8bvEYbFNhoCbx+TWAmJShKe4zJeZc5G9rdXxJhEtKVUbCe
# 1kaofEyg/JP5MYIEXDCCBFgCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNVBAoT
# DERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8GA1UE
# AxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQB6lJ
# h4bZQO4EKW+8sKRBDTAJBgUrDgMCGgUAoIGcMBkGCSqGSIb3DQEJAzEMBgorBgEE
# AYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJ
# BDEWBBRDunBuEhCU6ykWkVSZ8PJkdfcIIzA8BgorBgEEAYI3AgEMMS4wLKAYgBYA
# QwBpAHQAcgBpAHgAIABGAGkAbABloRCADnd3dy5jaXRyaXguY29tMA0GCSqGSIb3
# DQEBAQUABIIBAAYRDKbJdoK2vlNtSFPzEfneCPlRR4JCRvoNCuSi7VF7OHXPQqvj
# buQJm91H2fGCYN4tZO1LurjQ8Wen37WPPdiPAVyZjwYEZJHGSvAI2URGet/NFrJu
# 0TQOEhX+LbAoZPWX5+YJxYlSaFjS+6kEwkWPJn62IbC0Y++T85Fqo6qdcWuHtJOj
# YiykNFcD+X98NEn6So05qDOJKwwji1AhsWpeU3ZAuQB2IEykVdkP5Og1SLIbeZk7
# E2wFqGTtudJr1+/f8uIFqL26d8YisnPYG6JxQJrORGfkvnsL5FROwnG5q1szlvpt
# /7KWFoxf8StE09Bqph9Odv9Zhh6sW1TkSPyhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcxMTA4MTk0MTUx
# WjAjBgkqhkiG9w0BCQQxFgQUMHjR1UDqPz1oxnmn+2mi9VZhfo0wDQYJKoZIhvcN
# AQEBBQAEggEAU9i3kc6MsCvEepH4cVQLOnSSVUPcgPGrj2GdTl66FmLliL+YhWP+
# 8ImXqkY1tYCw0SDsu1ODpw9L27jDNFSBFoHCgs/VlHo2lY3NWXG/hsQHJ4dGU9LJ
# y8oXLKqOi5j4OEk/94EVZQ7Pp2vh1elPdEZaX5q9M71DpjtE71E3aV5paL89Gvyw
# qDq1DESAiEbcUMdn8xjbPq+U0miLGsHE6GNWevJ/CYOqVLngRx3enmPKsDChkIgk
# iNKkNn9EdFLlypAYF5z/wYycDtOhoddXJJMHTi+gOUzrsdArxEsXBF7jjzqLSVqi
# WD7a5f1mrwGnrtHCSiqizG/eE85WtTDgkw==
# SIG # End signature block
