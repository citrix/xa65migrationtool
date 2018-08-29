# Copyright Citrix Systems, Inc.

#Requires -Version 2.0

. .\Version.ps1

$ErrorActionPreference = "Stop"

Set-Variable -Name NoPreview -Scope Script -Value $true
Set-Variable -Name IgnoredPolicies -Scope Script -Value 0
Set-Variable -Name ImportedPolicies -Scope Script -Value 0

function Set-PrinterSettings
{
    param
    (
        [string]$path,
        [object]$printer
    )

    $item = (Get-Item ($path + "\SessionPrinters\*")) | ? { $_.Path -eq $printer.Path }
    if ($item -eq $null)
    {
        Write-LogFile ([string]::Format('WARNING: Printer "{0}", not found, skipped', $printer.Path)) 5
        return
    }

    $item.Model = $printer.Model
    $item.Location = $printer.Location
    $printer.Settings.get_ChildNodes() | % {
        Write-LogFile ([string]::Format('{0} = "{1}"', [string]$n, $_.Name)) 5
        $n = $_.Name;
        Write-LogFile ([string]::Format('{0} = "{1}"', [string]($item.Settings.$n), [string]($printer.Settings.$n))) 5
        if ($Script:NoPreview)
        {
            $item.Settings.$n = $printer.Settings.$n
        }
    } 
}

function Add-PrinterAssignment
{
    param
    (
        [string]$path,
        [object]$setting
    )

    Write-LogFile ([string]::Format('Enabling printer assignments for "{0}"', $path)) 4

    [int]$i = 1
    foreach ($a in $setting.Assignments.Assignment)
    {
        $printers = @()
        $nodes = ($a.get_ChildNodes() | ? { $_.Name -eq "SessionPrinters" }).get_ChildNodes()
        $nodes | % { $printers += $_.Path }
        $filters = @()
        ($a.get_childNodes() | ? { $_.Name -eq "Filters" }).get_ChildNodes() | % { $filters += $_.InnerText }
        $dpo = $a.DefaultPrinterOption
        $sdp = $a.SpecificDefaultPrinter
        $log = [string]::Format('New-Item -Path ("{0}") -Name {1} -Filter "{2}" -DefaultPrinterOption {3} -SessionPrinter "{4}"',
            ($path + "\Assignments"), $i, [string]$filters, $dpo, [string]$printers)
        Write-LogFile ($log) 5
        if ($Script:NoPreview)
        {
            $item = New-Item -Path ($path + "\Assignments") -Name $i -Filter $filters -DefaultPrinterOption $dpo -SessionPrinter $printers
        }
        if (!([string]::IsNullOrEmpty($sdp)))
        {
            if ($Script:NoPreview)
            {
                Write-LogFile ([string]::Format('Set-ItemProperty -Path "{0}" -Name SpecificDefaultPrinter -Value {1}', $item, $sdp)) 5
                Set-ItemProperty -Path $item.PSPath -Name SpecificDefaultPrinter -Value $sdp
            }
            else
            {
                Write-LogFile ([string]::Format('Set-ItemProperty -Path "<item path>" -Name SpecificDefaultPrinter -Value {0}', $sdp)) 5
            }
        }
        if ($Script:NoPreview)
        {
            $sp = $item.PSPath.SubString("Citrix.Common.GroupPolicy\CitrixGroupPolicy::".Length)
            foreach ($p in $nodes)
            {
                Set-PrinterSettings $sp $p
            }
        }
    }

}

Set-Variable -Option Constant -Name IgnoredCategories -Value `
@(`
    "Licensing",`
    "PowerAndCapacityManagement",`
    "ServerSettings",`
    "XMLService",`
    "ServerSessionSettings",`
    "Shadowing",`
    "Ports"
)

Set-Variable -Option Constant -Name IgnoredSettings -Value `
@(`
    "ConcurrentLogOnLimit",`
    "LingerDisconnectTimerInterval",`
    "LingerTerminateTimerInterval",`
    "PrelaunchDisconnectTimerInterval",`
    "PrelaunchTerminateTimerInterval",`
    "PromptForPassword",`
    "PvsIntegrationEnabled",`
    "PvsImageUpdateDeadlinePeriod",`
    "RAVEBufferSize",`
    "UseDefaultBufferSize",`
    "EnableEnhancedCompatibility",`
    "EnhancedCompatibility",`
    "EnhancedCompatibilityPrograms",`
    "FilterAdapterAddresses",`
    "FilterAdapterAddressesPrograms",`
    "AllowSpeedFlash",`
    "HDXFlashEnable",`
    "HDXFlashBackwardsCompatibility",`
    "HDXFlashEnableLogging",`
    "HDXFlashLatencyThreshold",`
    "LimitComBw",`
    "LimitComBWPercent",`
    "LimitLptBw",`
    "LimitLptBwPercent",`
    "ClientPrinterNames",`
    "AllowRetainedRestoredClientPrinters",`
    "FlashClientContentURLRewritingRules",`
    "OemChannelBandwidthLimit",`
    "OemChannelBandwidthPercent",`
    "OemChannels"
)

function Enable-Setting
{
    param
    (
        [string]$root,
        [object]$setting
    )

    if (($setting -eq $null) -or ([string]::IsNullOrEmpty($setting.Name)))
    {
        return
    }

    Write-LogFile ([string]::Format('Importing setting "{0}"', $setting.Name)) 3
    foreach ($cat in ([string]$setting.Path).Split('\'))
    {
        if ($IgnoredCategories -contains $cat)
        {
            Write-LogFile ([string]::Format('INFO: Unsupported category "{0}" for "{1}", setting ignored', $setting.Path, $setting.Name)) 4
            return
        }
    }
    if ($IgnoredSettings -contains $setting.Name)
    {
        Write-LogFile ([string]::Format('INFO: Unsupported setting "{0}", ignored', $setting.Name)) 4
        return
    }

    $path = $root + "\Settings\" + $setting.Path + "\" + $setting.Name

    Write-LogFile ([string]::Format('Enabling setting "{0}"', $path)) 3
    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name State -Value {1}', $path, $setting.State)
    Write-LogFile ($log) 4
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $path -Name "State" -Value $setting.State
    }

    if ($setting.Value -ne $null)
    {
        $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Value -Value "{1}"', $path, $setting.Value)
        Write-LogFile ($log) 4
        if ($Script:NoPreview)
        {
            Set-ItemProperty -Path $path -Name "Value" -Value $setting.Value
        }
    }

    if ($setting.DefaultPrinterOption -ne $null)
    {
        $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name DefaultPrinterOption -Value "{1}"',
            $path, $setting.DefaultPrinterOption)
        Write-LogFile ($log) 4
        if ($Script:NoPreview)
        {
            Set-ItemProperty -Path $path -Name "DefaultPrinterOption" -Value $setting.DefaultPrinterOption
        }
    }

    1..3 | % {
        $t = "CgpPort" + $_
        if ($setting.$t -ne $null)
        {
            $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name "{1}" -Value "{2}"', $path, $t, $setting.$t)
            Write-LogFile ($log) 4
            if ($Script:NoPreview)
            {
                Set-ItemProperty -Path $path -Name $t -Value $setting.$t
            }
        }
    }

    1..3 | % {
        $t = "CgpPort" + $_ + "Priority"
        if ($setting.$t -ne $null)
        {
            $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name "{1}" -Value "{2}"', $path, $t, $setting.$t)
            Write-LogFile ($log) 4
            if ($Script:NoPreview)
            {
                Set-ItemProperty -Path $path -Name $t -Value $setting.$t
            }
        }
    }

    if ($setting.HmrTests -ne $null)
    {
        Write-LogFile ([string]::Format('INFO: HMR test settings for "{0}" ignored', $path)) 4
    }

    if ($setting.Values -ne $null)
    {
        $values = @()
        $setting.Values.Value | % { $values += $_ }
        $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Values -Value @({1})', $path, [string]$values)
        Write-LogFile ($log) 4
        if ($Script:NoPreview)
        {
            Set-ItemProperty -Path $path -Name "Values" -Value $values
        }
    }

    if ($setting.Name -eq "PrinterAssignments")
    {
        Add-PrinterAssignment $path $setting
    }
}

Set-Variable -Scope Script -Name FilterAdded -Value $false

function Add-Filter
{
    param
    (
        [string]$root,
        [object]$filter
    )

    $type = $filter.FilterType
    $name = $filter.Name

    if ([string]::IsNullOrEmpty($type) -or [string]::IsNullOrEmpty($name))
    {
        return
    }

    Write-LogFile ([string]::Format('Importing {0} assignment "{1}"', $type, $name)) 4

    if ($type -eq "WorkerGroup")
    {
        Write-LogFile ([string]::Format('INFO: WorkerGroup filter "{0}" ignored', $name)) 5
        return
    }

    $path = Join-Path (Join-Path $root "Filters") $type
    $item = Join-Path $path $name
    if (Test-Path $item)
    {
        Write-LogFile ([string]::Format('Filter "{0}" already exists, skipped', $name)) 5 -isWarning
        return
    }

    if (($type -eq "BranchRepeater") -or ($type -eq "AccessControl"))
    {
        $log = [string]::Format('New-Item -Path "{0}" -Name "{1}" -ErrorAction SilentlyContinue', $path, $name)
        Write-LogFile ($log) 5
        if ($Script:NoPreview)
        {
            [void]($r = New-Item -Path $path -Name $name -ErrorAction SilentlyContinue)
        }
    }
    elseif ($type -eq "OU")
    {
        $log = [string]::Format('New-Item -Path "{0}" -Name "{1}" -DN "{2}" -ErrorAction SilentlyContinue', $path, $name, $filter.DN)
        Write-LogFile ($log) 5
        try
        {
            if ($Script:NoPreview)
            {
                [void]($r = New-Item -Path $path -Name $name -DN $filter.DN -ErrorAction SilentlyContinue)
            }
        }
        catch
        {
        }
    }
    else
    {
        $log = [string]::Format('New-Item -Path "{0}" -Name "{1}" -FilterValue "{2}" -ErrorAction SilentlyContinue',
            $path, $name, $filter.FilterValue)
        Write-LogFile ($log) 5
        try
        {
            if ($Script:NoPreview)
            {
                [void]($r = New-Item -Path $path -Name $name -FilterValue $filter.FilterValue -ErrorAction SilentlyContinue)
            }
        }
        catch
        {
        }
    }
    if ($r -eq $null)
    {
        Write-LogFile ([string]::Format('Invalid data in filter "{0}", ignored', $name)) 5 -isWarning
        return
    }

    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Enabled -Value {1}', $item, $filter.Enabled)
    Write-LogFile ($log) 5
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $item -Name Enabled -Value $filter.Enabled
    }

    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Mode -Value {1}', $item, $filter.Mode)
    Write-LogFile ($log) 5
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $item -Name Mode -Value $filter.Mode
    }

    if (![string]::IsNullOrEmpty($filter.Comment))
    {
        $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Comment -Value "{1}"', $item, $filter.Comment)
        Write-LogFile ($log) 5
        if ($Script:NoPreview)
        {
            Set-ItemProperty -Path $item -Name Comment -Value $filter.Comment
        }
    }

    if ($type -eq "AccessControl")
    {
        $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name ConnectionType -Value {1}', $item, $filter.ConnectionType)
        Write-LogFile ($log) 5
        if ($Script:NoPreview)
        {
            Set-ItemProperty -Path $item -Name ConnectionType -Value $filter.ConnectionType
        }
        if (![string]::IsNullOrEmpty($filter.AccessGatewayFarm))
        {
            $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name AccessGatewayFarm -Value "{1}"',
                $item, $filter.AccessGatewayFarm)
            Write-LogFile ($log) 5
            if ($Script:NoPreview)
            {
                Set-ItemProperty -Path $item -Name AccessGatewayFarm -Value $filter.AccessGatewayFarm
            }
        }
        if (![string]::IsNullOrEmpty($filter.AccessCondition))
        {
            $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name AccessCondition -Value "{1}"',
                $item, $filter.AccessCondition)
            Write-LogFile ($log) 5
            if ($Script:NoPreview)
            {
                Set-ItemProperty -Path $item -Name AccessCondition -Value $filter.AccessCondition
            }
        }
    }

    $Script:FilterAdded = $true
}

<#
    .Synopsis
        Create new policy with the provided XML data.
#>

function Add-Policy
{
    param
    (
        [string]$root,
        [object]$policy
    )

    $scope = $root.SubString(5).Trim('\')
    $name = $policy.PolicyName
    $path = $root + $name

    $count = 0
    foreach ($s in $policy.Settings.Setting)
    {
        if ($IgnoredSettings -contains $s.Name)
        {
            continue
        }
        $ignore = $false
        foreach ($cat in ([string]$s.Path).Split('\'))
        {
            if ($IgnoredCategories -contains $cat)
            {
                $ignore = $true
                break
            }
        }
        if (!$ignore)
        {
            $count++
        }
    }

    if ($count -eq 0)
    {
        Write-LogFile ([string]::Format('Not importing policy "{0}" because it has no valid settings', $name)) 1 -isWarning
        $Script:IgnoredPolicies++
        return
    }

    Write-LogFile ([string]::Format('Importing {0} policy "{1}"', $scope, $name)) 1 $true
    if (Test-Path -Path $path)
    {
        Write-LogFile ([string]::Format("{0} policy {1} already exists, skipped", $scope, $name)) 2 $true -isWarning
        $Script:IgnoredPolicies++
        return
    }

    Write-LogFile ([string]::Format('Creating new {0} policy "{1}"', $scope, $name)) 2 $true
    Write-LogFile ([string]::Format('New-Item "{0}"', $path)) 3
    if ($Script:NoPreview)
    {
        [void](New-Item $path)
    }

    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Description -Value "{1}"', $path, $policy.Description)
    Write-LogFile ($log) 3
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $path -Name "Description" -Value $policy.Description
    }

    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Enabled -Value {1}', $path, $policy.Enabled)
    Write-LogFile ($log) 3
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $path -Name "Enabled" -Value $policy.Enabled
    }

    $log = [string]::Format('Set-ItemProperty -Path "{0}" -Name Priority -Value {1}', $path, $policy.Priority)
    Write-LogFile ($log) 3
    if ($Script:NoPreview)
    {
        Set-ItemProperty -Path $path -Name "Priority" -Value $policy.Priority
    }

    Write-LogFile ([string]::Format('Configure other settings for "{0}"', $name)) 3
    foreach ($s in $policy.Settings.Setting)
    {
        Enable-Setting $path $s
    }

    $Script:FilterAdded = $false
    Write-LogFile ([string]::Format('Configure object assignments for "{0}"', $name)) 3
    $policy.Filters.Filter | % { Add-Filter $path $_ }
    if ($Script:FilterAdded)
    {
        $log = [string]::Format('Object assignments for "{0}" imported. {1}', $name,
            "Please carefully review the object assignments to ensure the policy is applied properly")
        Write-LogFile $log 3 -isWarning
    }
    $Script:ImportedPolicies++
}

<#
    .Synopsis
        Import XenApp farm policies from a XML file.
    .Parameter XmlInputFile
        The name of the XML file that stores the output from a previous export action.
        The XML schema must conform to the schema as defined in the XSD file.
    .Parameter XsdFile
        The name of the XSD file for the XML file. If this parameter is not specified,
        the default XSD file is PolicyData.XSD. The XSD file is used to validate the
        syntax of the input XML file.
    .Parameter NoLog
        If this switch is specified, no logs are generated.
    .Parameter NoClobber
        If this switch is specified, do not overwrite existing log file. This switch is
        ignored if NoLog is specified or if LogFile is not specified.
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
    .Parameter Preview
        If this switch is specified, the policy data is read from the XML file but no
        policies are imported to the target site. The log file contains logging
        information about the commands to be used if actual import were executed. This
        is useful for administrators to see what will actually happen if real policies
        are imported.
    .Parameter NoDetails
        If this switch is specified, detailed messages about the progress of the script
        execution will not be sent to the console.
    .Parameter SuppressLogo
        Suppress the logo.
    .Description
        Use this cmdlet to import the policies that have been previously exported to a
        XML file by the Export-Policy cmdlet. This cmdlet must be run on a XenDesktop
        controller and must have the Citrix Group Policy PowerShell Provider snap-in
        installed on the local server. The administrator must have permissions to
        create new policies in the XenDesktop site.

        Although most of the XenApp 6.x policies are imported, many of them are no
        longer supported by XenApp/XenDesktop 7.5. Administrators should review all
        the policies being imported and all the ones not imported to ensure that the
        policy configuration for the target site is well defined.

        It's not necessary to explicitly load the Citrix PowerShell Snapins into the
        session, the script automatically loads the snapins.
    .Inputs
        A XML data file and optionally other parameters.
    .Outputs
        None
    .Link
        https://www.citrix.com/downloads/xenapp/sdks/powershell-sdk.html
    .Example
        Import-Policy -XmlInputFile .\MyPolicies.xml
        Import policies stored in the file 'MyPolicies.xml' located under the current
        directory. The PolicyData.Xsd file must be in the same directory. The log file
        is automatically generated and placed under the $HOME directory.
    .Example
        Import-Policy -XmlInputFile .\MyPolicies.xml -XsdFile ..\PolicyData.xsd -NoDetails
        Import policies stored in the file 'MyPolicies.xml' located in the current
        directory and use the XML schema file 'PolicyData.xsd' in the parent
        directory. Do not show the detailed information to the console, but everything
        will still be logged in the log file, which is under user's $HOME directory.
    .Example
        Import-Policy -XmlInputFile .\MyPolicies.xml -Preview -LogFile .\PolicyImport.log
        Import policies stored in the file 'MyPolicies.xml' located in the current
        directory but do not actually import anything by specifying the -Preview
        switch. Put the logs in the 'PolicyImport.log' file located in the current
        directory. The log file stores all the information about the commands used
        to create the policies.
#>

function Import-Policy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Explicit")]
        [string]$XmlInputFile,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [string]$XsdFile,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [switch]$NoLog,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [switch]$NoClobber,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [string]$LogFile,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [switch]$Preview,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [switch]$NoDetails,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
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

    $Script:NoPreview = !$Preview

    $ShowProgress = !$NoDetails
    try
    {
        Start-Logging -NoLog:$Nolog -NoClobber:$NoClobber $LogFile $XmlInputFile -ShowProgress:$ShowProgress
    }
    catch
    {
        Write-Error $_.Exception.Message
        return
    }

    Write-LogFile ([string]::Format('Import-Policy Command Line:'))
    Write-LogFile ([string]::Format('    -XmlInputFile {0}', $XmlInputFile))
    Write-LogFile ([string]::Format('    -XsdFile {0}', $XsdFile))
    Write-LogFile ([string]::Format('    -LogFile {0}', $LogFile))
    Write-LogFile ([string]::Format('    -Preview = {0}', $Preview))
    Write-LogFile ([string]::Format('    -NoClobber = {0}', $NoClobber))
    Write-LogFile ([string]::Format('    -NoDetails = {0}', $NoDetails))

    if ([string]::IsNullOrEmpty($XsdFile))
    {
        $XsdFile = ".\PolicyData.xsd"
    }
    $homedir = Resolve-Path .
    $xmlPath = Resolve-Path $XmlInputFile
    $xsdPath = Resolve-Path $XsdFile

    Assert-XmlInput "PolicyData.xsd" $xmlPath $xsdPath

    Write-LogFile ("Loading Citrix Group Policy Provider Snap-in") 0 $true
    Add-PSSnapin Citrix.Common.GroupPolicy

    Write-LogFile ("Mount Group Policy GPO") 0 $true
    Write-LogFile ("New-PSDrive -Name Site -Root \ -PSProvider CitrixGroupPolicy -Controller localhost") 1
    [void](New-PSDrive -Name Site -Root \ -PSProvider CitrixGroupPolicy -Controller localhost)

    Write-LogFile ("Turn off auto write back") 0 $true
    Write-LogFile ("(Get-PSDrive Site).AutoWriteBack = $false") 1
    if ($Script:NoPreview)
    {
        (Get-PSDrive Site).AutoWriteBack = $false
    }

    Write-LogFile ("Read XML file")
    Write-LogFile ([string]::Format('[xml]$policies = Get-Content "{0}"', $xmlPath)) 1
    [xml]$policies = Get-Content $xmlPath

    $TotalUserPolicies = 0
    $TotalComputerPolicies = 0
    $Script:IgnoredPolicies = 0
    $Script:ImportedPolicies = 0

    Write-LogFile ("Importing user policies") 0 $true
    try
    {
        foreach ($p in $policies.Policies.User.Policy)
        {
            Add-Policy "Site:\User\" $p
            $TotalUserPolicies++
        }
    }
    catch
    {
        Stop-Logging "User policy import aborted" $_.Exception.Message
        return
    }

    Write-LogFile ("Importing computer policies") 0 $true
    try
    {
        foreach ($p in $policies.Policies.Computer.Policy)
        {
            Add-Policy "Site:\Computer\" $p
            $TotalComputerPolicies++
        }
    }
    catch
    {
        Stop-Logging "Computer policy import aborted" $_.Exception.Message
        return
    }

    Write-LogFile ("Save changes")
    Write-LogFile ("(Get-PSDrive Site).Save()") 1
    if ($Script:NoPreview)
    {
        (Get-PSDrive Site).Save()
    }
    Write-LogFile ("Remove-PSDrive Site") 1
    Remove-PSDrive Site

    $broker = (Get-PSSnapin -Registered Citrix.Broker.Admin.V2 -ErrorAction SilentlyContinue)
    if ($broker -ne $null)
    {
        Import-Module (Get-PSSnapin -Registered Citrix.Broker.Admin.V2).ModuleName -Force
        Set-BrokerSiteMetadata -Name "PolicyImportToolVersion-f4ff73e5-8f40-4fa0-92db-ecdb1a878ac9" -Value $XAMigrationToolVersionNumber
    }

    # Summarize the activities, count number of policies imported, etc.
    Write-LogFile ([string]::Format('Total number of user policies : {0}', $TotalUserPolicies)) 0 $true
    Write-LogFile ([string]::Format('Total number of computer policies : {0}', $TotalComputerPolicies)) 0 $true
    Write-LogFile ([string]::Format('Number of policies ignored: {0}', $Script:IgnoredPolicies)) 0 $true
    Write-LogFile ([string]::Format('Number of policies imported: {0}', $Script:ImportedPolicies)) 0 $true

    Stop-Logging "Policy import completed"
}

# SIG # Begin signature block
# MIIYFQYJKoZIhvcNAQcCoIIYBjCCGAICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUymNwOM7ys9DQowTNGyeM4KnW
# EVmgghMjMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# BDEWBBQJgjrtrCRCttqF6RCSbnrbRVPdUjA8BgorBgEEAYI3AgEMMS4wLKAYgBYA
# QwBpAHQAcgBpAHgAIABGAGkAbABloRCADnd3dy5jaXRyaXguY29tMA0GCSqGSIb3
# DQEBAQUABIIBALcojuUO9O/06SMJM1asqibXM/+41Q/TJemkG+gxpxnAqLKrWLfG
# rDA92fnYTLE5ef+zSreaZH+EA5NhaTWJ7ZId17XMqmc+ukkKRhL9JKOkOaXBjjtg
# huopj3luhK3Ov7uCQDdS62+x58+pcso/CvUIfUBn9DfI39j9sviRoBSuFuSIlU+m
# dAedzX731JX+B025emHBrRqwI9UPnGxGR/co2tQOw22tO7GOjPKKiPwtkq4mHG0J
# uOdOmU2PbLHeQKOK0VJiVuOT2ygoa+ye3Lfy0GuAZ01qISLDyRpWUpXZ1o8T0gIl
# JXcT4g9zFvoaMjuHHR9MW4Gwoafw5l2q71KhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcxMTA4MTk0MTUy
# WjAjBgkqhkiG9w0BCQQxFgQUiOHd6cnEIoUoKJHfB4K7uw+6cd0wDQYJKoZIhvcN
# AQEBBQAEggEAQsOJ2mutVJYApNTRdPAoCuGVHShO5laSbQSQxVMakJ++5onMV37I
# iFuXZF+AZ4ENQcWttMfhHmaCo4pP9U18Ghx2TM0U5GKeXLzX7oJc93BARa2v7LX0
# EajpOLNtboDqKW7e2NForU5kdc50Tz+NDFiWQXIk9CoLEWNoEIiQ5b+OvbXZ6xY9
# BiPTDE3o97ONGZ9IKKsUiO4zC/SHTx+Cx0ZFrxcwJHZk779xvrl4uv8YP5FRr9jS
# 1a2ATBjnAIhKHapnuMsuUrg6ZUoWgWKJRfBjByryEdydMI8N0ZbK3zIn6iDNUBii
# Iw6z77DAvswciAu+A1gVvGHDpzBJHUuOcA==
# SIG # End signature block
