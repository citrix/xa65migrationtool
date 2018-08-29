# Copyright Citrix Systems, Inc.

$ErrorActionPreference = "Stop"

[System.Xml.XmlElement]
function New-PrinterNode
{
    param
    (
        [System.Object]$printer
    )

    $node = New-XmlNode "SessionPrinter"
    if ($printer.Path -ne $null) { [void]$node.AppendChild((New-XmlNode "Path" $printer.Path)) }
    if ($printer.Model -ne $null) { [void]$node.AppendChild((New-XmlNode "Model" $printer.Model)) }
    if ($printer.Location -ne $null) { [void]$node.AppendChild((New-XmlNode "Location" $printer.Location)) }
    if ($printer.Settings -ne $null)
    {
        $s = New-XmlNode "Settings"
        foreach ($setting in ($printer.Settings | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
        {
            if ($printer.Settings.$setting -ne $null)
            {
                [void]$s.AppendChild((New-XmlNode $setting $printer.Settings.$setting))
            }
        }
        [void]$node.AppendChild($s)
    }

    return $node
}

[System.Xml.XmlElement]
function New-AssignmentNode
{
    param
    (
        [System.Object]$item
    )

    $node = New-XmlNode "Assignment"

    if ($item.DefaultPrinterOption -ne $null)
    {
        [void]$node.AppendChild((New-XmlNode "DefaultPrinterOption" $item.DefaultPrinterOption))
    }
    if ($item.SpecificDefaultPrinter -ne $null)
    {
        [void]$node.AppendChild((New-XmlNode "SpecificDefaultPrinter" $item.SpecificDefaultPrinter))
    }

    $t = New-XmlNode "SessionPrinters"
    foreach ($printer in $item.SessionPrinters)
    {
        [void]$t.AppendChild((New-PrinterNode $printer))
    }
    [void]$node.AppendChild($t)

    $t = New-XmlNode "Filters"
    $item.Filters | % { [void]$t.AppendChild((New-XmlNode "Filter" $_)) }
    [void]$node.AppendChild($t)

    return $node
}

[System.Xml.XmlElement]
function New-SettingNode
{
    param
    (
        [string]$policy,
        [System.Object]$setting
    )

    Write-LogFile ([string]::Format('Exporting setting "{0}"', $setting.PSChildName)) 3

    $matches = [Regex]::Match($setting.PSParentPath, "[^:]*::Farm:\\[^\\]*\\[^\\]*\\Settings\\(.*)")
    $path = ""
    if ($matches.Success -and $matches.Groups.Count -ge 2)
    {
        $path = $matches.Groups[1].Value
    }

    $node = New-XmlNode "Setting"
    [void]$node.AppendChild((New-XmlNode "Name" $setting.PSChildName))
    [void]$node.AppendChild((New-XmlNode "Path" $path))
    [void]$node.AppendChild((New-XmlNode "State" $setting.State))
    if ($setting.Value -ne $null) { [void]$node.AppendChild((New-XmlNode "Value" $setting.Value)) }

    if ($setting.Values -ne $null)
    {
        $v = New-XmlNode "Values"
        $setting.Values | % { [void]$v.AppendChild((New-XmlNode "Value" $_)) }
        [void]$node.AppendChild($v)
    }

    # Special case for Multi-Port Policy.
    if ($setting.CgpPort1 -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort1" $setting.CgpPort1)) }
    if ($setting.CgpPort2 -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort2" $setting.CgpPort2)) }
    if ($setting.CgpPort3 -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort3" $setting.CgpPort3)) }
    if ($setting.CgpPort1Priority -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort1Priority" $setting.CgpPort1Priority)) }
    if ($setting.CgpPort2Priority -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort2Priority" $setting.CgpPort2Priority)) }
    if ($setting.CgpPort3Priority -ne $null) { [void]$node.AppendChild((New-XmlNode "CgpPort3Priority" $setting.CgpPort3Priority)) }

    # Special case for Printer Assignments.
    if ($setting.PSChildName -eq "PrinterAssignments")
    {
        if ($setting.Assignments.Count -gt 0)
        {
            $x = New-XmlNode "Assignments"
            foreach ($a in $setting.Assignments)
            {
                [void]$x.AppendChild((New-AssignmentNode $a))
            }
            [void]$node.AppendChild($x)
        }
        else
        {
            $log = [string]::Format('INFO: Empty PrinterAssignments setting for policy "{0}", value ignored and not exported', $policy)
            Write-LogFile $log 4
        }
    }

    # Special case for Default Printer
    if ($setting.DefaultPrinterOption -ne $null)
    {
        [void]$node.AppendChild((New-XmlNode "DefaultPrinterOption" $setting.DefaultPrinterOption))
    }
    if ($setting.SpecificDefaultPrinter -ne $null)
    {
        [void]$node.AppendChild((New-XmlNode "SpecificDefaultPrinter" $setting.SpecificDefaultPrinter))
    }

    # Special case for Session Printers
    if ($setting.PSChildName -eq "SessionPrinters")
    {
        if ($setting.Printers.Count -gt 0)
        {
            $x = New-XmlNode "SessionPrinters"
            foreach ($p in $setting.Printers)
            {
                [void]$x.AppendChild((New-PrinterNode $p))
            }
            [void]$node.AppendChild($x)
        }
        else
        {
            $log = [string]::Format('INFO: Empty SessionPrinters setting for policy "{0}", value ignored and not exported', $policy)
            Write-LogFile $log 4
        }
    }

    # Special case for Health Monitoring Tests
    if ($setting.PSChildName -eq "HealthMonitoringTests")
    {
        if ($setting.HmrTests.Tests.Count -gt 0)
        {
            $h = New-XmlNode "HmrTests"
            $s = New-XmlNode "Tests"
            foreach ($test in $setting.HmrTests.Tests)
            {
                $t = New-XmlNode "Test"
                foreach ($p in ($test | Get-Member -MemberType Property | Select-Object -ExpandProperty Name))
                {
                    if ($test.$p -ne $null)
                    {
                        [void]$t.AppendChild((New-XmlNode $p $test.$p))
                    }
                }
                [void]$s.AppendChild($t)
            }
            [void]$h.AppendChild($s)
            [void]$node.AppendChild($h)
        }
        else
        {
            $log = [string]::Format('INFO: Empty HmrTests setting for policy "{0}", value ignored and not exported', $policy)
            Write-LogFile $log 4
        }
    }

    return $node
}

[System.Xml.XmlElement]
function New-FilterNode
{
    param
    (
        [System.Object]$filter
    )

    Write-LogFile ([string]::Format('Exporting assignment "{0}"', $filter.Name)) 3

    $matches = [Regex]::Match($filter.PSParentPath, "[^\\]*\\[^\\]*\\[^\\]*\\[^\\]*\\[^\\]*\\(.*)")
    $path = ""
    if ($matches.Success -and $matches.Groups.Count -ge 2)
    {
        $path = $matches.Groups[1].Value
    }

    $node = New-XmlNode "Filter"
    [void]$node.AppendChild((New-XmlNode "Name" $filter.Name))
    [void]$node.AppendChild((New-XmlNode "Mode" $filter.Mode))
    [void]$node.AppendChild((New-XmlNode "Enabled" $filter.Enabled))
    [void]$node.AppendChild((New-XmlNode "FilterType" $filter.FilterType))
    [void]$node.AppendChild((New-XmlNode "FilterValue" $filter.FilterValue))
    [void]$node.AppendChild((New-XmlNode "Synopsis" $filter.Synopsis))
    [void]$node.AppendChild((New-XmlNode "Comment" $filter.Comment))
    [void]$node.AppendChild((New-XmlNode "Path" $path))

    if ($filter.FilterType -eq "AccessControl")
    {
        [void]$node.AppendChild((New-XmlNode "ConnectionType" $filter.ConnectionType))
        [void]$node.AppendChild((New-XmlNode "AccessGatewayFarm" $filter.AccessGatewayFarm))
        [void]$node.AppendChild((New-XmlNode "AccessCondition" $filter.AccessCondition))
    }

    if ($filter.FilterType -eq "OU")
    {
        [void]$node.AppendChild((New-XmlNode "DN" $filter.DN))
    }

    return $node
}

[System.Xml.XmlElement]
function New-PolicyNode
{
    param
    (
        [System.Object]$policy
    )

    $name = $policy.Name
    Write-LogFile ([string]::Format('Exporting policy "{0}"', $name)) 1 $true

    $node = New-XmlNode "Policy" $null $name
    [void]$node.AppendChild((New-XmlNode "PolicyName" $name))
    [void]$node.AppendChild((New-XmlNode "Description" $policy.Description))
    [void]$node.AppendChild((New-XmlNode "Enabled" $policy.Enabled))
    [void]$node.AppendChild((New-XmlNode "Priority" $policy.Priority))

    Write-LogFile ([string]::Format('Exporting settings')) 2
    $settings = New-XmlNode "Settings"
    $path = ($policy.PSPath + "\Settings")
    dir $path -Recurse | ? { ($_.State -ne $null) -and ($_.State -ne "NotConfigured") } | % {
        [void]$settings.AppendChild((New-SettingNode $name $_))
    }
    [void]$node.AppendChild($settings)

    if ($name -ne "Unfiltered")
    {
        Write-LogFile ([string]::Format('Exporting object assignments')) 2
        $filters = New-XmlNode "Filters"
        $path = ($policy.PSPath + "\Filters")
        dir $path -Recurse | ? { $_.FilterType -ne $null } | % { [void]$filters.AppendChild((New-FilterNode $_)) }
        [void]$node.AppendChild($filters)
    }

    return $node
}

<#
    .Synopsis
        Export XenApp farm policies to a XML file.
    .Parameter XmlOutputFile
        The name of the XML file that stores the output. The file name must be given
        with a .XML extension. The file must not exist. If a path is given, the parent
        path of the file must exist.
    .Parameter NoLog
        Do not generate log output. If this switch is specified, the LogFile parameter
        is ignored.
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
    .Parameter NoClobber
        Do not overwrite an existing log file. This switch has no effect if the given
        log file does not exist.
    .Parameter NoDetails
        If specified, detailed reports about the progress of the script execution is
        not sent to the console.
    .Parameter SuppressLogo
        Suppress the logo.
    .Description
        Use this cmdlet to export the policy data in XenApp farm GPO to a XML file.
        This cmdlet must be run on a XenApp controller and must have the Citrix Group
        Policy PowerShell Provider snap-in installed on the local server. The user who
        executes this command must have read access to the policy data in the XenApp
        farm.

        The XML file references the PolicyData.XSD file, which specifies the schema
        for the data stored in the file.
    .Inputs
        None
    .Outputs
        None
    .Example
        Export-Policy -XmlOutputFile .\MyPolicies.XML
        Export policies and store them in the 'MyPolicies.XML' file in the current
        directory. The log is generated and can be found under the $HOME directory.
    .Example
        Export-Policy -XmlOutputFile .\MyPolicies.XML -LogFile .\PolicyExport.log
        Export policies and store them in the 'MyPolicies.XML' file in the current
        directory. Store the log in the file PolicyExport.log file in the current
        directory.
#>
function Export-Policy
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Explicit")]
        [string] $XmlOutputFile,
        [Parameter(Mandatory=$false)]
        [switch] $NoLog,
        [Parameter(Mandatory=$false)]
        [switch] $NoClobber,
        [Parameter(Mandatory=$false, ParameterSetName="Explicit")]
        [string] $LogFile,
        [Parameter(Mandatory=$false)]
        [switch] $NoDetails,
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

    Write-LogFile ([string]::Format('Export-Policy Command Line:'))
    Write-LogFile ([string]::Format('    -XmlOutputFile {0}', $XmlOutputFile))
    Write-LogFile ([string]::Format('    -LogFile {0}', $LogFile))
    Write-LogFile ([string]::Format('    -NoClobber = {0}', $NoClobber))
    Write-LogFile ([string]::Format('    -NoDetails = {0}', $NoDetails))

    [void](Assert-XmlOutput $XmlOutputFile)

    $isXenApp = $true
    Write-LogFile ('Loading Citrix Group Policy Provider Snap-in')
    $s = (Get-PSSnapin Citrix.Common.GroupPolicy -Registered -ErrorAction SilentlyContinue)
    if ($s -ne $null)
    {
        if (Test-Path $s.ModuleName)
        {
            Import-Module $s.ModuleName
        }
        else
        {
            Import-Module ([Reflection.Assembly]::LoadWithPartialName("Citrix.GroupPolicy.PowerShellProvider"))
            $isXenApp = $false
        }
    }
    else
    {
        Write-Error ([string]::Format("{0}`n{1}", "Citrix Group Policy Provider Snapin is not installed",
            "You must have Citrix Group Policy Provider Snapin installed to use this script."))
        return
    }

    Write-LogFile ('Mount Group Policy GPO')
    if ($isXenApp)
    {
        [void](New-PSDrive -Name Farm -Root \ -PSProvider CitrixGroupPolicy -FarmGpo localhost)
    }
    else
    {
        [void](New-PSDrive -Name Farm -Root \ -PSProvider CitrixGroupPolicy -Controller localhost)
    }

    Initialize-Xml

    $root = New-XmlNode "Policies"
    [void]$root.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    [void]$root.SetAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    [void]$root.SetAttribute("xmlns", "PolicyData.xsd")

    Write-LogFile ('Exporting user policies') 0 $true
    $u = New-XmlNode "User"
    $count = 0
    try
    {
        Get-ChildItem Farm:\User\* | % { [void]$u.AppendChild((New-PolicyNode $_)); $count++ }
    }
    catch
    {
        Stop-Logging "User policy export aborted" $_.Exception.Message
        return
    }
    [void]$root.AppendChild($u)
    Write-LogFile ([string]::Format("{0} user policies exported", $count)) 0 $true

    Write-LogFile ('Exporting computer policies') 0 $true
    $c = New-XmlNode "Computer"
    $count = 0
    try
    {
        Get-ChildItem Farm:\Computer\* | % { [void]$c.AppendChild((New-PolicyNode $_)); $count++ }
    }
    catch
    {
        Stop-Logging "Computer policy export aborted" $_.Exception.Message
        return
    }
    [void]$root.AppendChild($c)
    Write-LogFile ([string]::Format("{0} computer policies exported", $count)) 0 $true

    Save-XmlData $root $XmlOutputFile

    Stop-Logging "Policy export completed"
}

# SIG # Begin signature block
# MIIYFQYJKoZIhvcNAQcCoIIYBjCCGAICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUMLHmZeSfMRzalaOBnlJzGK4x
# mBygghMjMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# BDEWBBQhYRIfx5Jwq3gMY3oj0BS5kBGTozA8BgorBgEEAYI3AgEMMS4wLKAYgBYA
# QwBpAHQAcgBpAHgAIABGAGkAbABloRCADnd3dy5jaXRyaXguY29tMA0GCSqGSIb3
# DQEBAQUABIIBAJI803tbsLjUg0Hz+wxyl9LhZzZy2M7uWwzoyEx6pFlhS8ptifNR
# QNmVBCbkP2zj5BNI2/Bxt3CLiK5nx0sOCn8TNS69S/MJjoZoerS7hhnM8/8zYgpE
# OnUcj1Ns4hFpvtaB+6t070C9z6bM13jIkHtvqDQFeTR/uTZZ9L+cM7yKfoNt5oVj
# SZ6+TeLPTWvso+PMCxK8p/BlxJALFS4wRHG9PyP7dnbikSnfRme3K0pslLjUlH/K
# urqR5/As4c2a5Wa1j64MJzKStGL7/QGYmZr5nqyiFTQUImkEqjskmnxqHwLV2FpF
# fGu6Gh8M2UociUBgKTeEb1pfafFbI4pL1K6hggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcxMTA4MTk0MTUx
# WjAjBgkqhkiG9w0BCQQxFgQUg5Uh8ScyIuoPXBICA4cHYluvcRcwDQYJKoZIhvcN
# AQEBBQAEggEAVJ2S1uMTs1p/5/FVpPZPOffJiJGCPd3IplifeKV9W2Xszcp82sbJ
# UyIONQqACsTH0K+xElTBZ0Qs1H+QorI4TloTY17pQs3NTFB/LskSrfhNSOfrxe+k
# Yhi+kODkN+0EthmlK32+84+yvFmuDyckK1pVsD0pyPQA1MRN2QYZavTLdj1x79HO
# mAXNowvqnb7nx7iZmC2DmKAg23q97gDueTR44oM9W6UER8vZTjSY3YGhBe1ZdHQ3
# bw47FsNFa5IUU1Gu68kEq99IgEACEGZWceQHZNNJu8Vyn0BrnzUuAckqvrXVWEG7
# LTsjVfVaxdsyCBFsto9asZ4MyQ16tl61qA==
# SIG # End signature block
