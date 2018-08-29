# Copyright Citrix Systems, Inc.

Set-Variable -Name TimeStampFormat -Scope Script -Option Constant -Value "{0:d4}-{1:d2}-{2:d2} {3:d2}:{4:d2}:{5:d2}:{6:d3}"
Set-Variable -Name LogFileNameFormat -Scope Script -Option Constant -Value "XFarm{0:d4}{1:d2}{2:d2}{3:d2}{4:d2}{5:d2}-{6:X}.Log"
Set-Variable -Name LogTxtFileName -Scope Script -Value $null
Set-Variable -Name LogXmlFileName -Scope Script -Value $null
Set-Variable -Name XmlLogDocument -Scope Script -Value $null
Set-Variable -Name XmlLogEntries -Scope Script -Value $null
Set-Variable -Name EnableLogging -Scope Script -Value $false
Set-Variable -Name ShowProgress -Scope Script -Value $false

$ErrorActionPreference = "Stop"

. .\Version.ps1

function Format-Message
{
    param
    (
        [string]$message,
        [int]$indent
    )

    $d = Get-Date
    $space = ""
    for ([int]$i = 0; $i -lt $indent; $i++)
    {
        $space += "  "
    }

    $t = [string]::Format($Script:TimeStampFormat, $d.Year, $d.Month, $d.Day, $d.Hour, $d.Minute, $d.Second, $d.Millisecond)
    return [string]::Format("{0} {1}{2}", $t, $space, $message)
}

[void]
function Check-LogFile
{
    param
    (
        [string] $fileName,
        [string] $xmlPath = $null
    )

    if ($xmlPath -ne $null)
    {
        $xmlFile = [System.IO.Path]::GetFileNameWithoutExtension($xmlPath)
        $logFile = [System.IO.Path]::GetFileNameWithoutExtension($fileName)
        if ($xmlFile -eq $logFile)
        {
            throw [string]::Format('The log file "{0}" and the data file "{1}" must be of different names', $fileName, $xmlPath)
        }
    }

    if (Test-Path -Path $fileName)
    {
        if ($noClobber)
        {
            throw("Log file " + $fileName + " already exits")
        }
        else
        {
            try
            {
                Remove-Item -Path $fileName
            }
            catch
            {
                throw [string]::Format('You do not have sufficient permission to clear the log file: "{0}"', $fileName)
            }
        }
    }
}

[void]
function Start-Logging
{
    [CmdletBinding()]
    param
    (
        [switch] $noLogging,
        [switch] $noClobber,
        [string] $logfile,
        [string] $xmlFile,
        [switch] $showProgress = $false
    )

    if (-not $PSBoundParameters.ContainsKey('Verbose'))
    {
        $VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
    }

    $message = Format-Message "Logging Started" 0
    Write-Verbose $message

    $Script:LogTxtFileName = $null
    $Script:LogXmlFileName = $null
    $Script:ShowProgress = $showProgress
    $Script:EnableLogging = !$noLogging
    if ($noLogging)
    {
        return
    }

    if ([string]::IsNullOrEmpty($logfile))
    {
        $d = Get-Date
        $r = (New-Object Random).Next()
        $Script:LogTxtFileName = [string]::Format($Script:LogFileNameFormat, $d.Year, $d.Month, $d.Day, $d.Hour, $d.Minute, $d.Second, $r)
        if (Test-Path $HOME)
        {
            $Script:LogTxtFileName = Join-Path $HOME $Script:LogTxtFileName
        }
        else
        {
            $Script:LogTxtFileName = ".\" + $Script:LogTxtFileName
        }
    }
    else
    {
        $Script:LogTxtFileName = $logfile
    }

    if (![System.IO.Path]::IsPathRooted($Script:LogTxtFileName))
    {
        $Script:LogTxtFileName = Join-Path (Resolve-Path .) $Script:LogTxtFileName
    }

    $Script:LogXmlFileName = [IO.Path]::ChangeExtension($Script:LogTxtFileName, ".xml")

    Check-LogFile $Script:LogTxtFileName
    Check-LogFile $Script:LogXmlFileName $xmlFile

    # Write a header and also test if the log file is accessible.
    try
    {
        $message | Out-File -FilePath $Script:LogTxtFileName -Append
    }
    catch
    {
        throw [string]::Format("You do not have sufficient permission to write the log file: {0}", $Script:LogTxtFileName)
    }

    $XAMigrationToolVersionString | Out-File -FilePath $Script:LogTxtFileName -Append

    $Script:XmlLogDocument = New-Object System.Xml.XmlDocument
    [void]$Script:XmlLogDocument.AppendChild(($Script:XmlLogDocument.CreateXmlDeclaration("1.0", "utf-8", $null)))
    $Script:XmlLogEntries = $Script:XmlLogDocument.CreateElement("LogEntries")
    [void]$Script:XmlLogEntries.SetAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    [void]$Script:XmlLogEntries.SetAttribute("xmlns:xsd", "http://www.w3.org/2001/XMLSchema")
    [void]$Script:XmlLogEntries.SetAttribute("xmlns", "LogFormat.xsd")
}

[void]
function Write-XmlLogFile
{
    [CmdletBinding()]
    param
    (
        [string] $message,
        [bool] $isWarning = $false
    )

    $message = $message.Trim()
    if ([string]::IsNullOrEmpty($message) -or !$Script:EnableLogging)
    {
        return
    }

    $logType = "Message"
    if ($isWarning)
    {
        $logType = "Warning"
    }

    $d = Get-Date
    $t = [string]::Format($Script:TimeStampFormat, $d.Year, $d.Month, $d.Day, $d.Hour, $d.Minute, $d.Second, $d.Millisecond)

    $entryNode = $Script:XmlLogDocument.CreateElement("LogEntry")
    [void]$entryNode.SetAttribute("LogType", $logType)
    [void]$entryNode.SetAttribute("TimeStamp", $t)
    $entryNode.InnerText = $message
    [void]$Script:XmlLogEntries.AppendChild($entryNode)
}

<#
    .Synopsis
        Log output to a text log file.
    .Parameter Message
        The message to be logged.
#>

[void]
function Write-TxtLogFile
{
    [CmdletBinding()]
    param
    (
        [string] $message,
        [int] $indent = 0,
        [bool] $isWarning = $false
    )

    if (!$Script:EnableLogging -or [string]::IsNullOrEmpty($Script:LogTxtFileName))
    {
        return
    }

    if ($isWarning)
    {
        $s = Format-Message ("WARNING: " + $message) $indent
        Write-Warning $message
    }
    else
    {
        $s = Format-Message $message $indent
    }
    $s | Out-File -FilePath $Script:LogTxtFileName -Append

    Write-Verbose $s
}


<#
    .Synopsis
        Log output to a file.
    .Parameter Message
        The message to be logged.
#>

[void]
function Write-LogFile
{
    [CmdletBinding()]
    param
    (
        [string] $message,
        [int] $indent = 0,
        [bool] $showProgress = $false,
        [switch] $isWarning = $false
    )

    if (-not $PSBoundParameters.ContainsKey('Verbose'))
    {
        $VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
    }

    if (($showProgress -and $Script:ShowProgress) -and (!($isWarning -and ($WarningPreference -eq "Continue"))))
    {
        Write-Host ([string]::Format("{0}{1}", $space, $message))
    }

    Write-TxtLogFile $message $indent $isWarning
    Write-XmlLogFile $message $isWarning
}

[void]
function Stop-Logging
{
    [CmdletBinding()]
    param
    (
        [string] $message,
        [string] $exception = $null
    )

    if (![string]::IsNullOrEmpty($exception))
    {
        Write-LogFile $exception
        Write-Host $exception -ForegroundColor Red
    }

    Write-LogFile $message

    if (![string]::IsNullOrEmpty($Script:LogTxtFileName))
    {

    }

    if ($Script:XmlLogDocument -ne $null -and $Script:XmlLogEntries -ne $null -and $Script:LogXmlFileName -ne $null)
    {
        [void]$Script:XmlLogDocument.AppendChild($Script:XmlLogEntries)
        [void]$Script:XmlLogDocument.Save($Script:LogXmlFileName)
    }

    if (![string]::IsNullOrEmpty($exception))
    {
        Write-Host $message -ForegroundColor Red
    }
    else
    {
        Write-Host $message
    }

    if ($Script:ShowProgress)
    {
        if ($Script:EnableLogging)
        {
            if ($Script:LogTxtFileName -ne $null)
            {
                Write-Host ([string]::Format("Log has been saved to {0}", [IO.Path]::GetFullPath($Script:LogTxtFileName)))
            }
            if ($Script:LogXmlFileName -ne $null)
            {
                Write-Host ([string]::Format("Log has been saved to {0}", $Script:LogXmlFileName))
            }
        }
    }
}

[void]
function Print-Logo
{
    param
    (
        [bool] $nologo = $true
    )

    if (!$nologo)
    {
        Write-Host $XAMigrationToolVersionString
    }
}

Export-ModuleMember -Function Start-Logging
Export-ModuleMember -Function Stop-Logging
Export-ModuleMember -Function Write-LogFile
Export-ModuleMember -Function Print-Logo

# SIG # Begin signature block
# MIIYFQYJKoZIhvcNAQcCoIIYBjCCGAICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUY+hvd3k6aHNzdVsOi2moiVQe
# yQygghMjMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# BDEWBBQdZ4IgGhi7L35BgI7M3ay2j+JU4TA8BgorBgEEAYI3AgEMMS4wLKAYgBYA
# QwBpAHQAcgBpAHgAIABGAGkAbABloRCADnd3dy5jaXRyaXguY29tMA0GCSqGSIb3
# DQEBAQUABIIBAFX15BwO6v1PprlC0tvJX1z3v/voPKIkPhc+5ZFMkmXAUTz6ek25
# zdqiyS7SjZ6xvPxLHAz0xls+gGQz+Gz/ocQWon2SvG5XM/joFcJI8rnf8eC94ohI
# 91BBl5+SG+rRgXmnFPlAz3egBfpbPsLM6KY3lZx0DrZXkDjD6j9WPjzT8hTP2VxS
# dz3rnT5MKNU9zaSEaZlObTLi1ESMiDaRd5zPdi4BtPeIvzHRkbJceKwN0xW2LnQf
# 25RDhJt7ImwJmnYDiFFK0yOPQMqzHr0+Th+AfQ+ab9Mo4YpOH+/54K9imGUgaOyN
# MFPXyKLuQ2n7Y+mJlRflzKTNhW+ie2u4+4KhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcxMTA4MTk0MTUy
# WjAjBgkqhkiG9w0BCQQxFgQUv5aZzlrWtqVlziLOt99tyT7RSxgwDQYJKoZIhvcN
# AQEBBQAEggEAZM0zmYKpKmNj0XDDW0N3/XMX5bOwe3PoaW/rvrOAQgS5ctR5oCii
# MUWQtGW4agsnirf+UTe8Z51ZW7HgwowpBv4n68sYnK4KHkU42kxOGIATFmDwf3TG
# 32RBtuf/FHfdgLeWcAs89Odd6qN+th3tBhB/Ie2ZDXDKGpsD7/DKJC9E0o8lOF5n
# Hson9JYI3519Nq89QIhKU9m6BqV6WPQjrBznGLccYb9QFRGH2o82fLsP5e2JFXa9
# yXxWigemQbB0+wo/rVxjwDeyncFJqdow4nm1+KNuPerdxlajBIWditTB01c90jiE
# FaOuRdMRVK3hEhmnICK9rX00ufnGRSebnA==
# SIG # End signature block
