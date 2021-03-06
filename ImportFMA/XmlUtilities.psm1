# Copyright Citrix Systems, Inc.

. .\Version.ps1

function Initialize-Xml
{
    Write-LogFile "Creating XML document"
    $comment = "Created by {0} at {1} on {2}" -f ([Environment]::UserName), ([Environment]::MachineName), (Get-Date)
    Write-LogFile ("New-Object System.Xml.XmlDocument") 1
    $Script:xDocument = New-Object System.Xml.XmlDocument
    [void]$Script:xDocument.AppendChild(($Script:xDocument.CreateXmlDeclaration("1.0", "utf-8", $null)))
    [void]$Script:xDocument.AppendChild(($Script:xDocument.CreateComment($XAMigrationToolVersionString)))
    [void]$Script:xDocument.AppendChild(($Script:xDocument.CreateComment($comment)))
}

function Save-XmlData
{
    param
    (
        [object] $root,
        [string] $file
    )

    $path = $file
    if (![System.IO.Path]::IsPathRooted($file))
    {
        $path = Join-Path (Resolve-Path .) $file
    }

    Write-LogFile ("Saving data to " + $path)
    [void]$Script:xDocument.AppendChild($root)
    [void]$Script:xDocument.Save($path)
}

<#
    .Synopsis
        Implement the [string]::IsNullOrWhiteSpace function, which requires .NET 4.0
#>

[bool]
function IsNullOrWhiteSpace
{
    param
    (
        [string] $t
    )

    return [string]::IsNullOrEmpty($t) -or [string]::IsNullOrEmpty($t.Trim())
}

<#
    .Synopsis
        Create a XML node with a given name and optionally children elements.
    .Parameter Name
        Name of the node.
    .Parameter Value
        Optional value of the node.
    .Parameter Children
        Existing sub nodes to be appended to the new node.
#>

[System.Xml.XmlElement]
function New-XmlNode
{
    param
    (
        [string] $name,
        [string] $value = $null,
        [string] $caption = $null
    )

    $node = $Script:xDocument.CreateElement($name)
    if (-not (IsNullOrWhiteSpace $value))
    {
        $lower = $value.ToLower()
        if (($lower -eq "true") -or ($lower -eq "false"))
        {
            $node.InnerText = $lower
        }
        else
        {
            $node.InnerText = $value
        }
    }
    if (-not (IsNullOrWhiteSpace $caption))
    {
        $node.SetAttribute("Name", $caption)
    }

    return $node
}

[void]
function Assert-XmlInput
{
    param
    (
        [string]$xsdName,
        [string]$xmlFile,
        [string]$xsdFile
    )

    if (([IO.FileInfo]$xmlFile).Extension -ne ".xml")
    {
        throw ([string]::Format("File {0} must be a XML file with a .xml extension", $xmlFile))
    }

    if (([IO.FileInfo]$xsdFile).Extension -ne ".xsd")
    {
        throw ([string]::Format("File {0} must be a XSD file with a .xsd extension", $xsdFile))
    }

    Write-LogFile ([string]::Format("Validating XML file {0} with XSD file {1}", $xmlFile, $xsdFile))
    $s = New-Object -TypeName "System.Xml.XmlReaderSettings"
    $s.ValidationType = [System.Xml.ValidationType]::Schema
    $s.ValidationFlags = [System.Xml.Schema.XmlSchemaValidationFlags]::ReportValidationWarnings
    [void]$s.Schemas.Add($xsdName, $xsdFile)
    $s.Add_ValidationEventHandler(
        {
            $e = $_.Exception
			throw [string]::Format("{0} contains invalid data: {1}, at line {2} character {3}",
                $xmlFile, $e.Message, $e.LineNumber, $e.LinePosition)
        }
    )

    $r = [System.Xml.XmlReader]::Create($xmlFile, $s)
    if ($r -ne $null)
    {
        try
        {
            while ($r.Read()) {}
        }
        catch
        {
            Write-LogFile ([string]::Format("XML file {0} validation failed: {1}", $xmlFile, $_.Exception.Message))
            throw
        }
        finally
        {
            $r.Close()
        }
        Write-LogFile ([string]::Format("XML file {0} validated", $xmlFile))
    }
    else
    {
        throw ([string]::Format("Can not open XML file {0} for read", $xmlFile))
    }
}

<#
    .Synopsis
        Ensure the given XML output file meet the following conditions:
        1.  It is a valid file path.
        2.  It doesn't exist.
        3.  If the file path is a network share, issue a warning.
        4.  The file has a .xml extension.
        5.  The parent path of the file exists.
#>

[bool]
function Assert-XmlOutput
{
    param
    (
        [string]$xmlFile
    )

    if (!(Test-Path -IsValid $xmlFile))
    {
        throw ([string]::Format("{0} is not a valid file path", $xmlFile))
    }

    if (Test-Path $xmlFile)
    {
        throw ([string]::Format("{0} already exists", $xmlFile))
    }

    if (([IO.FileInfo]$xmlFile).Extension -ne ".xml")
    {
        throw ([string]::Format("File {0} must have a .xml extension", $xmlFile))
    }

    $dir = Split-Path $xmlFile
    if ((![string]::IsNullOrEmpty($dir)) -and (!(Test-Path $dir)))
    {
        throw ([string]::Format("Directory {0} doesn't exist", $dir))
    }

    $uri = ($xmlFile -as [System.Uri])
    if (($uri -ne $null) -and $uri.IsUnc)
    {
        $warn = [String]::Format("{0} is on a network share, you should not use a public network share to store this data.", $xmlFile)
        Write-Warning $warn
        return
    }

    $root = [System.IO.Path]::GetPathRoot($xmlFile)
    if ([string]::IsNullOrEmpty($root) -or ($root -eq "\"))
    {
        $dir = Resolve-Path .
        $root = [System.IO.Path]::GetPathRoot($dir)
    }

    $info = $root -as [System.IO.DriveInfo]
    if (($info -ne $null) -and ($info.DriveType -eq "Network"))
    {
        $warn = [String]::Format("{0} is on a network share, you should not use a public network share to store this data.", $xmlFile)
        Write-Warning $warn
    }

    return $true
}

# SIG # Begin signature block
# MIIYFQYJKoZIhvcNAQcCoIIYBjCCGAICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUeqqvhtJ+u8tqme6gz5YrX+XY
# pZqgghMjMIID7jCCA1egAwIBAgIQfpPr+3zGTlnqS5p31Ab8OzANBgkqhkiG9w0B
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
# BDEWBBQKzQSYw88IjopwAE8om2ES8GUggTA8BgorBgEEAYI3AgEMMS4wLKAYgBYA
# QwBpAHQAcgBpAHgAIABGAGkAbABloRCADnd3dy5jaXRyaXguY29tMA0GCSqGSIb3
# DQEBAQUABIIBAKJeMxD8UvnAsJsi9cpHJvtrk9+7hKWaZlecWkZEkq/UgYcdsEDd
# G0Ix3GcZXaBr46jFGxIl4SFyrH/8BGH0Qy4ruSTW/fBtte51eXc14akspdw61yLG
# GgUnK7/31GIkcE5V6IMSSNsG7vhKssjNSz/QbMAkgB7vcm8iYlC0JtSWho5UdDNn
# P6lF2dNq/QQtfitkBXDP/YJpZFywtnSppFY6OXWx1j29mvp0yiTvzPebLBMo7G4Y
# M349vLyfoKzkKspKzBguMQ6G3W/vO7HEXMtwD0AofE0Fr8HEuQZFF6DLkIEZ+xii
# YI/gckjwGLvY8TD7/gjK0TbMCK4liA/3/bWhggILMIICBwYJKoZIhvcNAQkGMYIB
# +DCCAfQCAQEwcjBeMQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29y
# cG9yYXRpb24xMDAuBgNVBAMTJ1N5bWFudGVjIFRpbWUgU3RhbXBpbmcgU2Vydmlj
# ZXMgQ0EgLSBHMgIQDs/0OMj+vzVuBNhqmBsaUDAJBgUrDgMCGgUAoF0wGAYJKoZI
# hvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcxMTA4MTk0MTUz
# WjAjBgkqhkiG9w0BCQQxFgQU9Qx/ETYf4HHo/hhINeVc/Vfr/AUwDQYJKoZIhvcN
# AQEBBQAEggEAfAuAivRoACn4bL2St1a+PcKE/lbAaaNY/dOzaaiK0WzbVF7xp7Vb
# KMR+HKl/wKGnVhdzIqlz/3GsMT7cByRhpznjDJkM30IE030RH5pDID+ucjccsZzQ
# zqnI1tNzC4WhlpCQXv19B/9FLofttt5U/7b/RhYozbSt11BTTda9sQkd5Z0evmrC
# nwRP3EDtY3KtjKJi6HpjzB+d87dsgxNGYec+ftpURC6HxGZCNEyLeEWQ935IdNz0
# RJs0ywdPZJ5CRe93ombial19Gd3DyOxwOz9HBtY4QqyF4acmpWm5fr8cviMBbhEB
# vWlTtNsWd08yd1y7ZYBaHHEC+xx7puWAEQ==
# SIG # End signature block
