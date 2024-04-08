Function Get-OSBasedSSLFlags {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet("None","Sni","CentralCertStore","DisableHTTP2","DisableOCSPStp","DisableQUIC","DisableTLS13","DisableLegacyTLS")]
        [ValidateNotNullOrEmpty()]
        [string[]]$SslFlags
    )

    # Define SSL flag values for each OS
    $SslFlagValues = @{
        "2012r2" = @{
            None             = 0
            Sni              = 1
            CentralCertStore = 2
        }
        "2019" = @{
            None             = 0
            Sni              = 1
            CentralCertStore = 2
            DisableHTTP2     = 4
            DisableOCSPstp   = 8
        }
        "2022" = @{
            None             = 0
            Sni              = 1
            CentralCertStore = 2
            DisableHTTP2     = 4
            DisableOCSPstp   = 8
            DisableQUIC      = 16
            DisableTLS13     = 32
            DisableLegacyTLS = 64
        }
    }

    # Determine the OS version based on the PowerShell version
    $OSVersion = switch -Regex ($PSVersionTable.BuildVersion) {
        "^6\.3\.[9]\d{3,}\.\d+$"     { "2012r2" }
        "^10\.0\.[1]\d{4,}\.\d+$"    { "2019" }
        "^10\.0\.[2]\d{4,}\.\d+$"    { "2022" }
    }

    # Calculate the correct SSL flag value based on OS and input flags
    $CorrectSslFlagValue = ($SslFlags | ForEach-Object { $SslFlagValues[$OSVersion][$_] } | Measure-Object -Sum).Sum

    # Construct the result object
    $Result = [PSCustomObject]@{
        OS                    = $OSVersion
        CorrectSslFlagValue   = $CorrectSslFlagValue
    }

    return $Result
}
