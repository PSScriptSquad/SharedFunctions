Function Get-SslFlags {
    <#
    .SYNOPSIS
        Converts SSL flag value to string or retrieves OS-based SSL flags.

    .DESCRIPTION
        This function can either convert a given SSL flag value to its corresponding string representation or
        determine the correct SSL flag value based on the OS version and provided flags.

    .PARAMETER SslFlagValue
        An integer value representing the SSL flag to be converted to a string.

    .PARAMETER SslFlags
        An array of strings representing the SSL flags to be used for determining the correct SSL flag value.

    .OUTPUTS
        If SslFlagValue parameter set is used, outputs the string representation of the SSL flag value.
        If SslFlags parameter set is used, outputs a custom object containing the OS version and the correct SSL flag value.

    .EXAMPLE
        Get-SslFlags -SslFlagValue 3
        # Output: "CentralCertStore", "Sni"

    .EXAMPLE
        Get-SslFlags -SslFlags "None", "Sni"
        # Output: Error: "None cannot be used with other options."

    .NOTES
        Name: Get-SslFlags
        Author: [Author]
        Date: 08.04.2024
        Version: 1.0
        Changes: Initial release  
    #>

    [cmdletbinding(DefaultParameterSetName='BySslFlagValue')]
    param(
        # Parameter set for converting SSL flag value to string
        [Parameter(ParameterSetName='BySslFlagValue', Mandatory=$true)]
        [ValidateNotNullOrEmpty()]        
        [ValidateScript({
            if(!($_ -ge 0)){
                throw "int must be greater than or equal to 0"
            }
            if(!($_ -le 125)){
                throw "The value of: $($_) is greater than 125"  
            }
            if ((($_ -band 2) -and ($_ -ne 3)) -and (!($_ -eq 2))) {
                throw "CentralCertStore can only be combined with SNI"
            }
            $true
        })]
        [ValidateNotNullOrEmpty()]
        [Int]$SslFlagValue,

        # Parameter set for getting OS-based SSL flags
        [Parameter(ParameterSetName='BySslFlags', Mandatory=$true)]
        [ValidateSet("None","Sni","CentralCertStore","DisableHTTP2","DisableOCSPstp","DisableQUIC","DisableTLS13","DisableLegacyTLS")]
        [ValidateNotNullOrEmpty()]
        [string[]]$SslFlags
    )

    Begin {
        # Ensure 'None' is not combined with other flags
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('SslFlags') -and 
            $PSCmdlet.MyInvocation.BoundParameters['SslFlags'] -contains "None" -and 
            $PSCmdlet.MyInvocation.BoundParameters['SslFlags'].Count -gt 1) {
            throw "None cannot be used with other options."
        }

        # Ensure each flag is unique
        if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('SslFlags') -and ($SslFlags | Group-Object | Where-Object { $_.Count -gt 1 })) {
            throw "Each flag should only be passed once."
        }

        # Define a hashtable to map SSL flag values to their corresponding names
        $SslFlagValues = @{
            0 = "None"
            1 = "Sni"
            2 = "CentralCertStore"
            4 = "DisableHTTP2"
            8 = "DisableOCSPstp"
            16 = "DisableQUIC"
            32 = "DisableTLS13"
            64 = "DisableLegacyTLS"
        }

        # Define SSL flag values for each OS
        $OsSslFlagValues = @{
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
    }

    Process {
        switch ($PSCmdlet.ParameterSetName) {
            'BySslFlagValue' {
                # Filter the SSL flag values using bitwise AND and select the corresponding names
                $SelectedFlags = $SslFlagValues.Keys | Where-Object { $_ -band $SslFlagValue }
                
                # Output the names of selected SSL flags
                $SelectedFlags | ForEach-Object { Write-Output $SslFlagValues[$_] }
            }
            'BySslFlags' {
                # Determine the OS version based on the PowerShell version
                $OSVersion = switch -Regex ($PSVersionTable.BuildVersion) {
                    "^6\.3\.[9]\d{3,}\.\d+$"     { "2012r2" }
                    "^10\.0\.[1]\d{4,}\.\d+$"    { "2019" }
                    "^10\.0\.[2]\d{4,}\.\d+$"    { "2022" }
                }

                # Calculate the correct SSL flag value based on OS and input flags
                $CorrectSslFlagValue = ($SslFlags | ForEach-Object { $OsSslFlagValues[$OSVersion][$_] } | Measure-Object -Sum).Sum

                # Construct the result object
                $Result = [PSCustomObject]@{
                    OS                  = $OSVersion
                    CorrectSslFlagValue = $CorrectSslFlagValue
                }

                Write-Output $Result
            }
        }
    }
}
