Function Convert-ToSslFlagsString {
    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [Int]$SslFlagValue 
    )

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

    # Filter the SSL flag values using bitwise AND and select the corresponding names
    $SelectedFlags = $SslFlagValues.Keys | Where-Object { $_ -band $SslFlagValue }

    # Return the names of selected SSL flags as a string
    $SelectedFlags | ForEach-Object { $SslFlagValues[$_]; }
}
