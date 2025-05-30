function Get-CertificateDetailsFromBase64 {
    <#
    .SYNOPSIS
        Extracts detailed information from a Base64-encoded X.509 certificate.

    .DESCRIPTION
        This advanced function processes a Base64-encoded string representing an X.509 certificate and extracts 
        comprehensive details such as the issuer, subject, validity dates, Subject Alternative Names (SANs), 
        key usage, signature algorithm, and chain validity.

        The function supports optional website matching against SANs with wildcard support, validates certificate chains, 
        and provides pipeline-friendly output in the form of a custom object.

    .PARAMETER Base64CertString
        Specifies the Base64-encoded string of the X.509 certificate. This parameter is required and must be a valid Base64 string.

    .PARAMETER Website
        (Optional) Specifies the domain name to match against the Subject Alternative Names (SANs) in the certificate, supporting wildcard matching.

    .INPUTS
        [string] - A Base64-encoded string of an X.509 certificate.

    .OUTPUTS
        [PSCustomObject] - A detailed custom object containing certificate information.

    .EXAMPLE
        # Extract certificate details from a Base64-encoded certificate
        $Base64String = "<Base64 Encoded Certificate>"
        Get-CertificateDetailsFromBase64 -Base64CertString $Base64String

    .EXAMPLE
        # Extract certificate details and verify SAN against a specific website
        $Base64String = "<Base64 Encoded Certificate>"
        Get-CertificateDetailsFromBase64 -Base64CertString $Base64String -Website "example.com"

    .NOTES
        Name: Get-CertificateDetailsFromBase64
        Author: Ryan Whitlock
        Date: 01.27.2025
        Version: 1.1
        Changes: 
        - Added ValidateScript for Base64 string validation.
        - Improved error handling for certificate creation.
        - Enhanced SAN parsing and website matching with wildcard support.
        - Provided detailed chain validation errors.
        - Used PascalCase for output property names.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateScript({
            if ([string]::IsNullOrWhiteSpace($_)) {
                throw "Base64CertString cannot be null or empty."
            }
            elseif ($_ -notmatch '^[A-Za-z0-9+/=\r\n]+$') {
                throw "Base64CertString contains invalid characters. Only A-Z, a-z, 0-9, +, /, =, and newline characters are allowed."
            }
            else {
                $true
            }
        })]
        [string]$Base64CertString,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Website
    )

    begin {
        Write-Verbose "Initializing function to process Base64 certificate."

        # Helper function to convert SAN entries to regex patterns for wildcard matching
        function ConvertTo-RegexPattern {
            param($san)
            if ($san -like '*.*') {
                $parts = $san -split '\.', 2
                if ($parts[0] -eq '*') {
                    return "^[^.]+\." + [regex]::Escape($parts[1]) + "$"
                }
            }
            return "^" + [regex]::Escape($san) + "$"
        }
    }

    process {
        try {
            # Decode the Base64 string
            try {
                [byte[]]$Bytes = [System.Convert]::FromBase64String($Base64CertString)
            }
            catch [System.FormatException] {
                Write-Error "Failed to decode Base64 string: $_"
                return
            }

            # Create the X509Certificate2 object
            try {
                $Cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Bytes)
            }
            catch [System.Security.Cryptography.CryptographicException] {
                Write-Error "Failed to create X509Certificate2 object from decoded bytes: $_"
                return
            }
            catch {
                Write-Error "Unexpected error creating certificate: $_"
                return
            }

            # Initialize variables for detailed certificate properties
            $SAN = $null
            $ChainStatus = $false
            $CertStatus = "Unknown"
            $KeyUsage = $null
            $EnhancedKeyUsage = $null
            $ChainErrors = @()
            $Issuer = $Cert.Issuer
            $Subject = $Cert.Subject
            $SerialNumber = $Cert.SerialNumber
            $Thumbprint = $Cert.Thumbprint
            $SignatureAlgorithm = $Cert.SignatureAlgorithm.FriendlyName
            $StartDate = $Cert.NotBefore
            $EndDate = $Cert.NotAfter
            $ExpiresInDays = ($EndDate - (Get-Date)).Days
            $IsExpired = $EndDate -lt (Get-Date)

            # Extract Subject Alternative Names (SAN)
            try {
                $SANExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }
                if ($SANExtension) {
                    $SANRaw = $SANExtension.Format(0)
                    $SAN = ($SANRaw -split ", ") | ForEach-Object {
                        if ($_ -match 'DNS Name=(.+)') {
                            $matches[1]
                        }
                    }
                    Write-Verbose "Subject Alternative Names: $($SAN -join ', ')"
                }
            }
            catch {
                Write-Verbose "Failed to retrieve Subject Alternative Names (SAN)."
            }

            # Extract Key Usage
            try {
                $KeyUsageExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.15" }
                if ($KeyUsageExtension) {
                    $KeyUsage = $KeyUsageExtension.Format(0)
                    Write-Verbose "Key Usage: $KeyUsage"
                }
            }
            catch {
                Write-Verbose "Failed to retrieve Key Usage."
            }

            # Extract Enhanced Key Usage (EKU)
            try {
                $EkuExtension = $Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.37" }
                if ($EkuExtension) {
                    $EnhancedKeyUsage = $EkuExtension.Format(0) -split ", " | ForEach-Object { $_.Trim() }
                    Write-Verbose "Enhanced Key Usage: $($EnhancedKeyUsage -join ', ')"
                }
            }
            catch {
                Write-Verbose "Failed to retrieve Enhanced Key Usage."
            }

            # Validate the certificate chain
            $Chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $ChainStatus = $Chain.Build($Cert)
            if (-not $ChainStatus) {
                $ChainErrors = $Chain.ChainStatus | ForEach-Object { "$($_.Status): $($_.StatusInformation)" }
                Write-Verbose "Certificate chain validation failed: $($ChainErrors -join ', ')"
            }

            # Check SAN against the provided website with wildcard support
            if ($Website -and $SAN) {
                $CertStatus = "Website - Cert Mismatch"
                foreach ($sanEntry in $SAN) {
                    $pattern = ConvertTo-RegexPattern -san $sanEntry
                    if ($Website -match $pattern) {
                        $CertStatus = "Good"
                        break
                    }
                }
            }

            # Output the certificate details
            [PSCustomObject]@{
                CertIssuer                  = $Issuer
                CertSubject                 = $Subject
                CertSerialNumber            = $SerialNumber
                CertThumbprint              = $Thumbprint
                CertSignatureAlgorithm      = $SignatureAlgorithm
                CertStartDate               = $StartDate
                CertEndDate                 = $EndDate
                CertExpiresInDays           = $ExpiresInDays
                CertIsExpired               = $IsExpired
                CertSubjectAlternativeNames = if ($SAN) { $SAN } else { @() }
                CertKeyUsage                = if ($KeyUsage) { $KeyUsage } else { "N/A" }
                CertEnhancedKeyUsage        = if ($EnhancedKeyUsage) { $EnhancedKeyUsage } else { @() }
                CertChainIsValid            = $ChainStatus
                CertChainErrors             = if ($ChainStatus) { @() } else { $ChainErrors }
                CertStatus                  = $CertStatus
            }
        }
        catch {
            Write-Error "An unexpected error occurred while processing the certificate. Error: $_"
        }
    }

    end {
        Write-Verbose "Completed processing of Base64 certificate."
    }
}
