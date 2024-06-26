function Get-WebsiteCertData {
    <#
    .SYNOPSIS
        Retrieves SSL certificate information for a specified website.

    .DESCRIPTION
        This function connects to a specified website using HTTPS, retrieves the SSL certificate information,
        and returns details about the certificate including issuer, subject, subject alternative names, validity, and status.

    .EXAMPLE
        Get-WebsiteCertData -website 'example.com' -Timeout 15000

    .NOTES
        Name: Get-WebsiteCertData
        Author: Ryan Whitlock
        Date: 4.30.2022
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0, Mandatory = $true, HelpMessage = "Enter the website URL.")]
        [Alias("URL")]
        [ValidateNotNullOrEmpty()]
        [string]$website,

        [Parameter(Position = 1, Mandatory = $false, HelpMessage = "Specify the timeout in milliseconds.")]
        [ValidateRange(1000, 60000)]
        [int]$Timeout = 10000
    )

    # Set security protocol to TLS 1.2
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Bypass server certificate validation
    [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

    # Create HTTPS URI
    $HttpsUriRoot = New-Object System.UriBuilder('https', $website)
    [System.Net.WebRequest]$HttpsRequest = [Net.HttpWebRequest]::Create($HttpsUriRoot.Uri.AbsoluteUri)
    $HttpsRequest.AllowAutoRedirect = $false
    $HttpsRequest.Timeout = $Timeout

    try {
        # Attempt to get response
        $HttpsRequest.GetResponse() | Out-Null
        $HttpsRtn = "Success"
        Write-Verbose "HTTPS request to $($HttpsUriRoot.Uri.AbsoluteUri) succeeded."
    } catch [System.Net.WebException] {
        # Handle web exceptions
        $responseCode = [int]([regex]::Match($_.Exception.Message, '[0-9]{3}')).Value
        if ($responseCode -gt 0) {
            $HttpsRtn = "Failed with HTTP status code: $responseCode"
        } else {
            $HttpsRtn = "Failed: $($_.Exception.Message)"
        }
        Write-Verbose "HTTPS request failed with exception: $($_.Exception.Message)"
    } catch {
        # Handle other exceptions
        $HttpsRtn = "Failed: $($_.Exception.Message)"
        Write-Verbose "HTTPS request failed with general exception: $($_.Exception.Message)"
    } finally {
        # Abort the request to release resources
        $HttpsRequest.Abort()
    }

    Write-Verbose "HTTPS request status: $HttpsRtn"

    if ($HttpsRequest.ServicePoint.Certificate -ne $null) {
        # Convert the certificate
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2] $HttpsRequest.ServicePoint.Certificate.Handle

        Write-Verbose "Certificate retrieved for $website"

        try {
            # Extract Subject Alternative Names (SAN)
            $SAN = ($Cert.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }).Format(0) -split ", "
            Write-Verbose "Subject Alternative Names: $SAN"
        } catch {
            $SAN = $null
            Write-Verbose "Failed to retrieve Subject Alternative Names."
        }

        # Create and build the certificate chain
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")
        $ChainStatus = $chain.Build($Cert)

        # Check if the SAN contains the website
        If ($SAN -match $website) {
            $CertStatus = "Good"
        } else {
            $CertStatus = "Website - Cert Mismatch"
        }

        # Extract certificate details
        $Issuer = $Cert.Issuer
        $Subject = $Cert.Subject
        $StartDate = $Cert.NotBefore
        $EndDate = $Cert.NotAfter        
        [int]$certExpiresIn = ($EndDate - (Get-Date)).Days

        Write-Verbose "Certificate details: Issuer=$Issuer, Subject=$Subject, StartDate=$StartDate, EndDate=$EndDate, ExpiresIn=$certExpiresIn days"
    } else {
        $ChainStatus = $null
        $Issuer = $null
        $Subject = $null
        $SAN = $null
        $CertStatus = $null
        $StartDate = $null
        $EndDate = $null
        $certExpiresIn = $null

        Write-Verbose "No certificate found for $website"
    }

    # Return the certificate information as a custom object
    [PSCustomObject]@{
        'Http Web Request' = $HttpsRtn
        URL = $HttpsUriRoot.Uri.AbsoluteUri
        'Cert Issuer' = $Issuer
        'Cert Subject' = $Subject
        'Cert Subject Alternative Names' = $SAN
        'Cert Chain Is Valid' = $ChainStatus
        'Cert Status' = $CertStatus
        'Cert Start Date' = $StartDate
        'Cert End Date' = $EndDate
        'Cert Expires In' = $certExpiresIn
        'Cert Error Info' = $chain.ChainStatus | ForEach-Object { $_.Status }
    }
}
