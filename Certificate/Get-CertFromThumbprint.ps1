Function Get-CertFromThumbprint {
    <#
        .SYNOPSIS
            Retrieves certificate(s) from the certificate store by thumbprint.
        .DESCRIPTION
            This function retrieves certificate(s) from the certificate store by thumbprint.
            It searches for the specified thumbprint in the given certificate store location.
            If the thumbprint is found, it returns the certificate(s); otherwise, it throws an error.        
        .PARAMETER CertificateThumbPrint
            Specifies the thumbprint of the certificate to retrieve. It should be a hexadecimal string of 40 characters.        
        .PARAMETER CertStoreLocation
            Specifies the location of the certificate store.
            Default value is "WebHosting". Available options are "Cert:\LocalMachine\My", "Cert:\LocalMachine\WebHosting", "My", "WebHosting".        
        .EXAMPLE
            Get-CertFromThumbprint -CertificateThumbPrint "3E4F6E6A9F69..." -CertStoreLocation "WebHosting"
            Retrieves the certificate(s) with the specified thumbprint from the "WebHosting" certificate store.        
        .NOTES
            Name: Get-CertFromThumbprint
            Author: Ryan Whitlock
            Date: 12.13.2023
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2[]])]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateScript({
            If ($_ -match '[^a-fA-F0-9]'){
                throw "Invalid certificate thumbprint: $($_), has hidden characters"
            }elseif($_.Length -ne 40){
                throw "Invalid certificate thumbprint: $($_), must be 40 characters"
            }  
            $true
        })]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateThumbPrint,

        [Parameter(Mandatory=$false)]
        [ValidateSet("Cert:\LocalMachine\My","Cert:\LocalMachine\WebHosting","My","WebHosting")]
        [string]$CertStoreLocation = "WebHosting"
    )

    # Open the certificate store
    $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store(
        $CertStoreLocation, [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine )
    try {
        $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
    } catch {
        throw "Error opening certificate store: $_"
    }

    # Find the certificate by thumbprint
    $CertCollection = $CertStore.Certificates.Find(
        [System.Security.Cryptography.X509Certificates.X509FindType]::FindByThumbprint, $CertificateThumbPrint, $false)

    $CertStore.Close()

    # Check if certificate(s) found
    If ($CertCollection.Count -eq 0){
        throw "Error: No certificate found containing thumbprint: $($CertificateThumbPrint)"
    }
    
    return $CertCollection
}
