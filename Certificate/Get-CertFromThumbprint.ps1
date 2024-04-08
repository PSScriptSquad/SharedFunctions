Function Get-CertFromThumbprint {
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
