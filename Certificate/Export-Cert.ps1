Function Export-Cert {
    <#
        .SYNOPSIS
            Export certificates with various conditions.        
        .DESCRIPTION
            This function exports certificates based on specified conditions, such as whether the certificate has a private key,
            the certificate's expiration date, and the destination path. It exports certificates as either PFX or CER files,
            depending on the conditions.        
        .PARAMETER Cert
            The certificate to be exported.        
        .PARAMETER ChildPath
            The destination path for the exported certificate.        
        .PARAMETER HasPrivateKey
            Specifies whether the certificate has a private key.        
        .PARAMETER Password
            The password to protect the exported PFX file. Default is 'abc123'.        
        .EXAMPLE
            Export-Cert -Cert $certObject -ChildPath "webhosting" -HasPrivateKey $true
        
            This example exports the certificate specified by $certObject to the "webhosting" directory. 
            If the certificate has a private key and meets other specified conditions, it's exported as a PFX file.        
        .NOTES
            Name: Export-Cert
            Author: Ryan Whitlock
            Date: 12.13.2023
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    param(
        [Parameter(Mandatory=$true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        $Cert,

        [Parameter(Mandatory=$true, Position = 1)]
        [String]
        $ChildPath,

        [Parameter(Mandatory=$true, Position = 2)]
        [bool]
        $HasPrivateKey,

        [Parameter(Mandatory=$false, Position = 3)]
        [String]
        $Password = 'abc123'
    )

    # If the ChildPath contains 'Root', exit the function
    If ($ChildPath -match 'Root') {
        return
    }

    # Convert password to secure string
    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
    # Construct the output directory path
    $MyPath = Join-Path -Path "C:\temp\CertExport_DontManuallyUpdate\" -ChildPath $ChildPath
    $Date = Get-Date

    # Create an X509 chain object
    $Chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    # Add application policy to the chain
    [void]$Chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")

    # Build the chain
    $Chain.Build($Cert) | Out-Null
    # Get the number of elements in the chain
    $ChainCount = $Chain.ChainElements.Count

    # Create the output directory if it doesn't exist
    If (!(Test-Path $MyPath)) {
        New-Item -ItemType Directory -Force -Path $MyPath
    }

    # Generate the destination certificate name
    $DestCertName = "$($Cert.DnsNameList.Unicode -Replace '\*', '_')_$(Get-Date ($Cert.NotAfter) -Format 'yyyy-MM-dd')"

    try {
        switch -Regex ($ChildPath) {
            'webhosting' {
                # Export PFX if conditions are met
                if ($HasPrivateKey -and $Cert.PrivateKey.CspKeyContainerInfo.Exportable -and $ChainCount -gt 1 -and $Cert.NotAfter -gt $Date) {
                    $CertDestPath = Join-Path -Path $MyPath -ChildPath "$DestCertName.pfx"
                    Export-PfxCertificate -Cert $Cert -FilePath $CertDestPath -Password $SecurePassword -NoClobber
                    continue
                }
            }
            'my' {
                # Export PFX or CER depending on conditions
                if ($HasPrivateKey -and $Cert.PrivateKey.CspKeyContainerInfo.Exportable -and $DestCertName -notmatch "WMSvc" -and $Cert.NotAfter -gt $Date) {
                    $CertDestPath = Join-Path -Path $MyPath -ChildPath "$DestCertName.pfx"
                    Export-PfxCertificate -Cert $Cert -FilePath $CertDestPath -Password $SecurePassword -NoClobber
                    continue
                } elseif (-not $HasPrivateKey) {
                    $CertDestPath = Join-Path -Path $MyPath -ChildPath "$DestCertName.cer"
                    Export-Certificate -Cert $Cert -FilePath $CertDestPath -NoClobber
                    continue
                }
            }
        }
        $global:Status = "Successfully Exported"
    } catch {
        # Handle errors
        if ($_.Exception.Message -match 'ERROR_FILE_EXISTS|file exists') {
            $global:Status = "File previously exported"
        } else {
            $global:Status = $_.Exception.Message
        }
    } finally {
        # Output a custom object containing certificate details and export status
        [PsCustomObject]@{
            CertName = $DestCertName
            PSParentPath = $MyPath
            Status = $global:Status
        }
    }
}
