Function Import-cert {
    param(
        [Parameter(Mandatory=$false,Position=0)]
        [String]$Password = 'abc123'
    )

    # Convert password to secure string
    $SecurePassword = ConvertTo-SecureString -String $Password -Force -AsPlainText
    
    # Get certificate files from the specified directory
    $CertFiles = Get-ChildItem "C:\temp\T1CertExport_DontManuallyUpdate" -Recurse | Where-Object { -not $_.PSIsContainer }

    # Extract certificate data from each file
    $CertData = foreach ($File in $CertFiles) {
        if ($File.FullName -match '.*\\(?<Store>[^\\]+)\\(?<Cert>.+?(?=_))_(?<EXP>\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01]))\.') {
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($File.FullName, $Password)
            [PSCustomObject]@{
                Cert = $cert
                HasPrivateKey = $cert.HasPrivateKey
                FullPath = $File.FullName
                Store = $Matches.Store
                Name = $Matches.Cert
                Expiration = [datetime]::ParseExact($Matches.EXP, 'yyyy-MM-dd', $null)
            }
        }
    }

    # Group certificate data by name and select the newest certificate for each group
    $NewestCertFiles = $CertData | Group-Object -Property Name | ForEach-Object {
        $LatestCert = $_.Group | Sort-Object -Property { $_.Expiration -as [datetime]} -Descending | Select-Object -First 1
        [PSCustomObject]@{
            Cert = $LatestCert.Cert
            HasPrivateKey = $LatestCert.HasPrivateKey
            FullPath = $LatestCert.FullPath
            Store = $LatestCert.Store
            Name = $_.Name
            Expiration = $LatestCert.Expiration
        }
    }
    
    # Import each newest certificate into the certificate store
    foreach ($NewestCertFile in $NewestCertFiles) {        
        if ($NewestCertFile.HasPrivateKey) {
            Import-PfxCertificate -FilePath $NewestCertFile.FullPath -CertStoreLocation $(Join-Path -Path 'cert:\LocalMachine\' -ChildPath $NewestCertFile.Store) -Password $SecurePassword -Exportable | Out-Null
        } else {
            Import-Certificate -FilePath $NewestCertFile.FullPath -CertStoreLocation $(Join-Path -Path 'cert:\LocalMachine\' -ChildPath $NewestCertFile.Store) | Out-Null
        }        
    }
}
