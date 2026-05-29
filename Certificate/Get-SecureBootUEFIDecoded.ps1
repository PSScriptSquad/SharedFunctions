function Get-ByteRange {
    <#
        .SYNOPSIS
            Copies a byte range from a byte array.

        .DESCRIPTION
            Copies a fixed number of bytes from a source byte array into a new byte array.

        .PARAMETER Bytes
            The source byte array.

        .PARAMETER Offset
            The zero-based offset where copying starts.

        .PARAMETER Count
            The number of bytes to copy.

        .OUTPUTS
            System.Byte[]

        .NOTES
            Helper function for Secure Boot UEFI parsing.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -lt 0) {
                throw 'Offset must be zero or greater.'
            }

            $true
        })]
        [int]$Offset,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -lt 0) {
                throw 'Count must be zero or greater.'
            }

            $true
        })]
        [int]$Count
    )

    begin {}

    process {
        if (($Offset + $Count) -gt $Bytes.Count) {
            throw "Requested byte range exceeds source byte array length."
        }

        $CopiedBytes = New-Object byte[] $Count

        if ($Count -gt 0) {
            [System.Buffer]::BlockCopy($Bytes, $Offset, $CopiedBytes, 0, $Count)
        }

        Write-Output -NoEnumerate $CopiedBytes
    }

    end {}
}

function ConvertTo-HexString {
    <#
        .SYNOPSIS
            Converts bytes to an uppercase hexadecimal string.

        .DESCRIPTION
            Converts a byte array to an uppercase hexadecimal string without separators.

        .PARAMETER Bytes
            The byte array to convert.

        .OUTPUTS
            System.String

        .NOTES
            Helper function for displaying Secure Boot hashes and signature data.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    begin {}

    process {
        $StringBuilder = New-Object System.Text.StringBuilder

        foreach ($Byte in $Bytes) {
            [void]$StringBuilder.Append($Byte.ToString('X2'))
        }

        Write-Output $StringBuilder.ToString()
    }

    end {}
}

function ConvertFrom-EfiTime {
    <#
        .SYNOPSIS
            Converts an EFI_TIME structure to a DateTime value.

        .DESCRIPTION
            Converts the 16-byte EFI_TIME structure used by some Secure Boot revocation entries.

        .PARAMETER Bytes
            The source byte array containing the EFI_TIME structure.

        .PARAMETER Offset
            The zero-based offset where the EFI_TIME structure begins.

        .OUTPUTS
            System.DateTime

        .NOTES
            If the EFI_TIME value is empty or invalid, no DateTime is emitted.
    #>
    [CmdletBinding()]
    [OutputType([datetime])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($_ -lt 0) {
                throw 'Offset must be zero or greater.'
            }

            $true
        })]
        [int]$Offset = 0
    )

    begin {}

    process {
        if (($Offset + 16) -le $Bytes.Count) {
            $Year = [System.BitConverter]::ToUInt16($Bytes, $Offset)
            $Month = [int]$Bytes[$Offset + 2]
            $Day = [int]$Bytes[$Offset + 3]
            $Hour = [int]$Bytes[$Offset + 4]
            $Minute = [int]$Bytes[$Offset + 5]
            $Second = [int]$Bytes[$Offset + 6]

            if ($Year -gt 0 -and $Month -ge 1 -and $Month -le 12 -and $Day -ge 1 -and $Day -le 31) {
                try {
                    $DateTime = New-Object DateTime `
                        $Year, $Month, $Day, $Hour, $Minute, $Second, ([System.DateTimeKind]::Utc)

                    Write-Output $DateTime
                } catch {
                    Write-Verbose "Unable to convert EFI_TIME value. $($_.Exception.Message)"
                }
            }
        }
    }

    end {}
}

function Get-UefiSignatureTypeName {
    <#
        .SYNOPSIS
            Gets a friendly name for a UEFI Secure Boot signature type GUID.

        .DESCRIPTION
            Maps known Secure Boot EFI certificate and hash signature type GUIDs to friendly names.

        .PARAMETER SignatureType
            The UEFI signature type GUID.

        .OUTPUTS
            System.String

        .NOTES
            Unknown signature types return the original GUID string.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [guid]$SignatureType
    )

    begin {}

    process {
        $SignatureTypeMap = @{
            'c1c41626-504c-4092-aca9-41f936934328' = 'SHA256'
            '826ca512-cf10-4ac9-b187-be01496631bd' = 'SHA1'
            '0b6e5233-a65c-44c9-9407-d9ab83bfc8bd' = 'SHA224'
            'ff3e5307-9fd0-48c9-85f1-8ad56c701e01' = 'SHA384'
            '093e0fae-a6c4-4f50-9f1b-d41e2b89c19a' = 'SHA512'
            'a5c059a1-94e4-4aa7-87b5-ab155c2bf072' = 'X509'
            '3bd2a492-96c0-4079-b420-fcf98ef103ed' = 'X509_SHA256'
            '7076876e-80c2-4ee6-aad2-28b349a6865b' = 'X509_SHA384'
            '446dbf63-2502-4cda-bcfa-2465d2b0fe9d' = 'X509_SHA512'
            '3c5766e8-269c-4e34-aa14-ed776e85b3b6' = 'RSA2048'
            'e2b36190-879b-4a3d-ad8d-f2e7bba32784' = 'RSA2048_SHA256'
            '67f8444f-8743-48f1-a328-1eaab8736080' = 'RSA2048_SHA1'
        }

        $SignatureTypeKey = $SignatureType.Guid.ToLowerInvariant()

        if ($SignatureTypeMap.ContainsKey($SignatureTypeKey)) {
            Write-Output $SignatureTypeMap[$SignatureTypeKey]
        } else {
            Write-Output $SignatureType.Guid
        }
    }

    end {}
}

function ConvertFrom-SecureBootSignatureDatabase {
    <#
        .SYNOPSIS
            Decodes a Secure Boot UEFI signature database byte array.

        .DESCRIPTION
            Parses the raw Bytes property returned by Get-SecureBootUEFI for Secure Boot variables such
            as PK, KEK, db, and dbx. This provides a compatibility path for systems where the native
            -Decoded parameter is unavailable.

        .PARAMETER Bytes
            The raw byte array returned by Get-SecureBootUEFI.

        .PARAMETER Name
            The Secure Boot variable name associated with the byte array.

        .PARAMETER IncludeSignatureData
            Includes raw signature data as a hexadecimal string.

        .PARAMETER IncludeCertificateObject
            Includes the decoded X509Certificate2 object for X.509 certificate entries.

        .OUTPUTS
            System.Management.Automation.PSCustomObject

        .EXAMPLE
            $Db = Get-SecureBootUEFI -Name db
            ConvertFrom-SecureBootSignatureDatabase -Bytes $Db.Bytes -Name db

        .NOTES
            This function decodes EFI_SIGNATURE_LIST and EFI_SIGNATURE_DATA structures.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $false)]
        [ValidateSet('PK', 'KEK', 'db', 'dbx', 'PKDefault', 'KEKDefault', 'dbDefault', 'dbxDefault', 'dbt', 'dbtDefault')]
        [string]$Name = 'db',

        [Parameter(Mandatory = $false)]
        [switch]$IncludeSignatureData,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeCertificateObject
    )

    begin {
        $SignatureListHeaderLength = 28
        $SignatureOwnerLength = 16
        $Offset = 0
        $SignatureListIndex = 0
    }

    process {
        while (($Offset + $SignatureListHeaderLength) -le $Bytes.Count) {
            $SignatureListIndex++

            $SignatureTypeBytes = Get-ByteRange -Bytes $Bytes -Offset $Offset -Count 16
            $SignatureType = New-Object Guid (,$SignatureTypeBytes)

            $SignatureListSize = [System.BitConverter]::ToUInt32($Bytes, $Offset + 16)
            $SignatureHeaderSize = [System.BitConverter]::ToUInt32($Bytes, $Offset + 20)
            $SignatureSize = [System.BitConverter]::ToUInt32($Bytes, $Offset + 24)

            if ($SignatureListSize -lt $SignatureListHeaderLength) {
                throw "Invalid signature list size at offset $Offset."
            }

            if (($Offset + $SignatureListSize) -gt $Bytes.Count) {
                throw "Signature list at offset $Offset exceeds the source byte array length."
            }

            if ($SignatureSize -lt $SignatureOwnerLength) {
                throw "Invalid signature size at offset $Offset."
            }

            $SignatureTypeName = Get-UefiSignatureTypeName -SignatureType $SignatureType
            $SignatureDataOffset = $Offset + $SignatureListHeaderLength + $SignatureHeaderSize
            $SignatureDataTotalLength = $SignatureListSize - $SignatureListHeaderLength - $SignatureHeaderSize

            if (($SignatureDataTotalLength % $SignatureSize) -ne 0) {
                throw "Signature list at offset $Offset has a non-even signature data length."
            }

            $SignatureCount = [int]($SignatureDataTotalLength / $SignatureSize)

            for ($SignatureIndex = 0; $SignatureIndex -lt $SignatureCount; $SignatureIndex++) {
                $CurrentSignatureOffset = $SignatureDataOffset + ($SignatureIndex * $SignatureSize)

                $SignatureOwnerBytes = Get-ByteRange `
                    -Bytes $Bytes `
                    -Offset $CurrentSignatureOffset `
                    -Count $SignatureOwnerLength

                $SignatureOwner = New-Object Guid (,$SignatureOwnerBytes)

                $SignatureDataLength = $SignatureSize - $SignatureOwnerLength

                $SignatureData = Get-ByteRange `
                    -Bytes $Bytes `
                    -Offset ($CurrentSignatureOffset + $SignatureOwnerLength) `
                    -Count $SignatureDataLength

                $Certificate = $null
                $Subject = $null
                $Issuer = $null
                $Thumbprint = $null
                $SerialNumber = $null
                $Algorithm = $null
                $Version = $null
                $ValidFrom = $null
                $ValidTo = $null
                $Hash = $null
                $RevocationTimeUtc = $null

                if ($SignatureTypeName -eq 'X509') {
                    try {
                        $Certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
                            $SignatureData
                        )

                        $Subject = $Certificate.Subject
                        $Issuer = $Certificate.Issuer
                        $Thumbprint = $Certificate.Thumbprint
                        $SerialNumber = $Certificate.SerialNumber
                        $Algorithm = $Certificate.SignatureAlgorithm.FriendlyName
                        $Version = $Certificate.Version
                        $ValidFrom = $Certificate.NotBefore
                        $ValidTo = $Certificate.NotAfter
                    } catch {
                        Write-Verbose "Unable to decode X.509 certificate at offset $CurrentSignatureOffset."
                    }
                } elseif ($SignatureTypeName -in @('SHA1', 'SHA224', 'SHA256', 'SHA384', 'SHA512')) {
                    $Hash = ConvertTo-HexString -Bytes $SignatureData
                } elseif ($SignatureTypeName -eq 'X509_SHA256') {
                    $HashBytes = Get-ByteRange -Bytes $SignatureData -Offset 0 -Count 32
                    $Hash = ConvertTo-HexString -Bytes $HashBytes
                    $RevocationTimeUtc = ConvertFrom-EfiTime -Bytes $SignatureData -Offset 32
                } elseif ($SignatureTypeName -eq 'X509_SHA384') {
                    $HashBytes = Get-ByteRange -Bytes $SignatureData -Offset 0 -Count 48
                    $Hash = ConvertTo-HexString -Bytes $HashBytes
                    $RevocationTimeUtc = ConvertFrom-EfiTime -Bytes $SignatureData -Offset 48
                } elseif ($SignatureTypeName -eq 'X509_SHA512') {
                    $HashBytes = Get-ByteRange -Bytes $SignatureData -Offset 0 -Count 64
                    $Hash = ConvertTo-HexString -Bytes $HashBytes
                    $RevocationTimeUtc = ConvertFrom-EfiTime -Bytes $SignatureData -Offset 64
                } else {
                    $Hash = ConvertTo-HexString -Bytes $SignatureData
                }

                $OutputObject = [ordered]@{
                    Name                 = $Name
                    SignatureListIndex   = $SignatureListIndex
                    SignatureIndex       = $SignatureIndex
                    SignatureType        = $SignatureType
                    SignatureTypeName    = $SignatureTypeName
                    SignatureOwner       = $SignatureOwner
                    SignatureListSize    = $SignatureListSize
                    SignatureHeaderSize  = $SignatureHeaderSize
                    SignatureSize        = $SignatureSize
                    Subject              = $Subject
                    Issuer               = $Issuer
                    Thumbprint           = $Thumbprint
                    SerialNumber         = $SerialNumber
                    Algorithm            = $Algorithm
                    Version              = $Version
                    ValidFrom            = $ValidFrom
                    ValidTo              = $ValidTo
                    Hash                 = $Hash
                    RevocationTimeUtc    = $RevocationTimeUtc
                }

                if ($IncludeSignatureData) {
                    $OutputObject.SignatureDataHex = ConvertTo-HexString -Bytes $SignatureData
                }

                if ($IncludeCertificateObject) {
                    $OutputObject.Certificate = $Certificate
                }

                Write-Output ([pscustomobject]$OutputObject)
            }

            $Offset = $Offset + $SignatureListSize
        }

        if ($Offset -ne $Bytes.Count) {
            Write-Warning "Finished parsing at offset $Offset, but the byte array length is $($Bytes.Count)."
        }
    }

    end {}
}

function Get-SecureBootUEFIDecoded {
    <#
        .SYNOPSIS
            Decodes Secure Boot UEFI variables without using Get-SecureBootUEFI -Decoded.

        .DESCRIPTION
            Reads a Secure Boot UEFI variable using Get-SecureBootUEFI and decodes the raw Bytes value.
            This is intended for devices where Get-SecureBootUEFI does not support the -Decoded parameter.

            When ResolveFromCertificateStore is used, this function optionally calls an existing
            Get-CertFromThumbprint function to check whether decoded X.509 certificates also exist in
            a Windows certificate store.

        .PARAMETER Name
            The Secure Boot UEFI variable to decode.

        .PARAMETER IncludeSignatureData
            Includes raw signature data as a hexadecimal string.

        .PARAMETER IncludeCertificateObject
            Includes the decoded X509Certificate2 object for X.509 certificate entries.

        .PARAMETER ResolveFromCertificateStore
            Uses Get-CertFromThumbprint to check whether decoded certificate thumbprints exist in the
            specified local machine certificate store locations.

        .PARAMETER CertStoreLocation
            The certificate store location or locations to check when ResolveFromCertificateStore is used.

        .OUTPUTS
            System.Management.Automation.PSCustomObject

        .EXAMPLE
            Get-SecureBootUEFIDecodedCompat -Name db |
                Format-Table SignatureOwner, Subject, Thumbprint, ValidTo -AutoSize

        .EXAMPLE
            Get-SecureBootUEFIDecodedCompat -Name db |
                Where-Object { $_.Subject -like '*Windows UEFI CA 2023*' }

        .EXAMPLE
            Get-SecureBootUEFIDecodedCompat -Name db -ResolveFromCertificateStore -CertStoreLocation My, WebHosting

        .NOTES
            Requires elevation, the same as Get-SecureBootUEFI.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('PK', 'KEK', 'db', 'dbx', 'PKDefault', 'KEKDefault', 'dbDefault', 'dbxDefault', 'dbt', 'dbtDefault')]
        [string]$Name = 'db',

        [Parameter(Mandatory = $false)]
        [switch]$IncludeSignatureData,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeCertificateObject,

        [Parameter(Mandatory = $false)]
        [switch]$ResolveFromCertificateStore,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Cert:\LocalMachine\My', 'Cert:\LocalMachine\WebHosting', 'My', 'WebHosting')]
        [string[]]$CertStoreLocation = @('My', 'WebHosting')
    )

    begin {}

    process {
        $SecureBootVariable = Get-SecureBootUEFI -Name $Name -ErrorAction Stop

        $DecodedEntries = ConvertFrom-SecureBootSignatureDatabase `
            -Bytes $SecureBootVariable.Bytes `
            -Name $Name `
            -IncludeSignatureData:$IncludeSignatureData `
            -IncludeCertificateObject:$IncludeCertificateObject

        foreach ($DecodedEntry in $DecodedEntries) {
            $StoreMatchLocations = New-Object System.Collections.Generic.List[string]

            if ($ResolveFromCertificateStore -and -not [string]::IsNullOrWhiteSpace($DecodedEntry.Thumbprint)) {
                foreach ($StoreLocation in $CertStoreLocation) {
                    try {
                        if (Get-Command -Name Get-CertFromThumbprint -ErrorAction SilentlyContinue) {
                            $StoreCertificate = Get-CertFromThumbprint `
                                -CertificateThumbPrint $DecodedEntry.Thumbprint `
                                -CertStoreLocation $StoreLocation `
                                -ErrorAction Stop

                            if ($StoreCertificate) {
                                $StoreMatchLocations.Add($StoreLocation)
                            }
                        } else {
                            Write-Warning 'Get-CertFromThumbprint was not found in the current session.'
                        }
                    } catch {
                        Write-Verbose "Thumbprint was not found in $StoreLocation. $($_.Exception.Message)"
                    }
                }
            }

            if ($ResolveFromCertificateStore) {
                $DecodedEntry |
                    Add-Member -MemberType NoteProperty -Name CertificateStoreMatched -Value ($StoreMatchLocations.Count -gt 0)

                $DecodedEntry |
                    Add-Member -MemberType NoteProperty -Name CertificateStoreLocations -Value ($StoreMatchLocations.ToArray())
            }

            Write-Output $DecodedEntry
        }
    }

    end {}
}

Get-SecureBootUEFIDecoded -Name db |
    Format-Table SignatureOwner, Subject, Thumbprint, ValidTo -AutoSize
