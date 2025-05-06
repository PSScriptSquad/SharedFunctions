function Get-ADUserByLocationCode {
    <#
    .SYNOPSIS
        Retrieves Active Directory user accounts whose extensionAttribute1 matches specified location codes.

    .DESCRIPTION
        Performs a paged LDAP search (objectCategory=person, objectClass=user) where extensionAttribute1
        matches any of the supplied LocationCode values using a single OR-based filter. Returns the
        sAMAccountName of each matching user. Supports pipeline input for multiple location codes.

    .PARAMETER LocationCode
        The value(s) to match in extensionAttribute1. Accepts pipeline input. Format depends on your
        organization's AD configuration.

    .PARAMETER BaseDistinguishedName
        Optional. Search root DN. Defaults to the domain’s defaultNamingContext from RootDSE.

    .PARAMETER Server
        Optional. LDAP server (host or IP). Defaults to the current logon DC.

    .PARAMETER Credential
        Optional. Alternate credentials for the bind.

    .INPUTS
        [string] – LocationCode via the pipeline.

    .OUTPUTS
        [pscustomobject] – Property SamAccountName for each matching user.

    .EXAMPLE
        Get-ADUserByLocationCode -LocationCode 'ATL01' -Verbose
        # Retrieves users with extensionAttribute1 equal to 'ATL01'.

    .EXAMPLE
        'NYC03','DAL17' | Get-ADUserByLocationCode
        # Retrieves users with extensionAttribute1 equal to 'NYC03' or 'DAL17' using a single query.

    .EXAMPLE
        Get-ADUserByLocationCode -LocationCode 'CHI22' -Server 'dc01.contoso.com'
        # Queries a specific domain controller for users with extensionAttribute1 equal to 'CHI22'.

    .EXAMPLE
        $cred = Get-Credential
        Get-ADUserByLocationCode -LocationCode 'SEA15' -Credential $cred
        # Uses alternate credentials to query users with extensionAttribute1 equal to 'SEA15'.

    .LINK
        https://learn.microsoft.com/windows/win32/adsi/searching-with-adsisearcher

    .NOTES
        Author: Ryan Whitlock
        Date: 05.06.2025
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true,
                   ValueFromPipeline = $true,
                   Position = 0)]
        [ValidateScript({ -not [string]::IsNullOrWhiteSpace($_) })]
        [string[]]$LocationCode,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$BaseDistinguishedName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    begin {
        # Helper to escape filter values (RFC 4515).
        function ConvertTo-LdapFilterSafe {
            param([string]$Value)
            $Value -replace '([\\*\(\)\0])', {
                param($match)
                switch ($match.Value) {
                    '\' { '\5c' }
                    '*' { '\2a' }
                    '(' { '\28' }
                    ')' { '\29' }
                    "`0" { '\00' }
                }
            }
        }

        # Initialize a list to collect LocationCodes for batch processing.
        $LocationCodes = [System.Collections.Generic.List[string]]::new()

        # Resolve the base DN when not supplied.
        if (-not $BaseDistinguishedName) {
            Write-Verbose 'Querying RootDSE for defaultNamingContext'
            try {
                $RootDsePath = if ($Server) { "LDAP://$Server/RootDSE" } else { 'LDAP://RootDSE' }
                $RootDse     = [ADSI]$RootDsePath
                $BaseDistinguishedName = [string]$RootDse.defaultNamingContext
            }
            catch [System.DirectoryServices.DirectoryServicesCOMException] {
                throw "LDAP connection failed to retrieve RootDSE: $($_.Exception.Message)"
            }
            catch {
                throw "Unable to determine default naming context. Specify -BaseDistinguishedName. Details: $($_.Exception.Message)"
            }
        }

        # Build the LDAP path.
        $DirectoryEntryPath = if ($Server) {
            "LDAP://$Server/$BaseDistinguishedName"
        }
        else {
            "LDAP://$BaseDistinguishedName"
        }
        Write-Verbose ("Binding to LDAP path: {0}" -f $DirectoryEntryPath)

        # Bind using the appropriate DirectoryEntry constructor overload.
        try {
            if ($Credential) {
                $DirectoryEntry = [System.DirectoryServices.DirectoryEntry]::new(
                    $DirectoryEntryPath,
                    $Credential.UserName,
                    $Credential.GetNetworkCredential().Password,
                    [System.DirectoryServices.AuthenticationTypes]::Secure
                )
            }
            else {
                $DirectoryEntry = [System.DirectoryServices.DirectoryEntry]::new($DirectoryEntryPath)
            }
        }
        catch [System.Security.Authentication.AuthenticationException] {
            throw "Authentication failed with provided credentials: $($_.Exception.Message)"
        }
        catch {
            throw "Failed to bind to LDAP path '$DirectoryEntryPath': $($_.Exception.Message)"
        }

        # Prepare the searcher.
        try {
            $Searcher          = [System.DirectoryServices.DirectorySearcher]::new($DirectoryEntry)
            $Searcher.PageSize = 500
            $null = $Searcher.PropertiesToLoad.Add('sAMAccountName')
        }
        catch {
            throw "Failed to initialize DirectorySearcher: $($_.Exception.Message)"
        }
    }

    process {
        # Collect each LocationCode for batch processing.
        $LocationCodes.Add($LocationCode)
        Write-Progress -Activity "Collecting Location Codes" -Status "Processed: $LocationCode" -PercentComplete -1
    }

    end {
        # Build the OR-based LDAP filter for all LocationCodes.
        if ($LocationCodes.Count -eq 0) {
            Write-Warning "No valid LocationCodes provided."
            return
        }

        $EscapedLocationCodes = $LocationCodes | ForEach-Object { ConvertTo-LdapFilterSafe -Value $_ }
        $OrFilter = $EscapedLocationCodes | ForEach-Object { "(extensionAttribute1=$_)" }
        $Searcher.Filter = "(&(objectCategory=person)(objectClass=user)(|$($OrFilter -join '')))"
        Write-Verbose ("LDAP filter: {0}" -f $Searcher.Filter)

        # Execute the search with progress reporting.
        try {
            $Results = $Searcher.FindAll()
            $ResultCount = $Results.Count
            $Current = 0

            foreach ($Result in $Results) {
                $Current++
                Write-Progress -Activity "Processing LDAP Results" -Status "Processing $Current of $ResultCount" -PercentComplete (($Current / $ResultCount) * 100)

                $Sam = $Result.Properties['samaccountname']
                if ($Sam) {
                    [pscustomobject]@{
                        SamAccountName = $Sam[0]
                    }
                }
            }
            Write-Progress -Activity "Processing LDAP Results" -Completed
        }
        catch [System.DirectoryServices.DirectoryServicesCOMException] {
            Write-Warning "LDAP query failed: $($_.Exception.Message)"
        }
        catch [System.UnauthorizedAccessException] {
            Write-Warning "Access denied during LDAP query: $($_.Exception.Message)"
        }
        catch {
            Write-Warning "Unexpected error during LDAP query: $($_.Exception.Message)"
        }
        finally {
            # Clean up unmanaged resources.
            if ($Searcher)      { $Searcher.Dispose() }
            if ($DirectoryEntry){ $DirectoryEntry.Dispose() }
        }
    }
}
