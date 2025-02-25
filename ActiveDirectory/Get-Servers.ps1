function Get-Servers {
    <#
    .SYNOPSIS
        Retrieves server computer objects via LDAP across multiple domains and OUs.

    .DESCRIPTION
        This function queries Active Directory to find server computer objects by issuing raw LDAP queries
        through System.DirectoryServices. Remote LDAP paths (with corresponding credentials) can be supplied via 
        the –defaultNamingContext and –Credential parameters. The –IncludeLocal switch automatically adds the local 
        domain (converted from RootDSE) to the search. An optional –Filter parameter further restricts the search 
        on the computer's common name (cn). Paging is enabled for domain-wide searches.

        This approach provides greater flexibility and control compared to Get-ADComputer. Specifically, it allows:
          • Raw LDAP queries allow you to tailor the query filter precisely to your needs,
            potentially reducing the amount of data returned.
          • By using the PageSize property, the function retrieves large result sets in manageable batches,
            reducing memory overhead and improving response time compared to some native cmdlets.
          • This approach seamlessly handles local and remote queries in one function call,
            without the overhead of loading additional modules like ActiveDirectory.
          • With explicit resource cleanup (disposing DirectorySearcher objects),
            the function minimizes resource consumption during extended queries.

    .PARAMETER defaultNamingContext
        One or more LDAP paths (e.g. "LDAP://domain.com") to query. If none are provided, the function defaults to the local domain.

    .PARAMETER Credential
        An array of PSCredential objects for remote domains. Credentials are automatically matched by comparing base domains.
        No credential is required for the local domain.

    .PARAMETER OU
        An array of organizational units to search within. Allowed characters are alphabetic, spaces, underscores, and dashes.
        Each specified OU must exist in at least one of the provided domains.

    .PARAMETER IncludeLocal
        Switch parameter. When provided, the local domain ("LDAP://RootDSE") is added to the search along with any provided 
        defaultNamingContext values.

    .PARAMETER Filter
        Optional LDAP wildcard filter applied to the computer's common name (cn). For example, specifying "MS*" will restrict 
        results to servers whose common name starts with MS.

    .EXAMPLE
        # Query a remote domain and include the local domain, returning only servers with names starting with "MS"
        Get-Servers -defaultNamingContext "LDAP://domain2.uat.domain.com" -Credential $RemoteCreds -IncludeLocal -OU "Sales", "Marketing" -Filter "MS*"

    .NOTES
        Name: Get-Servers
        Author: Ryan Whitlock
        Date: 01.15.2021
        Version: 3.0
        Changes: Updated logic
    #>

    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string[]]$defaultNamingContext = @(),

        [Parameter(Position = 1)]
        [PSCredential[]]$Credential,

        [Parameter(Position = 2)]
        [ValidateNotNull()]
        [ValidateScript({
            foreach ($item in $_) {
                if ($item -notmatch '^[a-zA-Z _-]+$') {
                    throw "OU should only contain alphabetic characters, spaces, underscores, and dashes."
                }
            }
            $true
        })]
        [string[]]$OU,

        [Parameter()]
        [switch]$IncludeLocal,

        [Parameter(Position = 3)]
        [string]$Filter
    )

    begin {
        Write-Verbose "Starting Get-Servers function..."

        # Define the local LDAP constant.
        $localLDAP = "LDAP://RootDSE"
        if ($IncludeLocal -and ($defaultNamingContext -notcontains $localLDAP)) {
            Write-Verbose "IncludeLocal switch provided; adding local domain..."
            $defaultNamingContext = @($localLDAP) + $defaultNamingContext
        }
        if (-not $defaultNamingContext -or $defaultNamingContext.Count -eq 0) {
            Write-Verbose "No defaultNamingContext provided; defaulting to local domain..."
            $defaultNamingContext = @($localLDAP)
        }

        # Helper: Convert a distinguished name (e.g. "DC=domain,DC=com") to "domain.com"
        function Convert-DNToDomain {
            param(
                [Parameter(Mandatory = $true)]
                [string]$DN
            )
            $parts = $DN -split ','
            $domainParts = foreach ($part in $parts) {
                if ($part -match '^DC=(.+)$') { $matches[1] }
            }
            return ($domainParts -join '.')
        }

        # Helper: Extract the base domain (last two parts) from a domain string.
        function Get-BaseDomain {
            param(
                [Parameter(Mandatory = $true)]
                [string]$DomainName
            )
            $DomainParts = $DomainName -split '\.'
            if ($DomainParts.Count -ge 2) {
                return $DomainParts[-2..-1] -join '.'
            }
            else {
                return $DomainName
            }
        }

        # Helper: Adjust LDAP username so that only the name portion is used.
        function Get-LDAPUsername {
            param(
                [Parameter(Mandatory = $true)]
                [string]$UserName
            )
            if ($UserName -match '^(?<user>[^@]+)@') {
                return $matches['user']
            }
            if ($UserName -match '^[^\\]+\\(?<user>.+)$') {
                return $matches['user']
            }
            return $UserName
        }

        # Determine the actual local LDAP search path.
        $localNamingContextValue = ([ADSI]$localLDAP).defaultNamingContext
        $actualLocalLDAP = "LDAP://$localNamingContextValue"
        $LoggedInDomain = Convert-DNToDomain -DN $localNamingContextValue

        # Build the default server filter.
        $defaultServerFilter = "(&(objectClass=Computer)(operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        if ($Filter) {
            $combinedFilter = "(&" + $defaultServerFilter + "(cn=$Filter))"
        }
        else {
            $combinedFilter = $defaultServerFilter
        }
        Write-Verbose "Using LDAP filter: $combinedFilter"

        # Helper: Search for server computer objects under a given DirectoryEntry.
        function Search-ForServers {
            param(
                [Parameter(Mandatory = $true)]
                [System.DirectoryServices.DirectoryEntry]$SearchRoot,
                [bool]$UsePaging = $true,
                [string]$ServerFilter
            )
            try {
                $ds = New-Object System.DirectoryServices.DirectorySearcher($SearchRoot)
                $ds.Filter = $ServerFilter
                $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $ds.PageSize = if ($UsePaging) { 1000 } else { 0 }
                $ds.PropertiesToLoad.Add("dnshostname") | Out-Null
                $results = $ds.FindAll() | ForEach-Object {
                    $_.Properties["dnshostname"] | ForEach-Object { $_ }
                }
                return $results | Where-Object { $_ -ne $null }
            }
            catch {
                Write-Error "Error searching for servers: $_"
                return @()
            }
            finally {
                if ($ds -and $ds.Dispose) { $ds.Dispose() }
            }
        }

        # Helper: Retrieve OU entries from a given DirectoryEntry based on provided OU names.
        function Get-OUEntries {
            param(
                [Parameter(Mandatory = $true)]
                [System.DirectoryServices.DirectoryEntry]$RootEntry,
                [Parameter(Mandatory = $true)]
                [string[]]$OUArray
            )
            $ouFilterParts = $OUArray | ForEach-Object { "(ou=$($_ -replace ' ', '\20'))" }
            $filterOU = "(|$($ouFilterParts -join ''))"
            try {
                $ds = New-Object System.DirectoryServices.DirectorySearcher($RootEntry)
                $ds.Filter = $filterOU
                $ds.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
                $ds.PropertiesToLoad.Add("distinguishedName") | Out-Null
                $entries = @()
                foreach ($result in $ds.FindAll()) {
                    $entries += $result.GetDirectoryEntry()
                }
                return $entries
            }
            catch {
                Write-Error "Error retrieving OU entries: $_"
                return @()
            }
            finally {
                if ($ds -and $ds.Dispose) { $ds.Dispose() }
            }
        }
    }

    process {
        foreach ($domainLDAP in $defaultNamingContext) {
            Write-Verbose "Processing domain: $domainLDAP"
            if ($domainLDAP -eq $localLDAP) {
                # For local domain, use the actual naming context.
                $domainToSearch = $actualLocalLDAP
                $credToUse = $null
            }
            else {
                $trimmedDomain = $domainLDAP -replace '^LDAP://', ''
                $domainToSearch = "LDAP://$trimmedDomain"
                $baseDomain = Get-BaseDomain -DomainName $trimmedDomain
                $credToUse = $Credential | Where-Object {
                    $netCred = $_.GetNetworkCredential()
                    $credDomain = $netCred.Domain
                    if ([string]::IsNullOrEmpty($credDomain) -and $netCred.UserName -match "@(.+)$") {
                        $credDomain = $matches[1]
                    }
                    if ([string]::IsNullOrEmpty($credDomain)) {
                        $credDomain = $LoggedInDomain
                    }
                    $baseDomainFromCred = Get-BaseDomain -DomainName $credDomain
                    $baseDomainFromCred -eq $baseDomain
                } | Select-Object -First 1

                if (-not $credToUse) {
                    throw "No matching credential found for domain '$trimmedDomain' (base domain '$baseDomain')."
                }
            }

            # Create the DirectoryEntry using the appropriate credentials.
            if ($credToUse) {
                $username = Get-LDAPUsername -UserName $credToUse.UserName
                $password = $credToUse.GetNetworkCredential().Password
                $rootEntry = New-Object System.DirectoryServices.DirectoryEntry($domainToSearch, $username, $password)
            }
            else {
                $rootEntry = New-Object System.DirectoryServices.DirectoryEntry($domainToSearch)
            }

            # Search based on whether OU is specified.
            if ($OU) {
                $ouEntries = Get-OUEntries -RootEntry $rootEntry -OUArray $OU
                foreach ($ouEntry in $ouEntries) {
                    Write-Verbose "Searching within OU: $($ouEntry.distinguishedName)"
                    $servers = Search-ForServers -SearchRoot $ouEntry -UsePaging:$false -ServerFilter $combinedFilter
                    foreach ($server in $servers) {
                        Write-Output $server
                    }
                }
            }
            else {
                Write-Verbose "Performing domain-wide search on $domainToSearch"
                $servers = Search-ForServers -SearchRoot $rootEntry -UsePaging:$true -ServerFilter $combinedFilter
                foreach ($server in $servers) {
                    Write-Output $server
                }
            }
        }
    }
}
