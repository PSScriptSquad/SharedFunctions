function Get-DnsCNAMEs {
    <#
    .SYNOPSIS
        Retrieves CNAME records (including chained CNAMEs) that reference an A record based on either an IP address or a FQDN.

    .DESCRIPTION
        This function queries one or more DNS servers via the MicrosoftDNS CIM provider. It supports two parameter sets:
          - **ByIPAddress**: Accepts one or more IP addresses, finds the associated A record(s), and then looks up any CNAME records
                           whose PrimaryName matches the A record’s normalized OwnerName.
          - **ByHostName**: Accepts one or more fully qualified domain names (FQDN) and directly searches for CNAME records whose
                           PrimaryName matches the normalized FQDN.
        Each DNS server may require different credentials. For DNS servers whose base domain (last two labels) does not match the
        logged‑in domain’s base, a matching credential is required. Credentials are mapped by base domain from the supplied credentials.
        Results are emitted as PSCustomObject items with these properties:
            • Input         : The original IP or FQDN provided.
            • CanonicalName : The normalized canonical name (with a trailing dot).
            • Alias         : The alias (CNAME) discovered.
            • Depth         : The recursion level (0 for the original input, 1 for a direct CNAME, etc.).
            • DNSServer     : The DNS server queried.

    .PARAMETER IPAddress
        One or more IPv4 addresses. Each is validated to ensure it is a valid IPv4 address.
        Use this parameter when operating in the "ByIPAddress" parameter set.

    .PARAMETER Fqdn
        One or more fully qualified domain names (FQDN). Each value must match a regex pattern; otherwise an error is thrown stating
        that an FQDN is mandatory.
        Use this parameter when operating in the "ByHostName" parameter set.

    .PARAMETER DNSServer
        One or more DNS server names (or hostnames) where the MicrosoftDNS CIM provider is available.

    .PARAMETER Credentials
        An array of PSCredential objects. For any DNS server whose base domain (last two labels) is outside of the logged‑in
        domain’s base, a matching credential (mapped by base domain) must be provided.

    .EXAMPLE
        PS C:\> Get-DnsCNAMEs -IPAddress "192.168.1.10","192.168.1.11" -DNSServer "dns1.domain.com","dns2.domain.com" -Credentials $creds
        Retrieves the A record(s) for the given IP addresses from each DNS server and outputs any associated (direct or chained)
        CNAME records.

    .EXAMPLE
        PS C:\> Get-DnsCNAMEs -Fqdn "server.prod.domain1.com","app.prod.domain2.com" -DNSServer "dns1.domain.com","dns2.domain2.com" -Credentials $creds
        Directly queries for any CNAME records that point to the given FQDNs from each DNS server.

    .NOTES
        Name: Get-DnsCNAMEs
        Author: Ryan Whitlock
        Date: 02.27.2024
        Version: 1.0
        Changes: Initial release
    #>

    [CmdletBinding(DefaultParameterSetName = "ByHostName")]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = "ByIPAddress")]
        [ValidateScript({
            try { ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork' } catch { $false }
        })]
        [ValidateNotNullOrEmpty()]
        [string[]]$IPAddress,

        [Parameter(Mandatory = $true, ParameterSetName = "ByHostName")]
        [ValidateScript({
            if ($_ -notmatch '^(?=.{1,254}$)(?:(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$') {
                throw "A FQDN is mandatory."
            }
            $true
        })]
        [ValidateNotNullOrEmpty()]
        [string[]]$Fqdn,

        [Parameter(Mandatory = $true)]
        [string[]]$DNSServer,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential[]]$Credentials
    )

    begin {
        # Determine the logged-in domain using Win32_ComputerSystem.
        $LoggedInDomain = (Get-CimInstance -ClassName Win32_ComputerSystem).Domain
        Write-Verbose "Logged-in domain: $LoggedInDomain"

        # Helper: Extract the base domain (last two labels).
        function Get-BaseDomain {
            param(
                [string]$DomainName
            )
            $parts = $DomainName -split '\.'
            if ($parts.Count -ge 2) {
                return "$($parts[-2]).$($parts[-1])"
            }
            return $DomainName
        }

        # Determine the local base domain from the logged-in domain.
        $localBaseDomain = Get-BaseDomain -DomainName $LoggedInDomain
        Write-Verbose "Local base domain: $localBaseDomain"

        # Helper: Build a credential map by base domain.
        function Get-CredentialMap {
            param(
                [System.Management.Automation.PSCredential[]]$Creds,
                [string]$LoggedInDomain
            )
            $map = @{}
            foreach ($cred in $Creds) {
                $netCred = $cred.GetNetworkCredential()
                $Domain = ""
                if (-not [string]::IsNullOrEmpty($netCred.Domain)) {
                    $Domain = $netCred.Domain
                } elseif ($netCred.UserName -match "@(.+)$") {
                    $Domain = $matches[1]
                }
                if ([string]::IsNullOrEmpty($Domain)) {
                    $Domain = $LoggedInDomain
                    Write-Verbose "No domain found for credential '$($cred.UserName)'. Using logged-in domain: $Domain"
                }
                $DomainParts = $Domain -split '\.'
                if ($DomainParts.Count -ge 2) {
                    $BaseDomain = $DomainParts[-2..-1] -join '.'
                } else {
                    $BaseDomain = $Domain
                }
                if (-not [string]::IsNullOrEmpty($BaseDomain) -and (-not $map.ContainsKey($BaseDomain))) {
                    $map[$BaseDomain] = $cred
                    Write-Verbose "Mapping credential for base domain: $BaseDomain"
                }
            }
            Write-Verbose "Credential Mapping: $($map.Keys -join ', ')"
            return $map
        }

        # Build the credential map if credentials are supplied.
        if ($Credentials) {
            $CredentialMap = Get-CredentialMap -Creds $Credentials -LoggedInDomain $LoggedInDomain
        } else {
            $CredentialMap = @{}
        }

        # Build a mapping of DNS server names to CimSessions.
        $ServerSessions = @{}
        foreach ($dns in $DNSServer) {
            $trimmedDNS = $dns.Trim()
            $baseDomain = Get-BaseDomain -DomainName $trimmedDNS
            if ($baseDomain -eq $localBaseDomain) {
                # Local domain; create a session without explicit credentials.
                $session = New-CimSession -ComputerName $dns
                Write-Verbose "Created local CimSession for DNS server '$dns' (base domain $baseDomain)."
                $ServerSessions[$dns] = $session
            }
            else {
                if ($CredentialMap.ContainsKey($baseDomain)) {
                    $cred = $CredentialMap[$baseDomain]
                    $session = New-CimSession -ComputerName $dns -Credential $cred
                    Write-Verbose "Created remote CimSession for DNS server '$dns' (base domain $baseDomain) using mapped credential."
                    $ServerSessions[$dns] = $session
                }
                else {
                    throw "No credential provided for remote DNS server '$dns' (base domain '$baseDomain')."
                }
            }
        }

        # Helper: Recursively retrieve CNAME records using a CimSession.
        function Get-RecursiveCNAMEs {
            param(
                [string]$CanonicalName,
                [Microsoft.Management.Infrastructure.CimSession]$Session,
                [int]$Depth = 1
            )
            $cnameParams = @{
                Namespace = 'root\MicrosoftDNS'
                ClassName = 'MicrosoftDNS_CNAMEType'
                Filter    = "PrimaryName = '$CanonicalName'"
            }
            $cnameRecords = Get-CimInstance -CimSession $Session @cnameParams
            foreach ($record in $cnameRecords) {
                $alias = $record.OwnerName
                $aliasNormalized = if ($alias[-1] -ne '.') { "$alias." } else { $alias }
                Write-Output ([PSCustomObject]@{
                    CanonicalName = $CanonicalName
                    Alias         = $aliasNormalized
                    Depth         = $Depth
                    DNSServer     = $Session.ComputerName
                })
                Get-RecursiveCNAMEs -CanonicalName $aliasNormalized -Session $Session -Depth ($Depth + 1)
            }
        }
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            "ByIPAddress" {
                foreach ($ip in $IPAddress) {
                    foreach ($dns in $DNSServer) {
                        $session = $ServerSessions[$dns]
                        Write-Verbose "Querying for A record with IP address '$ip' on DNS server '$dns'..."
                        $aParams = @{
                            Namespace = 'root\MicrosoftDNS'
                            ClassName = 'MicrosoftDNS_AType'
                            Filter    = "IPAddress = '$ip'"
                        }
                        $aRecords = Get-CimInstance -CimSession $session @aParams
                        if (-not $aRecords) {
                            Write-Warning "No A record found for IP address '$ip' on '$dns'."
                            continue
                        }
                        foreach ($aRecord in $aRecords) {
                            $resolvedHostName = $aRecord.OwnerName
                            $normalizedCanonical = if ($resolvedHostName[-1] -ne '.') { "$resolvedHostName." } else { $resolvedHostName }
                            Write-Output ([PSCustomObject]@{
                                Input         = $ip
                                CanonicalName = $normalizedCanonical
                                Alias         = $null
                                Depth         = 0
                                DNSServer     = $dns
                            })
                            Write-Verbose "Found A record '$normalizedCanonical' for IP '$ip' on '$dns'. Searching for CNAME records..."
                            Get-RecursiveCNAMEs -CanonicalName $normalizedCanonical -Session $session -Depth 1 | ForEach-Object {
                                $_ | Add-Member -MemberType NoteProperty -Name Input -Value $ip -Force
                                Write-Output $_
                            }
                        }
                    }
                }
            }
            "ByHostName" {
                foreach ($fqdnInput in $Fqdn) {
                    foreach ($dns in $DNSServer) {
                        $session = $ServerSessions[$dns]
                        $fqdnNormalized = if ($fqdnInput[-1] -ne '.') { "$fqdnInput." } else { $fqdnInput }
                        Write-Output ([PSCustomObject]@{
                            Input         = $fqdnInput
                            CanonicalName = $fqdnNormalized
                            Alias         = $null
                            Depth         = 0
                            DNSServer     = $dns
                        })
                        Write-Verbose "Using FQDN '$fqdnNormalized'. Searching for CNAME records on DNS server '$dns'..."
                        Get-RecursiveCNAMEs -CanonicalName $fqdnNormalized -Session $session -Depth 1 | ForEach-Object {
                            $_ | Add-Member -MemberType NoteProperty -Name Input -Value $fqdnInput -Force
                            Write-Output $_
                        }
                    }
                }
            }
        }
    }
    end {
        # Close all CimSessions
        foreach ($session in $ServerSessions.Values) {
            if ($session) { Remove-CimSession -CimSession $session }
        }
    }
}
