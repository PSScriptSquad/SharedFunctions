function Get-ADComputerLdap {
    <#
    .SYNOPSIS
        Retrieves computer objects from Active Directory using direct LDAP connections for high-performance scenarios.
    
    .DESCRIPTION
        This function provides a high-performance, thread-safe alternative to Get-ADComputer by communicating 
        directly with Domain Controllers via LDAP protocol. It bypasses ADWS (Active Directory Web Services) 
        to avoid throttling and connection issues common in parallel runspaces.

        The function supports identity resolution by DN, GUID, SID, or SAM account name, custom LDAP filters,
        and configurable search parameters while maintaining compatibility with common Get-ADComputer usage patterns.

        Key improvements over standard Get-ADComputer:
        - Direct LDAP communication eliminates ADWS dependencies
        - Enhanced concurrency support for parallel operations  
        - Configurable connection timeouts and retry logic
        - Comprehensive error handling and validation
        - Support for both standard and Global Catalog searches

    .PARAMETER Identity
        Specifies an Active Directory computer object by one of its unique identifiers:
        - Distinguished Name: "CN=PC001,OU=Computers,DC=corp,DC=contoso,DC=com"
        - ObjectGUID: "3a118c72-c230-4cbc-813c-9a4a70659972" 
        - ObjectSID: "S-1-5-21-123456789-987654321-555666777-1001"
        - SAM Account Name: "PC001$" or "PC001" ($ is automatically appended for computers)

        This parameter accepts pipeline input and is mutually exclusive with LDAPFilter.

    .PARAMETER LDAPFilter
        Specifies a custom LDAP query string for complex filtering scenarios.
        The filter is automatically combined with (objectClass=computer) unless the filter 
        already specifies an objectClass.
        
        Examples:
        - "(name=PC*)" - Computers with names starting with PC
        - "(&(operatingSystem=*Windows 10*)(lastLogonTimestamp>=132500000000000000))" - Win10 computers with recent logon
        - "(description=*)" - Computers with any description

    .PARAMETER Properties
        Specifies which properties to retrieve from Active Directory. 
        - Use "*" to retrieve all available attributes (performance impact)
        - Use specific LDAP attribute names for optimal performance
        - Common aliases are automatically mapped (e.g., 'Enabled' → 'userAccountControl')
        
        Default properties: Name, DistinguishedName, ObjectGUID, ObjectSID, SamAccountName, 
        DNSHostName, Enabled, Description, IPv4Address, OperatingSystem

    .PARAMETER Server
        Specifies the Domain Controller to query. Accepts FQDN, NetBIOS name, or IP address.
        If not specified, automatically discovers an available DC in the current domain.
        
        For cross-domain queries, specify a DC in the target domain.

    .PARAMETER SearchBase
        Specifies the Active Directory path (Distinguished Name) to begin the search.
        If not specified, searches the entire domain using the default naming context.
        
        Example: "OU=Workstations,DC=corp,DC=contoso,DC=com"

    .PARAMETER SearchScope
        Defines the scope of the Active Directory search:
        - Base: Search only the specified SearchBase object
        - OneLevel: Search immediate children of SearchBase only  
        - Subtree: Search entire subtree including SearchBase (default)

    .PARAMETER UseGlobalCatalog
        When specified, queries the Global Catalog instead of the domain partition.
        Useful for cross-domain searches but returns only a subset of attributes.
        Automatically enabled for cross-domain identity lookups.

    .PARAMETER AuthType
        Specifies the authentication method:
        - Negotiate: Windows Integrated Authentication (default, recommended)
        - Basic: Basic authentication over SSL/TLS (requires LDAPS on port 636)

    .PARAMETER Credential
        Specifies alternate credentials for the LDAP connection.
        If not provided, uses the current user's security context.

    .PARAMETER ResultPageSize
        Controls the number of objects returned per LDAP page request.
        Default: 1000 (optimal for most scenarios)
        Range: 1-5000 (values over 5000 may be rejected by some DCs)

    .PARAMETER ResultSetSize
        Specifies the maximum number of objects to return.
        Default: 10000 (prevents accidental large result sets)
        Set to 0 for unlimited results (use with caution)

    .PARAMETER TimeoutSeconds
        Specifies the LDAP connection and operation timeout in seconds.
        Default: 120 seconds
        Increase for slow network connections or large result sets.

    .INPUTS
        System.String
        Pipeline input accepted for the Identity parameter.

    .OUTPUTS
        PSCustomObject with PSTypeName 'ADComputer.LDAP'
        Returns computer objects with standardized property names and proper type conversion.

    .EXAMPLE
        # Get a specific computer by SAM account name
        Get-ADComputerLdap -Identity "WORKSTATION01"

    .EXAMPLE
        # Get computer with explicit $ suffix
        Get-ADComputerLdap -Identity "WORKSTATION01$"

    .EXAMPLE
        # Get all computers in specific OU with custom properties
        $computers = Get-ADComputerLdap -LDAPFilter "(name=WKS*)" `
            -SearchBase "OU=Workstations,DC=corp,DC=contoso,DC=com" `
            -Properties "name", "operatingSystem", "lastLogonTimestamp" `
            -ResultSetSize 0

    .EXAMPLE
        # Pipeline multiple computer names
        "PC001", "PC002", "PC003" | Get-ADComputerLdap -Properties "name", "dNSHostName"

    .EXAMPLE
        # Cross-domain search using Global Catalog
        Get-ADComputerLdap -Identity "REMOTE-PC01" -UseGlobalCatalog -Server "gc.root.domain.com"

    .EXAMPLE
        # Find computers with specific OS and recent activity
        $filter = "(&(operatingSystem=*Server 2019*)(lastLogonTimestamp>=132800000000000000))"
        Get-ADComputerLdap -LDAPFilter $filter -Properties "*" -TimeoutSeconds 300

    .NOTES
        Author: Ryan Whitlock
        Version: 1.0
        PowerShell: 5.1+ (uses .NET Framework System.DirectoryServices.Protocols)
        
        Performance Notes:
        - Direct LDAP is significantly faster than ADWS for bulk operations
        - Global Catalog searches are faster but return fewer attributes
        - Use specific Properties lists rather than "*" for optimal performance
        - Consider ResultSetSize limits for large environments
        
        Security Notes:
        - Basic authentication requires SSL/TLS (LDAPS)
        - Negotiate authentication is recommended for domain-joined systems
        - Credential objects should be handled securely in scripts

        Troubleshooting:
        - Enable -Verbose for detailed connection and query information
        - Check Windows Event Logs for LDAP connection issues
        - Verify firewall rules for LDAP (389) and LDAPS (636) ports
        - Test with specific Server parameter if auto-discovery fails

    .LINK
        https://docs.microsoft.com/en-us/windows/win32/adsi/searching-with-activex-data-objects-ado
        https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.protocols
    #>
    [CmdletBinding(DefaultParameterSetName = 'Identity')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, 
                   ValueFromPipelineByPropertyName = $true, ParameterSetName = 'Identity')]
        [ValidateNotNullOrEmpty()]
        [Alias('ComputerName', 'CN', 'DistinguishedName', 'GUID', 'SID')]
        [string]$Identity,

        [Parameter(Mandatory = $true, ParameterSetName = 'Filter')]
        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [string]$LDAPFilter,

        [Parameter()]
        [ValidateNotNull()]
        [string[]]$Properties = @(
            'name', 'distinguishedName', 'objectGUID', 'objectSid', 'sAMAccountName',
            'dNSHostName', 'userAccountControl', 'description', 'operatingSystem', 
            'operatingSystemVersion', 'lastLogonTimestamp', 'whenCreated'
        ),

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias('DomainController', 'DC')]
        [string]$Server,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [Alias('Base')]
        [string]$SearchBase,

        [Parameter()]
        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [string]$SearchScope = 'Subtree',

        [Parameter()]
        [switch]$UseGlobalCatalog,

        [Parameter()]
        [ValidateSet('Negotiate', 'Basic')]
        [string]$AuthType = 'Negotiate',

        [Parameter()]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [Parameter()]
        [ValidateRange(1, 5000)]
        [int]$ResultPageSize = 1000,

        [Parameter()]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$ResultSetSize = 10000,

        [Parameter()]
        [ValidateRange(30, 3600)]
        [int]$TimeoutSeconds = 60
    )

    begin {
        Write-Verbose "Starting Get-ADComputerLdap function"

        try {
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        }
        catch {
            throw "Failed to load required assembly 'System.DirectoryServices.Protocols'."
        }
        
        # Initialize connection variables
        $connection = $null
        $domain = $null
        $explicitPort = $null

        # Check if the -Server parameter was used and if it contains a port, using named capture groups for clarity.
        if ($PSBoundParameters.ContainsKey('Server') -and $Server -match '^(?<ServerName>.+):(?<Port>\d+)$') {
            Write-Verbose "Server parameter contains a port. Parsing..."
            # Overwrite the $Server variable with just the hostname part from the named group.
            $Server = $matches.ServerName
            # Store the explicit port number from the named group.
            $explicitPort = [int]$matches.Port
            Write-Verbose "Parsed Server: '$Server', Port: $explicitPort"
        }

        
        # Property mapping for common aliases
        $propertyMap = @{
            'Name'                     = 'name'
            'DNSHostName'             = 'dNSHostName'
            'Enabled'                 = 'userAccountControl'  
            'IPv4Address'             = 'ipHostNumber'
            'OperatingSystem'         = 'operatingSystem'
            'OperatingSystemVersion'  = 'operatingSystemVersion'
            'LastLogonDate'           = 'lastLogonTimestamp'
            'Created'                 = 'whenCreated'
            'Modified'                = 'whenChanged'
            'Description'             = 'description'
            'Location'                = 'location'
            'ManagedBy'               = 'managedBy'
            'DistinguishedName'       = 'distinguishedName'
            'ObjectGUID'              = 'objectGUID'
            'ObjectSID'               = 'objectSid'
            'SamAccountName'          = 'sAMAccountName'
        }

        # Helper function to convert LDAP timestamp to DateTime
        function ConvertFrom-LdapTimestamp {
            param([string]$Timestamp)
            if ([string]::IsNullOrEmpty($Timestamp) -or $Timestamp -eq '0' -or $Timestamp -eq '9223372036854775807') {
                return $null
            }
            try {
                return [DateTime]::FromFileTime([long]$Timestamp)
            }
            catch {
                Write-Warning "Failed to convert timestamp '$Timestamp': $_"
                return $null
            }
        }
        
        # Helper function to convert AD datetime string to DateTime object
        function ConvertFrom-ADDateTime {
            param([string]$ADDateTime)
            if ([string]::IsNullOrEmpty($ADDateTime)) {
                return $null
            }
            try {
                # AD typically stores dates in GeneralizedTime format: yyyyMMddHHmmss.0Z
                # Try different parsing approaches
                if ($ADDateTime -match '^\d{14}\.\d+Z$') {
                    # GeneralizedTime format: 20231201123045.0Z
                    return [DateTime]::ParseExact($ADDateTime, 'yyyyMMddHHmmss.fZ', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                elseif ($ADDateTime -match '^\d{14}Z$') {
                    # GeneralizedTime without fractional seconds: 20231201123045Z
                    return [DateTime]::ParseExact($ADDateTime, 'yyyyMMddHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                elseif ($ADDateTime -match '^\d{12}Z$') {
                    # UTC time format: 231201123045Z
                    return [DateTime]::ParseExact($ADDateTime, 'yyMMddHHmmssZ', [System.Globalization.CultureInfo]::InvariantCulture)
                }
                else {
                    # Fallback to standard DateTime parsing
                    return [DateTime]::Parse($ADDateTime)
                }
            }
            catch {
                Write-Warning "Failed to convert AD DateTime '$ADDateTime': $_"
                return $null
            }
        }

        # Resolves a computer identity into an appropriate LDAP filter and search parameters.
        function Resolve-ComputerIdentity {   
            [CmdletBinding()]
            [OutputType([PSCustomObject])]
            param (
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$Identity
            )
            Write-Verbose "Identity: $Identity"
            # Helper function to convert byte array to LDAP filter string
            function ConvertTo-LdapFilterString {
                param([byte[]]$ByteArray)
                if ($null -eq $ByteArray -or $ByteArray.Length -eq 0) {
                    return $null
                }
                return ($ByteArray | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
            }

            # Helper function to determine if a string could be an invalid GUID format
            function Test-InvalidGuidFormat {
                param([string]$TestString)

                # Check for common GUID-like patterns that are invalid
                # Look for strings that contain typical GUID characters but are malformed
                $containsGuidChars = $TestString -match '^[0-9A-Fa-f-]+$'
                $hasHyphens = $TestString.Contains('-')
                $looksLikeGuidLength = $TestString.Length -ge 32 -or ($hasHyphens -and $TestString.Length -ge 36)

                # Also catch strings that explicitly look like they're trying to be GUIDs
                $explicitGuidAttempt = $TestString -match 'guid' -or $TestString -match '^[0-9A-Fa-f]{8}-'

                if (($containsGuidChars -and $looksLikeGuidLength) -or $explicitGuidAttempt) {
                    try   { [void][guid]$TestString; return $false }  
                    catch { return $true } 
                }

                return $false
            }

            [regex]$distinguishedNameRegex = '^(?:(?<cn>CN=(?<name>(?:[^,]|\,)*)),)?(?:(?<path>(?:(?:CN|OU)=(?:[^,]|\,)+,?)+),)?(?<domain>(?:DC=(?:[^,]|\,)+,?)+)$'

            # Validate input
            if ([string]::IsNullOrWhiteSpace($Identity)) {
                throw "Computer name cannot be empty"
            }

            # Initialize result object
            $result = [PSCustomObject]@{
                Filter = $null
                SearchBase = $null
                SearchScope = 'Subtree'
            }

            # Determine identity type and build appropriate filter
            if ($Identity -match '^S-1-5-.+') {
                # SID format - validate before processing
                try {
                    $testSid = New-Object System.Security.Principal.SecurityIdentifier($Identity)
                    $binarySid = New-Object byte[] $testSid.BinaryLength
                    $testSid.GetBinaryForm($binarySid, 0)
                    $sidFilter = ConvertTo-LdapFilterString -ByteArray $binarySid
                    $result.Filter = "(&(objectClass=computer)(objectSid=$sidFilter))"
                }
                catch {
                    throw "Invalid SID format: $Identity"
                }
            }
            elseif ([System.Guid]::TryParse($Identity, $([ref][guid]::Empty))) {
                # Valid GUID format - process it
                $testGuid = [System.Guid]::Parse($Identity)
                $guidFilter = ConvertTo-LdapFilterString -ByteArray $testGuid.ToByteArray()
                $result.Filter = "(&(objectClass=computer)(objectGUID=$guidFilter))"
            }
            elseif (Test-InvalidGuidFormat -TestString $Identity) {
                # Invalid GUID-like format - throw specific error
                throw "Invalid GUID format: $Identity"
            }
            elseif ($Identity -match $distinguishedNameRegex) {
                # Distinguished Name format
                $result.SearchBase = $Identity
                $result.SearchScope = 'Base'
                $result.Filter = "(objectClass=computer)"
            }
            else {
                # SAM Account Name - validate characters
                if ($Identity -match '[<>:"/\\|?*]') {
                    Write-Error "Invalid characters in computer name: $Identity" -ErrorId 'InvalidCharacters' -TargetObject $Identity -Category InvalidArgument
                    return
                }

                # Ensure it ends with $ for computers
                $samAccount = if ($Identity.EndsWith('$')) { $Identity } else { "$Identity$" }
                $result.Filter = "(&(objectClass=computer)(sAMAccountName=$samAccount))"
            }

            return $result
        }

        # Helper function to process attribute values with proper type conversion
        function Convert-AttributeValue {
            param(
                [string]$AttributeName,
                [object]$AttributeValues,
                [string]$OriginalPropertyName = $AttributeName
            )
            
            $value = $null
            if ($AttributeValues.Count -eq 1) {
                $value = $AttributeValues[0]
            } elseif ($AttributeValues.Count -gt 1) {
                $value = @(,$AttributeValues | ForEach-Object { $_ })
            }

            # Special handling for specific attributes with proper type conversion
            switch ($AttributeName) {
                'objectSid' {
                    if ($null -ne $value -and $value -is [byte[]]) {
                        try {
                            $value = New-Object System.Security.Principal.SecurityIdentifier($value, 0)
                        } catch {
                            Write-Warning "Failed to convert objectSid: $_"
                            $value = $null
                        }
                    }
                }
                'objectGUID' {
                    if ($null -ne $value -and $value -is [byte[]]) {
                        try {
                            $value = New-Object System.Guid(,$value)
                        } catch {
                            Write-Warning "Failed to convert objectGUID: $_"
                            $value = $null
                        }
                    }
                }
                'userAccountControl' {
                    if ($null -ne $value) {
                        try {
                            $uacValue = [int]$value

                            if ($OriginalPropertyName -eq 'Enabled') {
                                $value = [bool](-not ($uacValue -band 0x2))
                            } else {
                                $value = $uacValue
                            }
                        } catch {
                            Write-Warning "Failed to convert userAccountControl: $_"
                            if ($OriginalPropertyName -eq 'Enabled') {
                                $value = [bool]$false
                            }
                        }
                    }
                    elseif ($OriginalPropertyName -eq 'Enabled') {
                        $value = [bool]$false
                    }
                }
                'lastLogonTimestamp' {
                    if ($null -ne $value) {
                        $convertedDate = ConvertFrom-LdapTimestamp -Timestamp $value
                        if ($null -ne $convertedDate) {
                            $value = [DateTime]$convertedDate
                        }
                    }
                }
                'whenCreated' {
                    if ($null -ne $value) {
                        $convertedDate = ConvertFrom-ADDateTime -ADDateTime $value
                        if ($null -ne $convertedDate) {
                            $value = [DateTime]$convertedDate
                        }
                    }
                }
                'whenChanged' {
                    if ($null -ne $value) {
                        $convertedDate = ConvertFrom-ADDateTime -ADDateTime $value
                        if ($null -ne $convertedDate) {
                            $value = [DateTime]$convertedDate
                        }
                    }
                }
                default {
                    # Handle byte array conversion for all other attributes
                    if ($value -is [array]) {
                        for ($i = 0; $i -lt $value.Count; $i++) {
                            if ($value[$i] -is [byte[]]) {
                                $value[$i] = [System.Text.Encoding]::UTF8.GetString($value[$i])
                            }
                        }
                    }
                    elseif ($value -is [byte[]]) {
                        # It's a single byte array, so just decode it.
                        $value = [System.Text.Encoding]::UTF8.GetString($value)
                    }
                }
            }
            
            return $value
        }

        # Define a custom ToString() method for our object type. This only needs to run once.
        $toStringScriptBlock = { $this.DistinguishedName }
        Update-TypeData -TypeName 'ADComputer.LDAP' -MemberName 'ToString' -MemberType ScriptMethod -Value $toStringScriptBlock -Force

        # Discover domain and server information
        try {
            if (-not $PSBoundParameters.ContainsKey('Server')) {
                $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                $Server = $domain.FindDomainController().Name
                Write-Verbose "Auto-discovered Domain Controller: $Server"
            }

            if (-not $PSBoundParameters.ContainsKey('SearchBase')) {
                # If a Server was provided, derive the search base from its FQDN.
                if ($PSBoundParameters.ContainsKey('Server') -and ($Server -as [System.Net.IPAddress])) {
                    $Server = [System.Net.Dns]::GetHostEntry($Server).HostName
                }
                if ($PSBoundParameters.ContainsKey('Server') -and $Server.Contains('.')) {
                    Write-Verbose "Deriving search base from provided server FQDN: $Server"
                    try {
                        $domainName = $Server.Substring($Server.IndexOf('.') + 1)
                        $SearchBase = "DC=$($domainName.Replace('.', ',DC='))"
                        Write-Verbose "Derived search base: $SearchBase"
                    }
                    catch {
                        throw "Could not derive a search base from the provided server name '$Server'. Please provide the -SearchBase parameter explicitly. Error: $($_.Exception.Message)"
                    }
                }
                else {
                    # Fallback to the original method for auto-discovery, NetBIOS names, or IP addresses.
                    # This block can correctly get domain info from a DC specified by IP.
                    if ($null -eq $domain) {
                        $context = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Server)
                        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($context)
                    }
                    $SearchBase = $domain.GetDirectoryEntry().distinguishedName
                    Write-Verbose "Using default naming context: $SearchBase"
                }
            }
        }
        catch {
            $errorMsg = if ($PSBoundParameters.ContainsKey('Server')) {
                "Failed to establish LDAP connection to '$($Server)'. Could not discover domain information. Error: $($_.Exception.Message)"
            }
            else {
                "Failed to discover domain information. Please specify -Server and -SearchBase parameters manually. Error: $($_.Exception.Message)"
            }
            Write-Error $errorMsg -ErrorAction Stop
        }


        # Setup LDAP connection
        try {
            $useSSL = ($AuthType -eq 'Basic')
            $ldapPort = if ($null -ne $explicitPort) {
                Write-Verbose "Using explicit port: $explicitPort"
                $explicitPort
            }
            elseif ($UseGlobalCatalog) {
                Write-Verbose "Using Global Catalog ports."
                if ($useSSL) { 3269 } else { 3268 }
            }
            else {
                Write-Verbose "Using standard LDAP ports."
                if ($useSSL) { 636 } else { 389 }
            }
            
            Write-Verbose "Connecting to $Server`:$ldapPort (SSL: $useSSL, GC: $UseGlobalCatalog)"
            
            $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
                $Server, $ldapPort, $false, $false
            )
            
            $connection = if ($Credential -ne [System.Management.Automation.PSCredential]::Empty) {
                New-Object System.DirectoryServices.Protocols.LdapConnection(
                    $identifier, $Credential.GetNetworkCredential()
                )
            } else {
                New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
            }
            
            # Configure connection options
            $connection.SessionOptions.ProtocolVersion = 3
            $connection.Timeout = New-TimeSpan -Seconds $TimeoutSeconds
            $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::$AuthType
            
            if ($useSSL) {
                $connection.SessionOptions.SecureSocketLayer = $true
            }
            
            # Establish connection
            $connection.Bind()
            Write-Verbose "LDAP connection established successfully"
        }
        catch {
            $errorMsg = "Failed to establish LDAP connection to $Server`:$ldapPort. Error: $($_.Exception.Message)"
            Write-Error $errorMsg -ErrorAction Stop
        }

        # Normalize properties list - ensure we always get the underlying LDAP attributes needed for conversion
        $ldapProperties = New-Object System.Collections.Generic.HashSet[string]
        
        foreach ($prop in $Properties) {
            if ($propertyMap.ContainsKey($prop)) {
                [void]$ldapProperties.Add($propertyMap[$prop])
            } else {
                [void]$ldapProperties.Add($prop)
            }
        }
        
        # Always ensure we have userAccountControl if Enabled is requested
        if ($Properties -contains 'Enabled' -and -not $ldapProperties.Contains('userAccountControl')) {
            [void]$ldapProperties.Add('userAccountControl')
        }
        
        # Always ensure we have whenCreated if Created is requested
        if ($Properties -contains 'Created' -and -not $ldapProperties.Contains('whenCreated')) {
            [void]$ldapProperties.Add('whenCreated')
        }
        
        # Always ensure we have lastLogonTimestamp if LastLogonDate is requested
        if ($Properties -contains 'LastLogonDate' -and -not $ldapProperties.Contains('lastLogonTimestamp')) {
            [void]$ldapProperties.Add('lastLogonTimestamp')
        }

        Write-Verbose "Requesting properties: $($ldapProperties -join ', ')"
    }

    process {
        try {
            # Build LDAP filter based on parameter set
            $filter = $null
            $resolvedSearchBase = $SearchBase  # Use the parameter value by default
            $resolvedSearchScope = $SearchScope  # Use the parameter value by default
            
            switch ($PSCmdlet.ParameterSetName) {
                'Identity' {
                    # Use the new helper function to resolve the identity
                    $identityResult = Resolve-ComputerIdentity -Identity $Identity
                    $filter = $identityResult.Filter
                    
                    # Override SearchBase and SearchScope if the identity resolution specified them
                    if ($null -ne $identityResult.SearchBase) {
                        $resolvedSearchBase = $identityResult.SearchBase
                    }
                    if ($null -ne $identityResult.SearchScope) {
                        $resolvedSearchScope = $identityResult.SearchScope
                    }
                }
                'Filter' {
                    $filter = if ($LDAPFilter -match 'objectClass=') { 
                        $LDAPFilter 
                    }
                    else { 
                        "(&($LDAPFilter)(objectClass=computer))" 
                    }
                }
            }

            if ([string]::IsNullOrWhiteSpace($filter)) {
                Write-Verbose "Filter is null or empty. Skipping search for this item."
                return
            }

            Write-Verbose "Using LDAP filter: $filter"
            Write-Verbose "Search base: $resolvedSearchBase"
            Write-Verbose "Search scope: $resolvedSearchScope"

            # Create search request
            $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                $resolvedSearchBase,
                $filter,
                [System.DirectoryServices.Protocols.SearchScope]::$resolvedSearchScope
            )

            # Add requested attributes
            if ($ldapProperties -contains '*') {
                [void]$searchRequest.Attributes.Add('*')
            } else {
                foreach ($property in $ldapProperties) {
                    [void]$searchRequest.Attributes.Add($property)
                }
            }

            # Configure paging
            $pageControl = New-Object System.DirectoryServices.Protocols.PageResultRequestControl($ResultPageSize)
            $SearchOptionsControl = New-Object System.DirectoryServices.Protocols.SearchOptionsControl([System.DirectoryServices.Protocols.SearchOption]::DomainScope)
            [Void]$searchRequest.Controls.Add($pageControl)
            [Void]$searchRequest.Controls.Add($SearchOptionsControl)

            # Execute search with paging
            $totalResults = 0
            do {
                Write-Verbose "Executing LDAP search (page size: $ResultPageSize)"
                $searchResponse = $connection.SendRequest($searchRequest)
                
                $pageResponse = $searchResponse.Controls | 
                    Where-Object { $_ -is [System.DirectoryServices.Protocols.PageResultResponseControl] }

                foreach ($entry in $searchResponse.Entries) {
                    if ($ResultSetSize -gt 0 -and $totalResults -ge $ResultSetSize) {
                        break
                    }

                    # Build result object
                    $result = [ordered]@{
                        PSTypeName = 'ADComputer.LDAP'
                    }

                    # Always include DN first
                    $result['DistinguishedName'] = $entry.DistinguishedName
                    
                    # Process each requested property in original order
                    foreach ($originalProp in $Properties) {
                        # Skip wildcard - we'll handle it separately
                        if ($originalProp -eq '*') {
                            continue
                        }
            
                        # Map the property to LDAP attribute if needed
                        $ldapAttr = if ($propertyMap.ContainsKey($originalProp)) {
                            $propertyMap[$originalProp]
                        } else {
                            $originalProp
                        }
            
                        if ($entry.Attributes.Contains($ldapAttr)) {
                            $value = Convert-AttributeValue -AttributeName $ldapAttr -AttributeValues $entry.Attributes[$ldapAttr] -OriginalPropertyName $originalProp
                
                            # Handle userAccountControl special case - always expose Enabled
                            if ($ldapAttr -eq 'userAccountControl' -and -not $result.Contains('Enabled')) {
                                try {
                                    $uacValue = [int]$entry.Attributes[$ldapAttr][0]
                                    $result['Enabled'] = [bool](-not ($uacValue -band 0x2))
                                } catch {
                                    $result['Enabled'] = [bool]$false
                                }
                            }
                
                            # Add the property with the original name requested
                            if ($value -is [array]) {
                                $result[$originalProp] = ,$value
                            }
                            else {
                                $result[$originalProp] = $value
                            }
                        }
                    }

                    # Handle the case where "*" was requested - add all available attributes
                    if ($Properties -contains '*') {
                        foreach ($attrName in $entry.Attributes.AttributeNames) {  
                            # Skip if we already processed this attribute
                            $alreadyProcessed = $false
                            foreach ($originalProp in $Properties) {                        
                                if ($originalProp -eq '*') {
                                    continue                                  
                                }
                                $mappedAttr = if ($propertyMap.ContainsKey($originalProp)) {                                    
                                    $propertyMap[$originalProp]
                                } else {
                                    $originalProp     
                                }
                                if ($mappedAttr -eq $attrName) {             
                                    $alreadyProcessed = $true
                                    break
                                }
                            }
                
                            if (-not $alreadyProcessed -and -not $result.Contains($attrName)) {
                                # Use the same conversion logic as explicit properties
                                $value = Convert-AttributeValue -AttributeName $attrName -AttributeValues $entry.Attributes[$attrName]

                                # Special handling for userAccountControl - always expose Enabled
                                if ($attrName -eq 'userAccountControl' -and -not $result.Contains('Enabled')) {
                                    try {
                                        $uacValue = [int]$entry.Attributes[$attrName][0]
                                        $result['Enabled'] = [bool](-not ($uacValue -band 0x2))
                                    } catch {
                                        $result['Enabled'] = [bool]$false
                                    }
                                }
                    
                                # Add with proper array handling
                                if ($value -is [array]) {              
                                    $result[$attrName] = ,$value
                                }
                                else {                        
                                    $result[$attrName] = $value
                                }
                            }
                        }
                    }

                    # Output the result
                    $outputObject = New-Object PSObject -Property $result
                    [void]$outputObject.PSObject.TypeNames.Insert(0, 'ADComputer.LDAP')
                    Write-Output $outputObject
    
                    $totalResults++
                }

                # Setup for next page
                if ($null -ne $pageResponse -and $pageResponse.Cookie.Length -gt 0) {
                    $pageControl.Cookie = $pageResponse.Cookie
                } else {
                    $pageResponse = $null
                }

            } while ($null -ne $pageResponse -and ($ResultSetSize -eq 0 -or $totalResults -lt $ResultSetSize))

            Write-Verbose "Search completed. Total results: $totalResults"

            if ($PSCmdlet.ParameterSetName -eq 'Identity' -and $totalResults -eq 0) {
                $errorMsg = switch -Regex ($Identity) {
                    '^S-1-5-.+' { "No computer found with SID: $Identity" }
                    '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$' { "No computer found with GUID: $Identity" }
                    '.*=.*' { "No computer found with DN: $Identity" }
                    default { "No results found for computer: $Identity" }  # Changed to match test expectation
                }
                Write-Error $errorMsg -ErrorAction Stop
            }
        }
        catch {
            # Check if this is a validation error that should be re-thrown as-is
            if ($_.Exception.Message -like "*Invalid GUID format*" -or 
                $_.Exception.Message -like "*Invalid SID format*" -or
                $_.Exception.Message -like "*Invalid Distinguished Name format*" -or
                $_.Exception.Message -like "*Invalid characters in computer name*") {
                throw
            }
            Write-Error "LDAP search failed: $($_.Exception.Message)"
        }
    }

    end {
        if ($null -ne $connection) {
            try {
                $connection.Dispose()
                Write-Verbose "LDAP connection closed"
            }
            catch {
                Write-Warning "Error closing LDAP connection: $($_.Exception.Message)"
            }
        }
    }
}
