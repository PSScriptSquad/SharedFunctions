class IPEndPoint : System.Net.IPEndPoint {
    <#
    .SYNOPSIS
        Adds Parse/TryParse helpers to System.Net.IPEndPoint for PS 5.1.        
    .DESCRIPTION
        Provides overloads mirroring .NET 8's API so scripts run unchanged
        on Windows PowerShell 5.1 and PowerShell 7+.
        
        This enhanced version includes additional functionality:
        - Parse/TryParse methods supporting IP-endpoint and hostname-endpoint formats
        - Validation helpers for port numbers
        - Performance optimization via thread-safe caching
        - Proper equality and hash code implementations for use as dictionary keys
        - Built-in self-test capabilities        
    .EXAMPLE
        # Parse an IPv4 endpoint
        $endpoint = [IPEndPoint]::Parse("192.168.1.100:8080")        
    .EXAMPLE
        # Try to parse an IPv6 endpoint
        $ep = $null
        if ([IPEndPoint]::TryParse("2001:db8::1:443", [ref]$ep)) {
            "Successfully parsed: $($ep)"
        }        
    .EXAMPLE
        # Parse with hostname resolution
        $serverEndpoint = [IPEndPoint]::ParseWithHostname("localhost:8080")
    #>
    
    # Thread-safe cache for frequently parsed values
    static hidden [System.Collections.Concurrent.ConcurrentDictionary[string,IPEndPoint]] $ParseCache = [System.Collections.Concurrent.ConcurrentDictionary[string,IPEndPoint]]::new()
    static hidden [int]$MaxCacheSize = 100
    
    # Constructors that pass through to base class
    IPEndPoint([long]$Address, [int]$Port) : base($Address, [uint16]$Port) {}
    IPEndPoint([System.Net.IPAddress]$Address, [int]$Port) : base($Address, [uint16]$Port) {}
    
    <#
    .SYNOPSIS
        Tries to parse a string into an IPEndPoint object.
    .PARAMETER Value
        String representation of an IP endpoint in format "ip:port" or "[ipv6]:port"
    .PARAMETER Result
        When this method returns, contains the IPEndPoint equivalent if parsing succeeded, or null if parsing failed.
    .RETURNS
        True if parsing succeeded; otherwise, false.
    #>
    static [bool] TryParse([string]$Value, [ref]$Result) {
        # Assume failure until proven otherwise
        $Result.Value = $null
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        
        # Add [] around bare IPv6 literals so System.Uri parses them
        if ($Value -notmatch '^\[.+\]:\d+$' -and $Value -match '^[0-9a-f:]+:\d+$') {
            $Value = "[{0}]" -f ($Value -replace ':(\d+)$', '') + ':' + ($Value -replace '^.+:(\d+)$', '$1')
        }
        
        try {
            $uri = [Uri]::new("tcp://$Value")
            
            # Parse IP address
            $ipAddress = $null
            if (-not [System.Net.IPAddress]::TryParse($uri.Host, [ref]$ipAddress)) { return $false }
            
            # Validate port - uri.Port returns -1 when port is 0 in the uri
            $port = if ($uri.Port -eq -1) {
                # Special case: Uri treats port 0 as -1
                if ($Value -match ':0$') { 0 } else { return $false }
            } else {
                $uri.Port
            }
            
            if (-not [IPEndPoint]::IsValidPort($port)) { return $false }
            
            $Result.Value = [IPEndPoint]::new($ipAddress, [uint16]$port)
            return $true
        }
        catch {
            return $false
        }
    }
    
    <#
    .SYNOPSIS
        Parses a string into an IPEndPoint object.
    .PARAMETER Value
        String representation of an IP endpoint in format "ip:port" or "[ipv6]:port"
    .RETURNS
        An IPEndPoint object if parsing succeeded.
    .THROWS
        System.FormatException: Thrown when the input string is not a valid IP endpoint format.
    #>
    static [IPEndPoint] Parse([string]$Value) {
        $ep = $null
        if ([IPEndPoint]::TryParse($Value, [ref]$ep)) { return $ep }
        throw [System.FormatException]::new("Invalid IP-endpoint string: '$Value'")
    }
    
    <#
    .SYNOPSIS
        Tries to parse a string with hostname into an IPEndPoint object.
    .PARAMETER Value
        String representation of an endpoint in format "hostname:port" or "ip:port"
    .PARAMETER Result
        When this method returns, contains the IPEndPoint equivalent if parsing succeeded, or null if parsing failed.
    .RETURNS
        True if parsing succeeded; otherwise, false.
    #>
    static [bool] TryParseWithHostname([string]$Value, [ref]$Result) {
        # Initialize Result to null
        $Result.Value = $null
        
        if ([string]::IsNullOrWhiteSpace($Value)) { return $false }
        
        try {
            # Check if it's already an IP endpoint first
            $tempResult = $null
            if ([IPEndPoint]::TryParse($Value, [ref]$tempResult)) {
                $Result.Value = $tempResult
                return $true
            }
            
            # Try to parse as hostname:port
            $lastColon = $Value.LastIndexOf(':')
            if ($lastColon -eq -1) { return $false }
            
            $hostname = $Value.Substring(0, $lastColon)
            $portStr = $Value.Substring($lastColon + 1)
            
            # Validate port
            if (-not [uint16]::TryParse($portStr, [ref]$null)) { 
                return $false 
            }
            $port = [uint16]::Parse($portStr)
            
            # Try to resolve hostname
            try {
                $addresses = [System.Net.Dns]::GetHostAddresses($hostname)
                if ($addresses.Count -eq 0) { return $false }
                
                $ip = $addresses[0]
                $Result.Value = [IPEndPoint]::new($ip, $port)
                return $true
            }
            catch {
                # Failed to resolve hostname
                return $false
            }
        }
        catch {
            return $false
        }
    }
    
    <#
    .SYNOPSIS
        Parses a string with hostname into an IPEndPoint object.
    .PARAMETER Value
        String representation of an endpoint in format "hostname:port" or "ip:port"
    .RETURNS
        An IPEndPoint object if parsing succeeded.
    .THROWS
        System.FormatException: Thrown when the input string is not a valid endpoint format.
        System.Net.Sockets.SocketException: Thrown when the hostname cannot be resolved.
    #>
    static [IPEndPoint] ParseWithHostname([string]$Value) {
        $ep = $null
        if ([IPEndPoint]::TryParseWithHostname($Value, [ref]$ep)) { return $ep }
        throw [System.FormatException]::new("Invalid endpoint string: '$Value'")
    }
    
    <#
    .SYNOPSIS
        Parses a string into an IPEndPoint object with caching for performance.
    .PARAMETER Value
        String representation of an IP endpoint
    .RETURNS
        An IPEndPoint object if parsing succeeded.
    .THROWS
        System.FormatException: Thrown when the input string is not a valid IP endpoint format.
    #>
    static [IPEndPoint] ParseCached([string]$Value) {
        return [IPEndPoint]::ParseCache.GetOrAdd($Value, {
            param($key)
            return [IPEndPoint]::Parse($key)
        })
    }
    
    <#
    .SYNOPSIS
        Checks if a port number is valid.
    .PARAMETER Port
        The port number to validate.
    .RETURNS
        True if the port is valid (0-65535); otherwise, false.
    #>
    static [bool] IsValidPort([int]$Port) {
        return $Port -ge 0 -and $Port -le 65535
    }
    
    <#
    .SYNOPSIS
        Creates a new IPEndPoint from separate IP/hostname and port values.
    .PARAMETER Host
        IP address or hostname as string
    .PARAMETER Port
        Port number
    .RETURNS
        A new IPEndPoint instance
    .THROWS
        System.Net.Sockets.SocketException: Thrown when the hostname cannot be resolved.
        System.ArgumentOutOfRangeException: Thrown when the port is invalid.
    #>
    static [IPEndPoint] FromHostAndPort([string]$Host, [int]$Port) {
        if (-not [IPEndPoint]::IsValidPort($Port)) {
            throw [System.ArgumentOutOfRangeException]::new("Port", "Port must be between 0 and 65535")
        }
        
        $ipAddress = $null
        if ([System.Net.IPAddress]::TryParse($Host, [ref]$ipAddress)) {
            return [IPEndPoint]::new($ipAddress, $Port)
        }
        
        try {
            $ipAddress = [System.Net.Dns]::GetHostAddresses($Host)[0]
            return [IPEndPoint]::new($ipAddress, $Port)
        }
        catch {
            throw [System.Net.Sockets.SocketException]::new("Cannot resolve hostname: $Host")
        }
    }
    
    <#
    .SYNOPSIS
        Returns a string representation of this IPEndPoint.
    .RETURNS
        A string in the format "address:port" or "[address]:port" for IPv6.
    #>
    [string] ToString() {
        if ($this.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetworkV6) {
            return "[$($this.Address)]:$($this.Port)"
        }
        return "$($this.Address):$($this.Port)"
    }
    
    <#
    .SYNOPSIS
        Determines whether the specified object is equal to the current IPEndPoint.
    .PARAMETER obj
        The object to compare with the current IPEndPoint.
    .RETURNS
        True if the specified object is equal to the current IPEndPoint; otherwise, false.
    #>
    [bool] Equals([object]$obj) {
        if ($null -eq $obj -or -not ($obj -is [System.Net.IPEndPoint])) {
            return $false
        }
        
        $other = $obj -as [System.Net.IPEndPoint]
        return ($this.Address.Equals($other.Address)) -and ($this.Port -eq $other.Port)
    }
    
    <#
    .SYNOPSIS
        Returns the hash code for this IPEndPoint.
    .RETURNS
        A hash code for the current IPEndPoint.
    #>
    [int] GetHashCode() {
        return $this.Address.GetHashCode() -bxor $this.Port
    }
    
    <#
    .SYNOPSIS
        Runs self-tests on the IPEndPoint parsing functionality.
    .DESCRIPTION
        Tests various input formats to verify the parsing logic works correctly.
    .RETURNS
        None. Results are written to the host.
    #>
    static [void] RunSelfTest() {
        $testCases = @(
            @{ Input = "127.0.0.1:80"; Method = "TryParse"; ShouldSucceed = $true },
            @{ Input = "[::1]:443"; Method = "TryParse"; ShouldSucceed = $true },
            @{ Input = "2001:db8::1:8080"; Method = "TryParse"; ShouldSucceed = $true },
            @{ Input = "192.168.1.1:0"; Method = "TryParse"; ShouldSucceed = $true },
            @{ Input = "192.168.1.1:65535"; Method = "TryParse"; ShouldSucceed = $true },
            @{ Input = "invalid:123"; Method = "TryParse"; ShouldSucceed = $false },
            @{ Input = "127.0.0.1:99999"; Method = "TryParse"; ShouldSucceed = $false },
            @{ Input = "127.0.0.1"; Method = "TryParse"; ShouldSucceed = $false },
            @{ Input = "localhost:8080"; Method = "TryParseWithHostname"; ShouldSucceed = $true },
            @{ Input = "localhost:0"; Method = "TryParseWithHostname"; ShouldSucceed = $true },
            @{ Input = "127.0.0.1:8080"; Method = "TryParseWithHostname"; ShouldSucceed = $true },
            @{ Input = "nonexistent.domain:80"; Method = "TryParseWithHostname"; ShouldSucceed = $false }
        )
        
        $totalTests = $testCases.Count
        $passedTests = 0
        
        Write-Host "Running IPEndPoint Self-Test..."
        Write-Host "----------------------------------------"
        
        foreach ($test in $testCases) {
            $ep = $null
            $result = $false
            
            switch ($test.Method) {
                "TryParse" { $result = [IPEndPoint]::TryParse($test.Input, [ref]$ep) }
                "TryParseWithHostname" { $result = [IPEndPoint]::TryParseWithHostname($test.Input, [ref]$ep) }
                default { Write-Host "Unknown test method: $($test.Method)" }
            }
            
            $status = if ($result -eq $test.ShouldSucceed) { 
                $passedTests++
                "PASS" 
            } else { 
                "FAIL" 
            }
            
            $details = if ($result) { "-> $($ep)" } else { "" }
            Write-Host "$status - $($test.Method) '$($test.Input)' - Expected: $($test.ShouldSucceed), Got: $result $details"
        }
        
        Write-Host "----------------------------------------"
        Write-Host "Tests completed: $passedTests/$totalTests passed"
        
        # Test IsValidPort
        Write-Host "`nTesting IsValidPort:"
        @(
            @{ Port = -1; Expected = $false },
            @{ Port = 0; Expected = $true },
            @{ Port = 80; Expected = $true },
            @{ Port = 65535; Expected = $true },
            @{ Port = 65536; Expected = $false }
        ) | ForEach-Object {
            $result = [IPEndPoint]::IsValidPort($_.Port)
            $status = if ($result -eq $_.Expected) { "PASS" } else { "FAIL" }
            Write-Host "$status - IsValidPort($($_.Port)) - Expected: $($_.Expected), Got: $result"
        }
        
        # Test caching
        Write-Host "`nTesting ParseCached:"
        $testValue = "127.0.0.1:8080"
        [IPEndPoint]::ParseCached($testValue) | Out-Null
        $isCached = [IPEndPoint]::ParseCache.ContainsKey($testValue)
        Write-Host "Cache test: $(if ($isCached) { 'PASS' } else { 'FAIL' }) - Value should be cached: $isCached"
        
        # Test equality and hash code
        Write-Host "`nTesting Equals and GetHashCode:"
        $ep1 = [IPEndPoint]::Parse("127.0.0.1:80")
        $ep2 = [IPEndPoint]::Parse("127.0.0.1:80")
        $ep3 = [IPEndPoint]::Parse("127.0.0.1:81")
        
        $equalityTest = $ep1.Equals($ep2)
        Write-Host "Equality test (same values): $(if ($equalityTest) { 'PASS' } else { 'FAIL' }) - Equal: $equalityTest"
        
        $inequalityTest = -not $ep1.Equals($ep3)
        Write-Host "Inequality test (different ports): $(if ($inequalityTest) { 'PASS' } else { 'FAIL' }) - Not equal: $inequalityTest"
        
        $hashEqual = $ep1.GetHashCode() -eq $ep2.GetHashCode()
        Write-Host "Hash equality test: $(if ($hashEqual) { 'PASS' } else { 'FAIL' }) - Hash codes equal: $hashEqual"
        
        # Dictionary key test
        $dict = @{}
        $dict[$ep1] = "Test Value"
        $keyTest = $dict.ContainsKey($ep2) -and $dict[$ep2] -eq "Test Value"
        Write-Host "Dictionary key test: $(if ($keyTest) { 'PASS' } else { 'FAIL' }) - Can use as dictionary key: $keyTest"
    }
}
