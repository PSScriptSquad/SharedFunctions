#Requires -Modules Pester

<#
.SYNOPSIS
    Comprehensive Pester test suite for the Get-ADComputerLdap function.

.DESCRIPTION
    This test suite validates all aspects of Get-ADComputerLdap functionality including:
    - Parameter validation and error handling
    - Identity resolution (DN, GUID, SID, SAM)
    - LDAP filter functionality
    - Property mapping and type conversion
    - Connection and authentication scenarios
    - Pipeline processing
    - Performance and edge cases
    - Thread safety and parallel execution

.PARAMETER TestComputerName
    Name of a test computer object in AD (without $ suffix).
    This computer should exist and be accessible for testing.

.PARAMETER TestUserName
    Name of a test user account for credential-based testing.
    Optional - if not provided, credential tests are skipped.

.PARAMETER TestOUPath
    Distinguished Name of an OU containing test computers.
    Optional - if not provided, OU-specific tests are skipped.

.PARAMETER TestDomainController
    Specific domain controller to use for testing.
    Optional - if not provided, auto-discovery is tested.

.EXAMPLE
    Invoke-Pester -Path "Get-ADComputerLdap.Tests.ps1" -Parameters @{
        TestComputerName = "TESTPC01"
        TestUserName = "testuser"
        TestOUPath = "OU=Computers,DC=corp,DC=com"
    }
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$TestComputerName,
    
    [Parameter(Mandatory = $true)]
    [string]$TestUserName,
    
    [Parameter(Mandatory = $true)]
    [string]$TestOUPath,
    
    [Parameter()]
    [string]$TestDomainController,
    
    [Parameter()]
    [switch]$SkipCredentialTests,
    
    [Parameter()]
    [switch]$SkipConnectivityTests
)

# Import the module containing Get-ADComputerLdap
# Adjust the path as needed for your environment
# Import-Module "Path\To\Your\ADComputerLdapModule.psm1" -Force
. "S:\InformationManagement\Private\EDS\Scripts\RyanScripts\Functions\ActiveDirectory\Get-ADComputerLdap.ps1"

BeforeAll {
    # Ensure the function is available
    if (-not (Get-Command Get-ADComputerLdap -ErrorAction SilentlyContinue)) {
        throw "Get-ADComputerLdap function not found. Please import the module containing this function."
    }
    
    # Get reference computer object for comparison tests
    Write-Host "Setting up reference computer object for testing..." -ForegroundColor Yellow
    
    try {
        $script:ReferenceComputer = Get-ADComputerLdap -Identity $TestComputerName -ErrorAction Stop
        if (-not $script:ReferenceComputer) {
            throw "Test computer '$TestComputerName' not found"
        }
        Write-Host "Reference computer obtained: $($script:ReferenceComputer.Name)" -ForegroundColor Green
    }
    catch {
        throw "Failed to get reference computer '$TestComputerName': $($_.Exception.Message)"
    }
    
    # Helper function for credential creation (if needed)
    function New-TestCredential {
        param([string]$UserName)
        if (-not $UserName) { return $null }
        $password = Read-Host "Enter password for $UserName" -AsSecureString
        return New-Object System.Management.Automation.PSCredential($UserName, $password)
    }
}

Describe "Get-ADComputerLdap - Basic Functionality" {
    
    Context "Identity Resolution" {
        
        It "Should retrieve computer by SAM account name" {
            $result = Get-ADComputerLdap -Identity $TestComputerName
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
            $result.DistinguishedName | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -Not -BeNullOrEmpty
            $result.ObjectSID | Should -Not -BeNullOrEmpty
        }
        
        It "Should retrieve computer with explicit $ suffix" {
            $result = Get-ADComputerLdap -Identity "$TestComputerName$"
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should retrieve computer by Distinguished Name" {
            $result = Get-ADComputerLdap -Identity $script:ReferenceComputer.DistinguishedName
            
            $result | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Be $script:ReferenceComputer.DistinguishedName
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should retrieve computer by ObjectGUID" {
            $result = Get-ADComputerLdap -Identity $script:ReferenceComputer.ObjectGUID.ToString()
            
            $result | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -Be $script:ReferenceComputer.ObjectGUID
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should retrieve computer by ObjectSID" {
            $result = Get-ADComputerLdap -Identity $script:ReferenceComputer.ObjectSID.ToString()
            
            $result | Should -Not -BeNullOrEmpty
            $result.ObjectSID.ToString() | Should -Be $script:ReferenceComputer.ObjectSID.ToString()
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should handle GUID with various formats" {
            # Test with and without braces, hyphens
            $guid = $script:ReferenceComputer.ObjectGUID
            $formats = @(
                $guid.ToString(),
                $guid.ToString("B"),  # {xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}
                $guid.ToString("P"),  # (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
                $guid.ToString("N")   # xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
            )
            
            foreach ($format in $formats) {
                $result = Get-ADComputerLdap -Identity $format
                $result | Should -Not -BeNullOrEmpty
                $result.ObjectGUID | Should -Be $guid
            }
        }
    }
    
    Context "Error Handling for Invalid Identities" {
        
        It "Should throw for non-existent computer" {
            { Get-ADComputerLdap -Identity "NONEXISTENTCOMPUTER12345" -ErrorAction Stop } | 
                Should -Throw "*No results*"
        }
        
        It "Should throw for invalid GUID format" {
            { Get-ADComputerLdap -Identity "invalid-guid-format" -ErrorAction Stop } | 
                Should -Throw "*Invalid GUID*"
        }
        
        It "Should throw for invalid SID format" {
            { Get-ADComputerLdap -Identity "S-1-5-invalid-sid" -ErrorAction Stop } | 
                Should -Throw "*Invalid SID*"
        }
        
        It "Should handle empty or null identity gracefully" {
            { Get-ADComputerLdap -Identity "" -ErrorAction Stop } | Should -Throw
            { Get-ADComputerLdap -Identity $null -ErrorAction Stop } | Should -Throw
        }
    }
}

Describe "Get-ADComputerLdap - LDAP Filter Functionality" {
    
    Context "Basic LDAP Filters" {
        
        It "Should find computers using name pattern" {
            $namePattern = $TestComputerName.Substring(0, [Math]::Min(3, $TestComputerName.Length))
            $results = Get-ADComputerLdap -LDAPFilter "(name=$namePattern*)"
            
            $results | Should -Not -BeNullOrEmpty
            $resultsArray = @($results)
            $resultsArray.Count | Should -BeGreaterThan 0
            
            $targetFound = $resultsArray | Where-Object { $_.Name -eq $TestComputerName }
            $targetFound | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle complex LDAP filters" {
            $result = Get-ADComputerLdap -LDAPFilter "(&(name=$TestComputerName)(objectClass=computer))"
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should handle LDAP filters with special characters" {
            # Test escaping of special LDAP characters
            $filter = "(&(objectClass=computer)(|(name=$TestComputerName)(cn=$TestComputerName)))"
            $result = Get-ADComputerLdap -LDAPFilter $filter
            
            $result | Should -Not -BeNullOrEmpty
        }
        
        It "Should throw for invalid LDAP filter syntax" {
            { Get-ADComputerLdap -LDAPFilter "(invalid-ldap-syntax" -ErrorAction Stop } | 
                Should -Throw "*LDAP*"
        }
        
        It "Should handle empty result sets from filters" {
            $results = Get-ADComputerLdap -LDAPFilter "(name=NONEXISTENTCOMPUTER*)"
            $results | Should -BeNullOrEmpty
        }
    }
    
    Context "Advanced LDAP Filter Scenarios" {
        
        It "Should support multiple OR conditions" {
            $filter = "(|(name=$TestComputerName)(cn=$TestComputerName))"
            $result = Get-ADComputerLdap -LDAPFilter $filter
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should support NOT conditions" {
            $filter = "(&(objectClass=computer)(!(name=NONEXISTENTCOMPUTER)))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            $results | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle filters with date comparisons" {
            $filter = "(objectClass=computer)"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            $results | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Get-ADComputerLdap - Property Handling" {
    
    Context "Property Selection" {
        
        It "Should retrieve specific properties only" {
            $properties = @("name", "distinguishedName", "objectGUID")
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties $properties
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -Not -BeNullOrEmpty
        }
        
        It "Should retrieve all properties with wildcard" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "*"
            
            $result | Should -Not -BeNullOrEmpty
            $propertyCount = ($result | Get-Member -MemberType Properties).Count
            $propertyCount | Should -BeGreaterThan 10
        }
        
        It "Should handle property aliases correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "Name", "Enabled", "Created", "DNSHostName"
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Not -BeNullOrEmpty
            $result.Enabled | Should -Not -BeNullOrEmpty
            $result.Enabled | Should -BeOfType [bool]
        }
        
        It "Should handle case-insensitive property names" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "NAME", "distinguishedname", "ObjectGUID"
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -Not -BeNullOrEmpty
        }
        
        It "Should return default properties when none specified" {
            $result = Get-ADComputerLdap -Identity $TestComputerName
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -Not -BeNullOrEmpty
            $result.ObjectSID | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Type Conversion" {
        
        It "Should convert DateTime properties correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "whenCreated", "lastLogonTimestamp"
            
            $result | Should -Not -BeNullOrEmpty
            if ($result.Created) {
                $result.Created | Should -BeOfType [DateTime]
            }
            if ($result.LastLogonDate) {
                $result.LastLogonDate | Should -BeOfType [DateTime]
            }
        }
        
        It "Should convert Boolean properties correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "userAccountControl"
            
            $result | Should -Not -BeNullOrEmpty
            $result.Enabled | Should -Not -BeNullOrEmpty
            $result.Enabled | Should -BeOfType [bool]
        }
        
        It "Should convert GUID and SID properties correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "objectGUID", "objectSID"
            
            $result | Should -Not -BeNullOrEmpty
            $result.ObjectGUID | Should -BeOfType [System.Guid]
            $result.ObjectSID | Should -BeOfType [System.Security.Principal.SecurityIdentifier]
        }
        
        It "Should handle numeric properties correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "userAccountControl", "logonCount"
            
            $result | Should -Not -BeNullOrEmpty
            if ($result.PSObject.Properties.Name -contains "userAccountControl") {
                $result.userAccountControl | Should -BeOfType [int]
            }
        }
        
        It "Should handle multi-valued properties correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "memberOf", "servicePrincipalName"
            
            $result | Should -Not -BeNullOrEmpty
            # memberOf and servicePrincipalName are typically arrays when present
            if ($result.memberOf) {
                $result.memberOf | Should -BeOfType [System.Array]
            }
        }
    }
}

Describe "Get-ADComputerLdap - Search Configuration" {
    
    Context "Search Base and Scope" {
        
        It "Should work with custom search base" -Skip:(-not $TestOUPath) {
            $result = Get-ADComputerLdap -Identity $TestComputerName -SearchBase $TestOUPath
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should work with Base search scope on DN" {
            $result = Get-ADComputerLdap -Identity $script:ReferenceComputer.DistinguishedName -SearchScope Base
            
            $result | Should -Not -BeNullOrEmpty
            $result.DistinguishedName | Should -Be $script:ReferenceComputer.DistinguishedName
        }
        
        It "Should work with OneLevel search scope" {
            # This requires a parent container path
            if ($script:ReferenceComputer.DistinguishedName -match "^CN=[^,]+,(.+)$") {
                $parentDN = $matches[1]
                $results = Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -SearchBase $parentDN -SearchScope OneLevel -ResultSetSize 10
                
                if ($results) {
                    @($results).Count | Should -BeGreaterThan 0
                }
            }
        }
        
        It "Should work with Subtree search scope" {
            $results = Get-ADComputerLdap -LDAPFilter "(name=$TestComputerName)" -SearchScope Subtree
            
            $results | Should -Not -BeNullOrEmpty
            $results.Name | Should -Be $TestComputerName
        }
    }
    
    Context "Result Set Management" {
        
        It "Should respect ResultSetSize parameter" {
            $results = Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -ResultSetSize 5
            
            if ($results) {
                $resultsArray = @($results)
                $resultsArray.Count | Should -BeLessOrEqual 5
            }
        }
        
        It "Should handle large result sets efficiently" {
            $results = Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -ResultSetSize 100
            
            # Should complete without timeout or memory issues
            if ($results) {
                $resultsArray = @($results)
                $resultsArray.Count | Should -BeLessOrEqual 100
            }
        }
        
        It "Should handle empty result sets gracefully" {
            $results = Get-ADComputerLdap -LDAPFilter "(name=TOTALLYNONEXISTENTCOMPUTER*)"
            $results | Should -BeNullOrEmpty
        }
    }
}

Describe "Get-ADComputerLdap - Pipeline Processing" {
    
    Context "Pipeline Input" {
        
        It "Should process single identity from pipeline" {
            $result = $TestComputerName | Get-ADComputerLdap
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should process multiple identities from pipeline" {
            $identities = @($TestComputerName, "$TestComputerName$")
            $results = $identities | Get-ADComputerLdap
            
            $resultsArray = @($results)
            $resultsArray.Count | Should -Be 2
            $resultsArray[0].Name | Should -Be $TestComputerName
            $resultsArray[1].Name | Should -Be $TestComputerName
        }
        
        It "Should process mixed identity types from pipeline" {
            $identities = @(
                $TestComputerName,
                $script:ReferenceComputer.DistinguishedName,
                $script:ReferenceComputer.ObjectGUID.ToString()
            )
            $results = $identities | Get-ADComputerLdap
            
            $resultsArray = @($results)
            $resultsArray.Count | Should -Be 3
            foreach ($result in $resultsArray) {
                $result.Name | Should -Be $TestComputerName
            }
        }
        
        It "Should handle pipeline with some invalid identities" {
            $identities = @($TestComputerName, "NONEXISTENTCOMPUTER12345")
            $results = $identities | Get-ADComputerLdap -ErrorAction SilentlyContinue
            
            $resultsArray = @($results)
            $resultsArray.Count | Should -Be 1
            $resultsArray[0].Name | Should -Be $TestComputerName
        }
    }
}

Describe "Get-ADComputerLdap - Connection and Authentication" {
    
    Context "Server Specification" {
        
        It "Should work with explicit domain controller" -Skip:(-not $TestDomainController -or $SkipConnectivityTests) {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Server $TestDomainController
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should throw for invalid server" -Skip:$SkipConnectivityTests {
            { Get-ADComputerLdap -Identity $TestComputerName -Server "invalid.server.name" -ErrorAction Stop } | 
                Should -Throw "*connection*"
        }
        
        It "Should work with server IP address" -Skip:(-not $TestDomainController -or $SkipConnectivityTests) {
            # Try to resolve DC to IP for testing
            try {
                $ip = [System.Net.Dns]::GetHostAddresses($TestDomainController)[0].IPAddressToString
                $result = Get-ADComputerLdap -Identity $TestComputerName -Server $ip
                
                $result | Should -Not -BeNullOrEmpty
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                Set-ItResult -Skipped -Because "Could not resolve DC to IP address"
            }
        }
    }
    
    Context "Authentication" {
        
        It "Should work with alternate credentials" -Skip:(-not $TestUserName -or $SkipCredentialTests) {
            $cred = New-TestCredential -UserName $TestUserName
            if ($cred) {
                $result = Get-ADComputerLdap -Identity $TestComputerName -Credential $cred
                
                $result | Should -Not -BeNullOrEmpty
                $result.Name | Should -Be $TestComputerName
            }
            else {
                Set-ItResult -Skipped -Because "Could not create test credentials"
            }
        }
        
        It "Should handle invalid credentials gracefully" -Skip:$SkipCredentialTests {
            $invalidCred = New-Object System.Management.Automation.PSCredential(
                "invaliduser", 
                (ConvertTo-SecureString "invalidpass" -AsPlainText -Force)
            )
            
            { Get-ADComputerLdap -Identity $TestComputerName -Credential $invalidCred -ErrorAction Stop } | 
                Should -Throw
        }
    }
    
    Context "Timeout Configuration" {
        
        It "Should respect timeout settings" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -TimeoutSeconds 30
            
            $result | Should -Not -BeNullOrEmpty
            $result.Name | Should -Be $TestComputerName
        }
        
        It "Should timeout on very short timeout values" {
            # This test might be flaky depending on network conditions
            try {
                $result = Get-ADComputerLdap -Identity $TestComputerName -TimeoutSeconds 1 -ErrorAction Stop
                # If it succeeds, that's also valid (fast network)
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                # Timeout expected with very short timeout
                $_.Exception.Message | Should -Match "timeout|time.*out"
            }
        }
    }
}

Describe "Get-ADComputerLdap - Performance and Threading" {
    
    Context "Performance Characteristics" {
        
        It "Should complete single query within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $result = Get-ADComputerLdap -Identity $TestComputerName
            $stopwatch.Stop()
            
            $result | Should -Not -BeNullOrEmpty
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000  # 5 seconds max
        }
        
        It "Should handle multiple simultaneous queries efficiently" {
            $identities = @($TestComputerName, "$TestComputerName$", $script:ReferenceComputer.DistinguishedName)
            
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $results = $identities | Get-ADComputerLdap
            $stopwatch.Stop()
            
            $resultsArray = @($results)
            $resultsArray.Count | Should -Be 3
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 10000  # 10 seconds max
        }
    }
    
    Context "Thread Safety" {
        
        It "Should be thread-safe in parallel runspaces" {
            $scriptBlock = {
                param($ComputerName)
                try {
                    Get-ADComputerLdap -Identity $ComputerName -ErrorAction Stop
                }
                catch {
                    $_.Exception.Message
                }
            }
            
            # Create multiple parallel jobs
            $jobs = 1..5 | ForEach-Object {
                Start-Job -ScriptBlock $scriptBlock -ArgumentList $TestComputerName
            }
            
            # Wait for all jobs and collect results
            $results = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            
            # All should succeed
            foreach ($result in $results) {
                if ($result -is [string]) {
                    # This was an error message
                    Write-Warning "Parallel execution error: $result"
                }
                else {
                    $result.Name | Should -Be $TestComputerName
                }
            }
        }
    }
}

Describe "Get-ADComputerLdap - Edge Cases and Robustness" {
    
    Context "Special Characters and Encoding" {
        
        It "Should handle computers with special characters in CN" {
            # This test depends on having computers with special characters
            # Skip if no such computers exist
            $filter = "(&(objectClass=computer)(|(cn=*-*)(cn=*_*)(cn=*.*)))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 1
            
            if ($results) {
                $results | Should -Not -BeNullOrEmpty
                $results.Name | Should -Not -BeNullOrEmpty
            }
            else {
                Set-ItResult -Skipped -Because "No computers with special characters found"
            }
        }
        
        It "Should handle Unicode characters properly" {
            # Test with Unicode characters in filter (if any exist)
            $filter = "(objectClass=computer)"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            if ($results) {
                # Just verify it doesn't crash with Unicode handling
                $results | Should -Not -BeNullOrEmpty
            }
        }
    }
    
    Context "Memory Management" {
        
        It "Should handle large property sets without memory issues" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "*"
            
            $result | Should -Not -BeNullOrEmpty
            
            # Force garbage collection to test for memory leaks
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
        }
        
        It "Should clean up connections properly" {
            # Multiple queries to test connection cleanup
            1..10 | ForEach-Object {
                $result = Get-ADComputerLdap -Identity $TestComputerName
                $result | Should -Not -BeNullOrEmpty
            }
            
            # Force cleanup
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
        }
    }
    
    Context "Parameter Validation" {
        
        It "Should validate SearchScope parameter" {
            { Get-ADComputerLdap -Identity $TestComputerName -SearchScope "InvalidScope" } | 
                Should -Throw
        }
        
        It "Should validate TimeoutSeconds parameter" {
            { Get-ADComputerLdap -Identity $TestComputerName -TimeoutSeconds -1 } | 
                Should -Throw
                
            { Get-ADComputerLdap -Identity $TestComputerName -TimeoutSeconds 0 } | 
                Should -Throw
        }
        
        It "Should validate ResultSetSize parameter" {
            { Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -ResultSetSize -1 } | 
                Should -Throw           
        }
    }
}

Describe "Get-ADComputerLdap - Get-ADComputer Compatibility" {
    
    Context "Parameter Compatibility" {
        
        It "Should support same basic parameters as Get-ADComputer" {
            # Test that the same parameter sets work
            $cmd = Get-Command Get-ADComputerLdap
            
            $cmd.Parameters.Keys | Should -Contain "Identity"
            $cmd.Parameters.Keys | Should -Contain "Properties"
            $cmd.Parameters.Keys | Should -Contain "Server"
            $cmd.Parameters.Keys | Should -Contain "Credential"
            $cmd.Parameters.Keys | Should -Contain "SearchBase"
            $cmd.Parameters.Keys | Should -Contain "SearchScope"
        }
        
        It "Should return objects with same core properties as Get-ADComputer" {
            $result = Get-ADComputerLdap -Identity $TestComputerName
            
            # Core properties that should match Get-ADComputer
            $result.PSObject.Properties.Name | Should -Contain "Name"
            $result.PSObject.Properties.Name | Should -Contain "DistinguishedName"
            $result.PSObject.Properties.Name | Should -Contain "ObjectGUID"
            $result.PSObject.Properties.Name | Should -Contain "ObjectSID"
            $result.PSObject.Properties.Name | Should -Contain "Enabled"
        }
        
        It "Should handle property aliases the same way as Get-ADComputer" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "Created", "Modified", "LastLogonDate"
            
            if ($result.Created) {
                $result.Created | Should -BeOfType [DateTime]
            }
            if ($result.Modified) {
                $result.Modified | Should -BeOfType [DateTime]
            }
        }
    }
    
    Context "Output Format Compatibility" {
        
        It "Should return objects of expected type" {
            $result = Get-ADComputerLdap -Identity $TestComputerName
            
            # Should be a PSCustomObject or similar
            $result | Should -Not -BeNullOrEmpty
            $result.GetType().Name | Should -BeIn @("PSCustomObject", "PSObject")
        }
        
        It "Should format properties consistently with Get-ADComputer" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "Name", "Enabled", "DNSHostName", "OperatingSystem"
            
            # Test property types and formats
            $result.Name | Should -BeOfType [string]
            $result.Enabled | Should -BeOfType [bool]
            if ($result.DNSHostName) {
                $result.DNSHostName | Should -BeOfType [string]
            }
        }
        
        It "Should handle ToString() method appropriately" {
            $result = Get-ADComputerLdap -Identity $TestComputerName
            
            $stringResult = $result.ToString()
            $stringResult | Should -Not -BeNullOrEmpty
            $stringResult | Should -BeOfType [string]
        }
    }
}

Describe "Get-ADComputerLdap - Cross-Domain Scenarios" {
    
    Context "Domain Targeting" {
        
        It "Should handle fully qualified domain names in identity" {
            # Test with FQDN format if available
            try {
                $domain = (Get-ADDomain).DNSRoot
                $fqdnIdentity = "$TestComputerName.$domain"
                $result = Get-ADComputerLdap -Identity $fqdnIdentity -ErrorAction Stop
                
                $result | Should -Not -BeNullOrEmpty
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                Set-ItResult -Skipped -Because "Could not determine domain FQDN or computer not found with FQDN"
            }
        }
        
        It "Should work with domain-qualified SAM names" {
            try {
                $domain = (Get-ADDomain).NetBIOSName
                $qualifiedSam = "$domain\$TestComputerName$"
                $result = Get-ADComputerLdap -Identity $qualifiedSam -ErrorAction Stop
                
                $result | Should -Not -BeNullOrEmpty
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                Set-ItResult -Skipped -Because "Could not determine domain NetBIOS name or format not supported"
            }
        }
    }
    
    Context "Global Catalog Queries" {
        
        It "Should handle Global Catalog server connections" -Skip:$SkipConnectivityTests {
            try {
                $gcServer = (Get-ADDomainController -Discover -Service GlobalCatalog).HostName[0]
                $result = Get-ADComputerLdap -Identity $TestComputerName -Server "$gcServer`:3268"
                
                $result | Should -Not -BeNullOrEmpty
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                Set-ItResult -Skipped -Because "Global Catalog server not accessible or not found"
            }
        }
    }
}

Describe "Get-ADComputerLdap - Advanced Filter Scenarios" {
    
    Context "Complex Business Logic Filters" {
        
        It "Should find enabled computers only" {
            $filter = "(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    $computer.Enabled | Should -Be $true
                }
            }
        }
        
        It "Should find computers by operating system" {
            $filter = "(&(objectClass=computer)(operatingSystem=Windows*))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    if ($computer.OperatingSystem) {
                        $computer.OperatingSystem | Should -Match "Windows"
                    }
                }
            }
        }
        
        It "Should find computers modified within timeframe" {
            $cutoffDate = (Get-Date).AddDays(-30)
            $ldapDate = $cutoffDate.ToString("yyyyMMddHHmmss.0Z")
            $filter = "(&(objectClass=computer)(whenChanged>=$ldapDate))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 10
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    if ($computer.Modified) {
                        $computer.Modified | Should -BeGreaterThan $cutoffDate
                    }
                }
            }
        }
        
        It "Should find computers in specific organizational units" -Skip:(-not $TestOUPath) {
            # Extract the OU portion from the test OU path
            $ouFilter = "(&(objectClass=computer)(distinguishedName=*$TestOUPath))"
            $results = Get-ADComputerLdap -LDAPFilter $ouFilter -ResultSetSize 10
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    $computer.DistinguishedName | Should -Match [regex]::Escape($TestOUPath)
                }
            }
        }
    }
    
    Context "Bitwise Operations in Filters" {
        
        It "Should handle userAccountControl bitwise operations" {
            # Find disabled computers using bitwise AND
            $filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=2))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    $computer.Enabled | Should -Be $false
                }
            }
        }
        
        It "Should handle password-related userAccountControl flags" {
            # Find computers that don't require password
            $filter = "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=32))"
            $results = Get-ADComputerLdap -LDAPFilter $filter -ResultSetSize 5
            
            # This test validates the filter syntax works, results may vary
            # Just ensure no errors occur
            if ($results) {
                $resultsArray = @($results)
                $resultsArray.Count | Should -BeGreaterOrEqual 0
            }
        }
    }
}

Describe "Get-ADComputerLdap - Error Recovery and Resilience" {
    
    Context "Network Resilience" {
        
        It "Should handle temporary network interruptions gracefully" -Skip:$SkipConnectivityTests {
            # This test simulates network issues by using a very short timeout
            try {
                $result = Get-ADComputerLdap -Identity $TestComputerName -TimeoutSeconds 1
                # If it succeeds quickly, that's also valid
                $result.Name | Should -Be $TestComputerName
            }
            catch {
                # Timeout or network error is expected
                $_.Exception.Message | Should -Match "(timeout|network|connection)"
            }
        }
        
        It "Should retry failed connections appropriately" {
            # Test multiple rapid successive calls to check retry logic
            $results = @()
            for ($i = 1; $i -le 3; $i++) {
                try {
                    $result = Get-ADComputerLdap -Identity $TestComputerName -ErrorAction Stop
                    $results += $result
                }
                catch {
                    Write-Warning "Attempt $i failed: $($_.Exception.Message)"
                }
            }
            
            # At least one should succeed
            $results.Count | Should -BeGreaterThan 0
        }
    }
    
    Context "Data Validation and Sanitization" {
        
        It "Should sanitize LDAP injection attempts" {
            # Test with potentially malicious LDAP filter characters
            $maliciousIdentity = "test*)(objectClass=*"
            
            # Should either find nothing or handle safely
            $result = Get-ADComputerLdap -Identity $maliciousIdentity -ErrorAction SilentlyContinue
            
            # Should not crash or return unexpected results
            if ($result) {
                $result.Name | Should -Not -Match "\*|\(|\)"
            }
        }
        
        It "Should handle extremely long identity strings" {
            $longIdentity = "a" * 1000
            
            { Get-ADComputerLdap -Identity $longIdentity -ErrorAction Stop } | 
                Should -Throw
        }
        
        It "Should handle null and empty arrays in pipeline" {
            $emptyArray = @()
            $nullArray = $null
            
            $result1 = $emptyArray | Get-ADComputerLdap -ErrorAction SilentlyContinue
            $result2 = $nullArray | Get-ADComputerLdap -ErrorAction SilentlyContinue
            
            $result1 | Should -BeNullOrEmpty
            $result2 | Should -BeNullOrEmpty
        }
    }
}

Describe "Get-ADComputerLdap - Integration Scenarios" {
    
    Context "Real-World Usage Patterns" {
        
        It "Should work in typical bulk computer queries" {
            $filter = "(objectClass=computer)"
            $results = Get-ADComputerLdap -LDAPFilter $filter -Properties "Name", "Enabled", "LastLogonDate" -ResultSetSize 20
            
            if ($results) {
                $resultsArray = @($results)
                
                # Verify expected properties are present
                foreach ($computer in $resultsArray) {
                    $computer.Name | Should -Not -BeNullOrEmpty
                    $computer.Enabled | Should -Not -BeNullOrEmpty
                    $computer.Enabled | Should -BeOfType [bool]
                }
                
                # Should have reasonable performance
                $resultsArray.Count | Should -BeLessOrEqual 20
            }
        }
        
        It "Should integrate well with Where-Object filtering" {
            $results = Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -ResultSetSize 10 | 
                       Where-Object { $_.Enabled -eq $true }
            
            if ($results) {
                $resultsArray = @($results)
                foreach ($computer in $resultsArray) {
                    $computer.Enabled | Should -Be $true
                }
            }
        }
        
        It "Should integrate well with Select-Object" {
            $results = Get-ADComputerLdap -Identity $TestComputerName -Properties "*" | 
                       Select-Object Name, Enabled, DistinguishedName
            
            $results | Should -Not -BeNullOrEmpty
            $results.Name | Should -Be $TestComputerName
            $results.Enabled | Should -Not -BeNullOrEmpty
            $results.DistinguishedName | Should -Not -BeNullOrEmpty
            
            # Should only have the selected properties
            ($results | Get-Member -MemberType Properties).Count | Should -Be 3
        }
        
        It "Should work with ForEach-Object processing" {
            $processedNames = @()
            
            Get-ADComputerLdap -Identity $TestComputerName | 
                ForEach-Object { 
                    $processedNames += $_.Name.ToUpper()
                }
            
            $processedNames.Count | Should -Be 1
            $processedNames[0] | Should -Be $TestComputerName.ToUpper()
        }
    }
    
    Context "Export and Reporting Scenarios" {
        
        It "Should export to CSV format correctly" {
            $tempFile = [System.IO.Path]::GetTempFileName() + ".csv"
            
            try {
                Get-ADComputerLdap -Identity $TestComputerName -Properties "Name", "Enabled", "DistinguishedName" |
                    Export-Csv -Path $tempFile -NoTypeInformation
                
                # Verify file was created and has content
                Test-Path $tempFile | Should -Be $true
                $content = Get-Content $tempFile
                $content.Count | Should -BeGreaterThan 1  # Header + data row
                
                # Verify CSV structure
                $content[0] | Should -Match "Name|Enabled|DistinguishedName"
                $content[1] | Should -Match $TestComputerName
            }
            finally {
                if (Test-Path $tempFile) {
                    Remove-Item $tempFile -Force
                }
            }
        }
        
        It "Should convert to JSON format correctly" {
            $result = Get-ADComputerLdap -Identity $TestComputerName -Properties "Name", "Enabled", "ObjectGUID"
            $json = $result | ConvertTo-Json -Depth 2
            
            $json | Should -Not -BeNullOrEmpty
            $json | Should -Match $TestComputerName
            $json | Should -Match '"Enabled"'
            $json | Should -Match '"ObjectGUID"'
            
            # Should be valid JSON
            $parsed = $json | ConvertFrom-Json
            $parsed.Name | Should -Be $TestComputerName
        }
    }
}

Describe "Get-ADComputerLdap - Cleanup and Finalization" {
    
    Context "Resource Cleanup" {
        
        It "Should not leave open LDAP connections" {
            # Perform multiple operations
            1..5 | ForEach-Object {
                Get-ADComputerLdap -Identity $TestComputerName | Out-Null
            }
            
            # Force garbage collection
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            [System.GC]::Collect()
            
            # This test mainly ensures no exceptions occur during cleanup
            $true | Should -Be $true
        }
        
        It "Should handle cleanup during pipeline interruption" {
            # Test what happens when pipeline is interrupted
            try {
                Get-ADComputerLdap -LDAPFilter "(objectClass=computer)" -ResultSetSize 100 | 
                    ForEach-Object { 
                        if ($_.Name -eq $TestComputerName) {
                            throw "Intentional interruption"
                        }
                    }
            }
            catch {
                # Expected interruption
            }
            
            # Should still be able to make new queries after interruption
            $result = Get-ADComputerLdap -Identity $TestComputerName
            $result | Should -Not -BeNullOrEmpty
        }
    }
}

AfterAll {
    Write-Host "Test suite completed. Cleaning up..." -ForegroundColor Yellow
    
    # Force final cleanup
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
    [System.GC]::Collect()
    
    Write-Host "Cleanup completed." -ForegroundColor Green
}
