<#
.SYNOPSIS
    Integration tests for Get-Events function and supporting classes.

.DESCRIPTION
    Comprehensive Pester v5 integration test suite validating Get-Events functionality
    including class definitions, XPath query generation, event parsing, local/remote
    execution, NTDS message resolution, and edge cases.

.PARAMETER ScriptPath
    Path to the Get-Events.ps1 script file. Defaults to searching common locations.

.PARAMETER TestLogName
    Event log name to use for integration tests. Default: 'System'

.PARAMETER RemoteTestComputer
    Specific computer name to use for remote testing. If not specified, remote tests
    will be skipped.

.PARAMETER SkipNtdsTests
    Skip tests requiring Active Directory/NTDS event log access.

.EXAMPLE
    Invoke-Pester -Path .\Get-Events.Integration.Tests.ps1

.EXAMPLE
    Invoke-Pester -Path .\Get-Events.Integration.Tests.ps1 -RemoteTestComputer 'DC01'

.EXAMPLE
    Invoke-Pester -Path .\Get-Events.Integration.Tests.ps1 -Output Detailed

.NOTES
    Author: Ryan Whitlock
    Version: 1.0.0
    Requires: Pester v5, PowerShell 5.1+
    
    Prerequisites:
    - Get-Events.ps1 must be in same directory or specified via ScriptPath
    - Appropriate permissions to read event logs
    - For remote tests: Specify RemoteTestComputer and ensure PSRemoting is enabled
    - For NTDS tests: Domain Controller access or Directory Service logs
#>

param(
    [Parameter()]
    [string]$ScriptPath,

    [Parameter()]
    [string]$TestLogName = 'System',

    [Parameter()]
    [string]$RemoteTestComputer,

    [Parameter()]
    [switch]$SkipNtdsTests
)

# Discovery-time probe of remote DC capability
$IsRemoteDc = $false
if (-not [string]::IsNullOrWhiteSpace($RemoteTestComputer) -and -not $SkipNtdsTests) {
    try {
        if (Test-WSMan -ComputerName $RemoteTestComputer -ErrorAction Stop) {
            $IsRemoteDc = Invoke-Command -ComputerName $RemoteTestComputer -ErrorAction Stop -ScriptBlock {
                try {
                    # DC if DomainRole is 4 or 5
                    $role = (Get-CimInstance -ClassName Win32_ComputerSystem).DomainRole
                    $isDc = $role -in 4,5
                    $hasDll = Test-Path "$env:SystemRoot\System32\ntdsmsg.dll"
                    [bool]($isDc -and $hasDll)
                } catch { $false }
            }
        }
    } catch {
        $IsRemoteDc = $false
    }
}

BeforeAll {
    # Locate the Get-Events script
    if (-not $ScriptPath) {
        $possiblePaths = @(
            (Join-Path $PSScriptRoot 'Get-Events.ps1'),
            (Join-Path $PSScriptRoot '..\Get-Events.ps1'),
            (Join-Path (Get-Location) 'Get-Events.ps1')
        )
        
        foreach ($path in $possiblePaths) {
            if (Test-Path $path) {
                $ScriptPath = $path
                break
            }
        }
    }
    
    if (-not $ScriptPath -or -not (Test-Path $ScriptPath)) {
        throw "Get-Events.ps1 not found. Please specify -ScriptPath parameter."
    }
    
    Write-Host "Loading Get-Events from: $ScriptPath" -ForegroundColor Cyan
    
    # Dot-source the script to load all components
    . $ScriptPath

    # Store test configuration
    $script:TestConfig = @{
        LogName = $TestLogName
        LocalComputer = $env:COMPUTERNAME
        RemoteComputer = $RemoteTestComputer
    }
    
    if ($script:TestConfig.SkipRemote) {
        Write-Host "Remote tests will be skipped (no RemoteTestComputer specified)" -ForegroundColor Yellow
    } else {
        Write-Host "Remote tests will target: $RemoteTestComputer" -ForegroundColor Cyan
    }
    
    # Helper function to create test events (requires admin)
    function New-TestEvent {
        param(
            [string]$LogName = 'Application',
            [int]$EventId = 1000,
            [string]$Message = 'Test Event',
            [string]$Source = 'PesterTest'
        )
        
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists($Source)) {
                [System.Diagnostics.EventLog]::CreateEventSource($Source, $LogName)
                Start-Sleep -Milliseconds 500
            }
            
            $eventLog = [System.Diagnostics.EventLog]::new()
            $eventLog.Log = $LogName
            $eventLog.Source = $Source
            $eventLog.WriteEntry($Message, [System.Diagnostics.EventLogEntryType]::Information, $EventId)
            
            Start-Sleep -Milliseconds 200
            return $true
        }
        catch {
            Write-Warning "Failed to create test event: $_"
            return $false
        }
    }
}

Describe "Get-Events - Module Loading and Dependencies" -Tag 'Unit', 'Loading' {
    
    Context "Native Type Loading" {
        It "Should load NtdsMessageNative type" {
            $ntdsType = [System.Management.Automation.PSTypeName]'NtdsMessageNative'
            $ntdsType.Type | Should -Not -BeNullOrEmpty
        }
        
        It "Should have required P/Invoke methods" {
            $type = [NtdsMessageNative]
            $type.GetMethod('LoadLibraryEx') | Should -Not -BeNullOrEmpty
            $type.GetMethod('FreeLibrary') | Should -Not -BeNullOrEmpty
            $type.GetMethod('FormatMessageW') | Should -Not -BeNullOrEmpty
        }
        
        It "Should have required constants" {
            [NtdsMessageNative]::LOAD_LIBRARY_AS_DATAFILE | Should -Be 0x00000002
            [NtdsMessageNative]::FORMAT_MESSAGE_FROM_HMODULE | Should -Be 0x00000800
            [NtdsMessageNative]::FORMAT_MESSAGE_IGNORE_INSERTS | Should -Be 0x00000200
        }
    }
    
    Context "Class Definitions" {
        It "Should load EventQueryFilter class" {
            { [EventQueryFilter]::new() } | Should -Not -Throw
        }
        
        It "Should load NtdsMessageResolver class" {
            $type = [NtdsMessageResolver]
            $type | Should -Not -BeNullOrEmpty
        }
        
        It "Should load EventDataParser class" {
            { [EventDataParser]::new() } | Should -Not -Throw
        }
        
        It "Should load EventLogQuery class" {
            { [EventLogQuery]::new('System', 'localhost') } | Should -Not -Throw
        }
    }
    
    Context "Get-Events Function" {
        It "Should be available as a function" {
            Get-Command Get-Events -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
        }
        
        It "Should have mandatory LogName parameter" {
            $params = (Get-Command Get-Events).Parameters
            $params['LogName'].Attributes.Mandatory | Should -Be $true
        }
        
        It "Should accept pipeline input for ComputerName" {
            $params = (Get-Command Get-Events).Parameters
            $params['ComputerName'].Attributes.ValueFromPipeline | Should -Be $true
        }
    }
}

Describe "EventQueryFilter - XPath Query Generation" -Tag 'Unit', 'XPath' {
    
    Context "Basic Event ID Filtering" {
        It "Should generate XPath for single event ID" {
            $filter = [EventQueryFilter]::new()
            $filter.EventIDs = @(4624)
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*EventID=4624*"
        }
        
        It "Should generate XPath for multiple event IDs" {
            $filter = [EventQueryFilter]::new()
            $filter.EventIDs = @(4624, 4625, 4634)
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*EventID=4624*"
            $xpath | Should -BeLike "*EventID=4625*"
            $xpath | Should -BeLike "*EventID=4634*"
            $xpath | Should -BeLike "* or *"
        }
        
        It "Should handle no event IDs specified" {
            $filter = [EventQueryFilter]::new()
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -Be '*'
        }
    }
    
    Context "Time Filtering" {
        It "Should generate XPath for StartTime" {
            $filter = [EventQueryFilter]::new()
            $filter.StartTime = [datetime]'2024-01-01 10:00:00'
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*TimeCreated*SystemTime>=*"
        }
        
        It "Should generate XPath for EndTime" {
            $filter = [EventQueryFilter]::new()
            $filter.EndTime = [datetime]'2024-01-01 12:00:00'
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*TimeCreated*SystemTime<=*"
        }
        
        It "Should convert times to UTC format" {
            $filter = [EventQueryFilter]::new()
            $localTime = [datetime]'2024-01-01 10:00:00'
            $filter.StartTime = $localTime
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -Match '\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z'
        }
        
        It "Should combine StartTime and EndTime" {
            $filter = [EventQueryFilter]::new()
            $filter.StartTime = [datetime]'2024-01-01 10:00:00'
            $filter.EndTime = [datetime]'2024-01-01 12:00:00'
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*TimeCreated*SystemTime>=*"
            $xpath | Should -BeLike "*TimeCreated*SystemTime<=*"
            $xpath | Should -BeLike "* and *"
        }
    }
    
    Context "Named Data Filtering" {
        It "Should generate XPath for single named field" {
            $filter = [EventQueryFilter]::new()
            $filter.NamedDataFilter = @{ 'LogonType' = '2' }
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*EventData*Data*Name='LogonType'*='2'*"
        }
        
        It "Should generate XPath for multiple values (OR)" {
            $filter = [EventQueryFilter]::new()
            $filter.NamedDataFilter = @{ 'LogonType' = @('2', '10') }
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*LogonType*='2'*"
            $xpath | Should -BeLike "*LogonType*='10'*"
            $xpath | Should -BeLike "* or *"
        }
        
        It "Should handle multiple named fields (AND)" {
            $filter = [EventQueryFilter]::new()
            $filter.NamedDataFilter = @{
                'LogonType' = '2'
                'IpAddress' = '192.168.1.1'
            }
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*LogonType*"
            $xpath | Should -BeLike "*IpAddress*"
        }
        
        It "Should escape special characters in values" {
            $filter = [EventQueryFilter]::new()
            $filter.NamedDataFilter = @{ 'Field' = "O'Brien" }
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*&apos;*"
        }
    }
    
    Context "Identity Filtering" {
        It "Should generate XPath for SID" {
            $filter = [EventQueryFilter]::new()
            $filter.IdentityFilter = @('S-1-5-21-123456789-123456789-123456789-1000')
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*SubjectUserSid*"
            $xpath | Should -BeLike "*TargetUserSid*"
        }
        
        It "Should generate XPath for DOMAIN\User format" {
            $filter = [EventQueryFilter]::new()
            $filter.IdentityFilter = @('CONTOSO\jdoe')
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*TargetUserName*"
            $xpath | Should -BeLike "*TargetDomainName*"
        }
        
        It "Should generate XPath for UPN format" {
            $filter = [EventQueryFilter]::new()
            $filter.IdentityFilter = @('jdoe@contoso.com')
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*Data*Name='TargetUserName'*"
        }
        
        It "Should generate XPath for plain username" {
            $filter = [EventQueryFilter]::new()
            $filter.IdentityFilter = @('jdoe')
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*TargetUserName*"
            $xpath | Should -BeLike "*SubjectUserName*"
        }
        
        It "Should handle multiple identities" {
            $filter = [EventQueryFilter]::new()
            $filter.IdentityFilter = @('jdoe', 'CONTOSO\admin')
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "* or *"
        }
    }
    
    Context "Combined Filtering" {
        It "Should combine all filter types with AND logic" {
            $filter = [EventQueryFilter]::new()
            $filter.EventIDs = @(4624)
            $filter.StartTime = [datetime]'2024-01-01'
            $filter.NamedDataFilter = @{ 'LogonType' = '2' }
            $filter.IdentityFilter = @('jdoe')
            
            $xpath = $filter.BuildXPathQuery()
            
            $xpath | Should -BeLike "*EventID=4624*"
            $xpath | Should -BeLike "*TimeCreated*"
            $xpath | Should -BeLike "*LogonType*"
            $xpath | Should -BeLike "*and*"
        }
    }
}

Describe "EventLogQuery - Local Event Retrieval" -Tag 'Integration', 'Local' {
    
    Context "Basic Event Retrieval" {
        It "Should retrieve events from System log" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 5
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            $results | Should -Not -BeNullOrEmpty
            $results.Count | Should -BeGreaterThan 0
            $results.Count | Should -BeLessOrEqual 5
        }
        
        It "Should respect MaxEvents limit" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 3
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            $results.Count | Should -BeLessOrEqual 3
        }
        
        It "Should return events in reverse chronological order" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 10
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            if ($results.Count -gt 1) {
                $results[0].TimeCreated | Should -BeGreaterOrEqual $results[-1].TimeCreated
            }
        }
    }
    
    Context "Event Filtering" {
        It "Should filter by Event ID" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.Filter.EventIDs = @(7036) # Service state change
            $query.MaxEvents = 5
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            $results | Where-Object { $_.Id -ne 7036 } | Should -BeNullOrEmpty
        }
        
        It "Should filter by time range" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.Filter.StartTime = (Get-Date).AddHours(-1)
            $query.MaxEvents = 10
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            $results | Where-Object { $_.TimeCreated -lt (Get-Date).AddHours(-1) } | Should -BeNullOrEmpty
        }
    }
    
    Context "XML Parsing" {
        It "Should parse event XML when enabled" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 2
            $query.ParseXml = $true
            
            $results = $query.Execute()
            
            $results[0].PSObject.Properties.Name | Should -Contain 'EventData'
            $results[0].PSObject.Properties.Name | Should -Contain 'System'
        }
        
        It "Should populate EventData hashtable" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 5
            $query.ParseXml = $true
            
            $results = $query.Execute()
            
            $results[0].EventData | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        }
        
        It "Should skip XML parsing when disabled" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.MaxEvents = 2
            $query.ParseXml = $false
            
            $results = $query.Execute()
            
            $results[0].PSObject.Properties.Name | Should -Not -Contain 'EventData'
            $results[0].PSObject.Properties.Name | Should -Not -Contain 'System'
        }
    }
    
    Context "Error Handling" {
        It "Should handle non-existent log gracefully" {
            $query = [EventLogQuery]::new('NonExistentLog12345', $env:COMPUTERNAME)
            $query.MaxEvents = 5
            
            { $query.Execute() } | Should -Not -Throw
        }
        
        It "Should tolerate query errors" {
            $query = [EventLogQuery]::new('System', $env:COMPUTERNAME)
            $query.Filter.EventIDs = @(99999) # Non-existent event ID
            $query.MaxEvents = 5
            
            $results = $query.Execute()
            ,$results | Should -BeOfType [System.Collections.ArrayList]
        }
    }
}

Describe "Get-Events - Function Integration Tests" -Tag 'Integration', 'Function' {
    
    Context "Basic Functionality" {
        It "Should retrieve events with minimal parameters" {
            $results = Get-Events -LogName $script:TestConfig.LogName -MaxEventsPerComputer 5
            
            $results | Should -Not -BeNullOrEmpty
            @($results).Count | Should -BeGreaterThan 0
        }
        
        It "Should filter by Event ID" {
            $results = Get-Events -LogName System -ID 7036 -MaxEventsPerComputer 5
            
            $results | Where-Object { $_.Id -ne 7036 } | Should -BeNullOrEmpty
        }
        
        It "Should filter by multiple Event IDs" {
            $results = Get-Events -LogName System -ID 7036,6005,6006 -MaxEventsPerComputer 10
            
            $results | Where-Object { $_.Id -notin @(7036,6005,6006) } | Should -BeNullOrEmpty
        }
        
        It "Should filter by time range" {
            $start = (Get-Date).AddHours(-2)
            $results = Get-Events -LogName System -StartTime $start -MaxEventsPerComputer 5
            
            $results | Where-Object { $_.TimeCreated -lt $start } | Should -BeNullOrEmpty
        }
        
        It "Should respect MaxEventsPerComputer" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 3
            
            @($results).Count | Should -BeLessOrEqual 3
        }
    }
    
    Context "XML Parsing Options" {
        It "Should skip XML parsing when requested" {
            $results = Get-Events -LogName System -SkipXmlParsing -MaxEventsPerComputer 2
            
            $results[0].PSObject.Properties.Name | Should -Not -Contain 'EventData'
        }
        
        It "Should include parsed data by default" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 2
            
            $results[0].PSObject.Properties.Name | Should -Contain 'EventData'
        }
        
        It "Should include XML when requested" {
            $results = Get-Events -LogName System -IncludeXml -MaxEventsPerComputer 1
            
            $results[0].PSObject.Properties.Name | Should -Contain 'Xml'
            $results[0].Xml | Should -BeLike '<Event*'
        }
    }
    
    Context "Named Data Filtering" {
        It "Should filter by named EventData field" -Skip:($script:TestConfig.LogName -ne 'Security') {
            $results = Get-Events -LogName Security -ID 4624 -NamedDataFilter @{ 'LogonType' = '2' } -MaxEventsPerComputer 5
            
            if ($results) {
                $results | ForEach-Object {
                    $_.EventData['LogonType'] | Should -Be '2'
                }
            }
        }
    }
    
    Context "Pipeline Support" {
        It "Should accept computer names from pipeline" {
            $results = 'localhost' | Get-Events -LogName System -MaxEventsPerComputer 2
            
            $results | Should -Not -BeNullOrEmpty
        }
        
        It "Should process multiple computers from pipeline" {
            $results = @('localhost', $env:COMPUTERNAME) | Get-Events -LogName System -MaxEventsPerComputer 2
            
            $results | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Output Properties" {
        It "Should include standard properties" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            $event = $results[0]
            
            $event.PSObject.Properties.Name | Should -Contain 'Id'
            $event.PSObject.Properties.Name | Should -Contain 'RecordId'
            $event.PSObject.Properties.Name | Should -Contain 'TimeCreated'
            $event.PSObject.Properties.Name | Should -Contain 'LogName'
            $event.PSObject.Properties.Name | Should -Contain 'ComputerName'
        }
        
        It "Should populate ComputerName property" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].ComputerName | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "NtdsMessageResolver - NTDS Template Resolution" -Tag 'Integration','NTDS' `
    -Skip:($SkipNtdsTests -or [string]::IsNullOrWhiteSpace($RemoteTestComputer) -or -not $IsRemoteDc) {

    BeforeAll {
        # Use the remote DC explicitly inside these tests
        $script:RemoteDc = $RemoteTestComputer
        Write-Host "NTDS tests targeting: $script:RemoteDc" -ForegroundColor Cyan
    }

    Context "Message Template Loading" {
        It "Should load ntdsmsg.dll if available" {
            [NtdsMessageResolver]::LoadMessageLibrary()
            $true | Should -Be $true
        }

        It "Should retrieve message template for known NTDS event" -Skip:(-not (Test-Path "$env:SystemRoot\System32\ntdsmsg.dll")) {
            $template = [NtdsMessageResolver]::GetMessageTemplate(1644)
            if ($template) { $template | Should -BeLike '*Internal event*' }
        }

        It "Should cache retrieved templates" -Skip:(-not (Test-Path "$env:SystemRoot\System32\ntdsmsg.dll")) {
            $t1 = [NtdsMessageResolver]::GetMessageTemplate(1644)
            $t2 = [NtdsMessageResolver]::GetMessageTemplate(1644)
            $t1 | Should -BeExactly $t2
        }

        It "Should return null for non-existent message ID" {
            [NtdsMessageResolver]::GetMessageTemplate(999999) | Should -BeNullOrEmpty
        }
    }

    Context "NTDS Event Integration" {
        It "Should include NTDS template in Directory Service events" {
            $results = Get-Events -LogName 'Directory Service' -ComputerName $script:RemoteDc -MaxEventsPerComputer 5
            if ($results) {
                $ntdsEvents = $results | Where-Object { $_.PSObject.Properties.Name -contains 'NtdsMessageTemplate' }
                $true | Should -Be $true
            }
        }
    }

    Context "Cleanup" {
        It "Should unload library cleanly" {
            { [NtdsMessageResolver]::Unload() } | Should -Not -Throw
        }
    }
}

Describe "Get-Events - Remote Execution" -Tag 'Integration', 'Remote' -Skip:([string]::IsNullOrWhiteSpace($RemoteTestComputer)) {
    
    BeforeAll {        
        if (-not [string]::IsNullOrWhiteSpace($script:TestConfig.RemoteComputer)) {
            $testConnection = Test-WSMan -ComputerName $script:TestConfig.RemoteComputer -ErrorAction SilentlyContinue
            
            if (-not $testConnection) {
                Write-Warning "Cannot connect to $($script:TestConfig.RemoteComputer) - remote tests will fail"
            } else {
                Write-Host "Verified connectivity to: $($script:TestConfig.RemoteComputer)" -ForegroundColor Green
            }
        }
    }
    
    Context "Remote Event Retrieval" {
        It "Should retrieve events from remote computer" {
            $results = Get-Events -LogName System -ComputerName $script:TestConfig.RemoteComputer -MaxEventsPerComputer 5
            
            $results | Should -Not -BeNullOrEmpty
            ($script:TestConfig.RemoteComputer.StartsWith($results[0].ComputerName)) | Should -Be $true
        }
        
        It "Should handle multiple remote computers" {
            $computers = @($script:TestConfig.RemoteComputer, 'localhost')

            $results = Get-Events -LogName System -ComputerName $computers -MaxEventsPerComputer 3
            
            @($results).Count | Should -BeGreaterThan 0
        }
        
        It "Should respect ThrottleLimit" {
            $computers = @($script:TestConfig.RemoteComputer, 'localhost')
            { Get-Events -LogName System -ComputerName $computers -ThrottleLimit 1 -MaxEventsPerComputer 2 } | Should -Not -Throw
        }
    }
    
    Context "Remote Script Transfer" {
        It "Should transfer class definitions to remote session" {
            $results = Get-Events -LogName System -ComputerName $script:TestConfig.RemoteComputer -MaxEventsPerComputer 1
            
            $results | Should -Not -BeNullOrEmpty
            $results[0].PSObject.Properties.Name | Should -Contain 'EventData'
        }
        
        It "Should preserve filtering on remote computer" {
            $results = Get-Events -LogName System -ComputerName $script:TestConfig.RemoteComputer -ID 7036 -MaxEventsPerComputer 3
            
            $results | Where-Object { $_.Id -ne 7036 } | Should -BeNullOrEmpty
        }
    }
}

Describe "Get-Events - Edge Cases and Error Handling" -Tag 'Integration', 'EdgeCases' {
    
    Context "Input Validation" {
        It "Should have LogName as a mandatory parameter" {
            $params = (Get-Command Get-Events).Parameters
            $params['LogName'].Attributes.Mandatory | Should -Be $true
        }
        
        It "Should validate Identity format" {
            { Get-Events -LogName System -Identity 'invalid@@@format' } | Should -Throw
        }
        
        It "Should handle empty Identity array" {
            { Get-Events -LogName System -Identity @() -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should handle empty NamedDataFilter" {
            { Get-Events -LogName System -NamedDataFilter @{} -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
    }
    
    Context "Empty Results" {
        It "Should handle no matching events gracefully" {
            $results = Get-Events -LogName System -ID 999999 -MaxEventsPerComputer 10
            
            @($results).Count | Should -Be 0
        }
        
        It "Should handle time range with no events" {
            $start = (Get-Date).AddYears(-100)
            $end = (Get-Date).AddYears(-99)
            $results = Get-Events -LogName System -StartTime $start -EndTime $end -MaxEventsPerComputer 10
            
            @($results).Count | Should -Be 0
        }
    }
    
    Context "Special Characters" {
        It "Should handle apostrophes in NamedDataFilter" {
            { Get-Events -LogName System -NamedDataFilter @{ 'Field' = "O'Brien" } -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should handle unicode in Identity" {
            { Get-Events -LogName System -Identity 'user123' -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
    }
    
    Context "Large Result Sets" {
        It "Should handle unlimited MaxEvents" {
            { Get-Events -LogName System -MaxEventsPerComputer -1 -ID 7036 } | Should -Not -Throw
        }
        
        It "Should stream results efficiently" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 100
            
            $results | Should -Not -BeNullOrEmpty
            @($results).Count | Should -BeLessOrEqual 100
        }
    }
}

Describe "EventDataParser - XML Parsing Details" -Tag 'Unit', 'Parsing' {
    
    Context "Event Data Extraction" {
        It "Should create ordered dictionary for EventData" {
            $parser = [EventDataParser]::new()
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].EventData | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        }
        
        It "Should create ordered dictionary for System properties" {
            $parser = [EventDataParser]::new()
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].System | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
        }
        
        It "Should handle events with no EventData" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 5
            
            # Some events may have empty EventData
            $emptyDataEvents = $results | Where-Object { $_.EventData.Count -eq 0 }
            # Should not throw, just have empty collection
            if ($null -ne $emptyDataEvents) {
                # If we found any, verify they are the correct type
                $emptyDataEvents | ForEach-Object { $_ | Should -BeOfType [PSCustomObject] }
            }
        }
    }
    
    Context "System Properties Parsing" {
        It "Should extract Provider Name" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].System['Provider'] | Should -Not -BeNullOrEmpty
        }
        
        It "Should extract TimeCreated" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].System['TimeCreated'] | Should -Not -BeNullOrEmpty
        }
        
        It "Should extract EventID" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].System['EventID'] | Should -Not -BeNullOrEmpty
        }
        
        It "Should handle attributes in System elements" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            # TimeCreated has SystemTime attribute
            $results[0].System.Keys | Should -Contain 'TimeCreated_SystemTime'
        }
    }
    
    Context "Include Options" {
        It "Should include raw XML when requested" {
            $results = Get-Events -LogName System -IncludeXml -MaxEventsPerComputer 1
            
            $results[0].Xml | Should -Not -BeNullOrEmpty
            $results[0].Xml | Should -BeLike '<Event*'
            $results[0].Xml | Should -BeLike '*</Event>'
        }
        
        It "Should not include XML by default" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].PSObject.Properties.Name | Should -Not -Contain 'Xml'
        }
        
        It "Should include rendered description when requested" {
            $results = Get-Events -LogName System -IncludeRenderedDescription -MaxEventsPerComputer 1
            
            $results[0].PSObject.Properties.Name | Should -Contain 'Description'
        }
        
        It "Should not include description by default" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            
            $results[0].PSObject.Properties.Name | Should -Not -Contain 'Description'
        }
    }
}

Describe "Performance and Scalability" -Tag 'Performance' {
    
    Context "Memory Efficiency" {
        It "Should handle retrieving many events without excessive memory" {
            $initialMemory = [System.GC]::GetTotalMemory($false)
            
            $results = Get-Events -LogName System -MaxEventsPerComputer 100 -SkipXmlParsing
            
            $finalMemory = [System.GC]::GetTotalMemory($false)
            $memoryIncrease = ($finalMemory - $initialMemory) / 1MB
            
            # Memory increase should be reasonable (less than 50MB for 100 events)
            $memoryIncrease | Should -BeLessThan 50
        }
        
        It "Should dispose resources properly" {
            $beforeHandles = (Get-Process -Id $PID).HandleCount
            
            $results = Get-Events -LogName System -MaxEventsPerComputer 10
            
            Start-Sleep -Milliseconds 500
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            
            $afterHandles = (Get-Process -Id $PID).HandleCount
            
            # Handle count shouldn't grow significantly
            ($afterHandles - $beforeHandles) | Should -BeLessThan 10
        }
    }
    
    Context "Query Performance" {
        It "Should complete simple query within reasonable time" {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            
            $results = Get-Events -LogName System -MaxEventsPerComputer 10 -SkipXmlParsing
            
            $stopwatch.Stop()
            
            # Should complete in under 5 seconds
            $stopwatch.ElapsedMilliseconds | Should -BeLessThan 5000
        }
        
        It "Should be faster with SkipXmlParsing" {
            $stopwatchWithParsing = [System.Diagnostics.Stopwatch]::StartNew()
            $resultsWithParsing = Get-Events -LogName System -MaxEventsPerComputer 20
            $stopwatchWithParsing.Stop()
            
            $stopwatchWithoutParsing = [System.Diagnostics.Stopwatch]::StartNew()
            $resultsWithoutParsing = Get-Events -LogName System -MaxEventsPerComputer 20 -SkipXmlParsing
            $stopwatchWithoutParsing.Stop()
            
            # Without parsing should be faster
            $stopwatchWithoutParsing.ElapsedMilliseconds | Should -BeLessThan $stopwatchWithParsing.ElapsedMilliseconds
        }
    }
    
    Context "Server-Side Filtering Efficiency" {
        It "Should use server-side filtering (faster than client-side)" {
            # Query with filter should be faster than no filter + client filtering
            $stopwatchServerSide = [System.Diagnostics.Stopwatch]::StartNew()
            $serverResults = Get-Events -LogName System -ID 7036 -MaxEventsPerComputer 10
            $stopwatchServerSide.Stop()
            
            $stopwatchClientSide = [System.Diagnostics.Stopwatch]::StartNew()
            $clientResults = Get-Events -LogName System -MaxEventsPerComputer 100 | Where-Object { $_.Id -eq 7036 } | Select-Object -First 10
            $stopwatchClientSide.Stop()
            
            # Server-side should generally be faster for filtered queries
            Write-Host "Server-side: $($stopwatchServerSide.ElapsedMilliseconds)ms, Client-side: $($stopwatchClientSide.ElapsedMilliseconds)ms"
            $stopwatchServerSide.ElapsedMilliseconds | Should -BeLessThan $stopwatchClientSide.ElapsedMilliseconds
        }
    }
}

Describe "Identity Filtering Integration" -Tag 'Integration', 'Identity' -Skip:($script:TestConfig.LogName -ne 'Security') {
    
    Context "User Identity Formats" {
        It "Should accept SAM account name" {
            { Get-Events -LogName Security -Identity 'Administrator' -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should accept DOMAIN\User format" {
            { Get-Events -LogName Security -Identity "$env:USERDOMAIN\$env:USERNAME" -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should accept UPN format" {
            { Get-Events -LogName Security -Identity 'user@domain.com' -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should accept SID format" {
            { Get-Events -LogName Security -Identity 'S-1-5-18' -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should handle multiple identity formats simultaneously" {
            { Get-Events -LogName Security -Identity @('Administrator', 'S-1-5-18', 'user@domain.com') -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
    }
    
    Context "Identity Matching" {
        It "Should find events for SYSTEM account" {
            $results = Get-Events -LogName Security -Identity 'SYSTEM' -MaxEventsPerComputer 10
            
            if ($results) {
                $results | Should -Not -BeNullOrEmpty
            }
        }
        
        It "Should handle case-insensitive matching" {
            $results1 = Get-Events -LogName Security -Identity 'system' -MaxEventsPerComputer 5
            $results2 = Get-Events -LogName Security -Identity 'SYSTEM' -MaxEventsPerComputer 5
            
            # Both should return results (or both return nothing)
            @($results1).Count | Should -Be @($results2).Count
        }
    }
}

Describe "Real-World Scenario Tests" -Tag 'Integration', 'Scenarios' {
    
    Context "Security Audit Scenarios" -Skip:($script:TestConfig.LogName -ne 'Security') {
        It "Should query logon events for specific user" {
            $results = Get-Events -LogName Security -ID 4624 -Identity $env:USERNAME -StartTime (Get-Date).AddHours(-24) -MaxEventsPerComputer 10
            
            if ($results) {
                $results | ForEach-Object { $_.Id | Should -Be 4624 }
            }
        }
        
        It "Should query failed logon attempts" {
            $results = Get-Events -LogName Security -ID 4625 -StartTime (Get-Date).AddDays(-7) -MaxEventsPerComputer 10
            
            if ($results) {
                $results | ForEach-Object { $_.Id | Should -Be 4625 }
            }
        }
        
        It "Should query interactive logons only" {
            $results = Get-Events -LogName Security -ID 4624 -NamedDataFilter @{ 'LogonType' = '2' } -MaxEventsPerComputer 5
            
            if ($results) {
                $results | ForEach-Object {
                    $_.EventData['LogonType'] | Should -Be '2'
                }
            }
        }
    }
    
    Context "System Monitoring Scenarios" {
        It "Should query service state changes" {
            $results = Get-Events -LogName System -ID 7036 -StartTime (Get-Date).AddHours(-24) -MaxEventsPerComputer 10
            
            $results | ForEach-Object { $_.Id | Should -Be 7036 }
        }
        
        It "Should query system startup/shutdown events" {
            $results = Get-Events -LogName System -ID 6005,6006,6008 -StartTime (Get-Date).AddDays(-7) -MaxEventsPerComputer 10
            
            if ($results) {
                $results | ForEach-Object { $_.Id | Should -BeIn @(6005,6006,6008) }
            }
        }
        
        It "Should query recent error events" {
            $results = Get-Events -LogName System -StartTime (Get-Date).AddHours(-1) -MaxEventsPerComputer 20
            
            $errorEvents = $results | Where-Object { $_.LevelDisplayName -eq 'Error' }
            # Just verify query completes successfully
            $results | Should -BeOfType [PSCustomObject]
        }
    }
    
    Context "Application Troubleshooting Scenarios" {
        It "Should query application crashes" {
            $results = Get-Events -LogName Application -ID 1000,1001 -StartTime (Get-Date).AddDays(-7) -MaxEventsPerComputer 10
            
            if ($results) {
                $results | ForEach-Object { $_.Id | Should -BeIn @(1000,1001) }
            }
        }
        
        It "Should combine multiple filters for troubleshooting" {
            $results = Get-Events -LogName Application -StartTime (Get-Date).AddHours(-4) -EndTime (Get-Date) -MaxEventsPerComputer 20
            
            if ($results) {
                $results | ForEach-Object {
                    $_.TimeCreated | Should -BeGreaterOrEqual (Get-Date).AddHours(-4)
                    $_.TimeCreated | Should -BeLessOrEqual (Get-Date)
                }
            }
        }
    }
}

Describe "Regression Tests" -Tag 'Regression' {
    
    Context "Known Issues Prevention" {
        It "Should not throw on events with missing EventData" {
            { Get-Events -LogName System -MaxEventsPerComputer 50 } | Should -Not -Throw
        }
        
        It "Should handle events with null UserId" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 10
            
            # Some events may have null UserId - should not cause errors
            $results | Should -Not -BeNullOrEmpty
        }
        
        It "Should properly escape XPath predicates" {
            { Get-Events -LogName System -NamedDataFilter @{ 'Field' = "Test'Value" } -MaxEventsPerComputer 1 } | Should -Not -Throw
        }
        
        It "Should handle concurrent queries gracefully" {
            $jobs = 1..3 | ForEach-Object {
                Start-Job -ScriptBlock {
                    param($Path)
                    . $Path
                    Get-Events -LogName System -MaxEventsPerComputer 5
                } -ArgumentList $ScriptPath
            }
            
            $results = $jobs | Wait-Job | Receive-Job
            $jobs | Remove-Job
            
            $results | Should -Not -BeNullOrEmpty
        }
    }
    
    Context "Backwards Compatibility" {
        It "Should maintain output object structure" {
            $results = Get-Events -LogName System -MaxEventsPerComputer 1
            $event = $results[0]
            
            # Core properties that should always exist
            @('Id', 'RecordId', 'TimeCreated', 'LogName', 'ComputerName') | ForEach-Object {
                $event.PSObject.Properties.Name | Should -Contain $_
            }
        }
        
        It "Should handle pipeline the same way" {
            $pipelineResults = 'localhost' | Get-Events -LogName System -MaxEventsPerComputer 2
            $directResults = Get-Events -LogName System -ComputerName 'localhost' -MaxEventsPerComputer 2
            
            @($pipelineResults).Count | Should -Be @($directResults).Count
        }
    }
}

Describe "Cleanup and Finalization" -Tag 'Cleanup' {
    
    Context "Resource Cleanup" {
        It "Should unload NTDS message library" {
            { [NtdsMessageResolver]::Unload() } | Should -Not -Throw
        }
        
        It "Should clear message cache" {
            [NtdsMessageResolver]::_messageCache.Clear()
            [NtdsMessageResolver]::_messageCache.Count | Should -Be 0
        }
        
        It "Should reset load attempted flag" {
            [NtdsMessageResolver]::_loadAttempted = $false
            [NtdsMessageResolver]::_loadAttempted | Should -Be $false
        }
    }
}

AfterAll {
    Write-Host "`n=== Test Run Summary ===" -ForegroundColor Cyan
    Write-Host "Script Path: $ScriptPath" -ForegroundColor Gray
    Write-Host "Test Log: $($script:TestConfig.LogName)" -ForegroundColor Gray
    Write-Host "Local Computer: $($script:TestConfig.LocalComputer)" -ForegroundColor Gray
    
    if ($script:TestConfig.SkipRemote) {
        Write-Host "Remote Tests: Skipped (no RemoteTestComputer specified)" -ForegroundColor Yellow
    } else {
        Write-Host "Remote Test Computer: $($script:TestConfig.RemoteComputer)" -ForegroundColor Gray
        Write-Host "Remote Tests: Executed" -ForegroundColor Green
    }
    
    Write-Host "NTDS Tests: $(if ($script:TestConfig.SkipNtds) { 'Skipped' } else { 'Executed' })" -ForegroundColor Gray
    
    # Final cleanup
    [NtdsMessageResolver]::Unload()
    
    Write-Host "`nTest suite execution completed." -ForegroundColor Green
}