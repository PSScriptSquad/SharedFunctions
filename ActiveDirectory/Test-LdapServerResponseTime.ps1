function Test-LdapServerResponseTime {
    <#
    .SYNOPSIS
        This function tests the response time of LDAP servers for different protocols (LDAP, LDAPS, GC, GCSSL) over a specified duration.

    .DESCRIPTION
        The `Test-LdapServerResponseTime` function performs repeated LDAP searches against a list of servers to measure response times. 
        The results are displayed and include average, minimum, and maximum response times for each server. 
        The function supports multiple protocols: LDAP, LDAPS, GC, and GCSSL, and can be configured for a custom test duration.

    .PARAMETER Servers
        A list of LDAP servers to test. This parameter is mandatory and can accept an array of server names or IP addresses.

    .PARAMETER TestDuration
        The duration (in seconds) for which the test will run on each server. The default is 30 seconds. This parameter is optional.

    .PARAMETER Protocol
        The LDAP protocol to use for the connection. It can be one of the following: "LDAP", "LDAPS", "GC", or "GCSSL". The default is "LDAP". 
        This parameter is optional.

    .EXAMPLE
        Test-LdapServerResponseTime -Servers "ldap.example.com" -TestDuration 60 -Protocol "LDAPS"
        This command tests the response time of the server "ldap.example.com" using the "LDAPS" protocol for a duration of 60 seconds.

    .EXAMPLE
        Test-LdapServerResponseTime -Servers @("ldap1.example.com", "ldap2.example.com") -TestDuration 30 -Protocol "GC"
        This command tests the response time of two servers, "ldap1.example.com" and "ldap2.example.com", using the "GC" protocol for 30 seconds.

    .NOTES
        Name: Test-LdapServerResponseTime
        Author: Ryan Whitlock
        Date: 11.25.2024
        Version: 1.0
        Changes: Initial Release
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Servers,

        [Parameter(Mandatory = $false)]
        [int]$TestDuration = 30,

        [Parameter(Mandatory = $false)]
        [ValidateSet("LDAP", "LDAPS", "GC", "GCSSL")]
        [string]$Protocol = "LDAP"
    )

    Begin {

        # Store detailed results for summary
        $serverResults = @()

        function Test-LDAP {
            param (
                [string]$Server,
                [string]$Protocol,
                [int]$TestDuration,
                [System.Collections.Concurrent.ConcurrentQueue[string]]$Queue,
                [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]$ResultBag
            )

            # Map protocols to port numbers
            $LDAPPorts = @{
                "LDAP"   = 389
                "LDAPS"  = 636
                "GC"     = 3268
                "GCSSL"  = 3269
            }
            $Port = $LDAPPorts[$Protocol]

            # Load the required .NET assembly for Directory Services
            Add-Type -AssemblyName System.DirectoryServices.Protocols

            # Set the end time based on the test duration
            $endTime = (Get-Date).AddSeconds($TestDuration)
            $responseTimes = @()

            # Run the test until the duration is complete
            while ((Get-Date) -lt $endTime) {
                try {
                    # Start measuring the response time
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    
                    # Create an LDAP connection and searcher
                    $ldapConnection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server`:$Port")
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapConnection)
                    $searcher.Filter = "(objectClass=*)"
                    $searcher.PageSize = 1
                    $null = $searcher.FindOne()
                    
                    # Stop measuring and record the response time
                    $stopwatch.Stop()
                    $elapsedTime = $stopwatch.ElapsedMilliseconds
                    $responseTimes += $elapsedTime

                    # Record the timestamp and response time in the queue
                    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    $Queue.Enqueue("$Server`:$Port | $currentTime - Response time: $elapsedTime ms")

                } catch [System.DirectoryServices.Protocols.LdapException] {
                    $Queue.Enqueue("$Server`:$Port | LDAP Error: $($_.Message)")
                } catch [System.UnauthorizedAccessException] {
                    $Queue.Enqueue("$Server`:$Port | Access Denied: Current user ($Env:USERNAME) doesn't have access.")
                } catch [System.Net.Sockets.SocketException] {
                    $Queue.Enqueue("$Server`:$Port | Network Error: Unable to reach the server.")
                } catch {
                    $Queue.Enqueue("$Server`:$Port | Unexpected Error: $($_.Exception.Message)")
                }
                Start-Sleep -Seconds 1
            }

            # Collect statistics if there are response times
            if ($responseTimes.Count -gt 0) {
                $avgTime = [Math]::Round(($responseTimes | Measure-Object -Average).Average, 2)
                $minTime = ($responseTimes | Measure-Object -Minimum).Minimum
                $maxTime = ($responseTimes | Measure-Object -Maximum).Maximum

                # Add summary object to the ResultBag
                $result = [PSCustomObject]@{
                    Server    = $Server
                    Protocol  = $Protocol
                    Average   = $avgTime
                    Minimum   = $minTime
                    Maximum   = $maxTime
                }
                $null = $ResultBag.Add($result)
            } else {
                $Queue.Enqueue("No successful responses recorded for server: $Server")
            }
        }

        # Setup runspace pool for parallel processing
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "Test-LDAP", ${function:Test-LDAP}))

        # Create the runspace pool for concurrent execution
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($iss)
        $runspacePool.SetMinRunspaces(1) | Out-Null
        $runspacePool.SetMaxRunspaces([Environment]::ProcessorCount) | Out-Null
        $runspacePool.Open()

        # Initialize concurrent collections for storing results
        $queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $resultBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $runspaces = @()
    }

    Process {
        # Start a new runspace for each server to test in parallel
        $runspaces = foreach ($Server in $Servers) {
            $runspace = [powershell]::Create().AddScript({
                param($Server, $Protocol, $TestDuration, $Queue, $ResultBag)
                Test-LDAP -Server $Server -Protocol $Protocol -TestDuration $TestDuration -Queue $Queue -ResultBag $ResultBag
            }).AddArgument($Server).AddArgument($Protocol).AddArgument($TestDuration).AddArgument($queue).AddArgument($resultBag)

            # Assign the runspace to the pool
            $runspace.RunspacePool = $runspacePool
            [PSCustomObject]@{
                Pipe   = $runspace
                Handle = $runspace.BeginInvoke()
            }
        }

        # Monitor and output progress while the runspaces are running
        while ($runspaces.Handle.IsCompleted -contains $false -or !$queue.IsEmpty) {
            while (!$queue.IsEmpty) {
                $item = $null
                if ($queue.TryDequeue([ref]$item)) {
                    Write-Host $item -ForegroundColor Green
                }
            }
            Start-Sleep -Milliseconds 100
        }
        
        # Output the summary results of all tests
        Write-Output $resultBag
    }

    End {
        # Cleanup and finalize by disposing runspaces
        foreach ($runspace in $runspaces) {
            $runspace.Pipe.EndInvoke($runspace.Handle)
            $runspace.Pipe.Dispose()
        }

        $runspacePool.Close()
    }
}
