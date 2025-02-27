function Test-LdapServerResponseTime {
    <#
    .SYNOPSIS
        Tests the response time of LDAP servers for different protocols (LDAP, LDAPS, GC, GCSSL) over a specified duration.

    .DESCRIPTION
        This function performs repeated LDAP searches against a list of servers to measure response times. 
        The results are displayed and include average, minimum, and maximum response times for each server. 
        The function supports multiple protocols: LDAP, LDAPS, GC, and GCSSL, and can be configured for a custom test duration.
        Additionally, the frequency at which queries are sent can be adjusted from 0.5 seconds to 60 seconds.

    .PARAMETER Servers
        A list of LDAP servers to test. Accepts an array of server names or IP addresses.

    .PARAMETER TestDuration
        The duration (in seconds) for which the test will run on each server. The default is 30 seconds.

    .PARAMETER Protocol
        The LDAP protocol to use for the connection. Valid values: "LDAP", "LDAPS", "GC", "GCSSL". Default: "LDAP".

    .PARAMETER RequestFrequency
        How often (in seconds) to send each LDAP query to the server. 
        Accepts a decimal value between 0.5 (half a second) and 60 (one minute). 
        Default is 1 (one second).

    .EXAMPLE
        Test-LdapServerResponseTime -Servers "ldap.example.com" -TestDuration 60 -Protocol "LDAPS"
        Tests the response time of "ldap.example.com" over LDAPS for 60 seconds, sending a query every second.

    .EXAMPLE
        Test-LdapServerResponseTime -Servers @("ldap1.example.com","ldap2.example.com") -TestDuration 30 -Protocol "GC" -RequestFrequency 0.5
        Tests the response time of two servers using the GC protocol for 30 seconds, sending queries every half second.

    .NOTES
        Name: Test-LdapServerResponseTime
        Author: Ryan Whitlock
        Date: 11.25.2024
        Version: 1.1
        Changes:
            - Switched to named capturing groups in regex.
            - Parameterized the sleep interval for the LDAP requests (RequestFrequency).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [string[]]$Servers,

        [Parameter(Mandatory = $false)]
        [int]$TestDuration = 30,

        [Parameter(Mandatory = $false)]
        [ValidateSet("LDAP", "LDAPS", "GC", "GCSSL")]
        [string]$Protocol = "LDAP",

        [Parameter(Mandatory = $false)]
        [ValidateRange(0.25, 60)]
        [double]$RequestFrequency = 1
    )

    Begin {
        # Hashtable for server-specific colors
        $global:serverColors = @{}
        # Define a list of available foreground colors (can be adjusted as needed)
        $global:availableColors = @(
            "Yellow", "Cyan", "Magenta", "Gray", 
            "DarkYellow", "DarkCyan", "DarkMagenta", "White"
        )

        # Helper function to get a (mostly) unique color for each server
        function Get-ServerColor {
            param ([string]$ServerName)

            if (-not $global:serverColors.ContainsKey($ServerName)) {
                # Find which colors are already in use
                $usedColors = $global:serverColors.Values
                # Filter out used colors to find what's unassigned
                $unassigned = $global:availableColors | Where-Object { $usedColors -notcontains $_ }

                if ($unassigned.Count -gt 0) {
                    # If there is at least one unassigned color, pick from that subset
                    $randIndex = Get-Random -Minimum 0 -Maximum $unassigned.Count
                    $global:serverColors[$ServerName] = $unassigned[$randIndex]
                }
                else {
                    # All colors used, pick from the full list again
                    $randIndex = Get-Random -Minimum 0 -Maximum $global:availableColors.Count
                    $global:serverColors[$ServerName] = $global:availableColors[$randIndex]
                }
            }
            return $global:serverColors[$ServerName]
        }

        # Store detailed results for summary
        $serverResults = @()

        function Test-LDAP {
            param (
                [string]$Server,
                [string]$Protocol,
                [int]$TestDuration,
                [double]$Frequency,
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

            # Load .NET assembly for Directory Services
            Add-Type -AssemblyName System.DirectoryServices.Protocols

            # End time
            $endTime = (Get-Date).AddSeconds($TestDuration)
            $responseTimes = @()

            while ((Get-Date) -lt $endTime) {
                try {
                    # Start measuring
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    
                    # Create an LDAP connection/search
                    $ldapConnection = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server`:$Port")
                    $searcher = New-Object System.DirectoryServices.DirectorySearcher($ldapConnection)
                    $searcher.Filter = "(objectClass=*)"
                    $searcher.PageSize = 1
                    $null = $searcher.FindOne()
                    
                    # Stop measuring
                    $stopwatch.Stop()
                    $elapsedTime = $stopwatch.ElapsedMilliseconds
                    $responseTimes += $elapsedTime

                    # Stats
                    $avgTime = [Math]::Round(($responseTimes | Measure-Object -Average).Average, 2)
                    $minTime = ($responseTimes | Measure-Object -Minimum).Minimum
                    $maxTime = ($responseTimes | Measure-Object -Maximum).Maximum

                    # Enqueue results
                    $currentTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
                    $Queue.Enqueue("$Server`:$Port | $currentTime - Response time: $elapsedTime ms | Avg: $avgTime ms | Min: $minTime ms | Max: $maxTime ms")

                } catch [System.DirectoryServices.Protocols.LdapException] {
                    $Queue.Enqueue("$Server`:$Port | LDAP Error: $($_.Message)")
                } catch [System.UnauthorizedAccessException] {
                    $Queue.Enqueue("$Server`:$Port | Access Denied: Current user ($Env:USERNAME) doesn't have access.")
                } catch [System.Net.Sockets.SocketException] {
                    $Queue.Enqueue("$Server`:$Port | Network Error: Unable to reach the server.")
                } catch {
                    $Queue.Enqueue("$Server`:$Port | Unexpected Error: $($_.Exception.Message)")
                }

                # Sleep for the user-defined interval (0.25 to 60 seconds)
                Start-Sleep -Seconds $Frequency
            }

            # Summary
            if ($responseTimes.Count -gt 0) {
                $avgTime = [Math]::Round(($responseTimes | Measure-Object -Average).Average, 2)
                $minTime = ($responseTimes | Measure-Object -Minimum).Minimum
                $maxTime = ($responseTimes | Measure-Object -Maximum).Maximum

                $result = [PSCustomObject]@{
                    Server    = $Server
                    Protocol  = $Protocol
                    Average   = $avgTime
                    Minimum   = $minTime
                    Maximum   = $maxTime
                }
                $null = $ResultBag.Add($result)
            }
            else {
                $Queue.Enqueue("No successful responses recorded for server: $Server")
            }
        }

        # Runspace pool
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $iss.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "Test-LDAP", ${function:Test-LDAP}))
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($iss)
        $runspacePool.SetMinRunspaces(1) | Out-Null
        $runspacePool.SetMaxRunspaces([Environment]::ProcessorCount) | Out-Null
        $runspacePool.Open()

        # Shared data structures
        $queue = [System.Collections.Concurrent.ConcurrentQueue[string]]::new()
        $resultBag = [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new()
        $runspaces = @()
    }

    Process {
        # Launch a runspace for each server
        $runspaces = foreach ($Server in $Servers) {
            $runspace = [powershell]::Create().AddScript({
                param($Server, $Protocol, $TestDuration, $Frequency, $Queue, $ResultBag)
                Test-LDAP -Server $Server -Protocol $Protocol -TestDuration $TestDuration -Frequency $Frequency -Queue $Queue -ResultBag $ResultBag
            }).AddArgument($Server).AddArgument($Protocol).AddArgument($TestDuration).AddArgument($RequestFrequency).AddArgument($queue).AddArgument($resultBag)

            $runspace.RunspacePool = $runspacePool
            [PSCustomObject]@{
                Pipe   = $runspace
                Handle = $runspace.BeginInvoke()
            }
        }

        # Collect output
        while ($runspaces.Handle.IsCompleted -contains $false -or !$queue.IsEmpty) {
            while (!$queue.IsEmpty) {
                $item = $null
                if ($queue.TryDequeue([ref]$item)) {
                    # Typical format: "servername:port | yyyy-MM-dd HH:mm:ss.fff - Response time: XXX ms | Avg: X ms | Min: X ms | Max: X ms"
                    $serverPort = $item.Split(" |")[0]
                    $serverName = $serverPort.Split(":")[0]

                    # Retrieve or assign a color for this server
                    $serverColor = Get-ServerColor -ServerName $serverName

                    # For errors or "No successful responses", just print everything in the server color
                    if ($item -match "Error|No successful responses|Access Denied|Network Error|Unexpected Error") {
                        Write-Host "[$serverName] $item" -ForegroundColor $serverColor
                        continue
                    }

                    # Remove "servername:port | " to avoid double printing
                    $parsedMessage = $item.Substring($serverPort.Length + 3) 

                    # Use named capturing groups to parse date/time, response time, and the remainder
                    $regex = '^(?<prefix>.*?) - Response time: (?<time>\d+) ms(?<rest>.*)$'
                    if ($parsedMessage -match $regex) {
                        $dateAndPrefix = $Matches['prefix']  # e.g. "2025-02-26 08:46:00.000"
                        $timeVal       = [int]$Matches['time']
                        $rest          = $Matches['rest']    # e.g. " | Avg: 61.32 ms | Min: 35 ms | Max: 167 ms"

                        # Write the server name in its color
                        Write-Host -NoNewLine "[" -ForegroundColor "White"
                        Write-Host -NoNewLine $serverName -ForegroundColor $serverColor
                        Write-Host -NoNewLine "] " -ForegroundColor "White"

                        # Date/time portion in white
                        Write-Host -NoNewLine $dateAndPrefix -ForegroundColor "White"
                        Write-Host -NoNewLine " - Response time: " -ForegroundColor "White"

                        # Numeric response time in red or green
                        if ($timeVal -gt 150) {
                            Write-Host -NoNewLine "$timeVal ms" -ForegroundColor "Red"
                        }
                        else {
                            Write-Host -NoNewLine "$timeVal ms" -ForegroundColor "Green"
                        }

                        # The rest (Avg/Min/Max) in the server's color
                        Write-Host $rest -ForegroundColor $serverColor
                    }
                    else {
                        # If we can't parse the line with the regex, just print everything in white plus the server name
                        Write-Host "[$serverName] $parsedMessage" -ForegroundColor "White"
                    }
                }
            }
            Start-Sleep -Milliseconds 100
        }

        # Return the summary
        Write-Output $resultBag
    }

    End {
        # Cleanup
        foreach ($runspace in $runspaces) {
            $runspace.Pipe.EndInvoke($runspace.Handle)
            $runspace.Pipe.Dispose()
        }
        $runspacePool.Close()
    }
}
