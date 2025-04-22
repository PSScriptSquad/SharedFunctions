function Invoke-DNSLoadTest {
    <#
    .SYNOPSIS
        Performs a high-performance DNS load test against multiple DNS servers.

    .DESCRIPTION
        This function queries specified FQDNs across multiple DNS servers using runspaces.
        It measures response times, tracks success/failure counts, and provides live, color-coded console output.
        The total number of queries is scheduled exactly as (QueriesPerSecond * DurationSeconds).
        It dynamically calculates maximum concurrency (half of QPS, minimum 1) and enforces a timeout.
        Overall metrics (average, min, max, standard deviation) are computed and included in the final summary.
        Optionally, detailed results can be exported to CSV.

    .PARAMETER FQDNs
        An array of fully qualified domain names to resolve.

    .PARAMETER DNSServers
        An array of DNS servers (IPv4, IPv6, or FQDN) to query.

    .PARAMETER QueriesPerSecond
        The target number of DNS queries per second.

    .PARAMETER DurationSeconds
        The test duration in seconds.

    .PARAMETER TimeoutMilliseconds
        The maximum time (in milliseconds) allowed for each DNS query.

    .PARAMETER CsvOutputPath
        Optional file path to export detailed results as CSV (e.g., C:\Temp\Results.csv).

    .EXAMPLE
        Invoke-DNSLoadTest -FQDNs @("example.com", "google.com") -DNSServers @("8.8.8.8", "1.1.1.1") `
            -QueriesPerSecond 100 -DurationSeconds 10 -TimeoutMilliseconds 2000 -CsvOutputPath "C:\Temp\DNSResults.csv"

    .NOTES
        Name: Invoke-DNSLoadTest
        Author: Ryan Whitlock
        Date: 04.22.2025
        Version: 1.0
        Changes: Initial Release
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidatePattern('^(?!:\/\/)(?=.{1,255}$)(([a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,63})$')]
        [string[]]$FQDNs,

        [Parameter(Mandatory)]
        [ValidateScript({
            foreach ($server in $_) {
                if ($server -notmatch '^(\d{1,3}\.){3}\d{1,3}$' -and 
                    $server -notmatch '^\[?([A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\]?$' -and 
                    $server -notmatch '^(?!:\/\/)(?=.{1,255}$)(([a-zA-Z0-9][a-zA-Z0-9-]{0,62}\.)+[a-zA-Z]{2,63})$') {
                    throw "Each DNS server must be a valid IPv4, IPv6, or FQDN."
                }
            }
            return $true
        })]
        [string[]]$DNSServers,

        [Parameter(Mandatory)]
        [ValidateScript({ if ($_ -lt 1) { throw "QueriesPerSecond must be at least 1." } else { $true } })]
        [int]$QueriesPerSecond,

        [ValidateScript({ if ($_ -lt 1) { throw "DurationSeconds must be at least 1 second." } else { $true } })]
        [int]$DurationSeconds = 10,

        [ValidateScript({ if ($_ -lt 100) { throw "TimeoutMilliseconds must be at least 100ms." } else { $true } })]
        [int]$TimeoutMilliseconds = 2000,

        [ValidateScript({
            if (![string]::IsNullOrEmpty($_) -and -not ($_ -match '^[a-zA-Z]:\\.*\.csv$')) {
                throw "CsvOutputPath must be a valid CSV file path (e.g., C:\Temp\Results.csv)."
            } else { $true }
        })]
        [string]$CsvOutputPath
    )

    begin {
        # Global counters
        $TotalQueries = 0
        $SuccessCount = 0
        $FailureCount = 0
        $Errors = @()
        $PerServerMetrics = @{}
        $OverallSumRT = 0
        $OverallSumSqRT = 0
        $OverallMinRT = [double]::MaxValue
        $OverallMaxRT = [double]::MinValue

        # Thread-safe bag for results (only if CSV output is needed)
        $ResultBag = if ($CsvOutputPath) { [System.Collections.Concurrent.ConcurrentBag[PSCustomObject]]::new() }

        # Buffer for batched console output
        $OutputBuffer = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $FlushInterval = 500  # milliseconds
        $LastFlushTime = [datetime]::MinValue

        # Color settings
        $global:serverColors = @{}
        $global:availableColors = @("Yellow", "Cyan", "Magenta", "Gray", "DarkYellow", "DarkCyan", "DarkMagenta", "White")
        function Get-ServerColor {
            param ([string]$ServerName)
            if (-not $global:serverColors.ContainsKey($ServerName)) {
                $unused = $global:availableColors | Where-Object { $global:serverColors.Values -notcontains $_ }
                if ($unused.Count -gt 0) {
                    $global:serverColors[$ServerName] = $unused | Get-Random
                } else {
                    $global:serverColors[$ServerName] = $global:availableColors | Get-Random
                }
            }
            return $global:serverColors[$ServerName]
        }

        function Resolve-DnsUdpPacket {
            <#
            .SYNOPSIS
                Issues a single DNS query over UDP and returns raw records plus the exact wire‑time duration.

            .DESCRIPTION
                Re‑implements the DNS client at packet level to avoid the overhead of Resolve‑DnsName.  Supports A / AAAA / CNAME / NS.

            .PARAMETER ServerIp
                Target DNS server IP (v4 or v6).

            .PARAMETER QueryName
                FQDN to resolve.

            .PARAMETER QueryType
                Record type (A, AAAA, CNAME, or NS).  Defaults to A.

            .PARAMETER TimeoutMs
                Timeout in milliseconds.  Defaults to 2000.

            .OUTPUTS
                [pscustomobject] with Records[], RCODE, Duration (ms), and Error (null if success).

            .NOTES
                Name: Resolve-DnsUdpPacket
                Author: Ryan Whitlock
                Date: 03.27.2025
                Version: 1.0
                Changes: Initial Release
            #>
            [CmdletBinding()]
            param (
                [Parameter(Mandatory)][string]$ServerIp,
                [Parameter(Mandatory)][string]$QueryName,
                [ValidateSet('A','AAAA','CNAME','NS')][string]$QueryType = 'A',
                [int]$TimeoutMs = 2000
            )
            begin {
                # Helper function to build the DNS query
                function Build-DnsQuery($QueryName, $typeCode) {
                    $id = Get-Random -Maximum 0xFFFF
                    $header = [System.Collections.Generic.List[byte]]::new()
                    $header.AddRange([byte[]](
                        [byte]($id -shr 8), [byte]($id -band 0xFF),
                        0x01, 0x00,  # Flags: standard query
                        0x00, 0x01,  # QDCOUNT=1
                        0x00, 0x00,  # ANCOUNT=0
                        0x00, 0x00,  # NSCOUNT=0
                        0x00, 0x00   # ARCOUNT=0
                    ))

                    $question = [System.Collections.Generic.List[byte]]::new()
                    $labels = $QueryName.Split('.')
                    foreach ($label in $labels) {
                        $len = [byte]$label.Length
                        $question.Add($len)
                        $question.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
                    }
                    $question.Add(0x00)  # End of labels
                    $question.AddRange([byte[]](
                        [byte]($typeCode -shr 8), [byte]($typeCode -band 0xFF),
                        0x00, 0x01  # Class IN
                    ))

                    $payload = [System.Collections.Generic.List[byte]]::new()
                    $payload.AddRange($header)
                    $payload.AddRange($question)
                    return $payload.ToArray()
                }

                # Helper function to send the DNS query and receive the response
                function Send-DnsQuery {
                    param (
                        [string]$ServerIp,
                        [byte[]]$payload,
                        [int]$TimeoutMs
                    )
                    $Client = [System.Net.Sockets.UdpClient]::new()
                    try {
                        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                        # Send the query
                        $sendTask = $Client.SendAsync($payload, $payload.Length, $ServerIp, 53)
                        $sendTask.GetAwaiter().GetResult()

                        # Receive the response
                        $recvTask = $Client.ReceiveAsync()
                        if ($recvTask.Wait($TimeoutMs)) {
                            $buffer = $recvTask.Result.Buffer
                            $stopwatch.Stop()
                            return @{
                                Buffer = $buffer
                                Duration = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
                                Error = $null
                            }
                        } else {
                            $stopwatch.Stop()
                            return @{
                                Buffer = $null
                                Duration = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
                                Error = "Timeout"
                            }
                        }
                    } catch {
                        $stopwatch.Stop()
                        return @{
                            Buffer = $null
                            Duration = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
                            Error = $_.Exception.Message
                        }
                    } finally {
                        $Client.Dispose()
                    }
                }

                # Helper function to read a 16-bit unsigned integer (big-endian)
                function ReadUInt16($buffer, [ref]$offset) {
                    $value = ($buffer[$offset.Value] -shl 8) + $buffer[$offset.Value + 1]
                    $offset.Value += 2
                    return $value
                }

                # Helper function to read a 32-bit unsigned integer (big-endian)
                function ReadUInt32($buffer, [ref]$offset) {
                    $value = ($buffer[$offset.Value] -shl 24) + ($buffer[$offset.Value + 1] -shl 16) + ($buffer[$offset.Value + 2] -shl 8) + $buffer[$offset.Value + 3]
                    $offset.Value += 4
                    return $value
                }

                # Helper function to read a DNS name (handles compression)
                function Read-DnsName($buffer, [ref]$offset, $maxDepth = 10) {
                    if ($maxDepth -le 0) { throw "Max recursion depth reached" }
                    $nameParts = @()
                    while ($true) {
                        $len = $buffer[$offset.Value]
                        if ($len -eq 0) {
                            $offset.Value++
                            break
                        }
                        if ($len -band 0xC0) {  # Pointer
                            $pointer = (($len -band 0x3F) -shl 8) + $buffer[$offset.Value + 1]
                            $offset.Value += 2
                            $ptrOffset = $pointer
                            $ptrName = Read-DnsName $buffer ([ref]$ptrOffset) ($maxDepth - 1)
                            $nameParts += $ptrName
                            break
                        } else {
                            $offset.Value++
                            $label = [System.Text.Encoding]::ASCII.GetString($buffer, $offset.Value, $len)
                            $nameParts += $label
                            $offset.Value += $len
                        }
                    }
                    return $nameParts -join '.'
                }

                # Function to parse the DNS response
                function Parse-DnsResponse($buffer) {
                    $offset = 0
                    # Parse header
                    $id = ReadUInt16 $buffer ([ref]$offset)
                    $flags = ReadUInt16 $buffer ([ref]$offset)
                    $rcode = $flags -band 0x0F
                    $qdcount = ReadUInt16 $buffer ([ref]$offset)
                    $ancount = ReadUInt16 $buffer ([ref]$offset)
                    $nscount = ReadUInt16 $buffer ([ref]$offset)
                    $arcount = ReadUInt16 $buffer ([ref]$offset)

                    # Skip question section
                    for ($i = 0; $i -lt $qdcount; $i++) {
                        $name = Read-DnsName $buffer ([ref]$offset)
                        $type = ReadUInt16 $buffer ([ref]$offset)
                        $class = ReadUInt16 $buffer ([ref]$offset)
                    }

                    # Parse resource records
                    $records = @()

                    # Answers
                    for ($i = 0; $i -lt $ancount; $i++) {
                        $rr = Parse-RR $buffer ([ref]$offset) "Answer"
                        $records += $rr
                    }

                    # Authority
                    for ($i = 0; $i -lt $nscount; $i++) {
                        $rr = Parse-RR $buffer ([ref]$offset) "Authority"
                        $records += $rr
                    }

                    # Additional
                    for ($i = 0; $i -lt $arcount; $i++) {
                        $rr = Parse-RR $buffer ([ref]$offset) "Additional"
                        $records += $rr
                    }

                    return @{
                        Records = $records
                        RCODE = $rcode
                    }
                }

                # Function to parse a single resource record
                function Parse-RR($buffer, [ref]$offset, $section) {
                    $name = Read-DnsName $buffer $offset
                    $type = ReadUInt16 $buffer $offset
                    $class = ReadUInt16 $buffer $offset
                    $ttl = ReadUInt32 $buffer $offset
                    $dataLength = ReadUInt16 $buffer $offset
                    $data = $null

                    # Handle different record types
                    if ($type -eq 1) {  # A
                        $ipBytes = $buffer[($offset.Value)..($offset.Value + 3)]
                        $data = $ipBytes -join '.'
                        $offset.Value += 4
                    } elseif ($type -eq 28) {  # AAAA
                        $ipBytes = $buffer[($offset.Value)..($offset.Value + 15)]
                        $data = ($ipBytes | ForEach-Object { $_.ToString("X2") }) -join ':'
                        $offset.Value += 16
                    } elseif ($type -eq 5 -or $type -eq 2) {  # CNAME or NS
                        $data = Read-DnsName $buffer $offset
                    } else {
                        # For other types, read as bytes
                        $data = $buffer[($offset.Value)..($offset.Value + $dataLength - 1)]
                        $offset.Value += $dataLength
                    }

                    # Map type to string
                    $typeStr = switch ($type) {
                        1 { "A" }
                        28 { "AAAA" }
                        5 { "CNAME" }
                        2 { "NS" }
                        default { "Type$($type)" }
                    }

                    return [PSCustomObject]@{
                        Name = $name
                        Type = $typeStr
                        TTL = $ttl
                        DataLength = $dataLength
                        Section = $section
                        Data = $data
                    }
                }
            }

            process {
                # Map QueryType to numeric value
                $typeMap = @{
                    "A" = 1
                    "AAAA" = 28
                    "CNAME" = 5
                    "NS" = 2
                    # Add more types as needed
                }
                $typeCode = $typeMap[$QueryType]
                if (-not $typeCode) { throw "Unsupported query type: $QueryType" }

                # Build the DNS query
                $payload = Build-DnsQuery $QueryName $typeCode

                # Send the query and receive the response
                $result = Send-DnsQuery $ServerIp $payload $TimeoutMs

                if ($result.Error) {
                    return [PSCustomObject]@{
                        Records = @()
                        RCODE = $null
                        Duration = $result.Duration
                        Error = $result.Error
                    }
                }

                # Parse the DNS response
                $parsed = Parse-DnsResponse $result.Buffer

                return [PSCustomObject]@{
                    Records = $parsed.Records
                    RCODE = $parsed.RCODE
                    Duration = $result.Duration
                    Error = $null
                }
            }
        }

        # DNS query function
        function Test-DNSQuery {
            param($FQDN, $DNSServer, $TimeoutMilliseconds)

            try {
                $DnsUdpPacket = Resolve-DnsUdpPacket -QueryName $FQDN -ServerIp $DNSServer -TimeoutMs $TimeoutMilliseconds -ErrorAction Stop     
                return [PSCustomObject]@{
                    Timestamp    = Get-Date
                    DNS_Server   = $DNSServer
                    FQDN         = $FQDN
                    Success      = $true
                    ResponseTime = $DnsUdpPacket.Duration
                    ErrorMessage = $null
                }
            } catch {
                return [PSCustomObject]@{
                    Timestamp    = Get-Date
                    DNS_Server   = $DNSServer
                    FQDN         = $FQDN
                    Success      = $false
                    ResponseTime = $null
                    ErrorMessage = $_.Exception.Message
                }
            }
        }

        # Setup runspace pool
        $DynamicMaxConcurrentThreads = [Math]::Max(1, [Math]::Ceiling($QueriesPerSecond / 2))
        $ISS = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $ISS.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "Resolve-DnsUdpPacket", ${function:Resolve-DnsUdpPacket}))
        $ISS.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList "Test-DNSQuery", ${function:Test-DNSQuery}))
        $RunspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($ISS)
        $RunspacePool.SetMinRunspaces(1) | Out-Null
        $RunspacePool.SetMaxRunspaces($DynamicMaxConcurrentThreads) | Out-Null
        $RunspacePool.Open()

        # Pre-create PowerShell instances
        $LocalScriptBlock = { 
            param($FQDN, $DNSServer, $TimeoutMilliseconds) 
            Test-DNSQuery -FQDN $FQDN -DNSServer $DNSServer -TimeoutMilliseconds $TimeoutMilliseconds 
        }
        $PowerShellPool = New-Object 'System.Collections.Generic.List[powershell]'
        for ($i = 0; $i -lt $DynamicMaxConcurrentThreads; $i++) {
            $psInstance = [powershell]::Create().AddScript($LocalScriptBlock)
            $psInstance.RunspacePool = $RunspacePool
            $PowerShellPool.Add($psInstance)
        }
        $AvailablePowerShellInstances = [System.Collections.Concurrent.ConcurrentQueue[powershell]]::new($PowerShellPool)
        $ActiveRunspaces = New-Object 'System.Collections.Generic.List[object]'

        $QueryInterval = 1000 / $QueriesPerSecond
        $TotalQueriesToSchedule = $QueriesPerSecond * $DurationSeconds
    }

    process {
        # Warm-up phase: Initialize runspaces with dummy queries
        $warmUpQueries = $DynamicMaxConcurrentThreads
        $warmUpActiveRunspaces = New-Object 'System.Collections.Generic.List[object]'

        for ($i = 0; $i -lt $warmUpQueries; $i++) {
            $fqdn = $FQDNs[$i % $FQDNs.Count]
            $dnss = $DNSServers[$i % $DNSServers.Count]

            # Get a PowerShell instance from the pool
            [powershell]$psInstance = $null
            while (-not $AvailablePowerShellInstances.TryDequeue([ref]$psInstance)) {
                Start-Sleep -Milliseconds 1
            }
            $psInstance.Commands.Clear()
            $psInstance.AddScript($LocalScriptBlock).AddArgument($fqdn).AddArgument($dnss).AddArgument($TimeoutMilliseconds) | Out-Null
            $handle = $psInstance.BeginInvoke()
            $warmUpActiveRunspaces.Add([PSCustomObject]@{ Pipeline = $psInstance; Handle = $handle; StartTime = (Get-Date); FQDN = $fqdn; DNSServer = $dnss })
        }

        # Wait for all warm-up queries to complete and return instances to the pool
        while ($warmUpActiveRunspaces.Count -gt 0) {
            $Completed = $warmUpActiveRunspaces | Where-Object { $_.Handle.IsCompleted }
            foreach ($r in $Completed) {
                # End the invocation and discard the result
                $r.Pipeline.EndInvoke($r.Handle) | Out-Null
                # Reset and return the PowerShell instance to the pool
                $r.Pipeline.Commands.Clear()
                $r.Pipeline.AddScript($LocalScriptBlock) | Out-Null
                $AvailablePowerShellInstances.Enqueue($r.Pipeline)
                $warmUpActiveRunspaces.Remove($r) | Out-Null
            }
            Start-Sleep -Milliseconds 5
        }

        # Proceed with the actual test
        $startTime = Get-Date
        for ($i = 0; $i -lt $TotalQueriesToSchedule; $i++) {
            $targetTime = $startTime.AddMilliseconds($i * $QueryInterval)
            $timeToWait = ($targetTime - (Get-Date)).TotalMilliseconds
            if ($timeToWait -gt 0) { Start-Sleep -Milliseconds $timeToWait }

            $totalCombos = $FQDNs.Count * $DNSServers.Count
            $comboIndex = $i % $totalCombos
            $fqdn = $FQDNs[$comboIndex % $FQDNs.Count]
            $dnss = $DNSServers[[Math]::Floor($comboIndex / $FQDNs.Count) % $DNSServers.Count]

            while ($ActiveRunspaces.Count -ge $DynamicMaxConcurrentThreads) {
                $Completed = $ActiveRunspaces | Where-Object { $_.Handle.IsCompleted }
                foreach ($r in $Completed) {
                    $result = $r.Pipeline.EndInvoke($r.Handle)
                    $TotalQueries++
                    if (-not $PerServerMetrics.ContainsKey($result.DNS_Server)) {
                        $PerServerMetrics[$result.DNS_Server] = @{ Queries = 0; Success = 0; Failure = 0; SumRT = 0; SumSqRT = 0; MinRT = [double]::MaxValue; MaxRT = [double]::MinValue }
                    }
                    $server = $PerServerMetrics[$result.DNS_Server]
                    $server.Queries++
                    if ($result.Success) {
                        $SuccessCount++
                        $rt = $result.ResponseTime
                        $server.Success++
                        $server.SumRT += $rt
                        $server.SumSqRT += $rt * $rt
                        if ($rt -lt $server.MinRT) { $server.MinRT = $rt }
                        if ($rt -gt $server.MaxRT) { $server.MaxRT = $rt }
                        $OverallSumRT += $rt
                        $OverallSumSqRT += $rt * $rt
                        if ($rt -lt $OverallMinRT) { $OverallMinRT = $rt }
                        if ($rt -gt $OverallMaxRT) { $OverallMaxRT = $rt }
                    } else {
                        $FailureCount++
                        $server.Failure++
                        $Errors += $result.ErrorMessage
                    }
                    if ($CsvOutputPath) { $ResultBag.Add($result) }

                    # Generate output string and add to buffer
                    $color = Get-ServerColor -ServerName $result.DNS_Server
                    $avg = if ($server.Success -gt 0) { [math]::Round($server.SumRT / $server.Success, 2) } else { 0 }
                    $variance = if ($server.Success -gt 0) { ($server.SumSqRT / $server.Success) - ($avg * $avg) } else { 0 }
                    $stddev = if ($server.Success -gt 0) { [math]::Round([math]::Sqrt($variance), 2) } else { 0 }
                    $min = if ($server.Success -gt 0) { $server.MinRT } else { 0 }
                    $max = if ($server.Success -gt 0) { $server.MaxRT } else { 0 }
                    $currentRT = if ($result.ResponseTime -ne $null) { $result.ResponseTime } else { "Error" }
                    $outputString = ("[{0}] {1} | Domain: {2,-25} | Total: {3,5} | Current RT: {4,8} | Success: {5,6}% | Avg: {6,8}ms | Min: {7,8}ms | Max: {8,8}ms | StdDev: {9,8}ms" -f `
                        $result.DNS_Server, (Get-Date -Format "HH:mm:ss"), $result.FQDN, $TotalQueries, $currentRT, `
                        [math]::Round(($SuccessCount / $TotalQueries) * 100, 2), $avg, $min, $max, $stddev)
                    $OutputBuffer.Add([PSCustomObject]@{ Text = $outputString; Color = $color })

                    # Return the PowerShell instance to the pool after resetting
                    $r.Pipeline.Commands.Clear()
                    $r.Pipeline.AddScript($LocalScriptBlock) | Out-Null
                    $AvailablePowerShellInstances.Enqueue($r.Pipeline)
                    $ActiveRunspaces.Remove($r) | Out-Null
                }
                # Flush output buffer if interval has passed
                if ((Get-Date) -ge $LastFlushTime.AddMilliseconds($FlushInterval)) {
                    foreach ($item in $OutputBuffer) {
                        Write-Host $item.Text -ForegroundColor $item.Color
                    }
                    $OutputBuffer.Clear()
                    $LastFlushTime = Get-Date
                }
                Start-Sleep -Milliseconds 5
            }

            # Reuse a PowerShell instance from the pool
            [powershell]$psInstance = $null
            while (-not $AvailablePowerShellInstances.TryDequeue([ref]$psInstance)) {
                Start-Sleep -Milliseconds 1
            }
            $psInstance.Commands.Clear()  # Clear previous arguments
            $psInstance.AddScript($LocalScriptBlock).AddArgument($fqdn).AddArgument($dnss).AddArgument($TimeoutMilliseconds) | Out-Null
            $handle = $psInstance.BeginInvoke()
            $ActiveRunspaces.Add([PSCustomObject]@{ Pipeline = $psInstance; Handle = $handle; StartTime = (Get-Date); FQDN = $fqdn; DNSServer = $dnss })
        }

        while ($ActiveRunspaces.Count -gt 0) {
            $Completed = $ActiveRunspaces | Where-Object { $_.Handle.IsCompleted }
            foreach ($r in $Completed) {
                $result = $r.Pipeline.EndInvoke($r.Handle)
                $TotalQueries++
                if (-not $PerServerMetrics.ContainsKey($result.DNS_Server)) {
                    $PerServerMetrics[$result.DNS_Server] = @{ Queries = 0; Success = 0; Failure = 0; SumRT = 0; SumSqRT = 0; MinRT = [double]::MaxValue; MaxRT = [double]::MinValue }
                }
                $server = $PerServerMetrics[$result.DNS_Server]
                $server.Queries++
                if ($result.Success) {
                    $SuccessCount++
                    $rt = $result.ResponseTime
                    $server.Success++
                    $server.SumRT += $rt
                    $server.SumSqRT += $rt * $rt
                    if ($rt -lt $server.MinRT) { $server.MinRT = $rt }
                    if ($rt -gt $server.MaxRT) { $server.MaxRT = $rt }
                    $OverallSumRT += $rt
                    $OverallSumSqRT += $rt * $rt
                    if ($rt -lt $OverallMinRT) { $OverallMinRT = $rt }
                    if ($rt -gt $OverallMaxRT) { $OverallMaxRT = $rt }
                } else {
                    $FailureCount++
                    $server.Failure++
                    $Errors += $result.ErrorMessage
                }
                if ($CsvOutputPath) { $ResultBag.Add($result) }

                # Generate output string and add to buffer
                $color = Get-ServerColor -ServerName $result.DNS_Server
                $avg = if ($server.Success -gt 0) { [math]::Round($server.SumRT / $server.Success, 2) } else { 0 }
                $variance = if ($server.Success -gt 0) { ($server.SumSqRT / $server.Success) - ($avg * $avg) } else { 0 }
                $stddev = if ($server.Success -gt 0) { [math]::Round([math]::Sqrt($variance), 2) } else { 0 }
                $min = if ($server.Success -gt 0) { $server.MinRT } else { 0 }
                $max = if ($server.Success -gt 0) { $server.MaxRT } else { 0 }
                $currentRT = if ($result.ResponseTime -ne $null) { $result.ResponseTime } else { "Error" }
                $outputString = ("[{0}] {1} | Domain: {2,-25} | Total: {3,5} | Current RT: {4,8} | Success: {5,6}% | Avg: {6,8}ms | Min: {7,8}ms | Max: {8,8}ms | StdDev: {9,8}ms" -f `
                    $result.DNS_Server, (Get-Date -Format "HH:mm:ss"), $result.FQDN, $TotalQueries, $currentRT, `
                    [math]::Round(($SuccessCount / $TotalQueries) * 100, 2), $avg, $min, $max, $stddev)
                $OutputBuffer.Add([PSCustomObject]@{ Text = $outputString; Color = $color })

                # Return the PowerShell instance to the pool after resetting
                $r.Pipeline.Commands.Clear()
                $r.Pipeline.AddScript($LocalScriptBlock) | Out-Null
                $AvailablePowerShellInstances.Enqueue($r.Pipeline)
                $ActiveRunspaces.Remove($r) | Out-Null
            }
            # Flush output buffer if interval has passed
            if ((Get-Date) -ge $LastFlushTime.AddMilliseconds($FlushInterval)) {
                foreach ($item in $OutputBuffer) {
                    Write-Host $item.Text -ForegroundColor $item.Color
                }
                $OutputBuffer.Clear()
                $LastFlushTime = Get-Date
            }
            Start-Sleep -Milliseconds 5
        }
    }

    end {
        # Flush any remaining output
        if ($OutputBuffer.Count -gt 0) {
            foreach ($item in $OutputBuffer) {
                Write-Host $item.Text -ForegroundColor $item.Color
            }
            $OutputBuffer.Clear()
        }

        # Clean up PowerShell instances and runspace pool
        foreach ($ps in $PowerShellPool) {
            $ps.Dispose()
        }
        $RunspacePool.Close()
        $RunspacePool.Dispose()

        # Compute overall metrics
        $OverallAvg = if ($SuccessCount -gt 0) { [math]::Round($OverallSumRT / $SuccessCount, 2) } else { 0 }
        $OverallVariance = if ($SuccessCount -gt 0) { ($OverallSumSqRT / $SuccessCount) - ($OverallAvg * $OverallAvg) } else { 0 }
        $OverallStdDev = if ($SuccessCount -gt 0) { [math]::Round([math]::Sqrt($OverallVariance), 2) } else { 0 }
        $OverallMin = if ($SuccessCount -gt 0) { $OverallMinRT } else { 0 }
        $OverallMax = if ($SuccessCount -gt 0) { $OverallMaxRT } else { 0 }

        # Create summary object
        $Summary = [PSCustomObject]@{
            TotalQueries               = $TotalQueries
            SuccessCount               = $SuccessCount
            FailureCount               = $FailureCount
            OverallAverageResponseTime = $OverallAvg
            OverallMinResponseTime     = $OverallMin
            OverallMaxResponseTime     = $OverallMax
            OverallStdDevResponseTime  = $OverallStdDev
            PerServerMetrics           = @()
            PerFQDNMetrics             = @()
            Errors                     = $Errors
        }

        # Populate per-server metrics
        foreach ($server in $PerServerMetrics.Keys) {
            $s = $PerServerMetrics[$server]
            $avg = if ($s.Success -gt 0) { [math]::Round($s.SumRT / $s.Success, 2) } else { 0 }
            $variance = if ($s.Success -gt 0) { ($s.SumSqRT / $s.Success) - ($avg * $avg) } else { 0 }
            $stddev = if ($s.Success -gt 0) { [math]::Round([math]::Sqrt($variance), 2) } else { 0 }
            $min = if ($s.Success -gt 0) { $s.MinRT } else { 0 }
            $max = if ($s.Success -gt 0) { $s.MaxRT } else { 0 }
            $Summary.PerServerMetrics += [PSCustomObject]@{
                DNS_Server   = $server
                TotalQueries = $s.Queries
                Success      = $s.Success
                Failure      = $s.Failure
                AverageRT    = $avg
                MinRT        = $min
                MaxRT        = $max
                StdDevRT     = $stddev
            }
        }

        foreach ($Key in $PerFQDNMetrics.Keys) {
            $D = $PerFQDNMetrics[$Key]
            $Avg = if ($D.Success) { [math]::Round($D.SumRT / $D.Success,2) } else { 0 }
            $Var = if ($D.Success) { ($D.SumSqRT / $D.Success) - ($Avg*$Avg) } else { 0 }
            $Std = if ($D.Success) { [math]::Round([math]::Sqrt($Var),2) } else { 0 }
            $Summary.PerFQDNMetrics += [pscustomobject]@{
                FQDN         = $Key
                TotalQueries = $D.Queries
                Success      = $D.Success
                Failure      = $D.Failure
                AverageRT    = $Avg
                MinRT        = if ($D.Success) { $D.MinRT } else { 0 }
                MaxRT        = if ($D.Success) { $D.MaxRT } else { 0 }
                StdDevRT     = $Std
            }
        }

        # Performance checks
        $FinalCPU = (Get-Counter '\Processor(_Total)\% Processor Time').CounterSamples.CookedValue
        $FinalMemory = (Get-Counter '\Memory\Available MBytes').CounterSamples.CookedValue
        if ($FinalCPU -gt 85) { Write-Host "🚨 Client bottleneck detected: High CPU usage ($FinalCPU%)" -ForegroundColor Red }
        if ($FinalMemory -lt 500) { Write-Host "🚨 Client bottleneck detected: Low available memory ($FinalMemory MB)" -ForegroundColor Red }
        if ($OverallAvg -gt 200) { Write-Host "⚠️  Server bottleneck detected: High response time ($OverallAvg ms)" -ForegroundColor Yellow }

        # Export to CSV if specified
        if ($CsvOutputPath) { $ResultBag | Export-Csv -Path $CsvOutputPath -NoTypeInformation }

        return $Summary
    }
}
