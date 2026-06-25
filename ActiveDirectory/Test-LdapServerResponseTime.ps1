function Test-TargetFileLock {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $parentPath = Split-Path -Path $Path -Parent    
    if ([string]::IsNullOrWhiteSpace($parentPath)) { $parentPath = ".\" }

    if (-not (Test-Path -Path $parentPath)) {
        throw "Path Error: The destination directory '$parentPath' does not exist."
    }

    if (Test-Path -Path $Path -PathType Leaf) {
        try {
            $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
            $stream.Close()
            return $true
        }
        catch {
            throw "File Lock Error: The file '$Path' is currently open in another program. Please close it."
        }
    }

    return $true
}

function Test-LdapServerResponseTime {
    <#
    .SYNOPSIS
        Tests LDAP server response time using timed LDAP search requests.

    .DESCRIPTION
        Performs repeated LDAP RootDSE searches against one or more LDAP servers and reports
        realtime latency, rolling statistics, Welford cumulative statistics, success percentage,
        percentile latency, actual QPS, elapsed timing, and optional per-request CSV output.

        Measurement intentionally excludes:
            - Runspace creation
            - LdapConnection creation
            - Bind/setup
            - Warmup requests
            - Console output
            - CSV export
            - Response validation from the RT measurement

        The RT stopwatch measures only the LDAP SendRequest() call.

        A request is counted as successful only when:
            - SendRequest() completes
            - The response is a SearchResponse
            - The LDAP ResultCode is Success
            - At least one entry is returned
            - defaultNamingContext is present and populated

        Invalid responses count as failures and do not contribute to RT, Avg, Min, Max, StdDev,
        P50, P95, or P99.

    .PARAMETER Servers
        One or more LDAP servers to test.

    .PARAMETER TestDuration
        Number of measured seconds to run after warmup completes.

    .PARAMETER WarmupSeconds
        Number of seconds to send warmup requests before recording metrics.

    .PARAMETER Protocol
        LDAP, LDAPS, GC, or GCSSL.

    .PARAMETER QPS
        Queries per second per server during warmup and measurement.

    .PARAMETER RollingWindowSize
        Number of recent measured attempts used for rolling success percentage.
        Only successful validated responses contribute to rolling latency metrics.

    .PARAMETER CsvPath
        Optional path for per-request CSV output. Warmup requests are not exported.

    .PARAMETER CsvSummaryPath
        Optional path for per-server summary CSV output. One row per server containing
        the same fields returned in the summary objects written to the pipeline.

    .EXAMPLE
        $params = @{
            Servers = @(
                "ldap1.example.com",
                "ldap2.example.com"
            )
            Protocol          = "LDAP"
            TestDuration      = 60
            WarmupSeconds     = 5
            QPS               = 1
            RollingWindowSize = 20
            CsvPath           = "C:\Temp\ldap-latency.csv"
            CsvSummaryPath    = "C:\Temp\ldap-summary.csv"
        }

        Test-LdapServerResponseTime @params

    .NOTES
        Name: Test-LdapServerResponseTime
        Author: Ryan Whitlock
        Date: 06.25.2025
        Version: 4
        Changes:
            v4: Added CsvSummaryPath parameter for per-server summary CSV export.
            v3: Simplified Calculate-Metrics into Get-WindowMetrics/Get-WelfordMetrics,
                merged Get-RollingSuccessPercent into Get-SuccessPercent, inlined
                Add-RollingValue, removed one-shot splatting for internal helper calls.
            v2: QPS is per server. Testing 4 servers with -QPS 2 sends roughly 8 total
                LDAP requests per second.
    #>

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Servers,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 86400)]
        [int]$TestDuration = 30,

        [Parameter(Mandatory = $false)]
        [ValidateRange(0, 3600)]
        [int]$WarmupSeconds = 5,

        [Parameter(Mandatory = $false)]
        [ValidateSet("LDAP", "LDAPS", "GC", "GCSSL")]
        [string]$Protocol = "LDAP",

        [Parameter(Mandatory = $false)]
        [ValidateRange(0.001, 1000)]
        [double]$QPS = 1,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 100000)]
        [int]$RollingWindowSize = 20,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-TargetFileLock -Path $_ })]
        [string]$CsvPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-TargetFileLock -Path $_ })]
        [string]$CsvSummaryPath
    )

    Begin {
        $serverList = New-Object 'System.Collections.Generic.List[string]'

        $serverColors = @{}
        $availableColors = @(
            "Yellow",
            "Cyan",
            "Magenta",
            "Gray",
            "DarkYellow",
            "DarkCyan",
            "DarkMagenta",
            "White"
        )

        function Get-ServerColor {
            param (
                [Parameter(Mandatory = $true)]
                [string]$ServerName
            )
 
            if (-not $serverColors.ContainsKey($ServerName)) {
                $usedColors  = @($serverColors.Values)
                $unassigned  = @($availableColors | Where-Object { $usedColors -notcontains $_ })
 
                if ($unassigned.Count -gt 0) {
                    $serverColors[$ServerName] = $unassigned[(Get-Random -Minimum 0 -Maximum $unassigned.Count)]
                }
                else {
                    # More servers than colors - cycle by assignment order
                    $serverColors[$ServerName] = $availableColors[$serverColors.Count % $availableColors.Count]
                }
            }
 
            return $serverColors[$ServerName]
        }

        function Invoke-LdapLatencyWorker {
            param (
                [Parameter(Mandatory = $true)]
                [string]$Server,

                [Parameter(Mandatory = $true)]
                [string]$Protocol,

                [Parameter(Mandatory = $true)]
                [int]$TestDuration,

                [Parameter(Mandatory = $true)]
                [int]$WarmupSeconds,

                [Parameter(Mandatory = $true)]
                [double]$QPS,

                [Parameter(Mandatory = $true)]
                [int]$RollingWindowSize,

                [Parameter(Mandatory = $true)]
                [System.Collections.Concurrent.ConcurrentQueue[object]]$Queue,

                [Parameter(Mandatory = $true)]
                [System.Collections.Concurrent.ConcurrentBag[object]]$ResultBag,

                [Parameter(Mandatory = $true)]
                [System.Collections.Concurrent.ConcurrentBag[object]]$DetailBag
            )

            # Returns latency statistics computed over a sliding window queue.
            function Get-WindowMetrics {
                param (
                    [Parameter(Mandatory = $true)]
                    [System.Collections.Generic.Queue[double]]$Window
                )

                if ($Window.Count -eq 0) {
                    return [pscustomobject]@{ Avg = 0; Min = 0; Max = 0; StdDev = 0 }
                }

                $sum    = 0.0
                $sumSq  = 0.0
                $wMin   = [double]::MaxValue
                $wMax   = [double]::MinValue

                foreach ($v in $Window) {
                    $sum   += $v
                    $sumSq += $v * $v
                    if ($v -lt $wMin) { $wMin = $v }
                    if ($v -gt $wMax) { $wMax = $v }
                }

                $n   = $Window.Count
                $avg = $sum / $n
                $var = ($sumSq / $n) - ($avg * $avg)

                return [pscustomobject]@{
                    Avg    = [math]::Round($avg, 2)
                    Min    = [math]::Round($wMin, 2)
                    Max    = [math]::Round($wMax, 2)
                    StdDev = [math]::Round([math]::Sqrt([math]::Max($var, 0)), 2)
                }
            }

            # Returns latency statistics from Welford online algorithm accumulators.
            function Get-WelfordMetrics {
                param (
                    [Parameter(Mandatory = $true)]
                    [double]$Mean,

                    [Parameter(Mandatory = $true)]
                    [double]$M2,

                    [Parameter(Mandatory = $true)]
                    [int]$Success,

                    [Parameter(Mandatory = $true)]
                    [double]$Min,

                    [Parameter(Mandatory = $true)]
                    [double]$Max
                )

                if ($Success -le 0) {
                    return [pscustomobject]@{ Avg = 0; Min = 0; Max = 0; StdDev = 0 }
                }

                return [pscustomobject]@{
                    Avg    = [math]::Round($Mean, 2)
                    Min    = [math]::Round($Min, 2)
                    Max    = [math]::Round($Max, 2)
                    StdDev = [math]::Round([math]::Sqrt([math]::Max($M2 / $Success, 0)), 2)
                }
            }

            # Computes success percentage from a success count and total attempts.
            # Pass a Queue[int] of 0/1 values as -Window to compute rolling success percentage instead.
            function Get-SuccessPercent {
                param (
                    [Parameter(Mandatory = $true, ParameterSetName = "Cumulative")]
                    [int]$Success,

                    [Parameter(Mandatory = $true, ParameterSetName = "Cumulative")]
                    [int]$Attempts,

                    [Parameter(Mandatory = $true, ParameterSetName = "Rolling")]
                    [System.Collections.Generic.Queue[int]]$Window
                )

                if ($PSCmdlet.ParameterSetName -eq "Rolling") {
                    if ($Window.Count -eq 0) { return 0 }
                    $successCount = 0
                    foreach ($v in $Window) { if ($v -eq 1) { $successCount++ } }
                    return [math]::Round(($successCount / $Window.Count) * 100, 2)
                }

                if ($Attempts -le 0) { return 0 }
                return [math]::Round(($Success / $Attempts) * 100, 2)
            }

            function Get-Percentile {
                param (
                    [Parameter(Mandatory = $true)]
                    [AllowEmptyCollection()]
                    [double[]]$Values,

                    [Parameter(Mandatory = $true)]
                    [ValidateRange(0, 100)]
                    [double]$Percentile
                )

                if ($null -eq $Values -or $Values.Count -eq 0) {
                    return 0
                }

                $sortedValues = @($Values | Sort-Object)

                if ($sortedValues.Count -eq 1) {
                    return [math]::Round($sortedValues[0], 2)
                }

                $rank  = [math]::Ceiling(($Percentile / 100) * $sortedValues.Count)
                $index = [math]::Max(0, [math]::Min($rank - 1, $sortedValues.Count - 1))

                return [math]::Round($sortedValues[$index], 2)
            }

            function Wait-UntilDue {
                param (
                    [Parameter(Mandatory = $true)]
                    [datetime]$DueTimeUtc
                )

                $remainingMs = ($DueTimeUtc - [datetime]::UtcNow).TotalMilliseconds

                if ($remainingMs -gt 0) {
                    Start-Sleep -Milliseconds ([int][math]::Ceiling($remainingMs))
                }
            }

            function Test-LdapSearchResponse {
                param (
                    [Parameter(Mandatory = $true)]
                    [object]$Response
                )

                if ($Response -isnot [System.DirectoryServices.Protocols.SearchResponse]) {
                    return [pscustomobject]@{
                        IsValid = $false
                        Reason  = "Response was not a SearchResponse."
                    }
                }

                if ($Response.ResultCode -ne [System.DirectoryServices.Protocols.ResultCode]::Success) {
                    return [pscustomobject]@{
                        IsValid = $false
                        Reason  = "LDAP ResultCode was $($Response.ResultCode)."
                    }
                }

                if ($Response.Entries.Count -lt 1) {
                    return [pscustomobject]@{
                        IsValid = $false
                        Reason  = "SearchResponse did not contain any entries."
                    }
                }

                $entry     = $Response.Entries[0]
                $attribute = $entry.Attributes["defaultNamingContext"]

                if ($null -eq $attribute) {
                    return [pscustomobject]@{
                        IsValid = $false
                        Reason  = "RootDSE response did not include defaultNamingContext."
                    }
                }

                if ($attribute.Count -lt 1) {
                    return [pscustomobject]@{
                        IsValid = $false
                        Reason  = "defaultNamingContext was present but empty."
                    }
                }

                return [pscustomobject]@{
                    IsValid = $true
                    Reason  = $null
                }
            }

            $ldapPorts = @{
                LDAP  = 389
                LDAPS = 636
                GC    = 3268
                GCSSL = 3269
            }

            $port   = $ldapPorts[$Protocol]
            $useSsl = $Protocol -in @("LDAPS", "GCSSL")

            $responseTimes = New-Object 'System.Collections.Generic.List[double]'

            $stats = [ordered]@{
                Attempts             = 0
                Success              = 0
                Failure              = 0
                Mean                 = 0.0
                M2                   = 0.0
                Min                  = [double]::MaxValue
                Max                  = [double]::MinValue
                TotalSendRequestMs   = 0.0
                ResponseTimes        = $responseTimes
                RollingLatencyWindow = New-Object 'System.Collections.Generic.Queue[double]'
                RollingSuccessWindow = New-Object 'System.Collections.Generic.Queue[int]'
            }

            $connection = $null

            try {
                Add-Type -AssemblyName System.DirectoryServices.Protocols

                $identifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(
                    $Server, $port, $false, $false
                )

                $connection = New-Object System.DirectoryServices.Protocols.LdapConnection($identifier)
                $connection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
                $connection.Timeout  = [TimeSpan]::FromSeconds(10)
                $connection.SessionOptions.SecureSocketLayer = $useSsl
                $connection.SessionOptions.ReferralChasing   = [System.DirectoryServices.Protocols.ReferralChasingOptions]::None

                $connection.Bind()

                $searchRequest = New-Object System.DirectoryServices.Protocols.SearchRequest(
                    "",
                    "(objectClass=*)",
                    [System.DirectoryServices.Protocols.SearchScope]::Base,
                    [string[]]@("defaultNamingContext")
                )

                $stopwatch = New-Object System.Diagnostics.Stopwatch
                $interval  = [TimeSpan]::FromMilliseconds(1000.0 / $QPS)

                [void]$Queue.Enqueue([pscustomobject]@{
                    MessageType = "Status"
                    Server      = $Server
                    Port        = $port
                    Protocol    = $Protocol
                    Text        = "Connected. Starting warmup for $WarmupSeconds second(s)."
                })

                function Invoke-OneRequest {
                    param (
                        [Parameter(Mandatory = $true)]
                        [bool]$RecordStats
                    )

                    $timestampLocal  = Get-Date
                    $sendRequestMs   = $null
                    $responseTimeMs  = $null
                    $isSuccess       = $false
                    $errorType       = $null
                    $errorMessage    = $null
                    $response        = $null

                    try {
                        $stopwatch.Restart()
                        $response = $connection.SendRequest($searchRequest)
                        $stopwatch.Stop()
                        $sendRequestMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
                    }
                    catch {
                        if ($stopwatch.IsRunning) { $stopwatch.Stop() }
                        $sendRequestMs = [math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
                        $errorType     = $_.Exception.GetType().FullName
                        $errorMessage  = $_.Exception.Message
                    }

                    if ($null -eq $errorType) {
                        $validation = Test-LdapSearchResponse -Response $response

                        if ($validation.IsValid) {
                            $responseTimeMs = $sendRequestMs
                            $isSuccess      = $true
                        }
                        else {
                            $errorType    = "InvalidLdapResponse"
                            $errorMessage = $validation.Reason
                        }
                    }

                    if (-not $RecordStats) { return }

                    $stats.Attempts++

                    if ($null -ne $sendRequestMs) {
                        $stats.TotalSendRequestMs += $sendRequestMs
                    }

                    if ($isSuccess) {
                        $stats.Success++

                        $delta       = $responseTimeMs - $stats.Mean
                        $stats.Mean += $delta / $stats.Success
                        $delta2      = $responseTimeMs - $stats.Mean
                        $stats.M2   += $delta * $delta2

                        if ($responseTimeMs -lt $stats.Min) { $stats.Min = $responseTimeMs }
                        if ($responseTimeMs -gt $stats.Max) { $stats.Max = $responseTimeMs }

                        [void]$stats.ResponseTimes.Add($responseTimeMs)

                        [void]$stats.RollingLatencyWindow.Enqueue($responseTimeMs)
                        while ($stats.RollingLatencyWindow.Count -gt $RollingWindowSize) {
                            [void]$stats.RollingLatencyWindow.Dequeue()
                        }

                        [void]$stats.RollingSuccessWindow.Enqueue(1)
                    }
                    else {
                        $stats.Failure++
                        [void]$stats.RollingSuccessWindow.Enqueue(0)
                    }

                    while ($stats.RollingSuccessWindow.Count -gt $RollingWindowSize) {
                        [void]$stats.RollingSuccessWindow.Dequeue()
                    }

                    $rollingMetrics    = Get-WindowMetrics  -Window $stats.RollingLatencyWindow
                    $cumulativeMetrics = Get-WelfordMetrics -Mean $stats.Mean -M2 $stats.M2 -Success $stats.Success -Min $stats.Min -Max $stats.Max

                    $sample = [pscustomobject]@{
                        MessageType              = "Sample"
                        TimestampLocal           = $timestampLocal
                        Server                   = $Server
                        Port                     = $port
                        Protocol                 = $Protocol
                        Attempt                  = $stats.Attempts
                        IsSuccess                = $isSuccess
                        ResponseTimeMs           = $responseTimeMs
                        SendRequestMs            = $sendRequestMs
                        ErrorType                = $errorType
                        ErrorMessage             = $errorMessage
                        AvgMs                    = $rollingMetrics.Avg
                        MinMs                    = $rollingMetrics.Min
                        MaxMs                    = $rollingMetrics.Max
                        StdDevMs                 = $rollingMetrics.StdDev
                        SuccessPercent           = Get-SuccessPercent -Window $stats.RollingSuccessWindow
                        CumulativeAvgMs          = $cumulativeMetrics.Avg
                        CumulativeMinMs          = $cumulativeMetrics.Min
                        CumulativeMaxMs          = $cumulativeMetrics.Max
                        CumulativeStdDevMs       = $cumulativeMetrics.StdDev
                        CumulativeSuccessPercent = Get-SuccessPercent -Success $stats.Success -Attempts $stats.Attempts
                    }

                    [void]$Queue.Enqueue($sample)
                    [void]$DetailBag.Add($sample)
                }

                $nextDueUtc = [datetime]::UtcNow.Add($interval)

                if ($WarmupSeconds -gt 0) {
                    $warmupEndUtc = [datetime]::UtcNow.AddSeconds($WarmupSeconds)

                    while ([datetime]::UtcNow -lt $warmupEndUtc) {
                        Wait-UntilDue -DueTimeUtc $nextDueUtc
                        Invoke-OneRequest -RecordStats:$false
                        $nextDueUtc = $nextDueUtc.Add($interval)

                        if ($nextDueUtc -lt [datetime]::UtcNow.AddSeconds(-1)) {
                            $nextDueUtc = [datetime]::UtcNow
                        }
                    }
                }

                [void]$Queue.Enqueue([pscustomobject]@{
                    MessageType = "Status"
                    Server      = $Server
                    Port        = $port
                    Protocol    = $Protocol
                    Text        = "Warmup complete. Starting measured test for $TestDuration second(s) at $QPS QPS."
                })

                $expectedAttempts = [int][math]::Floor($TestDuration * $QPS)

                $nextDueUtc = [datetime]::UtcNow.Add($interval)
                $measurementStopwatch = [System.Diagnostics.Stopwatch]::StartNew()

                for ($attemptIndex = 0; $attemptIndex -lt $expectedAttempts; $attemptIndex++) {
                    Wait-UntilDue -DueTimeUtc $nextDueUtc
                    Invoke-OneRequest -RecordStats:$true
                    $nextDueUtc = $nextDueUtc.Add($interval)

                    if ($nextDueUtc -lt [datetime]::UtcNow.AddSeconds(-1)) {
                        $nextDueUtc = [datetime]::UtcNow
                    }
                }

                $measurementStopwatch.Stop()

                $elapsedSeconds        = [math]::Round($measurementStopwatch.Elapsed.TotalSeconds, 3)
                $requestElapsedSeconds = [math]::Round(($stats.TotalSendRequestMs / 1000.0), 3)

                if ($elapsedSeconds -gt 0) {
                    $actualQps                = [math]::Round(($stats.Attempts / $elapsedSeconds), 3)
                    $actualSuccessQps         = [math]::Round(($stats.Success  / $elapsedSeconds), 3)
                    $requestUtilizationPercent = [math]::Round((($requestElapsedSeconds / $elapsedSeconds) * 100), 2)
                }
                else {
                    $actualQps                = 0
                    $actualSuccessQps         = 0
                    $requestUtilizationPercent = 0
                }

                $summaryMetrics      = Get-WelfordMetrics -Mean $stats.Mean -M2 $stats.M2 -Success $stats.Success -Min $stats.Min -Max $stats.Max
                $responseTimeValues  = $stats.ResponseTimes.ToArray()

                $summary = [pscustomobject]@{
                    Server                    = $Server
                    Port                      = $port
                    Protocol                  = $Protocol
                    TestDurationSeconds       = $TestDuration
                    WarmupSeconds             = $WarmupSeconds
                    ElapsedSeconds            = $elapsedSeconds
                    RequestElapsedSeconds     = $requestElapsedSeconds
                    TargetQps                 = $QPS
                    ActualQps                 = $actualQps
                    ActualSuccessQps          = $actualSuccessQps
                    ExpectedAttempts          = $expectedAttempts
                    RequestUtilizationPercent = $requestUtilizationPercent
                    RollingWindowSize         = $RollingWindowSize
                    Attempts                  = $stats.Attempts
                    Success                   = $stats.Success
                    Failure                   = $stats.Failure
                    SuccessPercent            = Get-SuccessPercent -Success $stats.Success -Attempts $stats.Attempts
                    AvgMs                     = $summaryMetrics.Avg
                    MinMs                     = $summaryMetrics.Min
                    MaxMs                     = $summaryMetrics.Max
                    StdDevMs                  = $summaryMetrics.StdDev
                    P50Ms                     = Get-Percentile -Values $responseTimeValues -Percentile 50
                    P95Ms                     = Get-Percentile -Values $responseTimeValues -Percentile 95
                    P99Ms                     = Get-Percentile -Values $responseTimeValues -Percentile 99
                    Error                     = $null
                }

                [void]$ResultBag.Add($summary)
            }
            catch {
                [void]$Queue.Enqueue([pscustomobject]@{
                    MessageType  = "SetupError"
                    Server       = $Server
                    Port         = $port
                    Protocol     = $Protocol
                    ErrorType    = $_.Exception.GetType().FullName
                    ErrorMessage = $_.Exception.Message
                })

                [void]$ResultBag.Add([pscustomobject]@{
                    Server                    = $Server
                    Port                      = $port
                    Protocol                  = $Protocol
                    TestDurationSeconds       = $TestDuration
                    WarmupSeconds             = $WarmupSeconds
                    ElapsedSeconds            = 0
                    RequestElapsedSeconds     = 0
                    TargetQps                 = $QPS
                    ActualQps                 = 0
                    ActualSuccessQps          = 0
                    ExpectedAttempts          = [int][math]::Floor($TestDuration * $QPS)
                    RequestUtilizationPercent = 0
                    RollingWindowSize         = $RollingWindowSize
                    Attempts                  = 0
                    Success                   = 0
                    Failure                   = 0
                    SuccessPercent            = 0
                    AvgMs                     = 0
                    MinMs                     = 0
                    MaxMs                     = 0
                    StdDevMs                  = 0
                    P50Ms                     = 0
                    P95Ms                     = 0
                    P99Ms                     = 0
                    Error                     = $_.Exception.Message
                })
            }
            finally {
                if ($null -ne $connection) {
                    $connection.Dispose()
                }
            }
        }

        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()

        $functionEntry = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry(
            "Invoke-LdapLatencyWorker",
            ${function:Invoke-LdapLatencyWorker}
        )

        $iss.Commands.Add($functionEntry)

        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool($iss)
        $runspacePool.SetMinRunspaces(1) | Out-Null
        $runspacePool.SetMaxRunspaces([Environment]::ProcessorCount) | Out-Null
        $runspacePool.Open()

        $queue      = [System.Collections.Concurrent.ConcurrentQueue[object]]::new()
        $resultBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $detailBag  = [System.Collections.Concurrent.ConcurrentBag[object]]::new()
        $runspaces = New-Object 'System.Collections.Generic.List[object]'
    }

    Process {
        foreach ($server in $Servers) {
            if (-not [string]::IsNullOrWhiteSpace($server)) {
                [void]$serverList.Add($server)
            }
        }
    }

    End {
        function Format-FixedWidthText {
            param (
                [Parameter(Mandatory = $false)]
                [AllowNull()]
                [object]$Value,

                [Parameter(Mandatory = $true)]
                [int]$Width,

                [Parameter(Mandatory = $false)]
                [switch]$RightAlign
            )

            if ($null -eq $Value) {
                $text = ""
            }
            else {
                $text = [string]$Value
            }

            if ($text.Length -gt $Width) {
                if ($Width -le 3) {
                    $text = $text.Substring(0, $Width)
                }
                else {
                    $text = $text.Substring(0, $Width - 3) + "..."
                }
            }

            if ($RightAlign) {
                return $text.PadLeft($Width)
            }

            return $text.PadRight($Width)
        }

        function Write-LdapSampleHeader {
            param (
                [Parameter(Mandatory = $true)]
                [hashtable]$ColumnWidths
            )

            $headerParts = @(
                Format-FixedWidthText -Value "Server"    -Width $ColumnWidths["Server"]
                Format-FixedWidthText -Value "Timestamp" -Width $ColumnWidths["Timestamp"]
                Format-FixedWidthText -Value "RT"        -Width $ColumnWidths["RT"]        -RightAlign
                Format-FixedWidthText -Value "Avg"       -Width $ColumnWidths["Avg"]       -RightAlign
                Format-FixedWidthText -Value "Min"       -Width $ColumnWidths["Min"]       -RightAlign
                Format-FixedWidthText -Value "Max"       -Width $ColumnWidths["Max"]       -RightAlign
                Format-FixedWidthText -Value "StdDev"    -Width $ColumnWidths["StdDev"]    -RightAlign
                Format-FixedWidthText -Value "Success"   -Width $ColumnWidths["Success"]   -RightAlign
            )

            Write-Host ($headerParts -join " ") -ForegroundColor Gray
        }

        function Write-LdapSampleLine {
            param (
                [Parameter(Mandatory = $true)]
                [object]$Item,

                [Parameter(Mandatory = $true)]
                [string]$ServerColor,

                [Parameter(Mandatory = $true)]
                [hashtable]$ColumnWidths
            )

            $serverText    = "[{0}]" -f $Item.Server
            $timestampText = $Item.TimestampLocal.ToString("yyyy-MM-dd HH:mm:ss.fff")

            if ($Item.IsSuccess) {
                $rtText  = "{0:N2} ms" -f $Item.ResponseTimeMs
                $rtColor = if ($Item.ResponseTimeMs -gt 150) { "Red" } else { "Green" }
            }
            else {
                $rtText  = "FAILED"
                $rtColor = "Red"
            }

            $metricParts = @(
                Format-FixedWidthText -Value ("{0:N2} ms" -f $Item.AvgMs)        -Width $ColumnWidths["Avg"]    -RightAlign
                Format-FixedWidthText -Value ("{0:N2} ms" -f $Item.MinMs)        -Width $ColumnWidths["Min"]    -RightAlign
                Format-FixedWidthText -Value ("{0:N2} ms" -f $Item.MaxMs)        -Width $ColumnWidths["Max"]    -RightAlign
                Format-FixedWidthText -Value ("{0:N2} ms" -f $Item.StdDevMs)     -Width $ColumnWidths["StdDev"] -RightAlign
                Format-FixedWidthText -Value ("{0:N2}%"   -f $Item.SuccessPercent) -Width $ColumnWidths["Success"] -RightAlign
            )

            Write-Host -NoNewLine (Format-FixedWidthText -Value $serverText    -Width $ColumnWidths["Server"])    -ForegroundColor $ServerColor
            Write-Host -NoNewLine " "
            Write-Host -NoNewLine (Format-FixedWidthText -Value $timestampText -Width $ColumnWidths["Timestamp"]) -ForegroundColor White
            Write-Host -NoNewLine " "
            Write-Host -NoNewLine (Format-FixedWidthText -Value $rtText        -Width $ColumnWidths["RT"] -RightAlign) -ForegroundColor $rtColor
            Write-Host -NoNewLine " "
            Write-Host ($metricParts -join " ") -ForegroundColor $ServerColor

            if (-not $Item.IsSuccess -and -not [string]::IsNullOrWhiteSpace($Item.ErrorMessage)) {
                $indentWidth = $ColumnWidths["Server"] + $ColumnWidths["Timestamp"] + $ColumnWidths["RT"] + 3
                $errorPrefix = Format-FixedWidthText -Value "" -Width $indentWidth
                Write-Host ("{0}Error: {1}" -f $errorPrefix, $Item.ErrorMessage) -ForegroundColor DarkGray
            }
        }

        $columnWidths = @{
            Server    = 42
            Timestamp = 23
            RT        = 12
            Avg       = 12
            Min       = 12
            Max       = 12
            StdDev    = 12
            Success   = 10
        }

        $sampleHeaderWritten = $false

        try {
            foreach ($server in $serverList) {
                $pipe = [powershell]::Create()

                $scriptBlock = {
                    param (
                        $Server,
                        $Protocol,
                        $TestDuration,
                        $WarmupSeconds,
                        $QPS,
                        $RollingWindowSize,
                        $Queue,
                        $ResultBag,
                        $DetailBag
                    )

                    $workerParams = @{
                        Server            = $Server
                        Protocol          = $Protocol
                        TestDuration      = $TestDuration
                        WarmupSeconds     = $WarmupSeconds
                        QPS               = $QPS
                        RollingWindowSize = $RollingWindowSize
                        Queue             = $Queue
                        ResultBag         = $ResultBag
                        DetailBag         = $DetailBag
                    }

                    Invoke-LdapLatencyWorker @workerParams
                }

                [void]$pipe.AddScript($scriptBlock)
                [void]$pipe.AddArgument($server)
                [void]$pipe.AddArgument($Protocol)
                [void]$pipe.AddArgument($TestDuration)
                [void]$pipe.AddArgument($WarmupSeconds)
                [void]$pipe.AddArgument($QPS)
                [void]$pipe.AddArgument($RollingWindowSize)
                [void]$pipe.AddArgument($queue)
                [void]$pipe.AddArgument($resultBag)
                [void]$pipe.AddArgument($detailBag)

                $pipe.RunspacePool = $runspacePool

                [void]$runspaces.Add([pscustomobject]@{
                    Pipe   = $pipe
                    Handle = $pipe.BeginInvoke()
                })
            }

            while (($runspaces.Handle.IsCompleted -contains $false) -or (-not $queue.IsEmpty)) {
                while (-not $queue.IsEmpty) {
                    $item = $null

                    if (-not $queue.TryDequeue([ref]$item)) { continue }

                    $serverColor = Get-ServerColor -ServerName $item.Server

                    switch ($item.MessageType) {
                        "Status" {
                            Write-Host ("[{0}] {1}" -f $item.Server, $item.Text) -ForegroundColor $serverColor
                        }

                        "SetupError" {
                            Write-Host ("[{0}] Setup failed: {1}: {2}" -f $item.Server, $item.ErrorType, $item.ErrorMessage) -ForegroundColor Red
                        }

                        "Sample" {
                            if (-not $sampleHeaderWritten) {
                                Write-LdapSampleHeader -ColumnWidths $columnWidths
                                $sampleHeaderWritten = $true
                            }

                            Write-LdapSampleLine -Item $item -ServerColor $serverColor -ColumnWidths $columnWidths
                        }
                    }
                }

                Start-Sleep -Milliseconds 100
            }

            foreach ($runspace in $runspaces) {
                $runspace.Pipe.EndInvoke($runspace.Handle)
            }

            if ($PSBoundParameters.ContainsKey('CsvPath')) {
                $csvDirectory = Split-Path -Path $CsvPath -Parent

                if ($csvDirectory -and -not (Test-Path -Path $csvDirectory)) {
                    [void](New-Item -Path $csvDirectory -ItemType Directory -Force)
                }

                $csvProperties = @(
                    "TimestampLocal",
                    "Server",
                    "Port",
                    "Protocol",
                    "Attempt",
                    "IsSuccess",
                    "ResponseTimeMs",
                    "SendRequestMs",
                    "ErrorType",
                    "ErrorMessage",
                    "AvgMs",
                    "MinMs",
                    "MaxMs",
                    "StdDevMs",
                    "SuccessPercent",
                    "CumulativeAvgMs",
                    "CumulativeMinMs",
                    "CumulativeMaxMs",
                    "CumulativeStdDevMs",
                    "CumulativeSuccessPercent"
                )

                $detailBag.ToArray() |
                    Sort-Object TimestampLocal, Server, Attempt |
                    Select-Object -Property $csvProperties |
                    Export-Csv -Path $CsvPath -NoTypeInformation
            }

            $summaryResults = $resultBag.ToArray() | Sort-Object Server, Protocol

            if ($PSBoundParameters.ContainsKey('CsvSummaryPath')) {
                $csvSummaryDirectory = Split-Path -Path $CsvSummaryPath -Parent

                if ($csvSummaryDirectory -and -not (Test-Path -Path $csvSummaryDirectory)) {
                    [void](New-Item -Path $csvSummaryDirectory -ItemType Directory -Force)
                }

                $summaryResults | Export-Csv -Path $CsvSummaryPath -NoTypeInformation
            }

            $summaryResults | Write-Output
        }
        finally {
            foreach ($runspace in $runspaces) {
                if ($null -ne $runspace.Pipe) {
                    $runspace.Pipe.Dispose()
                }
            }

            if ($null -ne $runspacePool) {
                $runspacePool.Close()
                $runspacePool.Dispose()
            }
        }
    }
}
