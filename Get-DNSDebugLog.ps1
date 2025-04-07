function Get-DNSDebugLog {
    <#
    .SYNOPSIS
        This cmdlet parses a Windows DNS Debug log.

    .DESCRIPTION
        When a DNS log is converted with this cmdlet it will be turned into objects for further parsing.

    .EXAMPLE
        Get-DNSDebugLog -DNSLog ".\Something.log" | Format-Table
        Outputs the contents of the dns debug file "Something.log" as a table.

    .EXAMPLE
        Get-DNSDebugLog -DNSLog ".\Something.log" | Export-Csv .\ProperlyFormatedLog.csv -NoTypeInformation
        Turns the debug file into a csv-file.

    .PARAMETER DNSLog
        Mandatory. Path to the DNS log or DNS log data. Allows pipelining from for example Get-ChildItem for files, and supports pipelining DNS log data.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True)]
        [String]$DNSLog
        )

    BEGIN {
        Write-Verbose "BEGIN: Initializing settings"

        function getDNSLogLines {
            Param($DNSLog)

            # Don't bother if the file does not exist
            $PathCorrect=try { Test-Path $DNSLog -ErrorAction Stop } catch { $false }

            if ($DNSLog -match "^\d\d" -AND $DNSLog -notlike "*EVENT*" -AND $PathCorrect -ne $true)
            {
                $DNSLog
            }
            elseif ($PathCorrect -eq $true)
            {
                Get-Content $DNSLog | % { $_ }
            }
        }

        #stats
        $nTotalSuccess = 0      # No of lines of interest and saved with SUCCESS
        $nTotalFailed = 0       # No of lines of interest but FAILED to save
        $nTotalDiscarded = 0    # No of lines not of interest
        $nTotalEvaluated = 0    # No of lines looked at

      #
      # data sample from Windows Server 2012 R2, used for dnspattern below
      # 05/03/2019 16:05:31 0F9C PACKET  000000082A8141F0 UDP Snd 10.202.168.232  c1f8 R Q [8081   DR  NOERROR] A      (3)api(11)blahblah(3)com(0)
      #
       $dnspattern = "^(?<log_date>([0-9]{1,2}.[0-9]{1,2}.[0-9]{2,4}|[0-9]{2,4}-[0-9]{2}-[0-9]{2})\s*[0-9: ]{7,8}\s*(PM|AM)?) (?<ThreadID>[0-9A-Z]{3,4}) (?<Context>PACKET) \s(?<InternalPacketID>[0-9A-Za-z]{8,16}) (?<protocol>UDP|TCP) (?<Send_Receive>Snd|Rcv) (?<RemoteIP>[0-9.]{7,15}|[0-9a-f:]{3,50})\s*(?<Xid>[0-9a-z]{4}) (?<Query_Response>\s|R) (?<OpCode>Q|N|U|\?) \[(?<FlagsHex>\d{4})\s+(?<Flags>[A|T|D|R]*)\s+(?<ResponseCode>\w+)\] (?<QuestionType>[[a-zA-Z0-9]*)\s+(?<QuestionName>\(.*\)$)"
       $returnselect =  @{label="DateTime";expression={Get-Date $match.Groups['log_date'].value.trim()}},
                        @{label="ThreadID";expression={$match.Groups['ThreadID'].value.trim()}},
                        @{label="Context";expression={$match.Groups['Context'].value.trim()}},
                        @{label="InternalPacketID";expression={$match.Groups['InternalPacketID'].value.trim()}},
                        @{label="Protocol";expression={$match.Groups['protocol'].value.trim()}},
                        @{label="Send/Receive";expression={$match.Groups['Send_Receive'].value.trim()}},
                        @{label="RemoteIP";expression={[ipaddress] ($match.Groups['RemoteIP'].value.trim()).trim()}},
                        @{label="Xid";expression={$match.Groups['Xid'].value.trim()}},
                        @{label="Query/Response";expression={switch($match.Groups['Query_Response'].value.trim()) {"" { 'Query' }; "R" { 'Response' }}}},
                        @{label="OpCode";expression={switch($match.Groups['OpCode'].value.trim()) {"Q" { 'Standard Query' }; "N" { 'Notify'}; "U" { 'Update' }; "?" { 'Unknown' }}}},
                        @{label="FlagsHex";expression={$match.Groups['FlagsHex'].value.trim()}},
                        @{label="Flags";expression={switch -Regex ($match.Groups['Flags'].value.trim()) {"A" { 'Authoritative Answer' }; "T" { 'Truncated Response' }; "D" { 'Recursion Desired' }; "R" { 'Recursion Available' }}}},
                        @{label="ResponseCode";expression={$match.Groups['ResponseCode'].value.trim()}},                        
                        @{label="RecordType";expression={$match.Groups['QuestionType'].value.trim()}},
                        @{label="Query";expression={$match.Groups['QuestionName'].value.trim() -replace "(`\(.*)","`$1" -replace "`\(.*?`\)","." -replace "^.",""}}

        Write-Verbose "BEGIN: Initializing Settings - DONE"
    }

    PROCESS {
        Write-Verbose "PROCESS: Starting to processing File: $DNSLog"

        getDNSLogLines -DNSLog $DNSLog | % {

            # Overall Total
            $nTotalEvaluated = $nTotalEvaluated + 1

            $match = [regex]::match($_,$dnspattern) #approach 2
            if ($match.success )
            {
                Try
                {
                    $true | Select-Object $returnselect
                    $nTotalSuccess = $nTotalSuccess + 1
                    # No of lines of interest and saved with SUCCESS
                } # end try
                Catch
                {
                    # Lines of Interest but FAILED to save
                    Write-Verbose "Failed to process row: $_"
                    $nTotalFailed = $nTotalFailed + 1
                } #end catch
            } #end if($match.success )
            else
            {
                # No of lines not of interest
                $nTotalDiscarded = $nTotalDiscarded + 1
            } #end else

        } # end of getDNSLogLine

        Write-Verbose "PROCESS: Finished Processing File: $DNSLog"

    } # end PROCESS

    END
    {
        # print summary
        Write-Verbose "Summary"
        Write-Verbose "Total lines in the file ($DNSLog): $nTotalEvaluated"
        Write-Verbose "Records Processed with Success: $nTotalSuccess"
        Write-Verbose "Records Processed with failure: $nTotalFailed"
        Write-Verbose "Records discarded as not relevant: $nTotalDiscarded"
    }

}

# Function to group entries by InternalPacketID and Xid
function Group-DNSRequests {
    param(
        [Array]$ParsedLogData
    )
    # Group entries by InternalPacketID and Xid
    $GroupedEntries = $ParsedLogData | Group-Object -Property InternalPacketID, Xid

    # Create a new object for each group, merging the related data
    $GroupedEntries | ForEach-Object {
        $group = $_.Group
        $request = [PSCustomObject]@{
            DateTime         = $group[0].DateTime
            ThreadID         = $group[0].ThreadID
            Context          = $group[0].Context
            InternalPacketID = $group[0].InternalPacketID
            Protocol         = $group[0].Protocol
            RemoteIP         = $group[0].RemoteIP
            Xid              = $group[0].Xid
            QueryName        = $group[0].Query
            QueryResponse    = $group | Where-Object { $_.'Query/Response' -eq 'Response' } | ForEach-Object { $_.Query }
            SendReceive      = ($group | ForEach-Object { $_.'Send/Receive' }) -join ', '
            ResponseCode     = $group[0].ResponseCode
        }
        $request
    }
}

# Function to filter successful entries (NOERROR)
function Get-SuccessfulRequests {
    param(
        [Array]$GroupedRequests
    )
    $GroupedRequests | Where-Object { $_.ResponseCode -eq 'NOERROR' }
}

# Function to filter unsuccessful entries (not NOERROR)
function Get-UnsuccessfulRequests {
    param(
        [Array]$GroupedRequests
    )
    $GroupedRequests | Where-Object { $_.ResponseCode -ne 'NOERROR' }
}

# Function to count occurrences by a specific property
function Get-TopOccurrences {
    param(
        [Array]$GroupedRequests,
        [string]$Property
    )
    $GroupedRequests | Group-Object -Property $Property | Sort-Object -Property Count -Descending
}

# Function to output analytics for successful requests
function Get-SuccessfulRequestAnalytics {
    param(
        [Array]$GroupedRequests
    )
    $successfulRequests = Get-SuccessfulRequests -GroupedRequests $GroupedRequests

    Write-Host "Top successful queries by QuestionName count:"
    Get-TopOccurrences -GroupedRequests $successfulRequests -Property 'QueryName' | Select-Object -First 10

    Write-Host "`nTop successful queries by RemoteIP count:"
    Get-TopOccurrences -GroupedRequests $successfulRequests -Property 'RemoteIP' | Select-Object -First 10
}

# Function to output analytics for unsuccessful requests
function Get-UnsuccessfulRequestAnalytics {
    param(
        [Array]$GroupedRequests
    )
    $unsuccessfulRequests = Get-UnsuccessfulRequests -GroupedRequests $GroupedRequests

    Write-Host "Top unsuccessful queries by QuestionName count:"
    Get-TopOccurrences -GroupedRequests $unsuccessfulRequests -Property 'QueryName' | Select-Object -First 10

    Write-Host "`nTop unsuccessful queries by RemoteIP count:"
    Get-TopOccurrences -GroupedRequests $unsuccessfulRequests -Property 'RemoteIP' | Select-Object -First 10
}

# Function to Detect DNS Tunneling
# This script attempts to detect DNS tunneling by identifying queries with unusually long domain names, which might indicate data being exfiltrated through DNS queries.
function Detect-DNSTunneling {
    param(
        [Array]$ParsedLogData,
        [int]$LengthThreshold = 50  # Set a threshold for domain length that may indicate tunneling
    )

    Write-Host "Checking for potential DNS tunneling activity..."
    
    # Filter for long DNS queries
    $tunnelingSuspects = $ParsedLogData | Where-Object { $_.QueryName.Length -gt $LengthThreshold }

    if ($tunnelingSuspects.Count -gt 0) {
        Write-Host "Potential DNS Tunneling Detected:" -ForegroundColor Red
        $tunnelingSuspects | Format-Table -AutoSize
    } else {
        Write-Host "No potential DNS tunneling detected." -ForegroundColor Green
    }
}

# Function to Detect anomalous Traffic Patterns
# This script detects unusual DNS traffic patterns, such as a high volume of queries from a single IP address. This might indicate compromised hosts or misconfigurations.
function Detect-AnomalousTrafficPatterns {
    param(
        [Array]$ParsedLogData,
        [int]$QueryVolumeThreshold = 1000  # Threshold for what is considered "unusually high" query volume
    )

    Write-Host "Analyzing traffic patterns for anomalies..."

    # Group by RemoteIP and count the number of queries
    $anomalousTraffic = $ParsedLogData | Group-Object -Property RemoteIP | Where-Object { $_.Count -gt $QueryVolumeThreshold }

    if ($anomalousTraffic.Count -gt 0) {
        Write-Host "Anomalous DNS Traffic Detected:" -ForegroundColor Red
        $anomalousTraffic | Select-Object @{Name='RemoteIP'; Expression={$_.Name}}, Count | Format-Table -AutoSize
    } else {
        Write-Host "No anomalous DNS traffic detected." -ForegroundColor Green
    }
}

# Monitor NXDOMAIN Responses
# This script tracks NXDOMAIN (non-existent domain) responses, which could indicate suspicious activity such as reconnaissance attempts or misconfigurations in DNS queries.
function Monitor-NXDOMAINResponses {
    param(
        [Array]$ParsedLogData,
        [int]$NXDOMAINThreshold = 100  # Set a threshold for what is considered a high number of NXDOMAIN responses
    )

    Write-Host "Monitoring NXDOMAIN responses..."

    # Filter for NXDOMAIN responses
    $nxdomainResponses = $ParsedLogData | Where-Object { $_.ResponseCode -eq 'NXDOMAIN' }

    if ($nxdomainResponses.Count -gt $NXDOMAINThreshold) {
        Write-Host "High volume of NXDOMAIN responses detected:" -ForegroundColor Red
        $nxdomainResponses | Group-Object -Property RemoteIP | Sort-Object Count -Descending | Select-Object -First 10 | Format-Table -AutoSize
    } else {
        Write-Host "NXDOMAIN responses within normal range." -ForegroundColor Green
    }
}

# Evaluate DNSSEC Adoption
# This script checks whether DNS queries and responses are signed with DNS Security Extensions (DNSSEC). If not, it may indicate potential vulnerabilities to DNS spoofing attacks.
function Evaluate-DNSSECAdoption {
    param(
        [Array]$ParsedLogData
    )

    Write-Host "Evaluating DNSSEC adoption..."

    # Filter for DNS responses that do not use DNSSEC (typically indicated by lack of 'AD' flag in responses)
    $nonDNSSECResponses = $ParsedLogData | Where-Object { $_.Flags -notmatch 'AD' }

    if ($nonDNSSECResponses.Count -gt 0) {
        Write-Host "Some DNS responses are not secured with DNSSEC:" -ForegroundColor Yellow
        $nonDNSSECResponses | Format-Table -AutoSize
    } else {
        Write-Host "All DNS responses are secured with DNSSEC." -ForegroundColor Green
    }
}

# Baseline DNS Query Behavior
# This script establishes a baseline for DNS query behavior by analyzing historical data. Deviations from this baseline might indicate anomalies or potential security incidents.
function Baseline-DNSQueryBehavior {
    param(
        [Array]$ParsedLogData
    )

    Write-Host "Establishing DNS query behavior baseline..."

    # Establish baseline based on average query count per IP
    $baseline = $ParsedLogData | Group-Object -Property RemoteIP | Measure-Object Count -Average

    Write-Host "Average query count per IP: $($baseline.Average)"

    # Detect significant deviations from baseline
    $deviations = $ParsedLogData | Group-Object -Property RemoteIP | Where-Object { $_.Count -gt ($baseline.Average * 1.5) }

    if ($deviations.Count -gt 0) {
        Write-Host "Significant deviations from baseline detected:" -ForegroundColor Red
        $deviations | Select-Object @{Name='RemoteIP'; Expression={$_.Name}}, Count | Format-Table -AutoSize
    } else {
        Write-Host "No significant deviations from baseline detected." -ForegroundColor Green
    }
}

# Detect DNS Amplification Attacks
# This script helps identify potential DNS amplification attacks by looking for mismatches between the size of DNS queries and their responses, especially when a small query results in a disproportionately large response.
function Detect-DNSAmplificationAttacks {
    param(
        [Array]$ParsedLogData,
        [int]$AmplificationFactorThreshold = 10  # Threshold to detect amplification (e.g., response 10x the size of query)
    )

    Write-Host "Checking for potential DNS amplification attacks..."

    # Filter for potential amplification attacks
    $amplificationSuspects = $ParsedLogData | Where-Object {
        $_.Protocol -eq 'UDP' -and ($_.ResponseSize / $_.QuerySize) -gt $AmplificationFactorThreshold
    }

    if ($amplificationSuspects.Count -gt 0) {
        Write-Host "Potential DNS Amplification Attacks Detected:" -ForegroundColor Red
        $amplificationSuspects | Format-Table -AutoSize
    } else {
        Write-Host "No potential DNS amplification attacks detected." -ForegroundColor Green
    }
}

# Profile DNS Behavior for Specific Endpoints
# This script profiles DNS behavior for specific endpoints, which can help in identifying compromised hosts or insider threats.
function Profile-EndpointDNSBehavior {
    param(
        [Array]$ParsedLogData,
        [string]$TargetIP
    )

    Write-Host "Profiling DNS behavior for IP: $TargetIP..."

    # Filter DNS logs for the specified IP
    $endpointProfile = $ParsedLogData | Where-Object { $_.RemoteIP -eq $TargetIP }

    if ($endpointProfile.Count -gt 0) {
        Write-Host "DNS behavior for $($TargetIP):"
        $endpointProfile | Group-Object -Property QueryName | Sort-Object Count -Descending | Format-Table -AutoSize
    } else {
        Write-Host "No DNS activity found for $($TargetIP)." -ForegroundColor Yellow
    }
}

# DNS Traffic Summary Report
# This script generates a summary report of the DNS traffic, including the total number of queries, the most frequent query types, and the most active IP addresses.
function Generate-DNSTrafficSummary {
    param(
        [Array]$ParsedLogData
    )

    Write-Host "Generating DNS traffic summary report..."

    $totalQueries = $ParsedLogData.Count
    $topQueryNames = $ParsedLogData | Group-Object -Property QueryName | Sort-Object Count -Descending | Select-Object -First 10
    $topRemoteIPs = $ParsedLogData | Group-Object -Property RemoteIP | Sort-Object Count -Descending | Select-Object -First 10

    Write-Host "Total number of DNS queries: $totalQueries"
    Write-Host "`nTop 10 most queried domains:"
    $topQueryNames | Format-Table Name, Count -AutoSize

    Write-Host "`nTop 10 most active IP addresses:"
    $topRemoteIPs | Format-Table Name, Count -AutoSize
}

# Identify Slow DNS Queries
# This script identifies DNS queries that are taking an unusually long time to resolve, which could indicate network latency issues or problems with the DNS server itself.
function Get-SlowDNSQueries {
    param(
        [Array]$GroupedRequests,
        [int]$LatencyThreshold = 1500  # Time in milliseconds
    )

    Write-Host "Identifying DNS queries with latency greater than $LatencyThreshold ms..."

    # Assuming the log contains a 'ResponseTime' property, calculate the query latency
    $slowQueries = $ParsedLogData | Where-Object { $_.ResponseTime -gt $LatencyThreshold }

    if ($slowQueries.Count -gt 0) {
        Write-Host "Slow DNS queries detected:" -ForegroundColor Yellow
        $slowQueries | Format-Table -Property DateTime, RemoteIP, QueryName, ResponseTime -AutoSize
    } else {
        Write-Host "No slow DNS queries detected." -ForegroundColor Green
    }
}

# Check for DNS Request-Response Mismatches
# This script checks for mismatches between DNS requests and responses. It ensures that every DNS query has a corresponding response, which is crucial for diagnosing dropped packets or incomplete transactions.
function Get-DNSRequestResponseMismatches {
    param(
        [Array]$ParsedLogData
    )

    Write-Host "Checking for DNS request-response mismatches..."

    # Group by InternalPacketID and Xid to match queries with their responses
    $groupedData = $ParsedLogData | Group-Object -Property InternalPacketID, Xid

    # Find groups where either request or response is missing
    $mismatches = $groupedData | Where-Object {
        $_.Group.Count -eq 1 -or ($_.Group | Where-Object { $_.'Query/Response' -eq 'Query' }).Count -ne 1 -or ($_.Group | Where-Object { $_.'Query/Response' -eq 'Response' }).Count -ne 1
    }

    if ($mismatches.Count -gt 0) {
        Write-Host "Mismatches between DNS requests and responses detected:" -ForegroundColor Red
        $mismatches | ForEach-Object {
            $_.Group | Format-Table -Property DateTime, RemoteIP, QueryName, 'Query/Response' -AutoSize
        }
    } else {
        Write-Host "No mismatches detected between DNS requests and responses." -ForegroundColor Green
    }
}

# Identify Frequent DNS Query Retries
# This script identifies IP addresses or domains that are frequently making the same DNS query multiple times, which may indicate network issues or misconfigurations.
function Get-FrequentDNSQueryRetries {
    param(
        [Array]$ParsedLogData,
        [int]$RetryThreshold = 3
    )

    Write-Host "Identifying frequent DNS query retries..."

    # Group by RemoteIP and QueryName to identify repeated queries
    $queryRetries = $ParsedLogData | Group-Object -Property RemoteIP, QueryName | Where-Object { $_.Count -gt $RetryThreshold }

    if ($queryRetries.Count -gt 0) {
        Write-Host "Frequent DNS query retries detected:" -ForegroundColor Yellow
        $queryRetries | Format-Table -Property @{Name='RemoteIP';Expression={$_.Name.Split(',')[0]}}, @{Name='QueryName';Expression={$_.Name.Split(',')[1]}}, Count -AutoSize
    } else {
        Write-Host "No frequent DNS query retries detected." -ForegroundColor Green
    }
}




$parsedLogData = Get-DNSDebugLog -DNSLog "C:\Temp\dns.log" -Verbose

# Group requests by InternalPacketID and Xid
$groupedRequests = Group-DNSRequests -ParsedLogData $parsedLogData

# Output analytics for successful requests
$SuccessfulRequestAnalytics = Get-SuccessfulRequestAnalytics -GroupedRequests $groupedRequests

# Output analytics for unsuccessful requests
$UnsuccessfulRequestAnalytics = Get-UnsuccessfulRequestAnalytics -GroupedRequests $groupedRequests

# Detect DNS Tunneling
Detect-DNSTunneling -ParsedLogData $parsedLogData -LengthThreshold 50

# Output Anomalous Traffic Patterns
Detect-AnomalousTrafficPatterns -ParsedLogData $parsedLogData -QueryVolumeThreshold 500

# Output NXDOMAIN Responses
Monitor-NXDOMAINResponses -ParsedLogData $parsedLogData -NXDOMAINThreshold 50

# Output DNSSEC Adoption
Evaluate-DNSSECAdoption -ParsedLogData $parsedLogData

# Output Baseline DNS Query Behavior
Baseline-DNSQueryBehavior -ParsedLogData $parsedLogData

# Output DNS Amplification Attacks
# Detect-DNSAmplificationAttacks -ParsedLogData $parsedLogData -AmplificationFactorThreshold 5

# Output DNS Behavior for Specific Endpoints
Profile-EndpointDNSBehavior -ParsedLogData $parsedLogData -TargetIP "10.236.9.117"

# Output DNS Traffic Summary Report
Generate-DNSTrafficSummary -ParsedLogData $parsedLogData
