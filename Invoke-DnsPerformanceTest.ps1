function Invoke-DnsPerformanceTest {
    <#
    .SYNOPSIS
        Compares cached DNS resolution performance at a controlled per-server rate.

    .DESCRIPTION
        Sends DNS queries directly to every supplied DNS server. QueriesPerSecond is
        the rate delivered to each resolved server endpoint, not an aggregate rate.

        Each scheduling round sends the same FQDN to every server, rotating both the
        FQDN and the first server in the round. This makes server comparisons occur
        under nearly identical network conditions without consistently favoring the
        first server.

        Persistent UDP sockets, query scheduling, response matching, metric
        aggregation, percentile histograms, fixed packet-parser workers, centralized
        timeout scanning, pooled receive buffers, and optional batched CSV writing run
        in compiled C#. PowerShell only renders periodic snapshots and the final
        summary. An unmeasured warm-up prepares the client before the timed run.

        The live dashboard uses a rolling window. Final statistics are cumulative and
        include overall, per-server, per-FQDN, and server-by-FQDN measurements.
        Interactive PowerShell ISE and console sessions redraw the dashboard in place.
        Redirected or noninteractive output receives appended snapshots instead.
        Latency statistics contain successful resolutions only. For UDP, socket-observed
        response latency is measured from the send timestamp to the timestamp captured
        immediately after Socket.Receive returns. Parser-queue, parsing, continuation,
        scheduler, CPU, garbage-collection, memory, and thread-pool observations are
        reported separately so client pressure is visible. TCP fallbacks use final TCP
        read completion as their receive point.

    .PARAMETER FQDNs
        Cached DNS names to query. Names are normalized before the timed test.

    .PARAMETER DNSServers
        DNS server IP addresses or hostnames. Hostnames are resolved once before the
        test and expand to all unique returned addresses.

    .PARAMETER QueriesPerSecond
        Target QPS sent to every resolved DNS endpoint. With 10 endpoints and a value
        of 200, the target aggregate rate is 2,000 QPS.

    .PARAMETER DurationSeconds
        Scheduling duration. Outstanding queries may drain after this period.

    .PARAMETER QueryType
        DNS record type to request.

    .PARAMETER TimeoutMilliseconds
        End-to-end timeout for UDP and any TCP fallback combined.

    .PARAMETER MaxOutstandingPerServer
        Maximum in-flight queries per endpoint. Zero calculates a value from the
        per-server QPS and timeout.

    .PARAMETER SchedulerToleranceMilliseconds
        A whole paired round is skipped if it is later than this threshold. Skipping
        the round preserves fairness and prevents a large catch-up burst.

    .PARAMETER DisplayIntervalSeconds
        Live dashboard refresh interval. The default is five seconds.

    .PARAMETER RollingWindowSeconds
        Window used for live QPS and latency statistics. Final metrics are cumulative.

    .PARAMETER WarmupSeconds
        Unmeasured warm-up at the requested rate. This primes JIT compilation,
        worker threads, packet buffers, and DNS parsing before measurement begins.

    .PARAMETER ProcessingWorkerCount
        Fixed number of compiled C# packet-parsing workers. Zero selects a value
        from the logical processor count. These workers do not use the shared
        PowerShell thread pool for DNS response parsing.

    .PARAMETER ObserverProcessingThresholdMilliseconds
        Client processing delay that marks a paired query round as observer-suspect.
        This affects attribution labels only; it never removes measurements or
        changes the DNS latency objectives.

    .PARAMETER DegradationWindowSeconds
        Sliding window used by the final DNS latency degradation analysis. The default
        is five seconds, evaluated once per second for each server-by-FQDN pair after
        a complete window has accumulated.

    .PARAMETER MinimumDegradationSamples
        Minimum violating queries required before a degradation objective can fail.
        This prevents an isolated maximum from being reported as a degradation event.

    .PARAMETER MaximumDegradationEvents
        Maximum number of correlated degradation incidents printed and returned.
        Pair-level server-by-FQDN spikes are grouped by measured time overlap. If more
        incidents qualify, the most severe are retained and the omitted count is reported.

    .PARAMETER DisableTcpFallback
        Do not retry a truncated UDP answer over TCP.

    .PARAMETER NoRecursion
        Clear the recursion-desired flag in generated DNS queries.

    .PARAMETER NoEdns
        Do not include an EDNS OPT record in generated DNS queries.

    .PARAMETER UdpPayloadSize
        Advertised EDNS UDP payload size. This is ignored when NoEdns is used.

    .PARAMETER AllowNoAnswer
        Treat a NOERROR response with zero answer records as successful.

    .PARAMETER CsvOutputPath
        Optional CSV containing one row per planned query. Large tests are streamed
        during the workload. When CoordinatedCapture is enabled, the completed file is
        then enriched in a bounded-memory pass with correlated client/server Npcap
        timestamps, packet-boundary durations, and directional delay deltas. Rows for
        endpoints that cannot provide server-side capture are labeled ClientOnly and
        retain the workload's normal UdpSocketReceive timing.

    .PARAMETER IncludeDetailedResults
        Return individual query rows in memory. This is rejected when the planned count
        exceeds MaximumDetailedResults. CSV is preferred for large tests.

    .PARAMETER MaximumDetailedResults
        Safety limit for rows retained by IncludeDetailedResults.

    .PARAMETER MaximumPlannedQueries
        Safety limit applied independently to the measured query plan and the
        warm-up query plan. The function stops before sending any queries when
        either phase would exceed this value.

    .PARAMETER CoordinatedCapture
        Attempt coordinated Npcap capture on this client and each DNS endpoint before
        the measured phase begins. An endpoint that does not support Windows remoting
        or server-side Npcap capture (for example, a load balancer VIP or Linux DNS
        server) automatically continues with normal client-side socket timing. Warm-up
        completes first; the runner then pauses in an ARMING phase until the available
        capture handles report ready. Server-side helpers are launched with PowerShell
        Remoting and removed after results are returned. Raw packets are parsed and
        discarded in compiled C#. Up to 16 resolved endpoints can participate.

    .PARAMETER CaptureComputerMap
        Optional mapping from a DNS server argument, resolved endpoint address, or
        endpoint label to the computer name used for PowerShell Remoting. This is
        used when a VIP or alias should be correlated with capture on a specific
        Windows backend. Without a usable mapping, an endpoint that cannot be remoted
        to is retained as ClientOnly rather than stopping the test.

    .PARAMETER CaptureCredential
        Optional credential for server-side PowerShell Remoting. When omitted, the
        current Windows identity is tried first. When a failure specifically indicates
        rejected or unauthorized credentials, an interactive run prompts once for
        alternate credentials and retries before the DNS workload starts. A failure
        that indicates an unavailable or non-Windows remoting target does not prompt;
        that endpoint continues as ClientOnly. No delegation or second hop is required.

    .PARAMETER CaptureUseSSL
        Use the WinRM HTTPS listener for coordinated server captures.

    .PARAMETER CaptureStartupTimeoutSeconds
        Maximum time per endpoint for server-side remoting preflight, and the maximum
        time for the accepted capture endpoints to open Npcap handles and report ready.

    .PARAMETER CaptureGraceSeconds
        Additional capture time after the planned scheduling duration. This permits
        outstanding DNS responses to drain through the ordinary query timeout.

    .PARAMETER CaptureMaximumPacketsPerEndpoint
        Safety limit on request and response packets accepted by each local or remote
        capture. Reaching the limit makes coordinated evidence incomplete.

    .PARAMETER CaptureSlowTransactionThresholdMilliseconds
        Minimum client-wire, server-turnaround, or combined-network remainder used
        when retaining bounded slow-transaction evidence in the returned summary.

    .PARAMETER CaptureMaximumSlowTransactions
        Maximum slow coordinated transactions returned per endpoint. All matched
        transactions still contribute to the distribution summaries. Retained rows
        include the client request/response and server receive/send UTC timestamps.

    .PARAMETER TraceConditionalForwarding
        Extend CoordinatedCapture on each DNS server to trace uncached queries through
        matching conditional forwarder zones. The server records the configured master
        list and the observed upstream attempt order, response or no-response interval,
        fallback target, RCODE, UDP/TCP transport, cache-served or otherwise unattributed
        client transactions, and coalesced client requests. A ClientOnly endpoint is
        labeled unavailable for this server-side trace while other endpoints continue.
        This switch requires CoordinatedCapture and never clears or changes the cache.

    .PARAMETER CaptureMaximumForwardingPacketsPerEndpoint
        Safety limit for relevant client and conditional-forwarder DNS packets accepted
        by the additional server-side trace handle. It is independent of the ordinary
        coordinated packet limit because an uncached transaction can contain both a
        client request/response and one or more upstream attempts. Events are retained
        in memory as compact records and returned compressed; no PCAP is written.

    .PARAMETER CaptureMaximumForwardingFlights
        Maximum detailed forwarding flights returned per endpoint. Aggregate counters
        include every observed flight. When the limit is exceeded, fallback, failed,
        and longest flights are retained first.

    .EXAMPLE
        $testParameters = @{
            FQDNs = 'app1.contoso.com','app2.contoso.com','www.microsoft.com'
            DNSServers = 'dns01.contoso.com','dns02.contoso.com'
            QueriesPerSecond = 200
            DurationSeconds = 120
        }
        $result = Invoke-DnsPerformanceTest @testParameters

    .EXAMPLE
        $captureMap = @{
            '10.20.30.10' = 'dns01.contoso.com'
            '10.20.30.11' = 'dns02.contoso.com'
        }
        $testParameters = @{
            FQDNs             = 'cached-app.contoso.com'
            DNSServers        = '10.20.30.10','10.20.30.11'
            QueriesPerSecond  = 400
            DurationSeconds   = 900
            CoordinatedCapture = $true
            TraceConditionalForwarding = $true
            CaptureComputerMap = $captureMap
        }
        $result = Invoke-DnsPerformanceTest @testParameters
        $result.CoordinatedCapture.Endpoints |
            Select-Object DNS_Server,MatchedPairs,CoveragePercent,
                ClientWire,ServerTurnaround,NetworkRemainder

    .EXAMPLE
        $testParameters = @{
            FQDNs = $names
            DNSServers = $servers
            QueriesPerSecond = 200
            DurationSeconds = 1800
            DisplayIntervalSeconds = 5
            CsvOutputPath = 'C:\Temp\DnsPerformance.csv'
        }
        $result = Invoke-DnsPerformanceTest @testParameters

    .OUTPUTS
        PSCustomObject containing configuration, timing, cumulative metrics, status
        counts, RCODE counts, observer-health evidence, DNS latency incidents with
        independently qualifying scope and paired-round evidence, their server-by-FQDN
        pair details, optional detailed results, and optional coordinated Npcap timing
        evidence with per-endpoint capture diagnostics. When requested, conditional-
        forwarding evidence includes per-flight upstream attempts and per-master
        response metrics.

    .NOTES
        Name: Invoke-DnsPerformanceTest
        Version: 4.2.6
        PowerShell: Windows PowerShell 5.1 (including ISE) or PowerShell 7+

        This is a controlled production probe. Confirm that the requested aggregate
        rate is acceptable before running against production infrastructure.

        DNS LATENCY DEGRADATION uses fixed objectives for known-cached names, applied
        independently to each server-by-FQDN pair in sliding windows and across the
        complete run:
          * at least 99.9% successful DNS answers;
          * at least 99% of successful answers below 10 ms; and
          * at least 99.9% of successful answers below 50 ms.

        Short-window evaluation begins only after a complete DegradationWindowSeconds
        window has accumulated, preventing shorter startup denominators from being
        more sensitive than later windows. A window must also contain at least
        MinimumDegradationSamples violations of an objective before it qualifies.
        The 10 ms and 50 ms grades are intentionally
        conservative relative to RFC 9199's observation that a cached response is
        typically below 1 ms and that 50 ms can be fast for a new query. They are
        service objectives for this controlled cached-answer test, not universal DNS
        standards. Primary incident scope is based on servers whose server-by-FQDN
        cells independently breach an objective. Simultaneous peer latency and observer
        overlap are reported separately as exact paired-round counts. These measurements
        do not claim a DNS-server, client, security-control, or network root cause.

        The percentile objectives follow the SLI/SLO practice of measuring the
        proportion of requests faster than fixed thresholds. Short sliding windows
        localize bursts for packet-capture correlation; isolated maxima remain in the
        ordinary summary and CSV without alone failing an objective.

        Pair-level spikes end after a complete one-second bucket without a qualifying
        observation. Spikes that overlap, or are separated by no more than 100 ms, are
        consolidated into a parent incident without using infrastructure topology.

        ResponseTimeMs is socket-observed response latency for UDP responses. It is not
        a packet-capture timestamp and therefore cannot, by itself, prove where delay
        occurred. ReceivedUtc, ParserQueueDelayMs, ParseDurationMs,
        ContinuationDelayMs, ClientProcessingDelayMs, EndToEndTimeMs, and TimingSource
        in detailed results and CSV distinguish socket receipt from test-client work.
        Packet capture and host/network telemetry remain the authority for root-cause
        attribution.

        CoordinatedCapture adds packet-boundary measurements without changing the
        normal DNS workload. Client packet-observed latency is measured between the
        client Npcap request and response timestamps. Server packet turnaround is
        measured between the corresponding server Npcap receive and transmit
        timestamps. Combined network time is client packet-observed latency minus
        server packet turnaround; it combines both network directions and any
        difference between the two capture points. Clock synchronization is
        not required because each duration is calculated on a single computer. The
        absolute client and server UTC timestamps returned for retained slow pairs do
        reflect their respective host clocks and should only be compared directly when
        those clocks are suitably synchronized.

        If server-side capture is unavailable for one endpoint, that endpoint is
        labeled ClientOnly. Its normal socket-observed metrics remain in the ordinary
        tables and CSV, but server turnaround, combined network time, directional
        deltas, and conditional-forwarding evidence are unavailable. Other endpoints
        in the same run still receive full coordinated analysis.

        OutboundDelayDeltaMs and ReturnDelayDeltaMs are directional changes relative
        to a nearby low-delay transaction from the same DNS endpoint. For each
        one-second interval, the reference is an actual transaction near the 10th
        percentile of combined network time within an approximately 11-second window.
        Subtracting the reference cancels a stable client/server clock offset. These
        fields show which direction became slower or faster than its nearby baseline;
        they are not absolute one-way latency. A clock adjustment or material drift
        inside the baseline window can invalidate the directional split.

        TraceConditionalForwarding adds a second, narrow server-side capture handle.
        It discovers only conditional forwarder zones matching the tested FQDNs and
        captures DNS between the test client, caching server, and those configured
        masters. A missing response means no response was observed at the caching server
        before its next action; it does not by itself prove the remote server was down.
        Repeated client requests can be coalesced behind one upstream resolution flight.
        Queries without an observed flight can be cache hits, locally answered queries,
        or unattributed traffic and are labeled accordingly rather than assumed cached.
        Attempt order is reported from packets, not inferred from configuration, because
        Windows DNS can adapt its forwarder preference. TCP DNS parsing is best effort
        when a message spans multiple TCP segments. The trace is restricted to the
        tested question names and does not follow different CNAME-derived child names.
        All relevant egress routes must use the DNS endpoint's adapter; the script stops
        with a clear error if it detects a matching master on another adapter.

        Npcap does not normally require the calling PowerShell process to be elevated.
        If Npcap was installed in admin-only mode, its local helper requests UAC when
        the capture handle is opened. Remote Npcap access is verified during preflight;
        an interactive run can prompt once when the failure specifically indicates
        rejected or unauthorized credentials. Unavailable and non-Windows remoting
        targets automatically continue with client-side timing. Unattended runs should
        supply CaptureCredential when alternate Windows credentials are required.

    .LINK
        https://datatracker.ietf.org/doc/html/rfc9199#section-3.5.1

    .LINK
        https://sre.google/workbook/implementing-slos/

    .LINK
        https://sre.google/sre-book/monitoring-distributed-systems/

    .LINK
        https://sre.google/workbook/alerting-on-slos/

    .LINK
        https://blog.powerdns.com/2017/11/02/dns-performance-metrics-the-logarithmic-percentile-histogram

    .LINK
        https://learn.microsoft.com/en-us/dotnet/api/system.net.sockets.socket.receive?view=netframework-4.8.1

    .LINK
        https://learn.microsoft.com/en-us/dotnet/api/system.threading.threadpool.setminthreads?view=netframework-4.8.1

    .LINK
        https://npcap.com/guide/npcap-users-guide.html
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(1, 10)]
        [string[]]$FQDNs,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(1, 64)]
        [string[]]$DNSServers,

        [Parameter(Mandatory)]
        [ValidateRange(1, 100000)]
        [Alias('QpsPerServer')]
        [int]$QueriesPerSecond,

        [ValidateRange(1, 86400)]
        [int]$DurationSeconds = 120,

        [ValidateSet('A','AAAA','CNAME','NS','PTR','SOA','MX','TXT','SRV')]
        [string]$QueryType = 'A',

        [ValidateRange(100, 60000)]
        [int]$TimeoutMilliseconds = 2000,

        [ValidateRange(0, 32768)]
        [int]$MaxOutstandingPerServer = 0,

        [ValidateRange(0.1, 1000.0)]
        [double]$SchedulerToleranceMilliseconds = 25.0,

        [ValidateRange(1.0, 60.0)]
        [double]$DisplayIntervalSeconds = 5.0,

        [ValidateRange(2, 300)]
        [int]$RollingWindowSeconds = 10,

        [ValidateRange(0, 60)]
        [int]$WarmupSeconds = 5,

        [ValidateRange(0, 64)]
        [int]$ProcessingWorkerCount = 0,

        [ValidateRange(0.1, 1000.0)]
        [double]$ObserverProcessingThresholdMilliseconds = 5.0,

        [ValidateRange(2, 300)]
        [int]$DegradationWindowSeconds = 5,

        [ValidateRange(1, 100000)]
        [int]$MinimumDegradationSamples = 3,

        [ValidateRange(1, 1000)]
        [int]$MaximumDegradationEvents = 20,

        [switch]$DisableTcpFallback,

        [switch]$NoRecursion,

        [switch]$NoEdns,

        [ValidateRange(512, 4096)]
        [int]$UdpPayloadSize = 1232,

        [switch]$AllowNoAnswer,

        [string]$CsvOutputPath,

        [switch]$IncludeDetailedResults,

        [ValidateRange(1, 10000000)]
        [long]$MaximumDetailedResults = 250000,

        [ValidateRange(1, 1000000000)]
        [long]$MaximumPlannedQueries = 10000000,

        [switch]$CoordinatedCapture,

        [hashtable]$CaptureComputerMap,

        [System.Management.Automation.PSCredential]$CaptureCredential,

        [switch]$CaptureUseSSL,

        [ValidateRange(5, 300)]
        [int]$CaptureStartupTimeoutSeconds = 45,

        [ValidateRange(1, 60)]
        [int]$CaptureGraceSeconds = 5,

        [ValidateRange(1000, 100000000)]
        [int]$CaptureMaximumPacketsPerEndpoint = 1000000,

        [ValidateRange(0.0, 60000.0)]
        [double]$CaptureSlowTransactionThresholdMilliseconds = 10.0,

        [ValidateRange(0, 100000)]
        [int]$CaptureMaximumSlowTransactions = 1000,

        [switch]$TraceConditionalForwarding,

        [ValidateRange(1000, 100000000)]
        [int]$CaptureMaximumForwardingPacketsPerEndpoint = 3000000,

        [ValidateRange(1, 100000)]
        [int]$CaptureMaximumForwardingFlights = 5000
    )

    begin {
        if (-not ('DnsPerformanceV420.DnsLoadRunner' -as [type])) {
            Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace DnsPerformanceV420
{
    public sealed class DnsTarget
    {
        public string Label { get; private set; }
        public string Address { get; private set; }
        internal IPAddress IpAddress { get; private set; }

        public DnsTarget(string label, string address)
        {
            IPAddress parsed;
            if (!IPAddress.TryParse(address, out parsed))
                throw new ArgumentException("The target address is invalid.", "address");
            Label = label;
            Address = parsed.ToString();
            IpAddress = parsed;
        }
    }

    public sealed class RunnerOptions
    {
        public int QueriesPerSecondPerServer { get; set; }
        public int DurationSeconds { get; set; }
        public int TimeoutMilliseconds { get; set; }
        public int MaxOutstandingPerServer { get; set; }
        public double SchedulerToleranceMilliseconds { get; set; }
        public bool RecursionDesired { get; set; }
        public bool UseEdns { get; set; }
        public ushort UdpPayloadSize { get; set; }
        public bool TcpFallback { get; set; }
        public bool RequireAnswer { get; set; }
        public string CsvOutputPath { get; set; }
        public bool KeepDetailedResults { get; set; }
        public int DegradationWindowSeconds { get; set; }
        public int MinimumDegradationSamples { get; set; }
        public int MaximumDegradationEvents { get; set; }
        public double NormalLatencyThresholdMs { get; set; }
        public double SevereLatencyThresholdMs { get; set; }
        public int WarmupSeconds { get; set; }
        public int ProcessingWorkerCount { get; set; }
        public double ObserverProcessingThresholdMs { get; set; }
        public bool WaitForMeasurementRelease { get; set; }
    }

    public sealed class RunnerProgress
    {
        private long scheduledRounds;
        private long startedQueries;
        private long completedQueries;
        private long schedulerMisses;
        private long concurrencyDrops;

        public DateTime StartUtc { get; internal set; }
        public DateTime WarmupStartUtc { get; internal set; }
        public int WarmupSeconds { get; internal set; }
        public string Phase { get; internal set; }
        public long PlannedRounds { get; internal set; }
        public long PlannedQueries { get; internal set; }
        public long ScheduledRounds { get { return Interlocked.Read(ref scheduledRounds); } }
        public long StartedQueries { get { return Interlocked.Read(ref startedQueries); } }
        public long CompletedQueries { get { return Interlocked.Read(ref completedQueries); } }
        public long SchedulerMisses { get { return Interlocked.Read(ref schedulerMisses); } }
        public long ConcurrencyDrops { get { return Interlocked.Read(ref concurrencyDrops); } }

        internal void MarkRound() { Interlocked.Increment(ref scheduledRounds); }
        internal void MarkStarted() { Interlocked.Increment(ref startedQueries); }
        internal void MarkCompleted() { Interlocked.Increment(ref completedQueries); }
        internal void MarkSchedulerMiss() { Interlocked.Increment(ref schedulerMisses); }
        internal void MarkConcurrencyDrop() { Interlocked.Increment(ref concurrencyDrops); }
    }

    public sealed class RunnerCompletion
    {
        public DateTime StartUtc { get; internal set; }
        public DateTime SchedulingEndUtc { get; internal set; }
        public DateTime EndUtc { get; internal set; }
        public long PlannedQueries { get; internal set; }
        public long StartedQueries { get; internal set; }
        public long SchedulerMisses { get; internal set; }
        public long ConcurrencyDrops { get; internal set; }
        public ObserverSnapshot Observer { get; internal set; }
    }

    public sealed class DnsQueryResult
    {
        public long Sequence { get; set; }
        public DateTime ScheduledUtc { get; set; }
        public DateTime StartedUtc { get; set; }
        public DateTime ReceivedUtc { get; set; }
        public DateTime CompletedUtc { get; set; }
        public string Server { get; set; }
        public string ServerAddress { get; set; }
        public string QueryName { get; set; }
        public string QueryType { get; set; }
        public ushort ClientPort { get; set; }
        public ushort TransactionId { get; set; }
        public uint CaptureOccurrence { get; set; }
        public string Status { get; set; }
        public bool Sent { get; set; }
        public bool ResponseReceived { get; set; }
        public bool Success { get; set; }
        public bool TcpFallbackUsed { get; set; }
        public bool Truncated { get; set; }
        public int AnswerCount { get; set; }
        public int RCode { get; set; }
        public string RCodeName { get; set; }
        public double ResponseTimeMs { get; set; }
        public double ClientProcessingDelayMs { get; set; }
        public double ParserQueueDelayMs { get; set; }
        public double ParseDurationMs { get; set; }
        public double ContinuationDelayMs { get; set; }
        public double EndToEndTimeMs { get; set; }
        public string TimingSource { get; set; }
        public double SchedulerLagMs { get; set; }
        public string ErrorMessage { get; set; }
    }

    internal sealed class ParsedResponse
    {
        public int RCode;
        public bool Truncated;
        public int AnswerCount;
    }

    internal sealed class DnsProtocolException : Exception
    {
        public DnsProtocolException(string message) : base(message) { }
    }

    internal static class WindowsTimerResolution
    {
        [DllImport("winmm.dll", EntryPoint = "timeBeginPeriod")]
        private static extern uint TimeBeginPeriod(uint milliseconds);
        [DllImport("winmm.dll", EntryPoint = "timeEndPeriod")]
        private static extern uint TimeEndPeriod(uint milliseconds);

        public static bool Begin()
        {
            if (Environment.OSVersion.Platform != PlatformID.Win32NT) return false;
            try { return TimeBeginPeriod(1) == 0; }
            catch { return false; }
        }

        public static void End(bool enabled)
        {
            if (!enabled) return;
            try { TimeEndPeriod(1); }
            catch { }
        }
    }

    public static class DnsWire
    {
        public static string NormalizeName(string name)
        {
            if (String.IsNullOrWhiteSpace(name))
                throw new ArgumentException("DNS query names cannot be empty.");

            string normalized = name.Trim();
            while (normalized.EndsWith(".", StringComparison.Ordinal))
                normalized = normalized.Substring(0, normalized.Length - 1);
            if (normalized.Length == 0)
                throw new ArgumentException("The DNS root cannot be queried.");

            string[] labels = normalized.Split('.');
            IdnMapping idn = new IdnMapping();
            int wireLength = 1;
            for (int i = 0; i < labels.Length; i++)
            {
                if (labels[i].Length == 0)
                    throw new ArgumentException("DNS query names cannot contain empty labels.");
                string ascii = IsAscii(labels[i]) ? labels[i] : idn.GetAscii(labels[i]);
                byte[] bytes = Encoding.ASCII.GetBytes(ascii);
                if (bytes.Length < 1 || bytes.Length > 63)
                    throw new ArgumentException("Each encoded DNS label must contain 1 through 63 bytes.");
                for (int j = 0; j < bytes.Length; j++)
                    if (bytes[j] < 0x21 || bytes[j] > 0x7e)
                        throw new ArgumentException("DNS labels cannot contain spaces or control characters.");
                labels[i] = ascii;
                wireLength += 1 + bytes.Length;
            }
            if (wireLength > 255)
                throw new ArgumentException("The encoded DNS name exceeds 255 wire bytes.");
            return String.Join(".", labels);
        }

        private static bool IsAscii(string value)
        {
            for (int i = 0; i < value.Length; i++) if (value[i] > 0x7f) return false;
            return true;
        }

        public static ushort GetQueryTypeCode(string queryType)
        {
            switch (queryType.ToUpperInvariant())
            {
                case "A": return 1;
                case "NS": return 2;
                case "CNAME": return 5;
                case "SOA": return 6;
                case "PTR": return 12;
                case "MX": return 15;
                case "TXT": return 16;
                case "AAAA": return 28;
                case "SRV": return 33;
                default: throw new ArgumentException("Unsupported DNS query type: " + queryType);
            }
        }

        public static string GetQueryTypeName(ushort queryType)
        {
            switch (queryType)
            {
                case 1: return "A";
                case 2: return "NS";
                case 5: return "CNAME";
                case 6: return "SOA";
                case 12: return "PTR";
                case 15: return "MX";
                case 16: return "TXT";
                case 28: return "AAAA";
                case 33: return "SRV";
                default: return queryType.ToString(CultureInfo.InvariantCulture);
            }
        }

        public static string GetRCodeName(int rcode)
        {
            switch (rcode)
            {
                case 0: return "NOERROR";
                case 1: return "FORMERR";
                case 2: return "SERVFAIL";
                case 3: return "NXDOMAIN";
                case 4: return "NOTIMP";
                case 5: return "REFUSED";
                case 6: return "YXDOMAIN";
                case 7: return "YXRRSET";
                case 8: return "NXRRSET";
                case 9: return "NOTAUTH";
                case 10: return "NOTZONE";
                case 16: return "BADVERS";
                case 17: return "BADKEY";
                case 18: return "BADTIME";
                case 19: return "BADMODE";
                case 20: return "BADNAME";
                case 21: return "BADALG";
                case 22: return "BADTRUNC";
                case 23: return "BADCOOKIE";
                default: return "RCODE" + rcode.ToString(CultureInfo.InvariantCulture);
            }
        }

        internal static byte[] BuildQuery(ushort id, string name, ushort queryType,
            bool recursionDesired, bool useEdns, ushort udpPayloadSize)
        {
            List<byte> bytes = new List<byte>(64);
            WriteUInt16(bytes, id);
            WriteUInt16(bytes, recursionDesired ? (ushort)0x0100 : (ushort)0);
            WriteUInt16(bytes, 1);
            WriteUInt16(bytes, 0);
            WriteUInt16(bytes, 0);
            WriteUInt16(bytes, useEdns ? (ushort)1 : (ushort)0);
            string[] labels = name.Split('.');
            for (int i = 0; i < labels.Length; i++)
            {
                byte[] label = Encoding.ASCII.GetBytes(labels[i]);
                bytes.Add((byte)label.Length);
                bytes.AddRange(label);
            }
            bytes.Add(0);
            WriteUInt16(bytes, queryType);
            WriteUInt16(bytes, 1);
            if (useEdns)
            {
                bytes.Add(0);
                WriteUInt16(bytes, 41);
                WriteUInt16(bytes, udpPayloadSize);
                WriteUInt32(bytes, 0);
                WriteUInt16(bytes, 0);
            }
            return bytes.ToArray();
        }

        internal static ParsedResponse ParseResponse(byte[] buffer, ushort expectedId,
            string expectedName, ushort expectedType)
        {
            return ParseResponse(buffer, buffer == null ? 0 : buffer.Length,
                expectedId, expectedName, expectedType);
        }

        internal static ParsedResponse ParseResponse(byte[] buffer, int packetLength,
            ushort expectedId, string expectedName, ushort expectedType)
        {
            if (buffer == null || packetLength < 12 || packetLength > buffer.Length)
                throw new DnsProtocolException("The DNS response is shorter than its header.");
            int offset = 0;
            ushort id = ReadUInt16(buffer, ref offset, packetLength);
            ushort flags = ReadUInt16(buffer, ref offset, packetLength);
            ushort questionCount = ReadUInt16(buffer, ref offset, packetLength);
            ushort answerCount = ReadUInt16(buffer, ref offset, packetLength);
            ushort authorityCount = ReadUInt16(buffer, ref offset, packetLength);
            ushort additionalCount = ReadUInt16(buffer, ref offset, packetLength);

            if (id != expectedId) throw new DnsProtocolException("Transaction ID mismatch.");
            if ((flags & 0x8000) == 0) throw new DnsProtocolException("Packet is not a DNS response.");
            if ((flags & 0x7800) != 0) throw new DnsProtocolException("Response opcode is not QUERY.");
            if (questionCount != 1) throw new DnsProtocolException("Response must contain one question.");

            string responseName = ReadName(buffer, ref offset, packetLength);
            ushort responseType = ReadUInt16(buffer, ref offset, packetLength);
            ushort responseClass = ReadUInt16(buffer, ref offset, packetLength);
            if (!String.Equals(responseName.TrimEnd('.'), expectedName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                throw new DnsProtocolException("Response question name mismatch.");
            if (responseType != expectedType) throw new DnsProtocolException("Response question type mismatch.");
            if (responseClass != 1) throw new DnsProtocolException("Response question class is not IN.");

            bool truncated = (flags & 0x0200) != 0;
            if (truncated)
                return new ParsedResponse { RCode = flags & 15, Truncated = true, AnswerCount = answerCount };

            int extendedRCode = 0;
            int records = checked((int)answerCount + (int)authorityCount + (int)additionalCount);
            for (int i = 0; i < records; i++)
            {
                ReadName(buffer, ref offset, packetLength);
                ushort type = ReadUInt16(buffer, ref offset, packetLength);
                ReadUInt16(buffer, ref offset, packetLength);
                uint ttl = ReadUInt32(buffer, ref offset, packetLength);
                ushort length = ReadUInt16(buffer, ref offset, packetLength);
                if (offset + length > packetLength)
                    throw new DnsProtocolException("A resource record extends beyond the packet.");
                if (type == 41) extendedRCode = (int)((ttl >> 24) & 0xff);
                offset += length;
            }
            return new ParsedResponse
            {
                RCode = (extendedRCode << 4) | (flags & 15),
                Truncated = false,
                AnswerCount = answerCount
            };
        }

        private static string ReadName(byte[] buffer, ref int offset, int packetLength)
        {
            if (offset < 0 || offset >= packetLength)
                throw new DnsProtocolException("A DNS name starts outside the packet.");
            StringBuilder name = new StringBuilder();
            HashSet<int> pointers = new HashSet<int>();
            int position = offset;
            bool jumped = false;
            int labels = 0;
            while (true)
            {
                if (position >= packetLength) throw new DnsProtocolException("A DNS name exceeds the packet.");
                byte length = buffer[position];
                if (length == 0)
                {
                    if (!jumped) offset = position + 1;
                    break;
                }
                if ((length & 0xc0) == 0xc0)
                {
                    if (position + 1 >= packetLength) throw new DnsProtocolException("Incomplete compression pointer.");
                    int pointer = ((length & 0x3f) << 8) | buffer[position + 1];
                    if (pointer >= packetLength || !pointers.Add(pointer))
                        throw new DnsProtocolException("Invalid DNS compression pointer.");
                    if (!jumped) offset = position + 2;
                    position = pointer;
                    jumped = true;
                    continue;
                }
                if ((length & 0xc0) != 0 || length > 63 || position + 1 + length > packetLength)
                    throw new DnsProtocolException("Invalid DNS label.");
                if (name.Length > 0) name.Append('.');
                name.Append(Encoding.ASCII.GetString(buffer, position + 1, length));
                position += 1 + length;
                labels++;
                if (labels > 127 || name.Length > 253) throw new DnsProtocolException("DNS name exceeds limits.");
                if (!jumped) offset = position;
            }
            return name.ToString();
        }

        private static ushort ReadUInt16(byte[] buffer, ref int offset, int packetLength)
        {
            if (offset < 0 || offset + 2 > packetLength) throw new DnsProtocolException("Invalid 16-bit field.");
            ushort value = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;
            return value;
        }

        private static uint ReadUInt32(byte[] buffer, ref int offset, int packetLength)
        {
            if (offset < 0 || offset + 4 > packetLength) throw new DnsProtocolException("Invalid 32-bit field.");
            uint value = ((uint)buffer[offset] << 24) | ((uint)buffer[offset + 1] << 16) |
                ((uint)buffer[offset + 2] << 8) | buffer[offset + 3];
            offset += 4;
            return value;
        }

        private static void WriteUInt16(List<byte> bytes, ushort value)
        {
            bytes.Add((byte)(value >> 8));
            bytes.Add((byte)(value & 0xff));
        }

        private static void WriteUInt32(List<byte> bytes, uint value)
        {
            bytes.Add((byte)(value >> 24));
            bytes.Add((byte)((value >> 16) & 0xff));
            bytes.Add((byte)((value >> 8) & 0xff));
            bytes.Add((byte)(value & 0xff));
        }
    }

    public sealed class MetricSnapshot
    {
        public long Planned { get; internal set; }
        public long Sent { get; internal set; }
        public long NotSent { get; internal set; }
        public long ResponseReceived { get; internal set; }
        public double ResponseRatePercent { get; internal set; }
        public long Success { get; internal set; }
        public double SuccessRatePercent { get; internal set; }
        public long Timeout { get; internal set; }
        public long DnsError { get; internal set; }
        public long OtherFailure { get; internal set; }
        public long SchedulerMiss { get; internal set; }
        public long ConcurrencyDrop { get; internal set; }
        public long TcpFallback { get; internal set; }
        public double? AverageMs { get; internal set; }
        public double? StdDevMs { get; internal set; }
        public double? MinMs { get; internal set; }
        public double? P50Ms { get; internal set; }
        public double? P95Ms { get; internal set; }
        public double? P99Ms { get; internal set; }
        public double? MaxMs { get; internal set; }
        public double? ClientProcessingAverageMs { get; internal set; }
        public double? ClientProcessingP95Ms { get; internal set; }
        public double? ClientProcessingP99Ms { get; internal set; }
        public double? ClientProcessingMaxMs { get; internal set; }
        public double MaxSchedulerLagMs { get; internal set; }
        public double Qps { get; internal set; }
    }

    public sealed class NamedMetricSnapshot
    {
        public string Name { get; internal set; }
        public string Address { get; internal set; }
        public MetricSnapshot Metrics { get; internal set; }
    }

    public sealed class CellMetricSnapshot
    {
        public string Server { get; internal set; }
        public string ServerAddress { get; internal set; }
        public string QueryName { get; internal set; }
        public MetricSnapshot Metrics { get; internal set; }
    }

    public sealed class CountSnapshot
    {
        public string Name { get; internal set; }
        public long Count { get; internal set; }
    }

    public sealed class FinalSnapshot
    {
        public MetricSnapshot Overall { get; internal set; }
        public NamedMetricSnapshot[] PerServer { get; internal set; }
        public NamedMetricSnapshot[] PerFqdn { get; internal set; }
        public CellMetricSnapshot[] PerServerFqdn { get; internal set; }
        public CountSnapshot[] StatusCounts { get; internal set; }
        public CountSnapshot[] RCodeCounts { get; internal set; }
        public DnsQueryResult[] DetailedResults { get; internal set; }
        public DegradationEventSnapshot[] DegradationEvents { get; internal set; }
        public int TotalDegradationEvents { get; internal set; }
        public int OmittedDegradationEvents { get; internal set; }
        public DegradationIncidentSnapshot[] DegradationIncidents { get; internal set; }
        public int TotalDegradationIncidents { get; internal set; }
        public int OmittedDegradationIncidents { get; internal set; }
        public DnsQueryResult LargestSuccessfulObservation { get; internal set; }
        public ObserverSnapshot Observer { get; internal set; }
    }

    public sealed class ObserverSnapshot
    {
        public int WarmupSeconds { get; internal set; }
        public int ParserWorkerCount { get; internal set; }
        public long ParserProcessedPackets { get; internal set; }
        public int ParserMaxQueueDepth { get; internal set; }
        public double ParserAverageQueueDelayMs { get; internal set; }
        public double ParserMaxQueueDelayMs { get; internal set; }
        public double ParserAverageParseMs { get; internal set; }
        public double ParserMaxParseMs { get; internal set; }
        public double ProcessCpuPercent { get; internal set; }
        public int Gen0Collections { get; internal set; }
        public int Gen1Collections { get; internal set; }
        public int Gen2Collections { get; internal set; }
        public double MaxManagedMemoryMb { get; internal set; }
        public double MaxWorkingSetMb { get; internal set; }
        public int MinAvailableWorkerThreads { get; internal set; }
        public int MinAvailableIoThreads { get; internal set; }
        public double ProcessingThresholdMs { get; internal set; }
    }

    public sealed class DegradationEventSnapshot
    {
        public DateTime StartUtc { get; internal set; }
        public DateTime EndUtc { get; internal set; }
        public double DurationMs { get; internal set; }
        public string Server { get; internal set; }
        public string ServerAddress { get; internal set; }
        public string QueryName { get; internal set; }
        public string Scope { get; internal set; }
        public string Objectives { get; internal set; }
        public long Sent { get; internal set; }
        public long Bad { get; internal set; }
        public long AvailabilityFailures { get; internal set; }
        public long Timeouts { get; internal set; }
        public long DnsErrors { get; internal set; }
        public long OtherFailures { get; internal set; }
        public long NormalSlow { get; internal set; }
        public long SevereSlow { get; internal set; }
        public double BadPercent { get; internal set; }
        public double MaxResponseMs { get; internal set; }
        public double MaxSchedulerLagMs { get; internal set; }
        public int AffectedEndpoints { get; internal set; }
        public int PeakAffectedEndpoints { get; internal set; }
        public int TotalEndpoints { get; internal set; }
        public string Attribution { get; internal set; }
        public int ObserverSuspectRounds { get; internal set; }
        public int SharedSlowRounds { get; internal set; }
        public int EndpointOnlyRounds { get; internal set; }
        internal int ServerIndex { get; set; }
        internal int NameIndex { get; set; }
        internal int FirstSecond { get; set; }
        internal int LastSecond { get; set; }
        internal byte ObjectiveFlags { get; set; }
    }

    public sealed class DegradationIncidentSnapshot
    {
        public int IncidentNumber { get; internal set; }
        public DateTime StartUtc { get; internal set; }
        public DateTime EndUtc { get; internal set; }
        public double DurationMs { get; internal set; }
        public string PrimaryScope { get; internal set; }
        // Retained as an alias for callers of earlier versions. In v3.5.3 this
        // has the same independently qualifying-server meaning as PrimaryScope.
        public string Correlation { get; internal set; }
        // Retained as an exact-count compatibility string; use the numeric
        // paired-round fields for analysis.
        public string ClientEvidence { get; internal set; }
        public string Objectives { get; internal set; }
        public string[] Servers { get; internal set; }
        public string[] ServerAddresses { get; internal set; }
        public string[] QueryNames { get; internal set; }
        public int AffectedEndpointCount { get; internal set; }
        public int TotalEndpoints { get; internal set; }
        public int AffectedNameCount { get; internal set; }
        public int TotalNames { get; internal set; }
        public int PairEventCount { get; internal set; }
        public long EvaluatedQueries { get; internal set; }
        public long AffectedQueries { get; internal set; }
        public long AvailabilityFailures { get; internal set; }
        public long Timeouts { get; internal set; }
        public long DnsErrors { get; internal set; }
        public long OtherFailures { get; internal set; }
        public long NormalSlow { get; internal set; }
        public long SevereSlow { get; internal set; }
        public double MaxResponseMs { get; internal set; }
        public double MaxSchedulerLagMs { get; internal set; }
        public int AffectedRoundCount { get; internal set; }
        public int PeakAffectedEndpoints { get; internal set; }
        public int ObserverSuspectRounds { get; internal set; }
        public int ObserverSharedRounds { get; internal set; }
        public int SharedSlowRounds { get; internal set; }
        public int MajoritySlowRounds { get; internal set; }
        public int EndpointOnlyRounds { get; internal set; }
        public DegradationEventSnapshot[] PairEvents { get; internal set; }
    }

    public sealed class LiveServerSnapshot
    {
        public string Server { get; internal set; }
        public string Address { get; internal set; }
        public MetricSnapshot Metrics { get; internal set; }
        public MetricSnapshot[] FqdnMetrics { get; internal set; }
    }

    public sealed class LiveSnapshot
    {
        public DateTime SnapshotUtc { get; internal set; }
        public double EffectiveWindowSeconds { get; internal set; }
        public MetricSnapshot Overall { get; internal set; }
        public LiveServerSnapshot[] Servers { get; internal set; }
    }

    internal sealed class MetricAccumulator
    {
        private readonly object sync = new object();
        private readonly long[] histogram = new long[8701];
        private readonly long[] processingHistogram = new long[8701];
        private long planned;
        private long sent;
        private long responseReceived;
        private long success;
        private long timeout;
        private long dnsError;
        private long otherFailure;
        private long schedulerMiss;
        private long concurrencyDrop;
        private long tcpFallback;
        private double mean;
        private double m2;
        private double min = Double.PositiveInfinity;
        private double max;
        private long processingCount;
        private double processingMean;
        private double processingMax;
        private double maxSchedulerLag;

        public void Add(DnsQueryResult result)
        {
            lock (sync)
            {
                planned++;
                if (result.SchedulerLagMs > maxSchedulerLag) maxSchedulerLag = result.SchedulerLagMs;
                if (!result.Sent)
                {
                    if (result.Status == "SchedulerMiss") schedulerMiss++;
                    else if (result.Status == "ConcurrencyLimit") concurrencyDrop++;
                    else otherFailure++;
                    return;
                }

                sent++;
                if (result.ResponseReceived)
                {
                    responseReceived++;
                    processingCount++;
                    double processingDelta = result.ClientProcessingDelayMs - processingMean;
                    processingMean += processingDelta / processingCount;
                    if (result.ClientProcessingDelayMs > processingMax)
                        processingMax = result.ClientProcessingDelayMs;
                    processingHistogram[GetBin(result.ClientProcessingDelayMs)]++;
                }
                if (result.TcpFallbackUsed) tcpFallback++;
                if (result.Success)
                {
                    success++;
                    double delta = result.ResponseTimeMs - mean;
                    mean += delta / success;
                    m2 += delta * (result.ResponseTimeMs - mean);
                    if (result.ResponseTimeMs < min) min = result.ResponseTimeMs;
                    if (result.ResponseTimeMs > max) max = result.ResponseTimeMs;
                    histogram[GetBin(result.ResponseTimeMs)]++;
                }
                else if (result.Status == "Timeout") timeout++;
                else if (result.Status == "DnsError") dnsError++;
                else otherFailure++;
            }
        }

        public MetricSnapshot Snapshot(double qps)
        {
            lock (sync)
            {
                MetricSnapshot value = NewBaseSnapshot(planned, sent, responseReceived, success,
                    timeout, dnsError, otherFailure, schedulerMiss, concurrencyDrop, tcpFallback,
                    maxSchedulerLag, qps);
                if (success > 0)
                {
                    value.AverageMs = Round(mean);
                    value.StdDevMs = Round(Math.Sqrt(Math.Max(0.0, m2 / success)));
                    value.MinMs = Round(min);
                    value.P50Ms = Round(GetPercentile(0.50));
                    value.P95Ms = Round(GetPercentile(0.95));
                    value.P99Ms = Round(GetPercentile(0.99));
                    value.MaxMs = Round(max);
                }
                if (processingCount > 0)
                {
                    value.ClientProcessingAverageMs = Round(processingMean);
                    value.ClientProcessingP95Ms = Round(GetProcessingPercentile(0.95));
                    value.ClientProcessingP99Ms = Round(GetProcessingPercentile(0.99));
                    value.ClientProcessingMaxMs = Round(processingMax);
                }
                return value;
            }
        }

        private double GetPercentile(double percentile)
        {
            long rank = (long)Math.Ceiling(percentile * success);
            if (rank < 1) rank = 1;
            long cumulative = 0;
            for (int i = 0; i < histogram.Length; i++)
            {
                cumulative += histogram[i];
                if (cumulative >= rank) return GetBinMidpoint(i);
            }
            return max;
        }

        private double GetProcessingPercentile(double percentile)
        {
            long rank = (long)Math.Ceiling(percentile * processingCount);
            if (rank < 1) rank = 1;
            long cumulative = 0;
            for (int i = 0; i < processingHistogram.Length; i++)
            {
                cumulative += processingHistogram[i];
                if (cumulative >= rank) return GetBinMidpoint(i);
            }
            return processingMax;
        }

        private static int GetBin(double milliseconds)
        {
            if (milliseconds < 0) return 0;
            if (milliseconds < 10.0) return Math.Min(999, (int)(milliseconds / 0.01));
            if (milliseconds < 100.0) return 1000 + Math.Min(899, (int)((milliseconds - 10.0) / 0.1));
            if (milliseconds < 1000.0) return 1900 + Math.Min(899, (int)((milliseconds - 100.0) / 1.0));
            if (milliseconds < 60000.0) return 2800 + Math.Min(5899, (int)((milliseconds - 1000.0) / 10.0));
            return 8700;
        }

        private static double GetBinMidpoint(int bin)
        {
            if (bin < 1000) return (bin + 0.5) * 0.01;
            if (bin < 1900) return 10.0 + (bin - 1000 + 0.5) * 0.1;
            if (bin < 2800) return 100.0 + (bin - 1900 + 0.5);
            if (bin < 8700) return 1000.0 + (bin - 2800 + 0.5) * 10.0;
            return 60000.0;
        }

        internal static MetricSnapshot NewBaseSnapshot(long planned, long sent,
            long responseReceived, long success, long timeout, long dnsError,
            long otherFailure, long schedulerMiss, long concurrencyDrop,
            long tcpFallback, double maxSchedulerLag, double qps)
        {
            return new MetricSnapshot
            {
                Planned = planned,
                Sent = sent,
                NotSent = planned - sent,
                ResponseReceived = responseReceived,
                ResponseRatePercent = sent > 0 ? Round(100.0 * responseReceived / sent) : 0.0,
                Success = success,
                SuccessRatePercent = sent > 0 ? Round(100.0 * success / sent) : 0.0,
                Timeout = timeout,
                DnsError = dnsError,
                OtherFailure = otherFailure,
                SchedulerMiss = schedulerMiss,
                ConcurrencyDrop = concurrencyDrop,
                TcpFallback = tcpFallback,
                MaxSchedulerLagMs = Round(maxSchedulerLag),
                Qps = Round(qps)
            };
        }

        internal static double Round(double value) { return Math.Round(value, 3); }
    }

    internal sealed class LiveMetricBuilder
    {
        private long planned;
        private long sent;
        private long responseReceived;
        private long success;
        private long timeout;
        private long dnsError;
        private long otherFailure;
        private long schedulerMiss;
        private long concurrencyDrop;
        private long tcpFallback;
        private double sum;
        private double sumSquares;
        private double min = Double.PositiveInfinity;
        private double max;
        private double maxSchedulerLag;
        private readonly List<double> latencies = new List<double>();

        public void Add(LiveEvent item)
        {
            planned++;
            if (item.SchedulerLagMs > maxSchedulerLag) maxSchedulerLag = item.SchedulerLagMs;
            if (!item.Sent)
            {
                if (item.Status == "SchedulerMiss") schedulerMiss++;
                else if (item.Status == "ConcurrencyLimit") concurrencyDrop++;
                else otherFailure++;
                return;
            }
            sent++;
            if (item.ResponseReceived) responseReceived++;
            if (item.TcpFallbackUsed) tcpFallback++;
            if (item.Success)
            {
                success++;
                sum += item.ResponseTimeMs;
                sumSquares += item.ResponseTimeMs * item.ResponseTimeMs;
                if (item.ResponseTimeMs < min) min = item.ResponseTimeMs;
                if (item.ResponseTimeMs > max) max = item.ResponseTimeMs;
                latencies.Add(item.ResponseTimeMs);
            }
            else if (item.Status == "Timeout") timeout++;
            else if (item.Status == "DnsError") dnsError++;
            else otherFailure++;
        }

        public MetricSnapshot Snapshot(double seconds)
        {
            MetricSnapshot value = MetricAccumulator.NewBaseSnapshot(planned, sent,
                responseReceived, success, timeout, dnsError, otherFailure,
                schedulerMiss, concurrencyDrop, tcpFallback, maxSchedulerLag,
                seconds > 0 ? sent / seconds : 0.0);
            if (success > 0)
            {
                latencies.Sort();
                double average = sum / success;
                double variance = Math.Max(0.0, sumSquares / success - average * average);
                value.AverageMs = MetricAccumulator.Round(average);
                value.StdDevMs = MetricAccumulator.Round(Math.Sqrt(variance));
                value.MinMs = MetricAccumulator.Round(min);
                value.P50Ms = MetricAccumulator.Round(Percentile(0.50));
                value.P95Ms = MetricAccumulator.Round(Percentile(0.95));
                value.P99Ms = MetricAccumulator.Round(Percentile(0.99));
                value.MaxMs = MetricAccumulator.Round(max);
            }
            return value;
        }

        private double Percentile(double percentile)
        {
            if (latencies.Count == 1) return latencies[0];
            double rank = (latencies.Count - 1) * percentile;
            int lower = (int)Math.Floor(rank);
            int upper = (int)Math.Ceiling(rank);
            if (lower == upper) return latencies[lower];
            return latencies[lower] + (latencies[upper] - latencies[lower]) * (rank - lower);
        }
    }

    internal sealed class LiveEvent
    {
        public long CompletedTicks;
        public int ServerIndex;
        public int NameIndex;
        public bool Sent;
        public bool ResponseReceived;
        public bool Success;
        public bool TcpFallbackUsed;
        public string Status;
        public double ResponseTimeMs;
        public double SchedulerLagMs;
    }

    internal sealed class CsvSink : IDisposable
    {
        private readonly BlockingCollection<DnsQueryResult> queue =
            new BlockingCollection<DnsQueryResult>(100000);
        private readonly Thread writerThread;
        private readonly string path;
        private Exception writerError;
        private int completed;

        public CsvSink(string outputPath)
        {
            path = outputPath;
            writerThread = new Thread(WriteLoop);
            writerThread.IsBackground = true;
            writerThread.Name = "DNS performance CSV writer";
            writerThread.Start();
        }

        public void Add(DnsQueryResult result)
        {
            while (!queue.TryAdd(result, 100))
            {
                if (writerError != null) throw new IOException("CSV writer failed.", writerError);
            }
            if (writerError != null) throw new IOException("CSV writer failed.", writerError);
        }

        public void Complete()
        {
            if (Interlocked.Exchange(ref completed, 1) != 0) return;
            queue.CompleteAdding();
            writerThread.Join();
            if (writerError != null) throw new IOException("CSV writer failed.", writerError);
        }

        private void WriteLoop()
        {
            try
            {
                using (StreamWriter writer = new StreamWriter(path, false, new UTF8Encoding(true), 65536))
                {
                    writer.WriteLine("Sequence,ScheduledUtc,StartedUtc,ReceivedUtc,CompletedUtc,Server,ServerAddress,QueryName,QueryType,ClientPort,TransactionId,CaptureOccurrence,Status,Sent,ResponseReceived,Success,TcpFallbackUsed,Truncated,AnswerCount,RCode,RCodeName,ResponseTimeMs,ClientProcessingDelayMs,ParserQueueDelayMs,ParseDurationMs,ContinuationDelayMs,EndToEndTimeMs,TimingSource,SchedulerLagMs,ErrorMessage");
                    StringBuilder batch = new StringBuilder(131072);
                    int batchCount = 0;
                    foreach (DnsQueryResult result in queue.GetConsumingEnumerable())
                    {
                        batch.AppendLine(String.Join(",", new string[]
                        {
                            result.Sequence.ToString(CultureInfo.InvariantCulture),
                            Csv(result.ScheduledUtc == DateTime.MinValue ? "" : result.ScheduledUtc.ToString("o", CultureInfo.InvariantCulture)),
                            Csv(result.StartedUtc == DateTime.MinValue ? "" : result.StartedUtc.ToString("o", CultureInfo.InvariantCulture)),
                            Csv(result.ReceivedUtc == DateTime.MinValue ? "" : result.ReceivedUtc.ToString("o", CultureInfo.InvariantCulture)),
                            Csv(result.CompletedUtc == DateTime.MinValue ? "" : result.CompletedUtc.ToString("o", CultureInfo.InvariantCulture)),
                            Csv(result.Server), Csv(result.ServerAddress), Csv(result.QueryName), Csv(result.QueryType),
                            result.Sent ? result.ClientPort.ToString(CultureInfo.InvariantCulture) : "",
                            result.Sent ? result.TransactionId.ToString(CultureInfo.InvariantCulture) : "",
                            result.Sent ? result.CaptureOccurrence.ToString(CultureInfo.InvariantCulture) : "",
                            Csv(result.Status),
                            result.Sent.ToString(), result.ResponseReceived.ToString(), result.Success.ToString(),
                            result.TcpFallbackUsed.ToString(), result.Truncated.ToString(),
                            result.AnswerCount.ToString(CultureInfo.InvariantCulture),
                            result.RCode.ToString(CultureInfo.InvariantCulture), Csv(result.RCodeName),
                            result.ResponseTimeMs.ToString("0.000", CultureInfo.InvariantCulture),
                            result.ClientProcessingDelayMs.ToString("0.000", CultureInfo.InvariantCulture),
                            result.ParserQueueDelayMs.ToString("0.000", CultureInfo.InvariantCulture),
                            result.ParseDurationMs.ToString("0.000", CultureInfo.InvariantCulture),
                            result.ContinuationDelayMs.ToString("0.000", CultureInfo.InvariantCulture),
                            result.EndToEndTimeMs.ToString("0.000", CultureInfo.InvariantCulture), Csv(result.TimingSource),
                            result.SchedulerLagMs.ToString("0.000", CultureInfo.InvariantCulture), Csv(result.ErrorMessage)
                        }));
                        batchCount++;
                        if (batchCount >= 256)
                        {
                            writer.Write(batch.ToString());
                            batch.Clear();
                            batchCount = 0;
                        }
                    }
                    if (batch.Length > 0) writer.Write(batch.ToString());
                }
            }
            catch (Exception ex) { writerError = ex; }
        }

        private static string Csv(string value)
        {
            if (value == null) return "";
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        }

        public void Dispose()
        {
            try { Complete(); }
            finally { queue.Dispose(); }
        }
    }

    internal sealed class DegradationBucket
    {
        public long Sent;
        public long Success;
        public long AvailabilityFailures;
        public long Timeouts;
        public long DnsErrors;
        public long OtherFailures;
        public long NormalSlow;
        public long SevereSlow;
        public double MaxResponseMs;
        public double MaxSchedulerLagMs;
        public long FirstViolationStartTicks = Int64.MaxValue;
        public long LastViolationEndTicks;
    }

    internal sealed class RoundEvidence
    {
        public int Second;
        public int NameIndex;
        public ulong BadEndpointMask;
        public double MaxClientProcessingMs;
        public double MaxSchedulerLagMs;
        public bool SchedulerMiss;
    }

    internal sealed class DegradationTracker
    {
        private const byte AvailabilityFlag = 1;
        private const byte NormalFlag = 2;
        private const byte SevereFlag = 4;
        private readonly object sync = new object();
        private readonly DnsTarget[] targets;
        private readonly string[] names;
        private readonly RunnerOptions options;
        private readonly Dictionary<int, DegradationBucket>[,] buckets;
        private readonly Dictionary<long, RoundEvidence> roundEvidence =
            new Dictionary<long, RoundEvidence>();
        private DateTime startUtc;

        public DegradationTracker(DnsTarget[] targets, string[] names, RunnerOptions options)
        {
            this.targets = targets;
            this.names = names;
            this.options = options;
            buckets = new Dictionary<int, DegradationBucket>[targets.Length, names.Length];
            for (int s = 0; s < targets.Length; s++)
                for (int n = 0; n < names.Length; n++)
                    buckets[s, n] = new Dictionary<int, DegradationBucket>();
        }

        public void SetStart(DateTime value) { startUtc = value; }

        public void Add(DnsQueryResult result, int serverIndex, int nameIndex)
        {
            if (startUtc == DateTime.MinValue || result.Sequence < 0) return;
            DateTime evidenceUtc = result.StartedUtc != DateTime.MinValue ?
                result.StartedUtc : result.ScheduledUtc;
            int second = (int)Math.Floor((evidenceUtc - startUtc).TotalSeconds);
            if (second < 0) second = 0;
            if (second > options.DurationSeconds + 1) second = options.DurationSeconds + 1;

            lock (sync)
            {
                long roundIndex = result.Sequence / targets.Length;
                RoundEvidence evidence;
                if (!roundEvidence.TryGetValue(roundIndex, out evidence))
                {
                    evidence = new RoundEvidence { Second = second, NameIndex = nameIndex };
                    roundEvidence.Add(roundIndex, evidence);
                }
                if (result.ClientProcessingDelayMs > evidence.MaxClientProcessingMs)
                    evidence.MaxClientProcessingMs = result.ClientProcessingDelayMs;
                if (result.SchedulerLagMs > evidence.MaxSchedulerLagMs)
                    evidence.MaxSchedulerLagMs = result.SchedulerLagMs;
                if (!result.Sent && result.Status == "SchedulerMiss") evidence.SchedulerMiss = true;
                if (serverIndex < 64 && result.Sent &&
                    (!result.Success || result.ResponseTimeMs >= options.NormalLatencyThresholdMs))
                    evidence.BadEndpointMask |= 1UL << serverIndex;

                if (!result.Sent || result.StartedUtc == DateTime.MinValue) return;
                DegradationBucket bucket;
                if (!buckets[serverIndex, nameIndex].TryGetValue(second, out bucket))
                {
                    bucket = new DegradationBucket();
                    buckets[serverIndex, nameIndex].Add(second, bucket);
                }
                bucket.Sent++;
                if (result.Success) bucket.Success++;
                else
                {
                    bucket.AvailabilityFailures++;
                    if (result.Status == "Timeout") bucket.Timeouts++;
                    else if (result.Status == "DnsError") bucket.DnsErrors++;
                    else bucket.OtherFailures++;
                }
                if (result.Success && result.ResponseTimeMs >= options.NormalLatencyThresholdMs)
                    bucket.NormalSlow++;
                if (result.Success && result.ResponseTimeMs >= options.SevereLatencyThresholdMs)
                    bucket.SevereSlow++;
                if (result.ResponseTimeMs > bucket.MaxResponseMs) bucket.MaxResponseMs = result.ResponseTimeMs;
                if (result.SchedulerLagMs > bucket.MaxSchedulerLagMs) bucket.MaxSchedulerLagMs = result.SchedulerLagMs;

                bool violation = !result.Success || result.ResponseTimeMs >= options.NormalLatencyThresholdMs;
                if (violation)
                {
                    if (result.StartedUtc.Ticks < bucket.FirstViolationStartTicks)
                        bucket.FirstViolationStartTicks = result.StartedUtc.Ticks;
                    DateTime eventEnd = result.ReceivedUtc != DateTime.MinValue ? result.ReceivedUtc :
                        (result.CompletedUtc == DateTime.MinValue ? result.StartedUtc : result.CompletedUtc);
                    if (eventEnd.Ticks > bucket.LastViolationEndTicks)
                        bucket.LastViolationEndTicks = eventEnd.Ticks;
                }
            }
        }

        public DegradationIncidentSnapshot[] Analyze(out int totalIncidents,
            out int omittedIncidents, out DegradationEventSnapshot[] displayedPairEvents,
            out int totalPairEvents, out int omittedPairEvents)
        {
            lock (sync)
            {
                List<DegradationEventSnapshot> pairEvents = new List<DegradationEventSnapshot>();
                int seconds = options.DurationSeconds;
                int window = Math.Max(1, Math.Min(options.DegradationWindowSeconds, seconds));

                for (int s = 0; s < targets.Length; s++)
                {
                    for (int n = 0; n < names.Length; n++)
                    {
                        byte[] marked = new byte[seconds];
                        long sent = 0, success = 0, availability = 0, normal = 0, severe = 0;
                        for (int i = 0; i < seconds; i++)
                        {
                            AddCounts(GetBucket(s, n, i), ref sent, ref success, ref availability, ref normal, ref severe, 1);
                            int expired = i - window;
                            if (expired >= 0)
                                AddCounts(GetBucket(s, n, expired), ref sent, ref success, ref availability, ref normal, ref severe, -1);

                            // Use identically sized denominators throughout the run.
                            // Partial startup windows would otherwise be more sensitive
                            // than the configured complete sliding window.
                            if (i < window - 1) continue;

                            bool availabilityBreach = IsBreach(availability, sent, 0.001);
                            bool normalBreach = IsBreach(normal, success, 0.01);
                            bool severeBreach = IsBreach(severe, success, 0.001);
                            if (!availabilityBreach && !normalBreach && !severeBreach) continue;

                            int first = Math.Max(0, i - window + 1);
                            for (int j = first; j <= i; j++)
                            {
                                DegradationBucket bucket = GetBucket(s, n, j);
                                if (bucket == null) continue;
                                if (availabilityBreach && bucket.AvailabilityFailures > 0) marked[j] |= AvailabilityFlag;
                                if (normalBreach && bucket.NormalSlow > 0) marked[j] |= NormalFlag;
                                if (severeBreach && bucket.SevereSlow > 0) marked[j] |= SevereFlag;
                            }
                        }

                        // A full-run backstop catches low-rate persistent degradation
                        // that is spread too evenly to breach an individual short window.
                        sent = success = availability = normal = severe = 0;
                        for (int i = 0; i < seconds; i++)
                            AddCounts(GetBucket(s, n, i), ref sent, ref success,
                                ref availability, ref normal, ref severe, 1);
                        bool fullAvailabilityBreach = IsBreach(availability, sent, 0.001);
                        bool fullNormalBreach = IsBreach(normal, success, 0.01);
                        bool fullSevereBreach = IsBreach(severe, success, 0.001);
                        if (fullAvailabilityBreach || fullNormalBreach || fullSevereBreach)
                        {
                            for (int i = 0; i < seconds; i++)
                            {
                                DegradationBucket bucket = GetBucket(s, n, i);
                                if (bucket == null) continue;
                                if (fullAvailabilityBreach && bucket.AvailabilityFailures > 0) marked[i] |= AvailabilityFlag;
                                if (fullNormalBreach && bucket.NormalSlow > 0) marked[i] |= NormalFlag;
                                if (fullSevereBreach && bucket.SevereSlow > 0) marked[i] |= SevereFlag;
                            }
                        }

                        int cursor = 0;
                        while (cursor < seconds)
                        {
                            while (cursor < seconds && marked[cursor] == 0) cursor++;
                            if (cursor >= seconds) break;
                            int first = cursor;
                            int last = cursor;
                            int probe = cursor + 1;
                            while (probe < seconds)
                            {
                                if (marked[probe] != 0)
                                {
                                    last = probe;
                                    probe++;
                                    continue;
                                }
                                // A complete clean one-second bucket ends the displayed
                                // spike. The objective detector still uses the configured
                                // sliding window; this only prevents separate observations
                                // from appearing to be continuous degradation.
                                break;
                            }
                            DegradationEventSnapshot pairEvent =
                                BuildEvent(s, n, first, last);
                            if (pairEvent != null) pairEvents.Add(pairEvent);
                            cursor = last + 1;
                        }
                    }
                }

                totalPairEvents = pairEvents.Count;
                List<DegradationIncidentSnapshot> incidents = BuildIncidents(pairEvents);
                totalIncidents = incidents.Count;
                incidents.Sort(CompareIncidentSeverity);
                if (incidents.Count > options.MaximumDegradationEvents)
                    incidents.RemoveRange(options.MaximumDegradationEvents,
                        incidents.Count - options.MaximumDegradationEvents);
                omittedIncidents = totalIncidents - incidents.Count;
                incidents.Sort(delegate(DegradationIncidentSnapshot x,
                    DegradationIncidentSnapshot y)
                {
                    return x.StartUtc.CompareTo(y.StartUtc);
                });
                List<DegradationEventSnapshot> returnedPairs =
                    new List<DegradationEventSnapshot>();
                for (int i = 0; i < incidents.Count; i++)
                {
                    incidents[i].IncidentNumber = i + 1;
                    returnedPairs.AddRange(incidents[i].PairEvents);
                }
                displayedPairEvents = returnedPairs.ToArray();
                omittedPairEvents = totalPairEvents - displayedPairEvents.Length;
                return incidents.ToArray();
            }
        }

        private bool IsBreach(long violations, long denominator, double allowedFraction)
        {
            if (denominator <= 0 || violations < options.MinimumDegradationSamples) return false;
            long firstFailingCount = (long)Math.Floor(allowedFraction * denominator) + 1;
            return violations >= Math.Max((long)options.MinimumDegradationSamples, firstFailingCount);
        }

        private DegradationBucket GetBucket(int serverIndex, int nameIndex, int second)
        {
            DegradationBucket value;
            buckets[serverIndex, nameIndex].TryGetValue(second, out value);
            return value;
        }

        private static void AddCounts(DegradationBucket bucket, ref long sent, ref long success,
            ref long availability, ref long normal, ref long severe, int multiplier)
        {
            if (bucket == null) return;
            sent += multiplier * bucket.Sent;
            success += multiplier * bucket.Success;
            availability += multiplier * bucket.AvailabilityFailures;
            normal += multiplier * bucket.NormalSlow;
            severe += multiplier * bucket.SevereSlow;
        }

        private DegradationEventSnapshot BuildEvent(int serverIndex, int nameIndex,
            int first, int last)
        {
            long sent = 0, availability = 0, timeouts = 0, dnsErrors = 0, otherFailures = 0;
            long normal = 0, severe = 0;
            double maxResponse = 0.0, maxLag = 0.0;
            long firstTicks = Int64.MaxValue, lastTicks = 0;
            for (int i = first; i <= last; i++)
            {
                DegradationBucket bucket = GetBucket(serverIndex, nameIndex, i);
                if (bucket == null) continue;
                sent += bucket.Sent;
                availability += bucket.AvailabilityFailures;
                timeouts += bucket.Timeouts;
                dnsErrors += bucket.DnsErrors;
                otherFailures += bucket.OtherFailures;
                normal += bucket.NormalSlow;
                severe += bucket.SevereSlow;
                if (bucket.MaxResponseMs > maxResponse) maxResponse = bucket.MaxResponseMs;
                if (bucket.MaxSchedulerLagMs > maxLag) maxLag = bucket.MaxSchedulerLagMs;
                if (bucket.FirstViolationStartTicks < firstTicks) firstTicks = bucket.FirstViolationStartTicks;
                if (bucket.LastViolationEndTicks > lastTicks) lastTicks = bucket.LastViolationEndTicks;
            }
            if (firstTicks == Int64.MaxValue) firstTicks = startUtc.AddSeconds(first).Ticks;
            if (lastTicks == 0) lastTicks = startUtc.AddSeconds(last + 1).Ticks;
            long success = Math.Max(0, sent - availability);
            byte qualifyingObjectives = 0;
            if (IsBreach(availability, sent, 0.001))
                qualifyingObjectives |= AvailabilityFlag;
            if (IsBreach(normal, success, 0.01))
                qualifyingObjectives |= NormalFlag;
            if (IsBreach(severe, success, 0.001))
                qualifyingObjectives |= SevereFlag;
            // A spike split away by a complete clean second must independently
            // satisfy an objective. Otherwise it remains an isolated observation
            // in the ordinary summary and CSV rather than extending an incident.
            if (qualifyingObjectives == 0) return null;
            long bad = availability + normal;
            DegradationEventSnapshot value = new DegradationEventSnapshot
            {
                StartUtc = new DateTime(firstTicks, DateTimeKind.Utc),
                EndUtc = new DateTime(lastTicks, DateTimeKind.Utc),
                DurationMs = MetricAccumulator.Round(Math.Max(0.0, TimeSpan.FromTicks(lastTicks - firstTicks).TotalMilliseconds)),
                Server = targets[serverIndex].Label,
                ServerAddress = targets[serverIndex].Address,
                QueryName = names[nameIndex],
                Objectives = BuildObjectiveText(qualifyingObjectives),
                Sent = sent,
                Bad = bad,
                AvailabilityFailures = availability,
                Timeouts = timeouts,
                DnsErrors = dnsErrors,
                OtherFailures = otherFailures,
                NormalSlow = normal,
                SevereSlow = severe,
                BadPercent = sent > 0 ? MetricAccumulator.Round(100.0 * bad / sent) : 0.0,
                MaxResponseMs = MetricAccumulator.Round(maxResponse),
                MaxSchedulerLagMs = MetricAccumulator.Round(maxLag),
                TotalEndpoints = targets.Length,
                ServerIndex = serverIndex,
                NameIndex = nameIndex,
                FirstSecond = first,
                LastSecond = last,
                ObjectiveFlags = qualifyingObjectives
            };
            ApplyAttribution(value, serverIndex, nameIndex, first, last);
            return value;
        }

        private static string BuildObjectiveText(byte flags)
        {
            List<string> values = new List<string>();
            if ((flags & AvailabilityFlag) != 0) values.Add("AVAILABILITY");
            if ((flags & NormalFlag) != 0) values.Add("10 MS LATENCY");
            if ((flags & SevereFlag) != 0) values.Add("50 MS LATENCY");
            return String.Join(", ", values.ToArray());
        }

        private void ApplyAttribution(DegradationEventSnapshot value,
            int serverIndex, int nameIndex, int firstSecond, int lastSecond)
        {
            ulong affectedMask = 0;
            int targetRounds = 0;
            int observerRounds = 0;
            int sharedRounds = 0;
            int endpointOnlyRounds = 0;
            int peakAffected = 0;
            ulong targetMask = serverIndex < 64 ? 1UL << serverIndex : 0;
            foreach (RoundEvidence evidence in roundEvidence.Values)
            {
                if (evidence.NameIndex != nameIndex || evidence.Second < firstSecond ||
                    evidence.Second > lastSecond || (evidence.BadEndpointMask & targetMask) == 0)
                    continue;
                targetRounds++;
                affectedMask |= evidence.BadEndpointMask;
                int peerCount = CountBits(evidence.BadEndpointMask);
                if (peerCount > peakAffected) peakAffected = peerCount;
                bool observer = evidence.MaxClientProcessingMs >=
                    options.ObserverProcessingThresholdMs || evidence.SchedulerMiss ||
                    evidence.MaxSchedulerLagMs >= options.SchedulerToleranceMilliseconds;
                if (observer) observerRounds++;
                if (peerCount >= 2) sharedRounds++;
                else endpointOnlyRounds++;
            }
            value.AffectedEndpoints = Math.Max(1, CountBits(affectedMask));
            value.PeakAffectedEndpoints = Math.Max(1, peakAffected);
            value.ObserverSuspectRounds = observerRounds;
            value.SharedSlowRounds = sharedRounds;
            value.EndpointOnlyRounds = endpointOnlyRounds;
            int majority = (targets.Length / 2) + 1;
            if (value.PeakAffectedEndpoints == 1) value.Scope = "ENDPOINT";
            else if (value.PeakAffectedEndpoints >= majority) value.Scope = "NAME-WIDE";
            else value.Scope = "MULTI";

            if (targetRounds > 0 && observerRounds == targetRounds)
                value.Attribution = "OBSERVER";
            else if (observerRounds > 0)
                value.Attribution = "MIXED";
            else if (sharedRounds > 0)
                value.Attribution = "MULTI";
            else value.Attribution = "ENDPOINT";
        }

        private List<DegradationIncidentSnapshot> BuildIncidents(
            List<DegradationEventSnapshot> pairEvents)
        {
            List<DegradationIncidentSnapshot> incidents =
                new List<DegradationIncidentSnapshot>();
            if (pairEvents.Count == 0) return incidents;

            pairEvents.Sort(delegate(DegradationEventSnapshot x,
                DegradationEventSnapshot y)
            {
                int value = x.StartUtc.CompareTo(y.StartUtc);
                if (value != 0) return value;
                return x.EndUtc.CompareTo(y.EndUtc);
            });

            // Temporally overlapping pair-level spikes, or spikes separated by no
            // more than 100 ms, describe one correlated incident. This uses only
            // measured timing and never assumes server, load-balancer, network, or
            // organizational relationships.
            const double CorrelationGapMs = 100.0;
            List<DegradationEventSnapshot> current =
                new List<DegradationEventSnapshot>();
            DateTime currentEnd = DateTime.MinValue;
            for (int i = 0; i < pairEvents.Count; i++)
            {
                DegradationEventSnapshot item = pairEvents[i];
                if (current.Count > 0 &&
                    item.StartUtc > currentEnd.AddMilliseconds(CorrelationGapMs))
                {
                    incidents.Add(BuildIncident(current));
                    current.Clear();
                    currentEnd = DateTime.MinValue;
                }
                current.Add(item);
                if (item.EndUtc > currentEnd) currentEnd = item.EndUtc;
            }
            if (current.Count > 0) incidents.Add(BuildIncident(current));
            return incidents;
        }

        private DegradationIncidentSnapshot BuildIncident(
            List<DegradationEventSnapshot> componentEvents)
        {
            DateTime firstUtc = DateTime.MaxValue;
            DateTime lastUtc = DateTime.MinValue;
            byte objectiveFlags = 0;
            long evaluated = 0, availability = 0, timeouts = 0;
            long dnsErrors = 0, otherFailures = 0, normal = 0, severe = 0;
            double maxResponse = 0.0, maxLag = 0.0;
            SortedSet<int> serverIndexes = new SortedSet<int>();
            SortedSet<int> nameIndexes = new SortedSet<int>();

            for (int i = 0; i < componentEvents.Count; i++)
            {
                DegradationEventSnapshot item = componentEvents[i];
                if (item.StartUtc < firstUtc) firstUtc = item.StartUtc;
                if (item.EndUtc > lastUtc) lastUtc = item.EndUtc;
                objectiveFlags |= item.ObjectiveFlags;
                evaluated += item.Sent;
                availability += item.AvailabilityFailures;
                timeouts += item.Timeouts;
                dnsErrors += item.DnsErrors;
                otherFailures += item.OtherFailures;
                normal += item.NormalSlow;
                severe += item.SevereSlow;
                if (item.MaxResponseMs > maxResponse) maxResponse = item.MaxResponseMs;
                if (item.MaxSchedulerLagMs > maxLag) maxLag = item.MaxSchedulerLagMs;
                serverIndexes.Add(item.ServerIndex);
                nameIndexes.Add(item.NameIndex);
            }

            // Map each name/second to the independently qualifying component
            // servers that actually formed this incident. This avoids counting
            // an unrelated server/name combination merely because it falls inside
            // the incident's broad first-to-last time range.
            ulong[,] qualifyingComponentMasks =
                new ulong[names.Length, options.DurationSeconds + 2];
            for (int i = 0; i < componentEvents.Count; i++)
            {
                DegradationEventSnapshot item = componentEvents[i];
                if (item.ServerIndex < 0 || item.ServerIndex >= 64 ||
                    item.NameIndex < 0 || item.NameIndex >= names.Length)
                    continue;
                int first = Math.Max(0, item.FirstSecond);
                int last = Math.Min(options.DurationSeconds + 1, item.LastSecond);
                ulong serverMask = 1UL << item.ServerIndex;
                for (int second = first; second <= last; second++)
                    qualifyingComponentMasks[item.NameIndex, second] |= serverMask;
            }

            int affectedRounds = 0, observerRounds = 0, sharedRounds = 0;
            int observerSharedRounds = 0, majorityRounds = 0;
            int endpointOnlyRounds = 0, peakAffected = 0;
            int majority = (targets.Length / 2) + 1;
            foreach (RoundEvidence evidence in roundEvidence.Values)
            {
                if (evidence.NameIndex < 0 || evidence.NameIndex >= names.Length ||
                    evidence.Second < 0 || evidence.Second > options.DurationSeconds + 1)
                    continue;
                ulong qualifyingMask =
                    qualifyingComponentMasks[evidence.NameIndex, evidence.Second];
                if (qualifyingMask == 0 ||
                    (evidence.BadEndpointMask & qualifyingMask) == 0)
                    continue;
                affectedRounds++;
                int peerCount = CountBits(evidence.BadEndpointMask);
                if (peerCount > peakAffected) peakAffected = peerCount;
                bool observer = evidence.MaxClientProcessingMs >=
                    options.ObserverProcessingThresholdMs || evidence.SchedulerMiss ||
                    evidence.MaxSchedulerLagMs >= options.SchedulerToleranceMilliseconds;
                if (observer) observerRounds++;
                if (peerCount >= majority) majorityRounds++;
                if (peerCount >= 2)
                {
                    sharedRounds++;
                    if (observer) observerSharedRounds++;
                }
                else endpointOnlyRounds++;
            }

            // Primary scope is based on independently qualifying servers, not
            // the maximum number of endpoints slow in one exceptional round.
            string primaryScope;
            if (serverIndexes.Count <= 1) primaryScope = "SINGLE SERVER";
            else if (serverIndexes.Count >= majority) primaryScope = "WIDESPREAD";
            else primaryScope = "MULTI SERVER";
            string clientEvidence = String.Format(CultureInfo.InvariantCulture,
                "{0}/{1} ROUNDS", observerRounds, affectedRounds);

            string[] serverValues = new string[serverIndexes.Count];
            string[] addressValues = new string[serverIndexes.Count];
            int serverPosition = 0;
            foreach (int serverIndex in serverIndexes)
            {
                serverValues[serverPosition] = targets[serverIndex].Label;
                addressValues[serverPosition] = targets[serverIndex].Address;
                serverPosition++;
            }
            string[] nameValues = new string[nameIndexes.Count];
            int namePosition = 0;
            foreach (int nameIndex in nameIndexes)
                nameValues[namePosition++] = names[nameIndex];

            componentEvents.Sort(delegate(DegradationEventSnapshot x,
                DegradationEventSnapshot y)
            {
                int value = x.ServerIndex.CompareTo(y.ServerIndex);
                if (value != 0) return value;
                value = x.NameIndex.CompareTo(y.NameIndex);
                if (value != 0) return value;
                return x.StartUtc.CompareTo(y.StartUtc);
            });

            return new DegradationIncidentSnapshot
            {
                StartUtc = firstUtc,
                EndUtc = lastUtc,
                DurationMs = MetricAccumulator.Round(Math.Max(0.0,
                    (lastUtc - firstUtc).TotalMilliseconds)),
                PrimaryScope = primaryScope,
                Correlation = primaryScope,
                ClientEvidence = clientEvidence,
                Objectives = BuildObjectiveText(objectiveFlags),
                Servers = serverValues,
                ServerAddresses = addressValues,
                QueryNames = nameValues,
                AffectedEndpointCount = serverValues.Length,
                TotalEndpoints = targets.Length,
                AffectedNameCount = nameValues.Length,
                TotalNames = names.Length,
                PairEventCount = componentEvents.Count,
                EvaluatedQueries = evaluated,
                AffectedQueries = availability + normal,
                AvailabilityFailures = availability,
                Timeouts = timeouts,
                DnsErrors = dnsErrors,
                OtherFailures = otherFailures,
                NormalSlow = normal,
                SevereSlow = severe,
                MaxResponseMs = MetricAccumulator.Round(maxResponse),
                MaxSchedulerLagMs = MetricAccumulator.Round(maxLag),
                AffectedRoundCount = affectedRounds,
                PeakAffectedEndpoints = Math.Max(1, peakAffected),
                ObserverSuspectRounds = observerRounds,
                ObserverSharedRounds = observerSharedRounds,
                SharedSlowRounds = sharedRounds,
                MajoritySlowRounds = majorityRounds,
                EndpointOnlyRounds = endpointOnlyRounds,
                PairEvents = componentEvents.ToArray()
            };
        }

        private static int CountBits(ulong value)
        {
            int count = 0;
            while (value != 0)
            {
                value &= value - 1;
                count++;
            }
            return count;
        }

        private static int CompareSeverity(DegradationEventSnapshot x, DegradationEventSnapshot y)
        {
            int value = y.AvailabilityFailures.CompareTo(x.AvailabilityFailures);
            if (value != 0) return value;
            value = y.SevereSlow.CompareTo(x.SevereSlow);
            if (value != 0) return value;
            value = y.NormalSlow.CompareTo(x.NormalSlow);
            if (value != 0) return value;
            value = y.MaxResponseMs.CompareTo(x.MaxResponseMs);
            if (value != 0) return value;
            return x.StartUtc.CompareTo(y.StartUtc);
        }

        private static int CompareIncidentSeverity(DegradationIncidentSnapshot x,
            DegradationIncidentSnapshot y)
        {
            int value = y.AvailabilityFailures.CompareTo(x.AvailabilityFailures);
            if (value != 0) return value;
            value = y.SevereSlow.CompareTo(x.SevereSlow);
            if (value != 0) return value;
            value = y.NormalSlow.CompareTo(x.NormalSlow);
            if (value != 0) return value;
            value = y.MaxResponseMs.CompareTo(x.MaxResponseMs);
            if (value != 0) return value;
            return x.StartUtc.CompareTo(y.StartUtc);
        }
    }

    internal sealed class AggregationStore
    {
        private readonly DnsTarget[] targets;
        private readonly string[] names;
        private readonly MetricAccumulator overall = new MetricAccumulator();
        private readonly MetricAccumulator[] perServer;
        private readonly MetricAccumulator[] perName;
        private readonly MetricAccumulator[,] cells;
        private readonly ConcurrentQueue<LiveEvent> liveEvents = new ConcurrentQueue<LiveEvent>();
        private readonly object countSync = new object();
        private readonly Dictionary<string, long> statusCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly Dictionary<string, long> rcodeCounts = new Dictionary<string, long>(StringComparer.Ordinal);
        private readonly object detailSync = new object();
        private readonly object observationSync = new object();
        private readonly List<DnsQueryResult> details;
        private readonly CsvSink csv;
        private readonly DegradationTracker degradation;
        private DateTime startUtc;
        private DnsQueryResult largestSuccessfulObservation;

        public AggregationStore(DnsTarget[] targets, string[] names, RunnerOptions options)
        {
            this.targets = targets;
            this.names = names;
            perServer = new MetricAccumulator[targets.Length];
            perName = new MetricAccumulator[names.Length];
            cells = new MetricAccumulator[targets.Length, names.Length];
            for (int s = 0; s < targets.Length; s++) perServer[s] = new MetricAccumulator();
            for (int n = 0; n < names.Length; n++) perName[n] = new MetricAccumulator();
            for (int s = 0; s < targets.Length; s++)
                for (int n = 0; n < names.Length; n++) cells[s, n] = new MetricAccumulator();
            if (options.KeepDetailedResults) details = new List<DnsQueryResult>();
            if (!String.IsNullOrEmpty(options.CsvOutputPath)) csv = new CsvSink(options.CsvOutputPath);
            degradation = new DegradationTracker(targets, names, options);
        }

        public void SetStart(DateTime value) { startUtc = value; degradation.SetStart(value); }

        public void Add(DnsQueryResult result, int serverIndex, int nameIndex)
        {
            overall.Add(result);
            perServer[serverIndex].Add(result);
            perName[nameIndex].Add(result);
            cells[serverIndex, nameIndex].Add(result);
            degradation.Add(result, serverIndex, nameIndex);
            if (result.Success)
            {
                lock (observationSync)
                {
                    if (largestSuccessfulObservation == null ||
                        result.ResponseTimeMs > largestSuccessfulObservation.ResponseTimeMs)
                        largestSuccessfulObservation = result;
                }
            }
            liveEvents.Enqueue(new LiveEvent
            {
                CompletedTicks = (result.ReceivedUtc != DateTime.MinValue ?
                    result.ReceivedUtc : result.CompletedUtc).Ticks,
                ServerIndex = serverIndex,
                NameIndex = nameIndex,
                Sent = result.Sent,
                ResponseReceived = result.ResponseReceived,
                Success = result.Success,
                TcpFallbackUsed = result.TcpFallbackUsed,
                Status = result.Status,
                ResponseTimeMs = result.ResponseTimeMs,
                SchedulerLagMs = result.SchedulerLagMs
            });

            lock (countSync)
            {
                Increment(statusCounts, result.Status ?? "Unknown");
                if (result.RCode >= 0)
                    Increment(rcodeCounts, (result.RCodeName ?? "RCODE") + " (" +
                        result.RCode.ToString(CultureInfo.InvariantCulture) + ")");
            }
            if (details != null) lock (detailSync) details.Add(result);
            if (csv != null) csv.Add(result);
        }

        public LiveSnapshot GetLiveSnapshot(int windowSeconds, DateTime nowUtc)
        {
            long cutoff = nowUtc.AddSeconds(-windowSeconds).Ticks;
            LiveEvent head;
            while (liveEvents.TryPeek(out head) && head.CompletedTicks < cutoff)
                liveEvents.TryDequeue(out head);

            double effectiveSeconds = startUtc == DateTime.MinValue ? 0.001 :
                Math.Min(windowSeconds, Math.Max(0.001, (nowUtc - startUtc).TotalSeconds));
            LiveMetricBuilder total = new LiveMetricBuilder();
            LiveMetricBuilder[] servers = new LiveMetricBuilder[targets.Length];
            LiveMetricBuilder[,] liveCells = new LiveMetricBuilder[targets.Length, names.Length];
            for (int s = 0; s < targets.Length; s++) servers[s] = new LiveMetricBuilder();
            for (int s = 0; s < targets.Length; s++)
                for (int n = 0; n < names.Length; n++) liveCells[s, n] = new LiveMetricBuilder();

            LiveEvent[] events = liveEvents.ToArray();
            for (int i = 0; i < events.Length; i++)
            {
                if (events[i].CompletedTicks < cutoff) continue;
                total.Add(events[i]);
                servers[events[i].ServerIndex].Add(events[i]);
                liveCells[events[i].ServerIndex, events[i].NameIndex].Add(events[i]);
            }

            LiveServerSnapshot[] serverSnapshots = new LiveServerSnapshot[targets.Length];
            for (int s = 0; s < targets.Length; s++)
            {
                MetricSnapshot[] nameMetrics = new MetricSnapshot[names.Length];
                for (int n = 0; n < names.Length; n++) nameMetrics[n] = liveCells[s, n].Snapshot(effectiveSeconds);
                serverSnapshots[s] = new LiveServerSnapshot
                {
                    Server = targets[s].Label,
                    Address = targets[s].Address,
                    Metrics = servers[s].Snapshot(effectiveSeconds),
                    FqdnMetrics = nameMetrics
                };
            }
            return new LiveSnapshot
            {
                SnapshotUtc = nowUtc,
                EffectiveWindowSeconds = MetricAccumulator.Round(effectiveSeconds),
                Overall = total.Snapshot(effectiveSeconds),
                Servers = serverSnapshots
            };
        }

        public FinalSnapshot GetFinalSnapshot(double elapsedSeconds)
        {
            NamedMetricSnapshot[] serverValues = new NamedMetricSnapshot[targets.Length];
            NamedMetricSnapshot[] nameValues = new NamedMetricSnapshot[names.Length];
            CellMetricSnapshot[] cellValues = new CellMetricSnapshot[targets.Length * names.Length];
            for (int s = 0; s < targets.Length; s++)
                serverValues[s] = new NamedMetricSnapshot { Name = targets[s].Label, Address = targets[s].Address, Metrics = perServer[s].Snapshot(elapsedSeconds) };
            for (int n = 0; n < names.Length; n++)
                nameValues[n] = new NamedMetricSnapshot { Name = names[n], Address = null, Metrics = perName[n].Snapshot(elapsedSeconds) };
            int index = 0;
            for (int s = 0; s < targets.Length; s++)
                for (int n = 0; n < names.Length; n++)
                    cellValues[index++] = new CellMetricSnapshot
                    {
                        Server = targets[s].Label,
                        ServerAddress = targets[s].Address,
                        QueryName = names[n],
                        Metrics = cells[s, n].Snapshot(elapsedSeconds)
                    };

            CountSnapshot[] statuses;
            CountSnapshot[] rcodes;
            lock (countSync)
            {
                statuses = ToCounts(statusCounts);
                rcodes = ToCounts(rcodeCounts);
            }
            DnsQueryResult[] detailArray = null;
            if (details != null)
            {
                lock (detailSync) detailArray = details.ToArray();
                Array.Sort(detailArray, delegate(DnsQueryResult x, DnsQueryResult y) { return x.Sequence.CompareTo(y.Sequence); });
            }
            int totalDegradationIncidents;
            int omittedDegradationIncidents;
            int totalDegradationEvents;
            int omittedDegradationEvents;
            DegradationEventSnapshot[] degradationEvents;
            DegradationIncidentSnapshot[] degradationIncidents = degradation.Analyze(
                out totalDegradationIncidents, out omittedDegradationIncidents,
                out degradationEvents, out totalDegradationEvents,
                out omittedDegradationEvents);
            DnsQueryResult largestObservation;
            lock (observationSync) largestObservation = largestSuccessfulObservation;
            return new FinalSnapshot
            {
                Overall = overall.Snapshot(elapsedSeconds),
                PerServer = serverValues,
                PerFqdn = nameValues,
                PerServerFqdn = cellValues,
                StatusCounts = statuses,
                RCodeCounts = rcodes,
                DetailedResults = detailArray,
                DegradationEvents = degradationEvents,
                TotalDegradationEvents = totalDegradationEvents,
                OmittedDegradationEvents = omittedDegradationEvents,
                DegradationIncidents = degradationIncidents,
                TotalDegradationIncidents = totalDegradationIncidents,
                OmittedDegradationIncidents = omittedDegradationIncidents,
                LargestSuccessfulObservation = largestObservation
            };
        }

        public void CompleteCsv() { if (csv != null) csv.Complete(); }
        public void DisposeCsv() { if (csv != null) csv.Dispose(); }

        private static void Increment(Dictionary<string, long> values, string key)
        {
            long count;
            values.TryGetValue(key, out count);
            values[key] = count + 1;
        }

        private static CountSnapshot[] ToCounts(Dictionary<string, long> values)
        {
            List<string> keys = new List<string>(values.Keys);
            keys.Sort(StringComparer.Ordinal);
            CountSnapshot[] output = new CountSnapshot[keys.Count];
            for (int i = 0; i < keys.Count; i++) output[i] = new CountSnapshot { Name = keys[i], Count = values[keys[i]] };
            return output;
        }
    }

    internal sealed class ReceivedPacket
    {
        public byte[] Data;
        public DateTime ReceivedUtc;
        public long ReceivedTimestamp;
        public string TimingSource;
        public ParsedResponse Parsed;
        public Exception Error;
        public double ParserQueueDelayMs;
        public double ParseDurationMs;
    }

    internal sealed class PendingResponse
    {
        public ushort Id;
        public string QueryName;
        public ushort QueryType;
        public long DeadlineTimestamp;
        public TaskCompletionSource<ReceivedPacket> Completion =
            new TaskCompletionSource<ReceivedPacket>(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal sealed class ParseWorkItem
    {
        public byte[] Buffer;
        public int Length;
        public PendingResponse Pending;
        public DateTime ReceivedUtc;
        public long ReceivedTimestamp;
        public long EnqueuedTimestamp;
    }

    internal sealed class ParserStatistics
    {
        public int WorkerCount;
        public long ProcessedPackets;
        public int MaxQueueDepth;
        public double AverageQueueDelayMs;
        public double MaxQueueDelayMs;
        public double AverageParseMs;
        public double MaxParseMs;
    }

    internal sealed class PacketParserPool : IDisposable
    {
        private const int PooledBufferSize = 4096;
        private readonly BlockingCollection<ParseWorkItem> queue =
            new BlockingCollection<ParseWorkItem>(new ConcurrentQueue<ParseWorkItem>(), 65536);
        private readonly ConcurrentBag<byte[]> buffers = new ConcurrentBag<byte[]>();
        private readonly Thread[] workers;
        private long processedPackets;
        private long totalQueueDelayTicks;
        private long maxQueueDelayTicks;
        private long totalParseTicks;
        private long maxParseTicks;
        private int maxQueueDepth;
        private int disposed;

        public PacketParserPool(int workerCount)
        {
            workers = new Thread[Math.Max(1, workerCount)];
            for (int i = 0; i < workers.Length; i++)
            {
                workers[i] = new Thread(ParseLoop);
                workers[i].IsBackground = true;
                workers[i].Name = "DNS parser " + (i + 1).ToString(CultureInfo.InvariantCulture);
                workers[i].Start();
            }
        }

        public byte[] RentBuffer(int length)
        {
            if (length > PooledBufferSize) return new byte[length];
            byte[] value;
            return buffers.TryTake(out value) ? value : new byte[PooledBufferSize];
        }

        public bool TryEnqueue(ParseWorkItem item)
        {
            if (queue.IsAddingCompleted) return false;
            bool added;
            try { added = queue.TryAdd(item); }
            catch (InvalidOperationException) { return false; }
            if (added) UpdateMax(ref maxQueueDepth, queue.Count);
            return added;
        }

        public ParserStatistics Snapshot()
        {
            long count = Interlocked.Read(ref processedPackets);
            return new ParserStatistics
            {
                WorkerCount = workers.Length,
                ProcessedPackets = count,
                MaxQueueDepth = Volatile.Read(ref maxQueueDepth),
                AverageQueueDelayMs = count > 0 ? MetricAccumulator.Round(
                    Interlocked.Read(ref totalQueueDelayTicks) * 1000.0 / Stopwatch.Frequency / count) : 0.0,
                MaxQueueDelayMs = MetricAccumulator.Round(
                    Interlocked.Read(ref maxQueueDelayTicks) * 1000.0 / Stopwatch.Frequency),
                AverageParseMs = count > 0 ? MetricAccumulator.Round(
                    Interlocked.Read(ref totalParseTicks) * 1000.0 / Stopwatch.Frequency / count) : 0.0,
                MaxParseMs = MetricAccumulator.Round(
                    Interlocked.Read(ref maxParseTicks) * 1000.0 / Stopwatch.Frequency)
            };
        }

        public void ResetStatistics()
        {
            Interlocked.Exchange(ref processedPackets, 0);
            Interlocked.Exchange(ref totalQueueDelayTicks, 0);
            Interlocked.Exchange(ref maxQueueDelayTicks, 0);
            Interlocked.Exchange(ref totalParseTicks, 0);
            Interlocked.Exchange(ref maxParseTicks, 0);
            Interlocked.Exchange(ref maxQueueDepth, 0);
        }

        private void ParseLoop()
        {
            foreach (ParseWorkItem item in queue.GetConsumingEnumerable())
            {
                long parseStart = Stopwatch.GetTimestamp();
                ParsedResponse parsed = null;
                Exception error = null;
                try
                {
                    parsed = DnsWire.ParseResponse(item.Buffer, item.Length,
                        item.Pending.Id, item.Pending.QueryName, item.Pending.QueryType);
                }
                catch (Exception ex) { error = ex; }
                long parseEnd = Stopwatch.GetTimestamp();
                long queueDelay = Math.Max(0, parseStart - item.EnqueuedTimestamp);
                long parseDuration = Math.Max(0, parseEnd - parseStart);
                Interlocked.Increment(ref processedPackets);
                Interlocked.Add(ref totalQueueDelayTicks, queueDelay);
                Interlocked.Add(ref totalParseTicks, parseDuration);
                UpdateMax(ref maxQueueDelayTicks, queueDelay);
                UpdateMax(ref maxParseTicks, parseDuration);
                ReturnBuffer(item.Buffer);
                item.Pending.Completion.TrySetResult(new ReceivedPacket
                {
                    ReceivedUtc = item.ReceivedUtc,
                    ReceivedTimestamp = item.ReceivedTimestamp,
                    TimingSource = "UdpSocketReceive",
                    Parsed = parsed,
                    Error = error,
                    ParserQueueDelayMs = MetricAccumulator.Round(
                        queueDelay * 1000.0 / Stopwatch.Frequency),
                    ParseDurationMs = MetricAccumulator.Round(
                        parseDuration * 1000.0 / Stopwatch.Frequency)
                });
            }
        }

        public void ReturnBuffer(byte[] buffer)
        {
            if (buffer != null && buffer.Length == PooledBufferSize) buffers.Add(buffer);
        }

        private static void UpdateMax(ref long location, long value)
        {
            long current;
            while (value > (current = Interlocked.Read(ref location)))
                if (Interlocked.CompareExchange(ref location, value, current) == current) break;
        }

        private static void UpdateMax(ref int location, int value)
        {
            int current;
            while (value > (current = Volatile.Read(ref location)))
                if (Interlocked.CompareExchange(ref location, value, current) == current) break;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            queue.CompleteAdding();
            for (int i = 0; i < workers.Length; i++)
                if (workers[i] != null && workers[i].IsAlive) workers[i].Join(2000);
            queue.Dispose();
        }
    }

    internal sealed class ServerWorker : IDisposable
    {
        private readonly DnsTarget target;
        private readonly RunnerOptions options;
        private readonly PacketParserPool parserPool;
        private readonly Socket socket;
        private readonly Thread receiveThread;
        private readonly Thread timeoutThread;
        private readonly object pendingSync = new object();
        private readonly Dictionary<ushort, PendingResponse> pending = new Dictionary<ushort, PendingResponse>();
        private readonly SemaphoreSlim outstanding;
        private readonly ushort clientPort;
        private readonly Dictionary<ushort, uint> measurementOccurrences =
            new Dictionary<ushort, uint>();
        private volatile bool stopping;
        private int nextTransactionId = Environment.TickCount;

        public ServerWorker(DnsTarget target, RunnerOptions options, PacketParserPool parserPool)
        {
            this.target = target;
            this.options = options;
            this.parserPool = parserPool;
            outstanding = new SemaphoreSlim(options.MaxOutstandingPerServer, options.MaxOutstandingPerServer);
            socket = new Socket(target.IpAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
            socket.ReceiveTimeout = 250;
            socket.SendBufferSize = Math.Max(socket.SendBufferSize, 1024 * 1024);
            socket.ReceiveBufferSize = Math.Max(socket.ReceiveBufferSize, 4 * 1024 * 1024);
            socket.Connect(new IPEndPoint(target.IpAddress, 53));
            clientPort = checked((ushort)((IPEndPoint)socket.LocalEndPoint).Port);
            receiveThread = new Thread(ReceiveLoop);
            receiveThread.IsBackground = true;
            receiveThread.Name = "DNS receive " + target.Label;
            receiveThread.Priority = ThreadPriority.AboveNormal;
            receiveThread.Start();
            timeoutThread = new Thread(TimeoutLoop);
            timeoutThread.IsBackground = true;
            timeoutThread.Name = "DNS timeout " + target.Label;
            timeoutThread.Start();
        }

        public bool TryAcquire() { return outstanding.Wait(0); }
        public void Release() { outstanding.Release(); }

        public async Task<DnsQueryResult> QueryAsync(long sequence, DateTime scheduledUtc,
            double schedulerLagMs, string queryName, ushort queryType,
            CancellationToken cancellationToken)
        {
            ushort id;
            uint captureOccurrence;
            PendingResponse pendingResponse;
            Reserve(queryName, queryType, sequence >= 0, out id, out captureOccurrence,
                out pendingResponse);
            byte[] query = DnsWire.BuildQuery(id, queryName, queryType,
                options.RecursionDesired, options.UseEdns, options.UdpPayloadSize);
            DateTime startedUtc = DateTime.UtcNow;
            long sentTimestamp = Stopwatch.GetTimestamp();
            Stopwatch timer = Stopwatch.StartNew();
            bool responseReceived = false;
            bool tcpFallback = false;
            bool truncated = false;
            ReceivedPacket finalPacket = null;

            DnsQueryResult result = new DnsQueryResult
            {
                Sequence = sequence,
                ScheduledUtc = scheduledUtc,
                StartedUtc = startedUtc,
                Server = target.Label,
                ServerAddress = target.Address,
                QueryName = queryName,
                QueryType = DnsWire.GetQueryTypeName(queryType),
                ClientPort = clientPort,
                TransactionId = id,
                CaptureOccurrence = captureOccurrence,
                Status = "ClientError",
                Sent = true,
                RCode = -1,
                TimingSource = "EndToEndNoResponse",
                SchedulerLagMs = MetricAccumulator.Round(schedulerLagMs)
            };

            try
            {
                // Refresh both clocks at the last possible point before the UDP send.
                result.StartedUtc = DateTime.UtcNow;
                sentTimestamp = Stopwatch.GetTimestamp();
                timer.Restart();
                int sent = socket.Send(query);
                if (sent != query.Length) throw new IOException("The complete DNS UDP query was not sent.");
                Interlocked.Exchange(ref pendingResponse.DeadlineTimestamp,
                    sentTimestamp + (long)Math.Ceiling(
                        options.TimeoutMilliseconds * Stopwatch.Frequency / 1000.0));

                ReceivedPacket packet = await pendingResponse.Completion.Task.ConfigureAwait(false);
                cancellationToken.ThrowIfCancellationRequested();
                finalPacket = packet;
                responseReceived = true;
                result.ReceivedUtc = packet.ReceivedUtc;
                result.ResponseTimeMs = MetricAccumulator.Round(
                    ElapsedMilliseconds(sentTimestamp, packet.ReceivedTimestamp));
                result.TimingSource = packet.TimingSource;
                result.ParserQueueDelayMs = packet.ParserQueueDelayMs;
                result.ParseDurationMs = packet.ParseDurationMs;
                if (packet.Error != null) throw packet.Error;
                ParsedResponse parsed = packet.Parsed;
                truncated = parsed.Truncated;
                if (parsed.Truncated && options.TcpFallback)
                {
                    tcpFallback = true;
                    packet = await QueryTcpAsync(query, timer, cancellationToken).ConfigureAwait(false);
                    finalPacket = packet;
                    result.ReceivedUtc = packet.ReceivedUtc;
                    result.ResponseTimeMs = MetricAccumulator.Round(
                        ElapsedMilliseconds(sentTimestamp, packet.ReceivedTimestamp));
                    result.TimingSource = packet.TimingSource;
                    long parseStart = Stopwatch.GetTimestamp();
                    try { parsed = DnsWire.ParseResponse(packet.Data, id, queryName, queryType); }
                    finally
                    {
                        long parseEnd = Stopwatch.GetTimestamp();
                        packet.ParseDurationMs = MetricAccumulator.Round(
                            ElapsedMilliseconds(parseStart, parseEnd));
                        result.ParserQueueDelayMs = 0.0;
                        result.ParseDurationMs = packet.ParseDurationMs;
                    }
                    truncated = parsed.Truncated;
                }

                result.ResponseReceived = true;
                result.TcpFallbackUsed = tcpFallback;
                result.Truncated = truncated;
                result.AnswerCount = parsed.AnswerCount;
                result.RCode = parsed.RCode;
                result.RCodeName = DnsWire.GetRCodeName(parsed.RCode);
                if (parsed.Truncated)
                {
                    result.Status = "Truncated";
                    result.ErrorMessage = "The final DNS response is truncated.";
                }
                else if (parsed.RCode != 0)
                {
                    result.Status = "DnsError";
                    result.ErrorMessage = result.RCodeName;
                }
                else if (options.RequireAnswer && parsed.AnswerCount == 0)
                {
                    result.Status = "NoAnswer";
                    result.ErrorMessage = "NOERROR response contains no answers.";
                }
                else
                {
                    result.Status = "Success";
                    result.Success = true;
                }
            }
            catch (TimeoutException ex)
            {
                result.Status = "Timeout";
                result.ResponseReceived = responseReceived;
                result.TcpFallbackUsed = tcpFallback;
                result.Truncated = truncated;
                result.ErrorMessage = ex.Message;
            }
            catch (DnsProtocolException ex)
            {
                result.Status = "ProtocolError";
                result.ResponseReceived = responseReceived;
                result.TcpFallbackUsed = tcpFallback;
                result.ErrorMessage = ex.Message;
            }
            catch (OperationCanceledException) { throw; }
            catch (SocketException ex)
            {
                result.Status = "NetworkError";
                result.ResponseReceived = responseReceived;
                result.ErrorMessage = ex.SocketErrorCode + ": " + ex.Message;
            }
            catch (IOException ex)
            {
                result.Status = "NetworkError";
                result.ResponseReceived = responseReceived;
                result.ErrorMessage = ex.Message;
            }
            catch (Exception ex)
            {
                result.Status = "ClientError";
                result.ResponseReceived = responseReceived;
                result.ErrorMessage = ex.GetType().Name + ": " + ex.Message;
            }
            finally
            {
                PendingResponse removed;
                lock (pendingSync)
                {
                    if (pending.TryGetValue(id, out removed) && Object.ReferenceEquals(removed, pendingResponse))
                        pending.Remove(id);
                }
                long completedTimestamp = Stopwatch.GetTimestamp();
                timer.Stop();
                result.EndToEndTimeMs = MetricAccumulator.Round(
                    ElapsedMilliseconds(sentTimestamp, completedTimestamp));
                if (finalPacket != null)
                {
                    result.ClientProcessingDelayMs = MetricAccumulator.Round(
                        Math.Max(0.0, ElapsedMilliseconds(
                            finalPacket.ReceivedTimestamp, completedTimestamp)));
                    result.ContinuationDelayMs = MetricAccumulator.Round(Math.Max(0.0,
                        result.ClientProcessingDelayMs - result.ParserQueueDelayMs -
                        result.ParseDurationMs));
                }
                else
                {
                    result.ResponseTimeMs = result.EndToEndTimeMs;
                    result.ClientProcessingDelayMs = 0.0;
                }
                result.CompletedUtc = DateTime.UtcNow;
            }
            return result;
        }

        private void Reserve(string queryName, ushort queryType, bool measured,
            out ushort id, out uint captureOccurrence, out PendingResponse response)
        {
            lock (pendingSync)
            {
                for (int attempt = 0; attempt < 65536; attempt++)
                {
                    id = unchecked((ushort)++nextTransactionId);
                    if (!pending.ContainsKey(id))
                    {
                        captureOccurrence = 0;
                        if (measured)
                        {
                            measurementOccurrences.TryGetValue(id, out captureOccurrence);
                            captureOccurrence++;
                            measurementOccurrences[id] = captureOccurrence;
                        }
                        response = new PendingResponse
                        {
                            Id = id,
                            QueryName = queryName,
                            QueryType = queryType
                        };
                        pending.Add(id, response);
                        return;
                    }
                }
            }
            throw new InvalidOperationException("No DNS transaction IDs are available.");
        }

        private void ReceiveLoop()
        {
            byte[] receiveBuffer = new byte[65535];
            while (!stopping)
            {
                try
                {
                    int length = socket.Receive(receiveBuffer);
                    long receivedTimestamp = Stopwatch.GetTimestamp();
                    DateTime receivedUtc = DateTime.UtcNow;
                    if (length < 2) continue;
                    ushort id = (ushort)((receiveBuffer[0] << 8) | receiveBuffer[1]);
                    PendingResponse match = null;
                    lock (pendingSync)
                    {
                        if (pending.TryGetValue(id, out match)) pending.Remove(id);
                    }
                    if (match != null)
                    {
                        byte[] response = parserPool.RentBuffer(length);
                        Buffer.BlockCopy(receiveBuffer, 0, response, 0, length);
                        ParseWorkItem work = new ParseWorkItem
                        {
                            Buffer = response,
                            Length = length,
                            Pending = match,
                            ReceivedUtc = receivedUtc,
                            ReceivedTimestamp = receivedTimestamp,
                            EnqueuedTimestamp = receivedTimestamp
                        };
                        if (!parserPool.TryEnqueue(work))
                        {
                            parserPool.ReturnBuffer(response);
                            match.Completion.TrySetResult(new ReceivedPacket
                            {
                                ReceivedUtc = receivedUtc,
                                ReceivedTimestamp = receivedTimestamp,
                                TimingSource = "UdpSocketReceive",
                                Error = new IOException("The DNS parser queue is unavailable.")
                            });
                        }
                    }
                }
                catch (SocketException ex)
                {
                    if (stopping) break;
                    if (ex.SocketErrorCode == SocketError.TimedOut || ex.SocketErrorCode == SocketError.Interrupted)
                        continue;
                    Thread.Sleep(10);
                }
                catch (ObjectDisposedException) { break; }
                catch { if (!stopping) Thread.Sleep(10); }
            }
        }

        private void TimeoutLoop()
        {
            int scanMilliseconds = Math.Max(1, Math.Min(10, options.TimeoutMilliseconds / 20));
            while (!stopping)
            {
                List<PendingResponse> expired = null;
                long now = Stopwatch.GetTimestamp();
                lock (pendingSync)
                {
                    List<ushort> ids = null;
                    foreach (KeyValuePair<ushort, PendingResponse> pair in pending)
                    {
                        PendingResponse candidate = pair.Value;
                        long deadline = Interlocked.Read(ref candidate.DeadlineTimestamp);
                        if (deadline <= 0 || now < deadline) continue;
                        if (ids == null)
                        {
                            ids = new List<ushort>();
                            expired = new List<PendingResponse>();
                        }
                        ids.Add(pair.Key);
                        expired.Add(pair.Value);
                    }
                    if (ids != null)
                        for (int i = 0; i < ids.Count; i++) pending.Remove(ids[i]);
                }
                if (expired != null)
                    for (int i = 0; i < expired.Count; i++)
                        expired[i].Completion.TrySetException(
                            new TimeoutException("The DNS UDP query timed out."));
                Thread.Sleep(scanMilliseconds);
            }
        }

        private async Task<ReceivedPacket> QueryTcpAsync(byte[] query, Stopwatch timer,
            CancellationToken cancellationToken)
        {
            using (TcpClient client = new TcpClient(target.IpAddress.AddressFamily))
            {
                int remaining = RemainingMilliseconds(timer);
                await WithTimeout(client.ConnectAsync(target.IpAddress, 53), remaining,
                    cancellationToken, "The DNS TCP connection timed out.").ConfigureAwait(false);
                using (NetworkStream stream = client.GetStream())
                {
                    byte[] framed = new byte[query.Length + 2];
                    framed[0] = (byte)(query.Length >> 8);
                    framed[1] = (byte)(query.Length & 0xff);
                    Buffer.BlockCopy(query, 0, framed, 2, query.Length);
                    remaining = RemainingMilliseconds(timer);
                    await WithTimeout(stream.WriteAsync(framed, 0, framed.Length, cancellationToken),
                        remaining, cancellationToken, "The DNS TCP send timed out.").ConfigureAwait(false);
                    byte[] size = await ReadExactlyAsync(stream, 2, timer, cancellationToken).ConfigureAwait(false);
                    int length = (size[0] << 8) | size[1];
                    if (length < 12) throw new DnsProtocolException("Invalid DNS TCP response length.");
                    byte[] response = await ReadExactlyAsync(stream, length, timer,
                        cancellationToken).ConfigureAwait(false);
                    return new ReceivedPacket
                    {
                        Data = response,
                        ReceivedUtc = DateTime.UtcNow,
                        ReceivedTimestamp = Stopwatch.GetTimestamp(),
                        TimingSource = "TcpReadCompletion"
                    };
                }
            }
        }

        private async Task<byte[]> ReadExactlyAsync(NetworkStream stream, int length,
            Stopwatch timer, CancellationToken cancellationToken)
        {
            byte[] buffer = new byte[length];
            int offset = 0;
            while (offset < length)
            {
                int remaining = RemainingMilliseconds(timer);
                int read = await WithTimeout(stream.ReadAsync(buffer, offset, length - offset, cancellationToken),
                    remaining, cancellationToken, "The DNS TCP receive timed out.").ConfigureAwait(false);
                if (read == 0) throw new IOException("The DNS TCP connection closed early.");
                offset += read;
            }
            return buffer;
        }

        private int RemainingMilliseconds(Stopwatch timer)
        {
            int remaining = (int)Math.Ceiling(options.TimeoutMilliseconds - timer.Elapsed.TotalMilliseconds);
            if (remaining <= 0) throw new TimeoutException("The DNS query exceeded its end-to-end timeout.");
            return remaining;
        }

        private static double ElapsedMilliseconds(long startTimestamp, long endTimestamp)
        {
            return (endTimestamp - startTimestamp) * 1000.0 / Stopwatch.Frequency;
        }

        private static async Task<T> WithTimeout<T>(Task<T> task, int milliseconds,
            CancellationToken token, string message)
        {
            Task delay = Task.Delay(milliseconds, token);
            Task completed = await Task.WhenAny(task, delay).ConfigureAwait(false);
            if (completed == task) return await task.ConfigureAwait(false);
            token.ThrowIfCancellationRequested();
            throw new TimeoutException(message);
        }

        private static async Task WithTimeout(Task task, int milliseconds,
            CancellationToken token, string message)
        {
            Task delay = Task.Delay(milliseconds, token);
            Task completed = await Task.WhenAny(task, delay).ConfigureAwait(false);
            if (completed == task)
            {
                await task.ConfigureAwait(false);
                return;
            }
            token.ThrowIfCancellationRequested();
            throw new TimeoutException(message);
        }

        public void Dispose()
        {
            stopping = true;
            try { socket.Close(); }
            catch { }
            if (receiveThread != null && receiveThread.IsAlive) receiveThread.Join(1000);
            if (timeoutThread != null && timeoutThread.IsAlive) timeoutThread.Join(1000);
            lock (pendingSync)
            {
                foreach (PendingResponse item in pending.Values)
                    item.Completion.TrySetException(new ObjectDisposedException("ServerWorker"));
                pending.Clear();
            }
            outstanding.Dispose();
        }
    }

    internal sealed class ObserverMonitor : IDisposable
    {
        private readonly RunnerOptions options;
        private readonly PacketParserPool parserPool;
        private readonly Process process = Process.GetCurrentProcess();
        private readonly Thread sampleThread;
        private volatile bool stopping;
        private DateTime startUtc;
        private TimeSpan startCpu;
        private int startGen0;
        private int startGen1;
        private int startGen2;
        private long maxManagedBytes;
        private long maxWorkingSetBytes;
        private int minAvailableWorkers = Int32.MaxValue;
        private int minAvailableIo = Int32.MaxValue;

        public ObserverMonitor(RunnerOptions options, PacketParserPool parserPool)
        {
            this.options = options;
            this.parserPool = parserPool;
            sampleThread = new Thread(SampleLoop);
            sampleThread.IsBackground = true;
            sampleThread.Name = "DNS observer monitor";
        }

        public void Start()
        {
            startUtc = DateTime.UtcNow;
            process.Refresh();
            startCpu = process.TotalProcessorTime;
            startGen0 = GC.CollectionCount(0);
            startGen1 = GC.CollectionCount(1);
            startGen2 = GC.CollectionCount(2);
            Sample();
            sampleThread.Start();
        }

        public ObserverSnapshot Stop()
        {
            stopping = true;
            if (sampleThread.IsAlive) sampleThread.Join(1000);
            Sample();
            process.Refresh();
            double elapsed = Math.Max(0.001, (DateTime.UtcNow - startUtc).TotalSeconds);
            double cpuSeconds = Math.Max(0.0, (process.TotalProcessorTime - startCpu).TotalSeconds);
            ParserStatistics parser = parserPool.Snapshot();
            return new ObserverSnapshot
            {
                WarmupSeconds = options.WarmupSeconds,
                ParserWorkerCount = parser.WorkerCount,
                ParserProcessedPackets = parser.ProcessedPackets,
                ParserMaxQueueDepth = parser.MaxQueueDepth,
                ParserAverageQueueDelayMs = parser.AverageQueueDelayMs,
                ParserMaxQueueDelayMs = parser.MaxQueueDelayMs,
                ParserAverageParseMs = parser.AverageParseMs,
                ParserMaxParseMs = parser.MaxParseMs,
                ProcessCpuPercent = MetricAccumulator.Round(
                    100.0 * cpuSeconds / elapsed / Math.Max(1, Environment.ProcessorCount)),
                Gen0Collections = GC.CollectionCount(0) - startGen0,
                Gen1Collections = GC.CollectionCount(1) - startGen1,
                Gen2Collections = GC.CollectionCount(2) - startGen2,
                MaxManagedMemoryMb = MetricAccumulator.Round(
                    maxManagedBytes / 1024.0 / 1024.0),
                MaxWorkingSetMb = MetricAccumulator.Round(
                    maxWorkingSetBytes / 1024.0 / 1024.0),
                MinAvailableWorkerThreads = minAvailableWorkers == Int32.MaxValue ? 0 : minAvailableWorkers,
                MinAvailableIoThreads = minAvailableIo == Int32.MaxValue ? 0 : minAvailableIo,
                ProcessingThresholdMs = options.ObserverProcessingThresholdMs
            };
        }

        private void SampleLoop()
        {
            while (!stopping)
            {
                Sample();
                Thread.Sleep(100);
            }
        }

        private void Sample()
        {
            long managed = GC.GetTotalMemory(false);
            if (managed > maxManagedBytes) maxManagedBytes = managed;
            try
            {
                process.Refresh();
                long working = process.WorkingSet64;
                if (working > maxWorkingSetBytes) maxWorkingSetBytes = working;
            }
            catch { }
            int workers, io;
            ThreadPool.GetAvailableThreads(out workers, out io);
            if (workers < minAvailableWorkers) minAvailableWorkers = workers;
            if (io < minAvailableIo) minAvailableIo = io;
        }

        public void Dispose()
        {
            stopping = true;
            if (sampleThread.IsAlive) sampleThread.Join(1000);
            process.Dispose();
        }
    }

    public sealed class DnsLoadRunner : IDisposable
    {
        private readonly DnsTarget[] targets;
        private readonly string[] names;
        private readonly ushort queryType;
        private readonly RunnerOptions options;
        private readonly AggregationStore store;
        private readonly PacketParserPool parserPool;
        private readonly ManualResetEventSlim measurementGate =
            new ManualResetEventSlim(false);
        private RunnerCompletion completion;
        private int started;
        private int disposed;

        public RunnerProgress Progress { get; private set; }
        public RunnerCompletion Completion { get { return completion; } }

        public void ReleaseMeasurementGate()
        {
            measurementGate.Set();
        }

        private DnsLoadRunner(DnsTarget[] targets, string[] names, ushort queryType,
            RunnerOptions options)
        {
            if (targets == null || targets.Length == 0) throw new ArgumentException("No DNS targets were supplied.");
            if (names == null || names.Length == 0) throw new ArgumentException("No query names were supplied.");
            if (options == null) throw new ArgumentNullException("options");
            this.targets = targets;
            this.names = names;
            this.queryType = queryType;
            this.options = options;
            int parserWorkers = options.ProcessingWorkerCount > 0 ?
                options.ProcessingWorkerCount : Math.Max(2, Math.Min(16, Environment.ProcessorCount));
            parserPool = new PacketParserPool(parserWorkers);
            Progress = new RunnerProgress();
            Progress.Phase = "STARTING";
            Progress.WarmupSeconds = options.WarmupSeconds;
            store = new AggregationStore(targets, names, options);
        }

        public static DnsLoadRunner Create(DnsTarget[] targets, string[] names,
            ushort queryType, RunnerOptions options)
        {
            return new DnsLoadRunner(targets, names, queryType, options);
        }

        public Task<RunnerCompletion> RunAsync(CancellationToken cancellationToken)
        {
            if (Interlocked.Exchange(ref started, 1) != 0)
                throw new InvalidOperationException("This runner has already been started.");
            return Task.Factory.StartNew(
                () => RunInternalAsync(cancellationToken),
                cancellationToken,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default).Unwrap();
        }

        public LiveSnapshot GetLiveSnapshot(int windowSeconds)
        {
            return store.GetLiveSnapshot(windowSeconds, DateTime.UtcNow);
        }

        public FinalSnapshot GetFinalSnapshot()
        {
            if (completion == null) throw new InvalidOperationException("The test has not completed.");
            double elapsed = Math.Max(0.001, (completion.EndUtc - completion.StartUtc).TotalSeconds);
            FinalSnapshot snapshot = store.GetFinalSnapshot(elapsed);
            snapshot.Observer = completion.Observer;
            return snapshot;
        }

        private async Task<RunnerCompletion> RunInternalAsync(CancellationToken cancellationToken)
        {
            long rounds = checked((long)options.QueriesPerSecondPerServer * options.DurationSeconds);
            long planned = checked(rounds * targets.Length);
            double intervalMs = 1000.0 / options.QueriesPerSecondPerServer;
            ServerWorker[] workers = new ServerWorker[targets.Length];
            List<Task> active = new List<Task>();
            DateTime startUtc = DateTime.MinValue;
            DateTime schedulingEndUtc = DateTime.MinValue;
            Stopwatch scheduleTimer = null;
            bool timerEnabled = WindowsTimerResolution.Begin();
            ObserverMonitor observer = null;
            int originalMinWorkers, originalMinIo;
            ThreadPool.GetMinThreads(out originalMinWorkers, out originalMinIo);
            int requestedMinWorkers = Math.Max(originalMinWorkers,
                targets.Length * 4 + parserPool.Snapshot().WorkerCount * 2);
            ThreadPool.SetMinThreads(requestedMinWorkers, originalMinIo);

            try
            {
                Thread.CurrentThread.Priority = ThreadPriority.AboveNormal;
                for (int i = 0; i < targets.Length; i++)
                    workers[i] = new ServerWorker(targets[i], options, parserPool);
                if (options.WarmupSeconds > 0)
                {
                    Progress.Phase = "WARMUP";
                    Progress.WarmupStartUtc = DateTime.UtcNow;
                    RunWarmup(workers, intervalMs, cancellationToken);
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }
                parserPool.ResetStatistics();
                if (options.WaitForMeasurementRelease)
                {
                    Progress.Phase = "ARMING";
                    while (!measurementGate.Wait(100))
                        cancellationToken.ThrowIfCancellationRequested();
                }
                observer = new ObserverMonitor(options, parserPool);
                observer.Start();
                // Capture the UTC epoch and start the scheduler clock together.
                // Observer initialization can take several milliseconds and must not
                // be included as an unreported offset in ScheduledUtc.
                startUtc = DateTime.UtcNow;
                scheduleTimer = Stopwatch.StartNew();
                store.SetStart(startUtc);
                Progress.StartUtc = startUtc;
                Progress.Phase = "RUN";
                Progress.PlannedRounds = rounds;
                Progress.PlannedQueries = planned;

                for (long round = 0; round < rounds; round++)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    double targetMs = round * intervalMs;
                    WaitUntil(scheduleTimer, targetMs, cancellationToken);
                    Progress.MarkRound();
                    double roundLag = Math.Max(0.0, scheduleTimer.Elapsed.TotalMilliseconds - targetMs);
                    int nameIndex = (int)(round % names.Length);
                    DateTime scheduledUtc = startUtc.AddMilliseconds(targetMs);
                    int firstServer = (int)((round / names.Length) % targets.Length);

                    if (roundLag > options.SchedulerToleranceMilliseconds)
                    {
                        for (int order = 0; order < targets.Length; order++)
                        {
                            int serverIndex = (firstServer + order) % targets.Length;
                            long sequence = round * targets.Length + order;
                            DnsQueryResult dropped = CreateNotSent(sequence, scheduledUtc,
                                serverIndex, nameIndex, "SchedulerMiss", roundLag,
                                "The paired round exceeded scheduler tolerance.");
                            Progress.MarkSchedulerMiss();
                            Progress.MarkCompleted();
                            store.Add(dropped, serverIndex, nameIndex);
                        }
                        continue;
                    }

                    for (int order = 0; order < targets.Length; order++)
                    {
                        int serverIndex = (firstServer + order) % targets.Length;
                        long sequence = round * targets.Length + order;
                        double queryLag = Math.Max(0.0, scheduleTimer.Elapsed.TotalMilliseconds - targetMs);
                        if (!workers[serverIndex].TryAcquire())
                        {
                            DnsQueryResult dropped = CreateNotSent(sequence, scheduledUtc,
                                serverIndex, nameIndex, "ConcurrencyLimit", queryLag,
                                "MaxOutstandingPerServer was reached.");
                            Progress.MarkConcurrencyDrop();
                            Progress.MarkCompleted();
                            store.Add(dropped, serverIndex, nameIndex);
                            continue;
                        }
                        Progress.MarkStarted();
                        active.Add(ExecuteAsync(workers[serverIndex], sequence, scheduledUtc,
                            queryLag, serverIndex, nameIndex, cancellationToken));
                    }

                    if ((round & 127) == 0)
                        active.RemoveAll(delegate(Task task) { return task.IsCompleted; });
                }

                WaitUntil(scheduleTimer, options.DurationSeconds * 1000.0,
                    cancellationToken);
                schedulingEndUtc = DateTime.UtcNow;
                Progress.Phase = "DRAIN";
                await Task.WhenAll(active.ToArray()).ConfigureAwait(false);
                DateTime endUtc = DateTime.UtcNow;
                ObserverSnapshot observerSnapshot = observer.Stop();
                store.CompleteCsv();
                Progress.Phase = "COMPLETE";
                completion = new RunnerCompletion
                {
                    StartUtc = startUtc,
                    SchedulingEndUtc = schedulingEndUtc,
                    EndUtc = endUtc,
                    PlannedQueries = planned,
                    StartedQueries = Progress.StartedQueries,
                    SchedulerMisses = Progress.SchedulerMisses,
                    ConcurrencyDrops = Progress.ConcurrencyDrops,
                    Observer = observerSnapshot
                };
                return completion;
            }
            finally
            {
                if (scheduleTimer != null) scheduleTimer.Stop();
                for (int i = 0; i < workers.Length; i++) if (workers[i] != null) workers[i].Dispose();
                if (observer != null) observer.Dispose();
                ThreadPool.SetMinThreads(originalMinWorkers, originalMinIo);
                WindowsTimerResolution.End(timerEnabled);
            }
        }

        private void RunWarmup(ServerWorker[] workers, double intervalMs,
            CancellationToken cancellationToken)
        {
            long rounds = checked((long)options.QueriesPerSecondPerServer * options.WarmupSeconds);
            List<Task> active = new List<Task>();
            Stopwatch timer = Stopwatch.StartNew();
            for (long round = 0; round < rounds; round++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                double targetMs = round * intervalMs;
                WaitUntil(timer, targetMs, cancellationToken);
                int nameIndex = (int)(round % names.Length);
                int firstServer = (int)((round / names.Length) % targets.Length);
                for (int order = 0; order < targets.Length; order++)
                {
                    int serverIndex = (firstServer + order) % targets.Length;
                    if (!workers[serverIndex].TryAcquire()) continue;
                    active.Add(ExecuteWarmupAsync(workers[serverIndex], names[nameIndex],
                        cancellationToken));
                }
                if ((round & 127) == 0)
                    active.RemoveAll(delegate(Task task) { return task.IsCompleted; });
            }
            WaitUntil(timer, options.WarmupSeconds * 1000.0, cancellationToken);
            Task.WhenAll(active.ToArray()).GetAwaiter().GetResult();
            timer.Stop();
        }

        private async Task ExecuteWarmupAsync(ServerWorker worker, string queryName,
            CancellationToken cancellationToken)
        {
            try
            {
                await worker.QueryAsync(-1, DateTime.UtcNow, 0.0, queryName,
                    queryType, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) { throw; }
            catch { }
            finally { worker.Release(); }
        }

        private async Task ExecuteAsync(ServerWorker worker, long sequence,
            DateTime scheduledUtc, double schedulerLagMs, int serverIndex,
            int nameIndex, CancellationToken cancellationToken)
        {
            try
            {
                DnsQueryResult result = await worker.QueryAsync(sequence, scheduledUtc,
                    schedulerLagMs, names[nameIndex], queryType, cancellationToken).ConfigureAwait(false);
                store.Add(result, serverIndex, nameIndex);
                Progress.MarkCompleted();
            }
            finally { worker.Release(); }
        }

        private DnsQueryResult CreateNotSent(long sequence, DateTime scheduledUtc,
            int serverIndex, int nameIndex, string status, double schedulerLagMs,
            string message)
        {
            return new DnsQueryResult
            {
                Sequence = sequence,
                ScheduledUtc = scheduledUtc,
                CompletedUtc = DateTime.UtcNow,
                Server = targets[serverIndex].Label,
                ServerAddress = targets[serverIndex].Address,
                QueryName = names[nameIndex],
                QueryType = DnsWire.GetQueryTypeName(queryType),
                Status = status,
                Sent = false,
                RCode = -1,
                SchedulerLagMs = MetricAccumulator.Round(schedulerLagMs),
                ErrorMessage = message
            };
        }

        private static void WaitUntil(Stopwatch timer, double targetMs,
            CancellationToken cancellationToken)
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                double remaining = targetMs - timer.Elapsed.TotalMilliseconds;
                if (remaining <= 0) return;
                // Keep a generous coarse-wait margin because Windows can resume a
                // sleeping thread several milliseconds late. At 200 rounds/second,
                // the interval is handled entirely by the high-resolution phase.
                if (remaining > 15.0)
                {
                    int delay = Math.Max(1, (int)Math.Floor(remaining - 10.0));
                    Thread.Sleep(delay);
                }
                else if (remaining > 0.5) Thread.Sleep(0);
                else Thread.SpinWait(64);
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref disposed, 1) != 0) return;
            measurementGate.Set();
            try { store.DisposeCsv(); }
            finally
            {
                parserPool.Dispose();
                measurementGate.Dispose();
            }
        }
    }
}
'@
        }

        $coordinatedCaptureTypeDefinition = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DnsCoordinatedCaptureV424
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct BpfProgram
    {
        public uint Length;
        public IntPtr Instructions;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PcapTimeval
    {
        public int Seconds;
        public int Microseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PcapPacketHeader
    {
        public PcapTimeval Timestamp;
        public uint CapturedLength;
        public uint OriginalLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PcapStatisticsNative
    {
        public uint Received;
        public uint Dropped;
        public uint InterfaceDropped;
        // WinPcap-compatible Windows headers include a fourth capture counter.
        // Keeping the native structure at that size is safe across Npcap builds;
        // pcap_stats() only exposes the first three portable fields here.
        public uint Captured;
    }

    internal static class PcapNative
    {
        internal const int ErrorBufferSize = 512;

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_create(string source, StringBuilder errorBuffer);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_snaplen(IntPtr handle, int snapshotLength);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_promisc(IntPtr handle, int enabled);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_timeout(IntPtr handle, int timeoutMilliseconds);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_buffer_size(IntPtr handle, int bufferBytes);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_activate(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_datalink(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi)]
        internal static extern int pcap_compile(IntPtr handle, out BpfProgram program,
            string filter, int optimize, uint networkMask);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_setfilter(IntPtr handle, ref BpfProgram program);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_freecode(ref BpfProgram program);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_next_ex(IntPtr handle, out IntPtr header,
            out IntPtr packetData);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_stats(IntPtr handle, out PcapStatisticsNative statistics);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pcap_geterr(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pcap_lib_version();

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_close(IntPtr handle);

        internal static string Error(IntPtr handle)
        {
            IntPtr value = handle == IntPtr.Zero ? IntPtr.Zero : pcap_geterr(handle);
            return value == IntPtr.Zero ? "Unknown Npcap error." : Marshal.PtrToStringAnsi(value);
        }

        internal static string Version()
        {
            IntPtr value = pcap_lib_version();
            return value == IntPtr.Zero ? "Unknown" : Marshal.PtrToStringAnsi(value);
        }
    }

    internal struct CaptureKey : IEquatable<CaptureKey>
    {
        internal ushort ClientPort;
        internal ushort TransactionId;

        internal CaptureKey(ushort clientPort, ushort transactionId)
        {
            ClientPort = clientPort;
            TransactionId = transactionId;
        }

        public bool Equals(CaptureKey other)
        {
            return ClientPort == other.ClientPort && TransactionId == other.TransactionId;
        }

        public override bool Equals(object value)
        {
            return value is CaptureKey && Equals((CaptureKey)value);
        }

        public override int GetHashCode()
        {
            return (ClientPort << 16) ^ TransactionId;
        }
    }

    internal sealed class PendingCapture
    {
        internal uint Occurrence;
        internal long RequestMicroseconds;
    }

    internal struct CapturePair
    {
        internal ushort ClientPort;
        internal ushort TransactionId;
        internal uint Occurrence;
        internal long RequestMicroseconds;
        internal long ResponseMicroseconds;
    }

    public sealed class CaptureReadyInfo
    {
        public string ComputerName { get; internal set; }
        public string LocalAddress { get; internal set; }
        public string PeerAddress { get; internal set; }
        public string AdapterName { get; internal set; }
        public string DeviceName { get; internal set; }
        public string Filter { get; internal set; }
        public string NpcapVersion { get; internal set; }
        public string TimestampSource { get; internal set; }
    }

    public sealed class CaptureResult
    {
        public string ComputerName { get; internal set; }
        public string LocalAddress { get; internal set; }
        public string PeerAddress { get; internal set; }
        public string AdapterName { get; internal set; }
        public string DeviceName { get; internal set; }
        public string Filter { get; internal set; }
        public string NpcapVersion { get; internal set; }
        public string TimestampSource { get; internal set; }
        public DateTime CaptureStartUtc { get; internal set; }
        public DateTime CaptureEndUtc { get; internal set; }
        public long ParsedPackets { get; internal set; }
        public long QueryPackets { get; internal set; }
        public long ResponsePackets { get; internal set; }
        public long CompletedPairs { get; internal set; }
        public long UnmatchedQueries { get; internal set; }
        public long UnmatchedResponses { get; internal set; }
        public long PcapReceived { get; internal set; }
        public long PcapDropped { get; internal set; }
        public long InterfaceDropped { get; internal set; }
        public bool StatisticsAvailable { get; internal set; }
        public bool PacketLimitReached { get; internal set; }
        public byte[] CompressedPairs { get; internal set; }
    }

    public sealed class CaptureMetricSummary
    {
        public long Count { get; internal set; }
        public double MinimumMs { get; internal set; }
        public double AverageMs { get; internal set; }
        public double StandardDeviationMs { get; internal set; }
        public double P50Ms { get; internal set; }
        public double P95Ms { get; internal set; }
        public double P99Ms { get; internal set; }
        public double MaximumMs { get; internal set; }
    }

    public sealed class SlowCaptureTransaction
    {
        public DateTime ClientRequestUtc { get; internal set; }
        public DateTime ClientResponseUtc { get; internal set; }
        public DateTime ServerReceiveUtc { get; internal set; }
        public DateTime ServerSendUtc { get; internal set; }
        public ushort ClientPort { get; internal set; }
        public ushort TransactionId { get; internal set; }
        public uint Occurrence { get; internal set; }
        public double ClientWireMs { get; internal set; }
        public double ServerTurnaroundMs { get; internal set; }
        public double NetworkRemainderMs { get; internal set; }
        public DateTime DirectionalBaselineUtc { get; internal set; }
        public double DirectionalBaselineCombinedNetworkMs { get; internal set; }
        public double OutboundDelayDeltaMs { get; internal set; }
        public double ReturnDelayDeltaMs { get; internal set; }
        internal double Score { get; set; }
        internal long TieBreaker { get; set; }
    }

    internal sealed class SlowCaptureComparer : IComparer<SlowCaptureTransaction>
    {
        public int Compare(SlowCaptureTransaction x, SlowCaptureTransaction y)
        {
            int value = x.Score.CompareTo(y.Score);
            if (value != 0) return value;
            return x.TieBreaker.CompareTo(y.TieBreaker);
        }
    }

    public sealed class CoordinatedCaptureAnalysis
    {
        public string Server { get; internal set; }
        public string ServerAddress { get; internal set; }
        public long LocalPairs { get; internal set; }
        public long ServerPairs { get; internal set; }
        public long MatchedPairs { get; internal set; }
        public long UnmatchedLocalPairs { get; internal set; }
        public long UnmatchedServerPairs { get; internal set; }
        public long NegativeNetworkRemainders { get; internal set; }
        public double CoveragePercent { get; internal set; }
        public CaptureMetricSummary ClientWire { get; internal set; }
        public CaptureMetricSummary ServerTurnaround { get; internal set; }
        public CaptureMetricSummary NetworkRemainder { get; internal set; }
        public CaptureMetricSummary OutboundDelayDelta { get; internal set; }
        public CaptureMetricSummary ReturnDelayDelta { get; internal set; }
        public string DirectionalDeltaMethod { get; internal set; }
        public SlowCaptureTransaction[] SlowTransactions { get; internal set; }
    }

    public sealed class CaptureCsvEndpoint
    {
        public string ServerAddress { get; set; }
        public byte[] ClientPairs { get; set; }
        public byte[] ServerPairs { get; set; }
        public bool ClientOnly { get; set; }
    }

    public sealed class CaptureCsvEnrichmentSummary
    {
        public long TotalRows { get; internal set; }
        public long MatchedRows { get; internal set; }
        public long ClientOnlyRows { get; internal set; }
        public long UnmatchedRows { get; internal set; }
        public long NotSentRows { get; internal set; }
        public long TcpFallbackRows { get; internal set; }
        public string DirectionalDeltaMethod { get; internal set; }
    }

    internal sealed class MatchedCaptureTransaction
    {
        internal CapturePair Local;
        internal CapturePair Remote;
        internal double ClientWireMs;
        internal double ServerTurnaroundMs;
        internal double NetworkRemainderMs;
        internal long BaselineClientRequestMicroseconds;
        internal double BaselineNetworkRemainderMs;
        internal double OutboundDelayDeltaMs;
        internal double ReturnDelayDeltaMs;
    }

    internal static class CaptureCorrelation
    {
        internal const string DirectionalDeltaMethod =
            "Same-endpoint actual P10 combined-network transaction in a nearby approximately 11-second window; directional values are deltas, not absolute one-way latency";

        internal static List<MatchedCaptureTransaction> Match(byte[] localData,
            byte[] serverData, out int localCount, out int serverCount)
        {
            CapturePair[] local = CaptureCodec.Decode(localData);
            CapturePair[] remote = CaptureCodec.Decode(serverData);
            localCount = local.Length;
            serverCount = remote.Length;
            Dictionary<ulong, CapturePair> remoteByKey =
                new Dictionary<ulong, CapturePair>();
            for (int i = 0; i < remote.Length; i++)
                remoteByKey[Key(remote[i])] = remote[i];

            List<MatchedCaptureTransaction> matched =
                new List<MatchedCaptureTransaction>();
            for (int i = 0; i < local.Length; i++)
            {
                CapturePair serverPair;
                if (!remoteByKey.TryGetValue(Key(local[i]), out serverPair)) continue;
                double wire = (local[i].ResponseMicroseconds -
                    local[i].RequestMicroseconds) / 1000.0;
                double turn = (serverPair.ResponseMicroseconds -
                    serverPair.RequestMicroseconds) / 1000.0;
                matched.Add(new MatchedCaptureTransaction
                {
                    Local = local[i],
                    Remote = serverPair,
                    ClientWireMs = wire,
                    ServerTurnaroundMs = turn,
                    NetworkRemainderMs = wire - turn
                });
            }
            matched.Sort(delegate(MatchedCaptureTransaction x,
                MatchedCaptureTransaction y)
            {
                return x.Local.RequestMicroseconds.CompareTo(
                    y.Local.RequestMicroseconds);
            });
            ApplyDirectionalBaselines(matched);
            return matched;
        }

        private static void ApplyDirectionalBaselines(
            List<MatchedCaptureTransaction> transactions)
        {
            if (transactions.Count == 0) return;
            const long oneSecond = 1000000L;
            const long radius = 5000000L;
            int bucketFirst = 0;
            int left = 0;
            int right = 0;
            while (bucketFirst < transactions.Count)
            {
                long bucketNumber = transactions[bucketFirst].Local.RequestMicroseconds /
                    oneSecond;
                long bucketStart = bucketNumber * oneSecond;
                long bucketEnd = bucketStart + oneSecond;
                int bucketLast = bucketFirst + 1;
                while (bucketLast < transactions.Count &&
                    transactions[bucketLast].Local.RequestMicroseconds < bucketEnd)
                    bucketLast++;

                long windowStart = bucketStart - radius;
                long windowEnd = bucketEnd + radius;
                while (left < transactions.Count &&
                    transactions[left].Local.RequestMicroseconds < windowStart) left++;
                if (right < left) right = left;
                while (right < transactions.Count &&
                    transactions[right].Local.RequestMicroseconds < windowEnd) right++;

                List<MatchedCaptureTransaction> candidates =
                    new List<MatchedCaptureTransaction>();
                for (int i = left; i < right; i++)
                    if (transactions[i].NetworkRemainderMs >= 0.0)
                        candidates.Add(transactions[i]);
                if (candidates.Count == 0)
                    for (int i = left; i < right; i++) candidates.Add(transactions[i]);

                candidates.Sort(delegate(MatchedCaptureTransaction x,
                    MatchedCaptureTransaction y)
                {
                    int value = x.NetworkRemainderMs.CompareTo(y.NetworkRemainderMs);
                    if (value != 0) return value;
                    return x.Local.RequestMicroseconds.CompareTo(
                        y.Local.RequestMicroseconds);
                });
                MatchedCaptureTransaction baseline = candidates[
                    (int)Math.Floor((candidates.Count - 1) * 0.10)];
                double baselineOutbound = baseline.Remote.RequestMicroseconds -
                    baseline.Local.RequestMicroseconds;
                double baselineReturn = baseline.Local.ResponseMicroseconds -
                    baseline.Remote.ResponseMicroseconds;
                for (int i = bucketFirst; i < bucketLast; i++)
                {
                    MatchedCaptureTransaction item = transactions[i];
                    item.BaselineClientRequestMicroseconds =
                        baseline.Local.RequestMicroseconds;
                    item.BaselineNetworkRemainderMs = baseline.NetworkRemainderMs;
                    item.OutboundDelayDeltaMs = ((item.Remote.RequestMicroseconds -
                        item.Local.RequestMicroseconds) - baselineOutbound) / 1000.0;
                    item.ReturnDelayDeltaMs = ((item.Local.ResponseMicroseconds -
                        item.Remote.ResponseMicroseconds) - baselineReturn) / 1000.0;
                }
                bucketFirst = bucketLast;
            }
        }

        internal static ulong Key(CapturePair pair)
        {
            return ((ulong)pair.ClientPort << 48) |
                ((ulong)pair.TransactionId << 32) | pair.Occurrence;
        }
    }

    public sealed class CaptureSession : IDisposable
    {
        private const int EthernetDataLink = 1;
        private readonly IntPtr handle;
        private readonly int maximumPackets;
        private readonly Dictionary<CaptureKey, Queue<PendingCapture>> pending =
            new Dictionary<CaptureKey, Queue<PendingCapture>>();
        private readonly Dictionary<CaptureKey, uint> occurrences =
            new Dictionary<CaptureKey, uint>();
        private readonly List<CapturePair> pairs = new List<CapturePair>();
        private bool disposed;
        private volatile bool stopRequested;

        public CaptureReadyInfo ReadyInfo { get; private set; }

        internal CaptureSession(IntPtr handle, int maximumPackets, CaptureReadyInfo readyInfo)
        {
            this.handle = handle;
            this.maximumPackets = maximumPackets;
            ReadyInfo = readyInfo;
        }

        public Task<CaptureResult> RunAsync(int durationSeconds)
        {
            return Task.Factory.StartNew(() => Run(durationSeconds),
                System.Threading.CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        public CaptureResult Run(int durationSeconds)
        {
            if (disposed) throw new ObjectDisposedException("CaptureSession");
            DateTime startUtc = DateTime.UtcNow;
            Stopwatch timer = Stopwatch.StartNew();
            long parsedPackets = 0;
            long queries = 0;
            long responses = 0;
            long unmatchedResponses = 0;
            bool packetLimit = false;

            while (!stopRequested && timer.Elapsed.TotalSeconds < durationSeconds)
            {
                IntPtr headerPointer;
                IntPtr packetPointer;
                int status = PcapNative.pcap_next_ex(handle, out headerPointer, out packetPointer);
                if (status == 0) continue;
                if (status == -2) break;
                if (status < 0) throw new IOException(PcapNative.Error(handle));

                PcapPacketHeader header = (PcapPacketHeader)Marshal.PtrToStructure(
                    headerPointer, typeof(PcapPacketHeader));
                int length = checked((int)header.CapturedLength);
                if (length <= 0) continue;
                byte[] packet = new byte[length];
                Marshal.Copy(packetPointer, packet, 0, length);
                ParsedDnsPacket parsed;
                if (!TryParseDnsPacket(packet, out parsed)) continue;
                parsedPackets++;
                long timestamp = ((long)header.Timestamp.Seconds * 1000000L) +
                    header.Timestamp.Microseconds;
                CaptureKey key = new CaptureKey(parsed.ClientPort, parsed.TransactionId);
                if (parsed.IsResponse)
                {
                    responses++;
                    Queue<PendingCapture> queue;
                    if (pending.TryGetValue(key, out queue) && queue.Count > 0)
                    {
                        PendingCapture request = queue.Dequeue();
                        if (queue.Count == 0) pending.Remove(key);
                        pairs.Add(new CapturePair
                        {
                            ClientPort = key.ClientPort,
                            TransactionId = key.TransactionId,
                            Occurrence = request.Occurrence,
                            RequestMicroseconds = request.RequestMicroseconds,
                            ResponseMicroseconds = timestamp
                        });
                    }
                    else unmatchedResponses++;
                }
                else
                {
                    queries++;
                    uint occurrence;
                    if (!occurrences.TryGetValue(key, out occurrence)) occurrence = 0;
                    occurrence++;
                    occurrences[key] = occurrence;
                    Queue<PendingCapture> queue;
                    if (!pending.TryGetValue(key, out queue))
                    {
                        queue = new Queue<PendingCapture>();
                        pending.Add(key, queue);
                    }
                    queue.Enqueue(new PendingCapture
                    {
                        Occurrence = occurrence,
                        RequestMicroseconds = timestamp
                    });
                }

                if (parsedPackets >= maximumPackets)
                {
                    packetLimit = true;
                    break;
                }
            }

            timer.Stop();
            long unmatchedQueries = 0;
            foreach (Queue<PendingCapture> queue in pending.Values)
                unmatchedQueries += queue.Count;

            PcapStatisticsNative statistics;
            bool statisticsAvailable = PcapNative.pcap_stats(handle, out statistics) == 0;
            return new CaptureResult
            {
                ComputerName = ReadyInfo.ComputerName,
                LocalAddress = ReadyInfo.LocalAddress,
                PeerAddress = ReadyInfo.PeerAddress,
                AdapterName = ReadyInfo.AdapterName,
                DeviceName = ReadyInfo.DeviceName,
                Filter = ReadyInfo.Filter,
                NpcapVersion = ReadyInfo.NpcapVersion,
                TimestampSource = ReadyInfo.TimestampSource,
                CaptureStartUtc = startUtc,
                CaptureEndUtc = DateTime.UtcNow,
                ParsedPackets = parsedPackets,
                QueryPackets = queries,
                ResponsePackets = responses,
                CompletedPairs = pairs.Count,
                UnmatchedQueries = unmatchedQueries,
                UnmatchedResponses = unmatchedResponses,
                PcapReceived = statisticsAvailable ? statistics.Received : 0,
                PcapDropped = statisticsAvailable ? statistics.Dropped : 0,
                InterfaceDropped = statisticsAvailable ? statistics.InterfaceDropped : 0,
                StatisticsAvailable = statisticsAvailable,
                PacketLimitReached = packetLimit,
                CompressedPairs = CaptureCodec.Encode(pairs)
            };
        }

        private struct ParsedDnsPacket
        {
            internal ushort ClientPort;
            internal ushort TransactionId;
            internal bool IsResponse;
        }

        private static bool TryParseDnsPacket(byte[] packet, out ParsedDnsPacket parsed)
        {
            parsed = new ParsedDnsPacket();
            if (packet == null || packet.Length < 54) return false;
            int offset = 14;
            ushort etherType = ReadUInt16(packet, 12);
            while ((etherType == 0x8100 || etherType == 0x88a8) && packet.Length >= offset + 4)
            {
                etherType = ReadUInt16(packet, offset + 2);
                offset += 4;
            }

            int udpOffset;
            if (etherType == 0x0800)
            {
                if (packet.Length < offset + 20 || (packet[offset] >> 4) != 4) return false;
                int ipHeaderLength = (packet[offset] & 15) * 4;
                if (ipHeaderLength < 20 || packet.Length < offset + ipHeaderLength + 8) return false;
                if (packet[offset + 9] != 17) return false;
                udpOffset = offset + ipHeaderLength;
            }
            else if (etherType == 0x86dd)
            {
                if (packet.Length < offset + 40 + 8 || (packet[offset] >> 4) != 6) return false;
                if (packet[offset + 6] != 17) return false;
                udpOffset = offset + 40;
            }
            else return false;

            if (packet.Length < udpOffset + 20) return false;
            ushort sourcePort = ReadUInt16(packet, udpOffset);
            ushort destinationPort = ReadUInt16(packet, udpOffset + 2);
            if (sourcePort != 53 && destinationPort != 53) return false;
            int dnsOffset = udpOffset + 8;
            ushort flags = ReadUInt16(packet, dnsOffset + 2);
            bool response = (flags & 0x8000) != 0;
            if ((!response && destinationPort != 53) || (response && sourcePort != 53)) return false;
            parsed.ClientPort = response ? destinationPort : sourcePort;
            parsed.TransactionId = ReadUInt16(packet, dnsOffset);
            parsed.IsResponse = response;
            return true;
        }

        private static ushort ReadUInt16(byte[] value, int offset)
        {
            return (ushort)((value[offset] << 8) | value[offset + 1]);
        }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (handle != IntPtr.Zero) PcapNative.pcap_close(handle);
        }

        public void RequestStop()
        {
            stopRequested = true;
        }
    }

    public static class CaptureRunner
    {
        public static CaptureSession Open(string localAddress, string peerAddress,
            int snapshotLength, int bufferMegabytes, int maximumPackets)
        {
            IPAddress local;
            IPAddress peer;
            if (!IPAddress.TryParse(localAddress, out local))
                throw new ArgumentException("The local capture address is invalid.", "localAddress");
            if (!IPAddress.TryParse(peerAddress, out peer))
                throw new ArgumentException("The peer capture address is invalid.", "peerAddress");
            if (local.AddressFamily != peer.AddressFamily)
                throw new ArgumentException("Local and peer capture addresses must use the same address family.");

            NetworkInterface selected = null;
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation address in
                    adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.Equals(local))
                    {
                        selected = adapter;
                        break;
                    }
                }
                if (selected != null) break;
            }
            if (selected == null)
                throw new InvalidOperationException("No local network adapter owns " + localAddress + ".");

            string id = selected.Id;
            if (!id.StartsWith("{", StringComparison.Ordinal)) id = "{" + id + "}";
            string deviceName = "\\Device\\NPF_" + id;
            string family = local.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork ?
                "ip" : "ip6";
            string filter = family + " and udp and port 53 and host " +
                localAddress + " and host " + peerAddress;
            StringBuilder error = new StringBuilder(PcapNative.ErrorBufferSize);
            IntPtr handle = PcapNative.pcap_create(deviceName, error);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("Npcap could not open " + deviceName + ": " + error);

            try
            {
                if (PcapNative.pcap_set_snaplen(handle, snapshotLength) != 0)
                    throw new InvalidOperationException(PcapNative.Error(handle));
                if (PcapNative.pcap_set_promisc(handle, 0) != 0)
                    throw new InvalidOperationException(PcapNative.Error(handle));
                if (PcapNative.pcap_set_timeout(handle, 100) != 0)
                    throw new InvalidOperationException(PcapNative.Error(handle));
                if (PcapNative.pcap_set_buffer_size(handle,
                    checked(bufferMegabytes * 1024 * 1024)) != 0)
                    throw new InvalidOperationException(PcapNative.Error(handle));
                int activation = PcapNative.pcap_activate(handle);
                if (activation < 0)
                    throw new InvalidOperationException("Npcap activation failed: " +
                        PcapNative.Error(handle));
                if (PcapNative.pcap_datalink(handle) != EthernetDataLink)
                    throw new NotSupportedException("Coordinated capture currently requires an Ethernet Npcap data link.");

                BpfProgram program;
                if (PcapNative.pcap_compile(handle, out program, filter, 1, 0xffffffff) != 0)
                    throw new InvalidOperationException("Npcap filter compilation failed: " +
                        PcapNative.Error(handle));
                try
                {
                    if (PcapNative.pcap_setfilter(handle, ref program) != 0)
                        throw new InvalidOperationException("Npcap filter activation failed: " +
                            PcapNative.Error(handle));
                }
                finally { PcapNative.pcap_freecode(ref program); }

                CaptureReadyInfo ready = new CaptureReadyInfo
                {
                    ComputerName = Environment.MachineName,
                    LocalAddress = localAddress,
                    PeerAddress = peerAddress,
                    AdapterName = selected.Name,
                    DeviceName = deviceName,
                    Filter = filter,
                    NpcapVersion = PcapNative.Version(),
                    TimestampSource = "Npcap default host timestamp (microsecond representation)"
                };
                return new CaptureSession(handle, maximumPackets, ready);
            }
            catch
            {
                PcapNative.pcap_close(handle);
                throw;
            }
        }

        private const int EthernetDataLink = 1;
    }

    internal static class CaptureCodec
    {
        private const int Magic = 0x44504331;

        internal static byte[] Encode(List<CapturePair> pairs)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress, true))
                using (BinaryWriter writer = new BinaryWriter(gzip, Encoding.UTF8, true))
                {
                    writer.Write(Magic);
                    writer.Write(1);
                    writer.Write(pairs.Count);
                    for (int i = 0; i < pairs.Count; i++)
                    {
                        CapturePair pair = pairs[i];
                        writer.Write(pair.ClientPort);
                        writer.Write(pair.TransactionId);
                        writer.Write(pair.Occurrence);
                        writer.Write(pair.RequestMicroseconds);
                        writer.Write(pair.ResponseMicroseconds);
                    }
                }
                return output.ToArray();
            }
        }

        internal static CapturePair[] Decode(byte[] compressed)
        {
            if (compressed == null || compressed.Length == 0) return new CapturePair[0];
            using (MemoryStream input = new MemoryStream(compressed, false))
            using (GZipStream gzip = new GZipStream(input, CompressionMode.Decompress))
            using (BinaryReader reader = new BinaryReader(gzip, Encoding.UTF8))
            {
                if (reader.ReadInt32() != Magic) throw new InvalidDataException("Invalid coordinated capture data.");
                if (reader.ReadInt32() != 1) throw new InvalidDataException("Unsupported coordinated capture data version.");
                int count = reader.ReadInt32();
                if (count < 0 || count > 100000000) throw new InvalidDataException("Invalid coordinated capture pair count.");
                CapturePair[] pairs = new CapturePair[count];
                for (int i = 0; i < count; i++)
                {
                    pairs[i] = new CapturePair
                    {
                        ClientPort = reader.ReadUInt16(),
                        TransactionId = reader.ReadUInt16(),
                        Occurrence = reader.ReadUInt32(),
                        RequestMicroseconds = reader.ReadInt64(),
                        ResponseMicroseconds = reader.ReadInt64()
                    };
                }
                return pairs;
            }
        }
    }

    internal struct CaptureCsvKey : IEquatable<CaptureCsvKey>
    {
        internal string ServerAddress;
        internal ushort ClientPort;
        internal ushort TransactionId;
        internal uint Occurrence;

        public bool Equals(CaptureCsvKey other)
        {
            return String.Equals(ServerAddress, other.ServerAddress,
                StringComparison.OrdinalIgnoreCase) && ClientPort == other.ClientPort &&
                TransactionId == other.TransactionId && Occurrence == other.Occurrence;
        }

        public override bool Equals(object value)
        {
            return value is CaptureCsvKey && Equals((CaptureCsvKey)value);
        }

        public override int GetHashCode()
        {
            return StringComparer.OrdinalIgnoreCase.GetHashCode(ServerAddress ?? "") ^
                (ClientPort << 16) ^ TransactionId ^ unchecked((int)Occurrence);
        }
    }

    internal struct CaptureCsvLooseKey : IEquatable<CaptureCsvLooseKey>
    {
        internal string ServerAddress;
        internal ushort ClientPort;
        internal ushort TransactionId;

        public bool Equals(CaptureCsvLooseKey other)
        {
            return String.Equals(ServerAddress, other.ServerAddress,
                StringComparison.OrdinalIgnoreCase) && ClientPort == other.ClientPort &&
                TransactionId == other.TransactionId;
        }

        public override bool Equals(object value)
        {
            return value is CaptureCsvLooseKey && Equals((CaptureCsvLooseKey)value);
        }

        public override int GetHashCode()
        {
            return StringComparer.OrdinalIgnoreCase.GetHashCode(ServerAddress ?? "") ^
                (ClientPort << 16) ^ TransactionId;
        }
    }

    public static class CaptureCsvEnricher
    {
        private const long CorrelationToleranceTicks = TimeSpan.TicksPerSecond;

        public static CaptureCsvEnrichmentSummary Enrich(string csvPath,
            CaptureCsvEndpoint[] endpoints)
        {
            if (String.IsNullOrEmpty(csvPath))
                throw new ArgumentException("The CSV path is required.", "csvPath");
            if (endpoints == null) throw new ArgumentNullException("endpoints");

            Dictionary<CaptureCsvKey, MatchedCaptureTransaction> exact =
                new Dictionary<CaptureCsvKey, MatchedCaptureTransaction>();
            Dictionary<CaptureCsvLooseKey, List<MatchedCaptureTransaction>> loose =
                new Dictionary<CaptureCsvLooseKey, List<MatchedCaptureTransaction>>();
            HashSet<string> clientOnlyAddresses = new HashSet<string>(
                StringComparer.OrdinalIgnoreCase);
            for (int endpointIndex = 0; endpointIndex < endpoints.Length;
                endpointIndex++)
            {
                CaptureCsvEndpoint endpoint = endpoints[endpointIndex];
                if (endpoint == null || String.IsNullOrEmpty(endpoint.ServerAddress))
                    continue;
                if (endpoint.ClientOnly)
                {
                    clientOnlyAddresses.Add(endpoint.ServerAddress);
                    continue;
                }
                int ignoredLocal;
                int ignoredServer;
                List<MatchedCaptureTransaction> matches = CaptureCorrelation.Match(
                    endpoint.ClientPairs, endpoint.ServerPairs, out ignoredLocal,
                    out ignoredServer);
                for (int i = 0; i < matches.Count; i++)
                {
                    MatchedCaptureTransaction item = matches[i];
                    CaptureCsvKey key = new CaptureCsvKey
                    {
                        ServerAddress = endpoint.ServerAddress,
                        ClientPort = item.Local.ClientPort,
                        TransactionId = item.Local.TransactionId,
                        Occurrence = item.Local.Occurrence
                    };
                    exact[key] = item;
                    CaptureCsvLooseKey looseKey = new CaptureCsvLooseKey
                    {
                        ServerAddress = endpoint.ServerAddress,
                        ClientPort = item.Local.ClientPort,
                        TransactionId = item.Local.TransactionId
                    };
                    List<MatchedCaptureTransaction> candidates;
                    if (!loose.TryGetValue(looseKey, out candidates))
                    {
                        candidates = new List<MatchedCaptureTransaction>();
                        loose.Add(looseKey, candidates);
                    }
                    candidates.Add(item);
                }
            }

            CaptureCsvEnrichmentSummary summary = new CaptureCsvEnrichmentSummary
            {
                DirectionalDeltaMethod = CaptureCorrelation.DirectionalDeltaMethod
            };
            HashSet<MatchedCaptureTransaction> used =
                new HashSet<MatchedCaptureTransaction>();
            string temporaryPath = csvPath + ".npcap." +
                Guid.NewGuid().ToString("N") + ".tmp";
            try
            {
                using (StreamReader reader = new StreamReader(csvPath, true))
                using (StreamWriter writer = new StreamWriter(temporaryPath, false,
                    new UTF8Encoding(true), 65536))
                {
                    string headerRecord = ReadCsvRecord(reader);
                    if (headerRecord == null)
                        throw new InvalidDataException("The detailed CSV is empty.");
                    string[] headers = ParseCsvRecord(headerRecord);
                    int serverAddressIndex = HeaderIndex(headers, "ServerAddress");
                    int startedUtcIndex = HeaderIndex(headers, "StartedUtc");
                    int clientPortIndex = HeaderIndex(headers, "ClientPort");
                    int transactionIdIndex = HeaderIndex(headers, "TransactionId");
                    int occurrenceIndex = HeaderIndex(headers, "CaptureOccurrence");
                    int sentIndex = HeaderIndex(headers, "Sent");
                    int tcpFallbackIndex = HeaderIndex(headers, "TcpFallbackUsed");
                    writer.WriteLine(headerRecord +
                        ",PacketTimingStatus,PacketTimingSource,ClientPacketRequestUtc," +
                        "ServerPacketReceiveUtc,ServerPacketSendUtc,ClientPacketResponseUtc," +
                        "ClientPacketObservedLatencyMs,ServerPacketTurnaroundMs," +
                        "CombinedNetworkTimeMs,DirectionalBaselineUtc," +
                        "DirectionalBaselineCombinedNetworkMs,OutboundDelayDeltaMs," +
                        "ReturnDelayDeltaMs");

                    string record;
                    while ((record = ReadCsvRecord(reader)) != null)
                    {
                        if (record.Length == 0) continue;
                        summary.TotalRows++;
                        string[] fields = ParseCsvRecord(record);
                        bool sent = BooleanField(fields, sentIndex);
                        bool tcpFallback = BooleanField(fields, tcpFallbackIndex);
                        if (!sent)
                        {
                            summary.NotSentRows++;
                            writer.WriteLine(record + EmptyEvidence("NotSent"));
                            continue;
                        }
                        if (tcpFallback)
                        {
                            summary.TcpFallbackRows++;
                            writer.WriteLine(record + EmptyEvidence(
                                "TcpFallbackExcluded"));
                            continue;
                        }

                        ushort clientPort;
                        ushort transactionId;
                        uint occurrence;
                        DateTime startedUtc;
                        if (!UInt16.TryParse(Field(fields, clientPortIndex),
                                NumberStyles.Integer, CultureInfo.InvariantCulture,
                                out clientPort) ||
                            !UInt16.TryParse(Field(fields, transactionIdIndex),
                                NumberStyles.Integer, CultureInfo.InvariantCulture,
                                out transactionId) ||
                            !UInt32.TryParse(Field(fields, occurrenceIndex),
                                NumberStyles.Integer, CultureInfo.InvariantCulture,
                                out occurrence) ||
                            !DateTime.TryParse(Field(fields, startedUtcIndex),
                                CultureInfo.InvariantCulture,
                                DateTimeStyles.RoundtripKind, out startedUtc))
                        {
                            summary.UnmatchedRows++;
                            writer.WriteLine(record + EmptyEvidence(
                                "CorrelationKeyUnavailable"));
                            continue;
                        }

                        string serverAddress = Field(fields, serverAddressIndex);
                        MatchedCaptureTransaction match = FindMatch(exact, loose, used,
                            serverAddress, clientPort, transactionId, occurrence,
                            startedUtc.ToUniversalTime().Ticks);
                        if (match == null)
                        {
                            if (clientOnlyAddresses.Contains(serverAddress))
                            {
                                summary.ClientOnlyRows++;
                                writer.WriteLine(record + EmptyEvidence(
                                    "ClientOnly", "UdpSocketReceive"));
                                continue;
                            }
                            summary.UnmatchedRows++;
                            writer.WriteLine(record + EmptyEvidence(
                                "NoMatchedCapturePair"));
                            continue;
                        }

                        used.Add(match);
                        summary.MatchedRows++;
                        writer.WriteLine(record + Evidence(match));
                    }
                }
                File.Replace(temporaryPath, csvPath, null);
            }
            finally
            {
                if (File.Exists(temporaryPath))
                    try { File.Delete(temporaryPath); }
                    catch { }
            }
            return summary;
        }

        private static MatchedCaptureTransaction FindMatch(
            Dictionary<CaptureCsvKey, MatchedCaptureTransaction> exact,
            Dictionary<CaptureCsvLooseKey, List<MatchedCaptureTransaction>> loose,
            HashSet<MatchedCaptureTransaction> used, string serverAddress,
            ushort clientPort, ushort transactionId, uint occurrence,
            long startedUtcTicks)
        {
            CaptureCsvKey exactKey = new CaptureCsvKey
            {
                ServerAddress = serverAddress,
                ClientPort = clientPort,
                TransactionId = transactionId,
                Occurrence = occurrence
            };
            MatchedCaptureTransaction value;
            if (exact.TryGetValue(exactKey, out value) && !used.Contains(value) &&
                Math.Abs(ToUtcTicks(value.Local.RequestMicroseconds) -
                    startedUtcTicks) <= CorrelationToleranceTicks)
                return value;

            CaptureCsvLooseKey looseKey = new CaptureCsvLooseKey
            {
                ServerAddress = serverAddress,
                ClientPort = clientPort,
                TransactionId = transactionId
            };
            List<MatchedCaptureTransaction> candidates;
            if (!loose.TryGetValue(looseKey, out candidates)) return null;
            MatchedCaptureTransaction best = null;
            long bestDistance = Int64.MaxValue;
            for (int i = 0; i < candidates.Count; i++)
            {
                if (used.Contains(candidates[i])) continue;
                long distance = Math.Abs(ToUtcTicks(
                    candidates[i].Local.RequestMicroseconds) - startedUtcTicks);
                if (distance < bestDistance)
                {
                    best = candidates[i];
                    bestDistance = distance;
                }
            }
            return bestDistance <= CorrelationToleranceTicks ? best : null;
        }

        private static string Evidence(MatchedCaptureTransaction item)
        {
            return ",\"Matched\",\"Npcap\"," +
                CsvDate(item.Local.RequestMicroseconds) + "," +
                CsvDate(item.Remote.RequestMicroseconds) + "," +
                CsvDate(item.Remote.ResponseMicroseconds) + "," +
                CsvDate(item.Local.ResponseMicroseconds) + "," +
                Number(item.ClientWireMs) + "," +
                Number(item.ServerTurnaroundMs) + "," +
                Number(item.NetworkRemainderMs) + "," +
                CsvDate(item.BaselineClientRequestMicroseconds) + "," +
                Number(item.BaselineNetworkRemainderMs) + "," +
                Number(item.OutboundDelayDeltaMs) + "," +
                Number(item.ReturnDelayDeltaMs);
        }

        private static string EmptyEvidence(string status)
        {
            return EmptyEvidence(status, "Npcap");
        }

        private static string EmptyEvidence(string status, string source)
        {
            return ",\"" + status.Replace("\"", "\"\"") +
                "\",\"" + source.Replace("\"", "\"\"") +
                "\",,,,,,,,,,,";
        }

        private static string CsvDate(long microseconds)
        {
            return "\"" + UnixMicrosecondsToUtc(microseconds).ToString("o",
                CultureInfo.InvariantCulture) + "\"";
        }

        private static string Number(double value)
        {
            return Math.Round(value, 3).ToString("0.000",
                CultureInfo.InvariantCulture);
        }

        private static long ToUtcTicks(long microseconds)
        {
            return UnixMicrosecondsToUtc(microseconds).Ticks;
        }

        private static DateTime UnixMicrosecondsToUtc(long value)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0,
                DateTimeKind.Utc).AddTicks(value * 10L);
        }

        private static int HeaderIndex(string[] headers, string name)
        {
            for (int i = 0; i < headers.Length; i++)
                if (String.Equals(headers[i], name, StringComparison.Ordinal)) return i;
            throw new InvalidDataException("The detailed CSV is missing " + name + ".");
        }

        private static string Field(string[] fields, int index)
        {
            return index >= 0 && index < fields.Length ? fields[index] : "";
        }

        private static bool BooleanField(string[] fields, int index)
        {
            return String.Equals(Field(fields, index), "True",
                StringComparison.OrdinalIgnoreCase);
        }

        private static string ReadCsvRecord(StreamReader reader)
        {
            string line = reader.ReadLine();
            if (line == null) return null;
            StringBuilder record = new StringBuilder(line);
            bool quoted = QuoteState(line, false);
            while (quoted)
            {
                line = reader.ReadLine();
                if (line == null)
                    throw new InvalidDataException("The detailed CSV ends inside a quoted field.");
                record.Append("\r\n");
                record.Append(line);
                quoted = QuoteState(line, quoted);
            }
            return record.ToString();
        }

        private static bool QuoteState(string value, bool quoted)
        {
            for (int i = 0; i < value.Length; i++)
            {
                if (value[i] != '\"') continue;
                if (quoted && i + 1 < value.Length && value[i + 1] == '\"')
                {
                    i++;
                    continue;
                }
                quoted = !quoted;
            }
            return quoted;
        }

        private static string[] ParseCsvRecord(string record)
        {
            List<string> fields = new List<string>();
            StringBuilder field = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < record.Length; i++)
            {
                char value = record[i];
                if (quoted)
                {
                    if (value == '\"')
                    {
                        if (i + 1 < record.Length && record[i + 1] == '\"')
                        {
                            field.Append('\"');
                            i++;
                        }
                        else quoted = false;
                    }
                    else field.Append(value);
                }
                else if (value == '\"') quoted = true;
                else if (value == ',')
                {
                    fields.Add(field.ToString());
                    field.Clear();
                }
                else field.Append(value);
            }
            fields.Add(field.ToString());
            return fields.ToArray();
        }
    }

    public static class CaptureAnalyzer
    {
        public static CoordinatedCaptureAnalysis Analyze(string server, string serverAddress,
            byte[] localData, byte[] serverData, double slowThresholdMilliseconds,
            int maximumSlowTransactions)
        {
            int localCount;
            int serverCount;
            List<MatchedCaptureTransaction> matchedTransactions =
                CaptureCorrelation.Match(localData, serverData, out localCount,
                    out serverCount);

            List<double> clientWire = new List<double>();
            List<double> serverTurn = new List<double>();
            List<double> networkRemainder = new List<double>();
            List<double> outboundDelayDelta = new List<double>();
            List<double> returnDelayDelta = new List<double>();
            SortedSet<SlowCaptureTransaction> slow = new SortedSet<SlowCaptureTransaction>(
                new SlowCaptureComparer());
            long negative = 0;
            long tie = 0;

            for (int i = 0; i < matchedTransactions.Count; i++)
            {
                MatchedCaptureTransaction matchedItem = matchedTransactions[i];
                double wire = matchedItem.ClientWireMs;
                double turn = matchedItem.ServerTurnaroundMs;
                double remainder = matchedItem.NetworkRemainderMs;
                if (remainder < 0) negative++;
                clientWire.Add(wire);
                serverTurn.Add(turn);
                networkRemainder.Add(remainder);
                outboundDelayDelta.Add(matchedItem.OutboundDelayDeltaMs);
                returnDelayDelta.Add(matchedItem.ReturnDelayDeltaMs);

                double score = Math.Max(wire, Math.Max(turn, remainder));
                if (maximumSlowTransactions > 0 && score >= slowThresholdMilliseconds)
                {
                    SlowCaptureTransaction item = new SlowCaptureTransaction
                    {
                        ClientRequestUtc = UnixMicrosecondsToUtc(
                            matchedItem.Local.RequestMicroseconds),
                        ClientResponseUtc = UnixMicrosecondsToUtc(
                            matchedItem.Local.ResponseMicroseconds),
                        ServerReceiveUtc = UnixMicrosecondsToUtc(
                            matchedItem.Remote.RequestMicroseconds),
                        ServerSendUtc = UnixMicrosecondsToUtc(
                            matchedItem.Remote.ResponseMicroseconds),
                        ClientPort = matchedItem.Local.ClientPort,
                        TransactionId = matchedItem.Local.TransactionId,
                        Occurrence = matchedItem.Local.Occurrence,
                        ClientWireMs = Round(wire),
                        ServerTurnaroundMs = Round(turn),
                        NetworkRemainderMs = Round(remainder),
                        DirectionalBaselineUtc = UnixMicrosecondsToUtc(
                            matchedItem.BaselineClientRequestMicroseconds),
                        DirectionalBaselineCombinedNetworkMs = Round(
                            matchedItem.BaselineNetworkRemainderMs),
                        OutboundDelayDeltaMs = Round(
                            matchedItem.OutboundDelayDeltaMs),
                        ReturnDelayDeltaMs = Round(matchedItem.ReturnDelayDeltaMs),
                        Score = score,
                        TieBreaker = ++tie
                    };
                    slow.Add(item);
                    if (slow.Count > maximumSlowTransactions) slow.Remove(slow.Min);
                }
            }

            SlowCaptureTransaction[] slowOutput = new SlowCaptureTransaction[slow.Count];
            int outputIndex = slow.Count - 1;
            foreach (SlowCaptureTransaction item in slow) slowOutput[outputIndex--] = item;
            long matched = matchedTransactions.Count;
            return new CoordinatedCaptureAnalysis
            {
                Server = server,
                ServerAddress = serverAddress,
                LocalPairs = localCount,
                ServerPairs = serverCount,
                MatchedPairs = matched,
                UnmatchedLocalPairs = localCount - matched,
                UnmatchedServerPairs = serverCount - matched,
                NegativeNetworkRemainders = negative,
                CoveragePercent = localCount > 0 ? Round(100.0 * matched / localCount) : 0.0,
                ClientWire = Metrics(clientWire),
                ServerTurnaround = Metrics(serverTurn),
                NetworkRemainder = Metrics(networkRemainder),
                OutboundDelayDelta = Metrics(outboundDelayDelta),
                ReturnDelayDelta = Metrics(returnDelayDelta),
                DirectionalDeltaMethod = CaptureCorrelation.DirectionalDeltaMethod,
                SlowTransactions = slowOutput
            };
        }

        private static CaptureMetricSummary Metrics(List<double> values)
        {
            CaptureMetricSummary result = new CaptureMetricSummary { Count = values.Count };
            if (values.Count == 0) return result;
            double sum = 0.0;
            double mean = 0.0;
            double m2 = 0.0;
            for (int i = 0; i < values.Count; i++)
            {
                double value = values[i];
                sum += value;
                double delta = value - mean;
                mean += delta / (i + 1);
                m2 += delta * (value - mean);
            }
            double[] sorted = values.ToArray();
            Array.Sort(sorted);
            result.MinimumMs = Round(sorted[0]);
            result.AverageMs = Round(sum / values.Count);
            result.StandardDeviationMs = Round(values.Count > 1 ?
                Math.Sqrt(m2 / (values.Count - 1)) : 0.0);
            result.P50Ms = Round(Percentile(sorted, 0.50));
            result.P95Ms = Round(Percentile(sorted, 0.95));
            result.P99Ms = Round(Percentile(sorted, 0.99));
            result.MaximumMs = Round(sorted[sorted.Length - 1]);
            return result;
        }

        private static double Percentile(double[] values, double percentile)
        {
            if (values.Length == 1) return values[0];
            double rank = percentile * (values.Length - 1);
            int lower = (int)Math.Floor(rank);
            int upper = (int)Math.Ceiling(rank);
            if (lower == upper) return values[lower];
            return values[lower] + (values[upper] - values[lower]) * (rank - lower);
        }

        private static DateTime UnixMicrosecondsToUtc(long value)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddTicks(value * 10L);
        }

        private static double Round(double value)
        {
            return Math.Round(value, 3);
        }
    }
}
'@

        $forwardingCaptureTypeDefinition = @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DnsForwardingCaptureV410
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ForwardBpfProgram
    {
        public uint Length;
        public IntPtr Instructions;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ForwardPcapTimeval
    {
        public int Seconds;
        public int Microseconds;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ForwardPcapPacketHeader
    {
        public ForwardPcapTimeval Timestamp;
        public uint CapturedLength;
        public uint OriginalLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ForwardPcapStatistics
    {
        public uint Received;
        public uint Dropped;
        public uint InterfaceDropped;
        public uint Captured;
    }

    internal static class ForwardPcapNative
    {
        internal const int ErrorBufferSize = 512;

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi)]
        internal static extern IntPtr pcap_create(string source, StringBuilder errorBuffer);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_snaplen(IntPtr handle, int snapshotLength);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_promisc(IntPtr handle, int enabled);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_timeout(IntPtr handle, int timeoutMilliseconds);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_set_buffer_size(IntPtr handle, int bufferBytes);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_activate(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_datalink(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl,
            CharSet = CharSet.Ansi)]
        internal static extern int pcap_compile(IntPtr handle, out ForwardBpfProgram program,
            string filter, int optimize, uint networkMask);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_setfilter(IntPtr handle, ref ForwardBpfProgram program);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_freecode(ref ForwardBpfProgram program);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_next_ex(IntPtr handle, out IntPtr header,
            out IntPtr packetData);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern int pcap_stats(IntPtr handle, out ForwardPcapStatistics statistics);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pcap_geterr(IntPtr handle);

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr pcap_lib_version();

        [DllImport("wpcap.dll", CallingConvention = CallingConvention.Cdecl)]
        internal static extern void pcap_close(IntPtr handle);

        internal static string Error(IntPtr handle)
        {
            IntPtr value = handle == IntPtr.Zero ? IntPtr.Zero : pcap_geterr(handle);
            return value == IntPtr.Zero ? "Unknown Npcap error." : Marshal.PtrToStringAnsi(value);
        }

        internal static string Version()
        {
            IntPtr value = pcap_lib_version();
            return value == IntPtr.Zero ? "Unknown" : Marshal.PtrToStringAnsi(value);
        }
    }

    internal static class ForwardTraceKind
    {
        internal const byte ClientQuery = 1;
        internal const byte ClientResponse = 2;
        internal const byte ForwardQuery = 3;
        internal const byte ForwardResponse = 4;
    }

    internal struct ForwardTraceEvent
    {
        internal long TimestampMicroseconds;
        internal byte Kind;
        internal bool Tcp;
        internal bool Truncated;
        internal ushort LocalPort;
        internal ushort TransactionId;
        internal ushort PeerIndex;
        internal int NameIndex;
        internal ushort QueryType;
        internal byte ResponseCode;
    }

    public sealed class ForwardingCaptureReadyInfo
    {
        public string ComputerName { get; internal set; }
        public string LocalAddress { get; internal set; }
        public string ClientAddress { get; internal set; }
        public string[] ForwardingLocalAddresses { get; internal set; }
        public string[] MasterAddresses { get; internal set; }
        public string AdapterName { get; internal set; }
        public string DeviceName { get; internal set; }
        public string Filter { get; internal set; }
        public string NpcapVersion { get; internal set; }
        public string TimestampSource { get; internal set; }
    }

    public sealed class ForwardingCaptureResult
    {
        public string ComputerName { get; internal set; }
        public string LocalAddress { get; internal set; }
        public string ClientAddress { get; internal set; }
        public string[] ForwardingLocalAddresses { get; internal set; }
        public string[] MasterAddresses { get; internal set; }
        public string AdapterName { get; internal set; }
        public string DeviceName { get; internal set; }
        public string Filter { get; internal set; }
        public string NpcapVersion { get; internal set; }
        public string TimestampSource { get; internal set; }
        public DateTime CaptureStartUtc { get; internal set; }
        public DateTime CaptureEndUtc { get; internal set; }
        public long CapturedPackets { get; internal set; }
        public long ParsedDnsPackets { get; internal set; }
        public long RelevantEvents { get; internal set; }
        public long UnparsedDnsPackets { get; internal set; }
        public long PcapReceived { get; internal set; }
        public long PcapDropped { get; internal set; }
        public long InterfaceDropped { get; internal set; }
        public bool StatisticsAvailable { get; internal set; }
        public bool PacketLimitReached { get; internal set; }
        public byte[] CompressedEvents { get; internal set; }
    }

    internal sealed class ParsedForwardDnsPacket
    {
        internal byte[] SourceAddress;
        internal byte[] DestinationAddress;
        internal ushort SourcePort;
        internal ushort DestinationPort;
        internal ushort TransactionId;
        internal string QueryName;
        internal ushort QueryType;
        internal bool IsResponse;
        internal bool Tcp;
        internal bool Truncated;
        internal byte ResponseCode;
    }

    public sealed class ForwardingCaptureSession : IDisposable
    {
        private readonly IntPtr handle;
        private readonly int maximumPackets;
        private readonly byte[] serviceAddressBytes;
        private readonly byte[][] forwardingLocalAddressBytes;
        private readonly byte[] clientAddressBytes;
        private readonly byte[][] masterAddressBytes;
        private readonly HashSet<string> testNames;
        private readonly Dictionary<string, int> nameIndexes =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> names = new List<string>();
        private readonly List<ForwardTraceEvent> events = new List<ForwardTraceEvent>();
        private volatile bool stopRequested;
        private bool disposed;

        public ForwardingCaptureReadyInfo ReadyInfo { get; private set; }

        internal ForwardingCaptureSession(IntPtr handle, int maximumPackets,
            IPAddress localAddress, IPAddress clientAddress,
            IPAddress[] forwardingLocalAddresses, IPAddress[] masterAddresses,
            string[] queryNames, ForwardingCaptureReadyInfo readyInfo)
        {
            this.handle = handle;
            this.maximumPackets = maximumPackets;
            serviceAddressBytes = localAddress.GetAddressBytes();
            forwardingLocalAddressBytes = new byte[forwardingLocalAddresses.Length][];
            for (int i = 0; i < forwardingLocalAddresses.Length; i++)
                forwardingLocalAddressBytes[i] = forwardingLocalAddresses[i].GetAddressBytes();
            clientAddressBytes = clientAddress.GetAddressBytes();
            masterAddressBytes = new byte[masterAddresses.Length][];
            for (int i = 0; i < masterAddresses.Length; i++)
                masterAddressBytes[i] = masterAddresses[i].GetAddressBytes();
            testNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < queryNames.Length; i++)
                testNames.Add(NormalizeName(queryNames[i]));
            ReadyInfo = readyInfo;
        }

        public Task<ForwardingCaptureResult> RunAsync(int durationSeconds)
        {
            return Task.Factory.StartNew(() => Run(durationSeconds),
                System.Threading.CancellationToken.None,
                TaskCreationOptions.LongRunning,
                TaskScheduler.Default);
        }

        public ForwardingCaptureResult Run(int durationSeconds)
        {
            if (disposed) throw new ObjectDisposedException("ForwardingCaptureSession");
            DateTime startUtc = DateTime.UtcNow;
            Stopwatch timer = Stopwatch.StartNew();
            long capturedPackets = 0;
            long parsedPackets = 0;
            long unparsedPackets = 0;
            bool packetLimit = false;

            while (!stopRequested && timer.Elapsed.TotalSeconds < durationSeconds)
            {
                IntPtr headerPointer;
                IntPtr packetPointer;
                int status = ForwardPcapNative.pcap_next_ex(handle,
                    out headerPointer, out packetPointer);
                if (status == 0) continue;
                if (status == -2) break;
                if (status < 0) throw new IOException(ForwardPcapNative.Error(handle));

                ForwardPcapPacketHeader header = (ForwardPcapPacketHeader)
                    Marshal.PtrToStructure(headerPointer, typeof(ForwardPcapPacketHeader));
                int length = checked((int)header.CapturedLength);
                if (length <= 0) continue;
                if (capturedPackets >= maximumPackets)
                {
                    packetLimit = true;
                    break;
                }
                capturedPackets++;
                byte[] packet = new byte[length];
                Marshal.Copy(packetPointer, packet, 0, length);
                ParsedForwardDnsPacket parsed;
                if (!TryParsePacket(packet, out parsed))
                {
                    unparsedPackets++;
                    continue;
                }
                parsedPackets++;
                if (!testNames.Contains(parsed.QueryName)) continue;

                byte kind;
                ushort peerIndex = ushort.MaxValue;
                if (AddressesEqual(parsed.SourceAddress, clientAddressBytes) &&
                    AddressesEqual(parsed.DestinationAddress, serviceAddressBytes) &&
                    !parsed.IsResponse && parsed.DestinationPort == 53)
                {
                    kind = ForwardTraceKind.ClientQuery;
                }
                else if (AddressesEqual(parsed.DestinationAddress, clientAddressBytes) &&
                    AddressesEqual(parsed.SourceAddress, serviceAddressBytes) &&
                    parsed.IsResponse && parsed.SourcePort == 53)
                {
                    kind = ForwardTraceKind.ClientResponse;
                }
                else
                {
                    if (!parsed.IsResponse &&
                        !IsForwardingLocalAddress(parsed.SourceAddress)) continue;
                    if (parsed.IsResponse &&
                        !IsForwardingLocalAddress(parsed.DestinationAddress)) continue;
                    int masterIndex = FindMaster(parsed.IsResponse ?
                        parsed.SourceAddress : parsed.DestinationAddress);
                    if (masterIndex < 0) continue;
                    if (!parsed.IsResponse && parsed.DestinationPort == 53)
                        kind = ForwardTraceKind.ForwardQuery;
                    else if (parsed.IsResponse && parsed.SourcePort == 53)
                        kind = ForwardTraceKind.ForwardResponse;
                    else continue;
                    peerIndex = checked((ushort)masterIndex);
                }

                int nameIndex;
                if (!nameIndexes.TryGetValue(parsed.QueryName, out nameIndex))
                {
                    nameIndex = names.Count;
                    names.Add(parsed.QueryName);
                    nameIndexes.Add(parsed.QueryName, nameIndex);
                }
                long timestamp = ((long)header.Timestamp.Seconds * 1000000L) +
                    header.Timestamp.Microseconds;
                events.Add(new ForwardTraceEvent
                {
                    TimestampMicroseconds = timestamp,
                    Kind = kind,
                    Tcp = parsed.Tcp,
                    Truncated = parsed.Truncated,
                    LocalPort = parsed.IsResponse ? parsed.DestinationPort : parsed.SourcePort,
                    TransactionId = parsed.TransactionId,
                    PeerIndex = peerIndex,
                    NameIndex = nameIndex,
                    QueryType = parsed.QueryType,
                    ResponseCode = parsed.ResponseCode
                });

            }

            timer.Stop();
            ForwardPcapStatistics statistics;
            bool statisticsAvailable = ForwardPcapNative.pcap_stats(handle, out statistics) == 0;
            return new ForwardingCaptureResult
            {
                ComputerName = ReadyInfo.ComputerName,
                LocalAddress = ReadyInfo.LocalAddress,
                ClientAddress = ReadyInfo.ClientAddress,
                ForwardingLocalAddresses = ReadyInfo.ForwardingLocalAddresses,
                MasterAddresses = ReadyInfo.MasterAddresses,
                AdapterName = ReadyInfo.AdapterName,
                DeviceName = ReadyInfo.DeviceName,
                Filter = ReadyInfo.Filter,
                NpcapVersion = ReadyInfo.NpcapVersion,
                TimestampSource = ReadyInfo.TimestampSource,
                CaptureStartUtc = startUtc,
                CaptureEndUtc = DateTime.UtcNow,
                CapturedPackets = capturedPackets,
                ParsedDnsPackets = parsedPackets,
                RelevantEvents = events.Count,
                UnparsedDnsPackets = unparsedPackets,
                PcapReceived = statisticsAvailable ? statistics.Received : 0,
                PcapDropped = statisticsAvailable ? statistics.Dropped : 0,
                InterfaceDropped = statisticsAvailable ? statistics.InterfaceDropped : 0,
                StatisticsAvailable = statisticsAvailable,
                PacketLimitReached = packetLimit,
                CompressedEvents = ForwardTraceCodec.Encode(names, events)
            };
        }

        private int FindMaster(byte[] address)
        {
            for (int i = 0; i < masterAddressBytes.Length; i++)
                if (AddressesEqual(address, masterAddressBytes[i])) return i;
            return -1;
        }

        private bool IsForwardingLocalAddress(byte[] address)
        {
            for (int i = 0; i < forwardingLocalAddressBytes.Length; i++)
                if (AddressesEqual(address, forwardingLocalAddressBytes[i])) return true;
            return false;
        }

        private static bool AddressesEqual(byte[] first, byte[] second)
        {
            if (first == null || second == null || first.Length != second.Length) return false;
            for (int i = 0; i < first.Length; i++)
                if (first[i] != second[i]) return false;
            return true;
        }

        private static bool TryParsePacket(byte[] packet, out ParsedForwardDnsPacket parsed)
        {
            parsed = null;
            if (packet == null || packet.Length < 14) return false;
            int ipOffset = 14;
            ushort etherType = ReadUInt16(packet, 12);
            while ((etherType == 0x8100 || etherType == 0x88a8) &&
                packet.Length >= ipOffset + 4)
            {
                etherType = ReadUInt16(packet, ipOffset + 2);
                ipOffset += 4;
            }

            byte protocol;
            int transportOffset;
            byte[] sourceAddress;
            byte[] destinationAddress;
            if (etherType == 0x0800)
            {
                if (packet.Length < ipOffset + 20 || (packet[ipOffset] >> 4) != 4) return false;
                int ipHeaderLength = (packet[ipOffset] & 15) * 4;
                if (ipHeaderLength < 20 || packet.Length < ipOffset + ipHeaderLength) return false;
                ushort fragment = ReadUInt16(packet, ipOffset + 6);
                if ((fragment & 0x1fff) != 0) return false;
                protocol = packet[ipOffset + 9];
                transportOffset = ipOffset + ipHeaderLength;
                sourceAddress = CopyBytes(packet, ipOffset + 12, 4);
                destinationAddress = CopyBytes(packet, ipOffset + 16, 4);
            }
            else if (etherType == 0x86dd)
            {
                if (packet.Length < ipOffset + 40 || (packet[ipOffset] >> 4) != 6) return false;
                sourceAddress = CopyBytes(packet, ipOffset + 8, 16);
                destinationAddress = CopyBytes(packet, ipOffset + 24, 16);
                protocol = packet[ipOffset + 6];
                transportOffset = ipOffset + 40;
                if (!AdvanceIpv6Extensions(packet, ref protocol, ref transportOffset)) return false;
            }
            else return false;

            bool tcp;
            ushort sourcePort;
            ushort destinationPort;
            int dnsOffset;
            if (protocol == 17)
            {
                if (packet.Length < transportOffset + 8) return false;
                tcp = false;
                sourcePort = ReadUInt16(packet, transportOffset);
                destinationPort = ReadUInt16(packet, transportOffset + 2);
                dnsOffset = transportOffset + 8;
            }
            else if (protocol == 6)
            {
                if (packet.Length < transportOffset + 20) return false;
                tcp = true;
                sourcePort = ReadUInt16(packet, transportOffset);
                destinationPort = ReadUInt16(packet, transportOffset + 2);
                int tcpHeaderLength = (packet[transportOffset + 12] >> 4) * 4;
                if (tcpHeaderLength < 20 || packet.Length < transportOffset + tcpHeaderLength + 2)
                    return false;
                int payloadOffset = transportOffset + tcpHeaderLength;
                ushort dnsLength = ReadUInt16(packet, payloadOffset);
                if (dnsLength < 12) return false;
                dnsOffset = payloadOffset + 2;
            }
            else return false;

            if (sourcePort != 53 && destinationPort != 53) return false;
            if (packet.Length < dnsOffset + 12) return false;
            ushort flags = ReadUInt16(packet, dnsOffset + 2);
            bool response = (flags & 0x8000) != 0;
            if ((!response && destinationPort != 53) || (response && sourcePort != 53))
                return false;
            if (ReadUInt16(packet, dnsOffset + 4) == 0) return false;
            string queryName;
            int nextOffset;
            if (!TryReadDnsName(packet, dnsOffset, dnsOffset + 12,
                out queryName, out nextOffset)) return false;
            if (packet.Length < nextOffset + 4) return false;

            parsed = new ParsedForwardDnsPacket
            {
                SourceAddress = sourceAddress,
                DestinationAddress = destinationAddress,
                SourcePort = sourcePort,
                DestinationPort = destinationPort,
                TransactionId = ReadUInt16(packet, dnsOffset),
                QueryName = NormalizeName(queryName),
                QueryType = ReadUInt16(packet, nextOffset),
                IsResponse = response,
                Tcp = tcp,
                Truncated = (flags & 0x0200) != 0,
                ResponseCode = (byte)(flags & 15)
            };
            return true;
        }

        private static bool AdvanceIpv6Extensions(byte[] packet, ref byte protocol,
            ref int offset)
        {
            for (int i = 0; i < 8; i++)
            {
                if (protocol == 6 || protocol == 17) return true;
                if (protocol == 0 || protocol == 43 || protocol == 60)
                {
                    if (packet.Length < offset + 2) return false;
                    byte next = packet[offset];
                    int length = (packet[offset + 1] + 1) * 8;
                    if (packet.Length < offset + length) return false;
                    protocol = next;
                    offset += length;
                }
                else if (protocol == 44)
                {
                    if (packet.Length < offset + 8) return false;
                    ushort fragment = ReadUInt16(packet, offset + 2);
                    if ((fragment & 0xfff8) != 0) return false;
                    protocol = packet[offset];
                    offset += 8;
                }
                else if (protocol == 51)
                {
                    if (packet.Length < offset + 2) return false;
                    byte next = packet[offset];
                    int length = (packet[offset + 1] + 2) * 4;
                    if (packet.Length < offset + length) return false;
                    protocol = next;
                    offset += length;
                }
                else return false;
            }
            return protocol == 6 || protocol == 17;
        }

        private static bool TryReadDnsName(byte[] packet, int dnsOffset, int startOffset,
            out string name, out int nextOffset)
        {
            name = null;
            nextOffset = startOffset;
            StringBuilder builder = new StringBuilder();
            int offset = startOffset;
            bool jumped = false;
            int jumps = 0;
            while (offset < packet.Length && jumps < 32)
            {
                byte length = packet[offset];
                if (length == 0)
                {
                    if (!jumped) nextOffset = offset + 1;
                    name = builder.ToString();
                    return name.Length > 0;
                }
                if ((length & 0xc0) == 0xc0)
                {
                    if (offset + 1 >= packet.Length) return false;
                    int pointer = dnsOffset + (((length & 0x3f) << 8) | packet[offset + 1]);
                    if (!jumped) nextOffset = offset + 2;
                    offset = pointer;
                    jumped = true;
                    jumps++;
                    continue;
                }
                if ((length & 0xc0) != 0 || length > 63 ||
                    offset + 1 + length > packet.Length) return false;
                if (builder.Length > 0) builder.Append('.');
                for (int i = 0; i < length; i++)
                {
                    byte value = packet[offset + 1 + i];
                    if (value < 33 || value > 126) return false;
                    builder.Append((char)value);
                }
                offset += 1 + length;
                if (!jumped) nextOffset = offset;
            }
            return false;
        }

        private static byte[] CopyBytes(byte[] source, int offset, int count)
        {
            byte[] result = new byte[count];
            Buffer.BlockCopy(source, offset, result, 0, count);
            return result;
        }

        private static ushort ReadUInt16(byte[] value, int offset)
        {
            return (ushort)((value[offset] << 8) | value[offset + 1]);
        }

        private static string NormalizeName(string value)
        {
            if (value == null) return String.Empty;
            return value.Trim().TrimEnd('.').ToLowerInvariant();
        }

        public void RequestStop() { stopRequested = true; }

        public void Dispose()
        {
            if (disposed) return;
            disposed = true;
            if (handle != IntPtr.Zero) ForwardPcapNative.pcap_close(handle);
        }
    }

    public static class ForwardingCaptureRunner
    {
        private const int EthernetDataLink = 1;

        public static ForwardingCaptureSession Open(string localAddress,
            string clientAddress, string[] forwardingLocalAddresses,
            string[] masterAddresses, string[] queryNames,
            int snapshotLength, int bufferMegabytes, int maximumPackets)
        {
            IPAddress local;
            IPAddress client;
            if (!IPAddress.TryParse(localAddress, out local))
                throw new ArgumentException("The local capture address is invalid.", "localAddress");
            if (!IPAddress.TryParse(clientAddress, out client))
                throw new ArgumentException("The client capture address is invalid.", "clientAddress");
            if (masterAddresses == null || masterAddresses.Length == 0)
                throw new ArgumentException("At least one conditional forwarder master is required.",
                    "masterAddresses");
            if (queryNames == null || queryNames.Length == 0)
                throw new ArgumentException("At least one test name is required.", "queryNames");

            List<IPAddress> forwardingLocals = new List<IPAddress>();
            HashSet<string> uniqueLocals =
                new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (forwardingLocalAddresses != null)
            {
                for (int i = 0; i < forwardingLocalAddresses.Length; i++)
                {
                    IPAddress forwardingLocal;
                    if (!IPAddress.TryParse(forwardingLocalAddresses[i], out forwardingLocal))
                        throw new ArgumentException("Invalid forwarding source address: " +
                            forwardingLocalAddresses[i]);
                    if (uniqueLocals.Add(forwardingLocal.ToString()))
                        forwardingLocals.Add(forwardingLocal);
                }
            }
            if (forwardingLocals.Count == 0) forwardingLocals.Add(local);

            List<IPAddress> masters = new List<IPAddress>();
            HashSet<string> unique = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < masterAddresses.Length; i++)
            {
                IPAddress master;
                if (!IPAddress.TryParse(masterAddresses[i], out master))
                    throw new ArgumentException("Invalid conditional forwarder master: " +
                        masterAddresses[i]);
                if (unique.Add(master.ToString())) masters.Add(master);
            }

            NetworkInterface selected = null;
            foreach (NetworkInterface adapter in NetworkInterface.GetAllNetworkInterfaces())
            {
                foreach (UnicastIPAddressInformation address in
                    adapter.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.Equals(local))
                    {
                        selected = adapter;
                        break;
                    }
                }
                if (selected != null) break;
            }
            if (selected == null)
                throw new InvalidOperationException("No local network adapter owns " +
                    localAddress + ".");

            string id = selected.Id;
            if (!id.StartsWith("{", StringComparison.Ordinal)) id = "{" + id + "}";
            string deviceName = "\\Device\\NPF_" + id;
            StringBuilder peerFilter = new StringBuilder();
            peerFilter.Append("host ").Append(client.ToString());
            for (int i = 0; i < masters.Count; i++)
                peerFilter.Append(" or host ").Append(masters[i].ToString());
            string filter = "(udp or tcp) and port 53 and (" + peerFilter + ")";
            StringBuilder error = new StringBuilder(ForwardPcapNative.ErrorBufferSize);
            IntPtr handle = ForwardPcapNative.pcap_create(deviceName, error);
            if (handle == IntPtr.Zero)
                throw new InvalidOperationException("Npcap could not open " + deviceName +
                    ": " + error);
            try
            {
                if (ForwardPcapNative.pcap_set_snaplen(handle, snapshotLength) != 0)
                    throw new InvalidOperationException(ForwardPcapNative.Error(handle));
                if (ForwardPcapNative.pcap_set_promisc(handle, 0) != 0)
                    throw new InvalidOperationException(ForwardPcapNative.Error(handle));
                if (ForwardPcapNative.pcap_set_timeout(handle, 100) != 0)
                    throw new InvalidOperationException(ForwardPcapNative.Error(handle));
                if (ForwardPcapNative.pcap_set_buffer_size(handle,
                    checked(bufferMegabytes * 1024 * 1024)) != 0)
                    throw new InvalidOperationException(ForwardPcapNative.Error(handle));
                int activation = ForwardPcapNative.pcap_activate(handle);
                if (activation < 0)
                    throw new InvalidOperationException("Npcap activation failed: " +
                        ForwardPcapNative.Error(handle));
                if (ForwardPcapNative.pcap_datalink(handle) != EthernetDataLink)
                    throw new NotSupportedException("Forwarding trace currently requires an Ethernet Npcap data link.");

                ForwardBpfProgram program;
                if (ForwardPcapNative.pcap_compile(handle, out program, filter, 1,
                    0xffffffff) != 0)
                    throw new InvalidOperationException("Npcap forwarding filter compilation failed: " +
                        ForwardPcapNative.Error(handle));
                try
                {
                    if (ForwardPcapNative.pcap_setfilter(handle, ref program) != 0)
                        throw new InvalidOperationException("Npcap forwarding filter activation failed: " +
                            ForwardPcapNative.Error(handle));
                }
                finally { ForwardPcapNative.pcap_freecode(ref program); }

                string[] normalizedMasters = new string[masters.Count];
                for (int i = 0; i < masters.Count; i++)
                    normalizedMasters[i] = masters[i].ToString();
                ForwardingCaptureReadyInfo ready = new ForwardingCaptureReadyInfo
                {
                    ComputerName = Environment.MachineName,
                    LocalAddress = local.ToString(),
                    ClientAddress = client.ToString(),
                    ForwardingLocalAddresses = forwardingLocals.ConvertAll(
                        delegate(IPAddress value) { return value.ToString(); }).ToArray(),
                    MasterAddresses = normalizedMasters,
                    AdapterName = selected.Name,
                    DeviceName = deviceName,
                    Filter = filter,
                    NpcapVersion = ForwardPcapNative.Version(),
                    TimestampSource = "Npcap default host timestamp (microsecond representation)"
                };
                return new ForwardingCaptureSession(handle, maximumPackets, local, client,
                    forwardingLocals.ToArray(), masters.ToArray(), queryNames, ready);
            }
            catch
            {
                ForwardPcapNative.pcap_close(handle);
                throw;
            }
        }
    }

    internal sealed class ForwardTraceData
    {
        internal string[] Names;
        internal ForwardTraceEvent[] Events;
    }

    internal static class ForwardTraceCodec
    {
        private const int Magic = 0x44465431;

        internal static byte[] Encode(List<string> names, List<ForwardTraceEvent> events)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(output, CompressionMode.Compress, true))
                using (BinaryWriter writer = new BinaryWriter(gzip, Encoding.UTF8, true))
                {
                    writer.Write(Magic);
                    writer.Write(1);
                    writer.Write(names.Count);
                    for (int i = 0; i < names.Count; i++) writer.Write(names[i]);
                    writer.Write(events.Count);
                    for (int i = 0; i < events.Count; i++)
                    {
                        ForwardTraceEvent item = events[i];
                        writer.Write(item.TimestampMicroseconds);
                        writer.Write(item.Kind);
                        writer.Write(item.Tcp);
                        writer.Write(item.Truncated);
                        writer.Write(item.LocalPort);
                        writer.Write(item.TransactionId);
                        writer.Write(item.PeerIndex);
                        writer.Write(item.NameIndex);
                        writer.Write(item.QueryType);
                        writer.Write(item.ResponseCode);
                    }
                }
                return output.ToArray();
            }
        }

        internal static ForwardTraceData Decode(byte[] compressed)
        {
            if (compressed == null || compressed.Length == 0)
                return new ForwardTraceData
                {
                    Names = new string[0], Events = new ForwardTraceEvent[0]
                };
            using (MemoryStream input = new MemoryStream(compressed, false))
            using (GZipStream gzip = new GZipStream(input, CompressionMode.Decompress))
            using (BinaryReader reader = new BinaryReader(gzip, Encoding.UTF8))
            {
                if (reader.ReadInt32() != Magic)
                    throw new InvalidDataException("Invalid forwarding capture data.");
                if (reader.ReadInt32() != 1)
                    throw new InvalidDataException("Unsupported forwarding capture data version.");
                int nameCount = reader.ReadInt32();
                if (nameCount < 0 || nameCount > 10000000)
                    throw new InvalidDataException("Invalid forwarding name count.");
                string[] names = new string[nameCount];
                for (int i = 0; i < nameCount; i++) names[i] = reader.ReadString();
                int eventCount = reader.ReadInt32();
                if (eventCount < 0 || eventCount > 100000000)
                    throw new InvalidDataException("Invalid forwarding event count.");
                ForwardTraceEvent[] events = new ForwardTraceEvent[eventCount];
                for (int i = 0; i < eventCount; i++)
                {
                    events[i] = new ForwardTraceEvent
                    {
                        TimestampMicroseconds = reader.ReadInt64(),
                        Kind = reader.ReadByte(),
                        Tcp = reader.ReadBoolean(),
                        Truncated = reader.ReadBoolean(),
                        LocalPort = reader.ReadUInt16(),
                        TransactionId = reader.ReadUInt16(),
                        PeerIndex = reader.ReadUInt16(),
                        NameIndex = reader.ReadInt32(),
                        QueryType = reader.ReadUInt16(),
                        ResponseCode = reader.ReadByte()
                    };
                }
                return new ForwardTraceData { Names = names, Events = events };
            }
        }
    }

    internal struct ClientTraceKey : IEquatable<ClientTraceKey>
    {
        internal ushort Port;
        internal ushort TransactionId;
        internal bool Tcp;

        public bool Equals(ClientTraceKey other)
        {
            return Port == other.Port && TransactionId == other.TransactionId &&
                Tcp == other.Tcp;
        }
        public override bool Equals(object value)
        {
            return value is ClientTraceKey && Equals((ClientTraceKey)value);
        }
        public override int GetHashCode()
        {
            return (Port << 16) ^ TransactionId ^ (Tcp ? Int32.MinValue : 0);
        }
    }

    internal struct AttemptTraceKey : IEquatable<AttemptTraceKey>
    {
        internal ushort PeerIndex;
        internal ushort Port;
        internal ushort TransactionId;
        internal bool Tcp;

        public bool Equals(AttemptTraceKey other)
        {
            return PeerIndex == other.PeerIndex && Port == other.Port &&
                TransactionId == other.TransactionId && Tcp == other.Tcp;
        }
        public override bool Equals(object value)
        {
            return value is AttemptTraceKey && Equals((AttemptTraceKey)value);
        }
        public override int GetHashCode()
        {
            return (PeerIndex << 24) ^ (Port << 8) ^ TransactionId ^
                (Tcp ? Int32.MinValue : 0);
        }
    }

    internal sealed class ClientTransactionState
    {
        internal string Name;
        internal ushort QueryType;
        internal long RequestUs;
        internal long ResponseUs;
        internal byte ResponseCode;
    }

    internal sealed class AttemptState
    {
        internal string Name;
        internal ushort QueryType;
        internal ushort PeerIndex;
        internal ushort TransactionId;
        internal bool Tcp;
        internal bool Truncated;
        internal long QueryUs;
        internal long ResponseUs;
        internal byte ResponseCode;
    }

    internal sealed class FlightState
    {
        internal string Name;
        internal ushort QueryType;
        internal List<AttemptState> Attempts = new List<AttemptState>();
        internal long FirstAttemptUs;
        internal long LastAttemptUs;
        internal long TerminalResponseUs;
        internal long FirstClientRequestUs;
        internal long FirstClientResponseUs;
        internal long LastClientResponseUs;
        internal int ClientQueries;
        internal int ClientResponses;
        internal byte FinalClientResponseCode;
    }

    public sealed class ForwardingLatencySummary
    {
        public long Count { get; internal set; }
        public double MinimumMs { get; internal set; }
        public double AverageMs { get; internal set; }
        public double P50Ms { get; internal set; }
        public double P95Ms { get; internal set; }
        public double P99Ms { get; internal set; }
        public double MaximumMs { get; internal set; }
    }

    public sealed class ForwardingAttemptTrace
    {
        public int AttemptNumber { get; internal set; }
        public string TargetAddress { get; internal set; }
        public string Protocol { get; internal set; }
        public ushort TransactionId { get; internal set; }
        public DateTime QuerySentUtc { get; internal set; }
        public DateTime? ResponseReceivedUtc { get; internal set; }
        public double ObservedWaitMs { get; internal set; }
        public int ResponseCode { get; internal set; }
        public string ResponseCodeName { get; internal set; }
        public bool Truncated { get; internal set; }
        public string Outcome { get; internal set; }
    }

    public sealed class ForwardingFlightTrace
    {
        public string ConditionalForwarderZone { get; internal set; }
        public string QueryName { get; internal set; }
        public string QueryType { get; internal set; }
        public DateTime? FirstClientQueryReceivedUtc { get; internal set; }
        public DateTime FirstForwardAttemptUtc { get; internal set; }
        public DateTime? FinalUpstreamResponseUtc { get; internal set; }
        public DateTime? FirstClientResponseUtc { get; internal set; }
        public DateTime? LastClientResponseUtc { get; internal set; }
        public int WaitingClientQueries { get; internal set; }
        public int ClientResponses { get; internal set; }
        public int CoalescedClientQueries { get; internal set; }
        public double PreForwardDelayMs { get; internal set; }
        public double ForwardingDurationMs { get; internal set; }
        public double PostForwardDelayMs { get; internal set; }
        public double ObservedServerTurnaroundMs { get; internal set; }
        public bool DifferentMasterFallbackUsed { get; internal set; }
        public int DistinctMastersAttempted { get; internal set; }
        public int SameMasterRetries { get; internal set; }
        public string FinalResponder { get; internal set; }
        public string Status { get; internal set; }
        public int FinalClientResponseCode { get; internal set; }
        public string FinalClientResponseCodeName { get; internal set; }
        public ForwardingAttemptTrace[] Attempts { get; internal set; }
        internal int Priority { get; set; }
        internal int Sequence { get; set; }
    }

    internal sealed class RetainedFlightComparer : IComparer<ForwardingFlightTrace>
    {
        public int Compare(ForwardingFlightTrace first, ForwardingFlightTrace second)
        {
            if (Object.ReferenceEquals(first, second)) return 0;
            int value = first.Priority.CompareTo(second.Priority);
            if (value != 0) return value;
            value = first.ForwardingDurationMs.CompareTo(second.ForwardingDurationMs);
            if (value != 0) return value;
            value = second.FirstForwardAttemptUtc.CompareTo(first.FirstForwardAttemptUtc);
            if (value != 0) return value;
            return first.Sequence.CompareTo(second.Sequence);
        }
    }

    public sealed class ForwardingMasterSummary
    {
        public string Address { get; internal set; }
        public int ConfiguredUnionPosition { get; internal set; }
        public long Queries { get; internal set; }
        public long Responses { get; internal set; }
        public long NoResponseObservations { get; internal set; }
        public long NoErrorResponses { get; internal set; }
        public long NegativeResponses { get; internal set; }
        public long FailureResponses { get; internal set; }
        public ForwardingLatencySummary ResponseLatency { get; internal set; }
    }

    public sealed class ConditionalForwardingAnalysis
    {
        public string Server { get; internal set; }
        public string ServerAddress { get; internal set; }
        public string[] ConfiguredMasterUnion { get; internal set; }
        public long ClientQueriesObserved { get; internal set; }
        public long ClientResponsesObserved { get; internal set; }
        public long ClientTransactionsAttributedToForwarding { get; internal set; }
        public long ClientTransactionsWithoutObservedForwarding { get; internal set; }
        public long CoalescedClientQueries { get; internal set; }
        public long TotalFlights { get; internal set; }
        public long AnsweredFlights { get; internal set; }
        public long NegativeAnswerFlights { get; internal set; }
        public long FailedFlights { get; internal set; }
        public long FlightsUsingDifferentMaster { get; internal set; }
        public long FlightsWithSameMasterRetry { get; internal set; }
        public long UnmatchedForwardResponses { get; internal set; }
        public int ReturnedFlights { get; internal set; }
        public long OmittedFlights { get; internal set; }
        public ForwardingLatencySummary ForwardingDuration { get; internal set; }
        public ForwardingMasterSummary[] Masters { get; internal set; }
        public ForwardingFlightTrace[] Flights { get; internal set; }
    }

    public static class ForwardingCaptureAnalyzer
    {
        public static ConditionalForwardingAnalysis Analyze(string server,
            string serverAddress, string[] masterAddresses, string[] conditionalZones,
            byte[] compressedEvents, DateTime captureEndUtc, int maximumFlights)
        {
            ForwardTraceData data = ForwardTraceCodec.Decode(compressedEvents);
            Array.Sort(data.Events, delegate(ForwardTraceEvent first, ForwardTraceEvent second)
            {
                return first.TimestampMicroseconds.CompareTo(second.TimestampMicroseconds);
            });

            List<ClientTransactionState> clients = BuildClientTransactions(data);
            long unmatchedForwardResponses;
            List<AttemptState> attempts = BuildAttempts(data, out unmatchedForwardResponses);
            List<FlightState> flights = BuildFlights(attempts, clients);
            AttributeClients(clients, flights);

            long captureEndUs = ToUnixMicroseconds(captureEndUtc);
            SortedSet<ForwardingFlightTrace> retainedFlights =
                new SortedSet<ForwardingFlightTrace>(new RetainedFlightComparer());
            List<double> forwardingDurations = new List<double>();
            List<double>[] masterLatencies = new List<double>[masterAddresses.Length];
            long[] masterQueries = new long[masterAddresses.Length];
            long[] masterResponses = new long[masterAddresses.Length];
            long[] masterNoResponses = new long[masterAddresses.Length];
            long[] masterNoError = new long[masterAddresses.Length];
            long[] masterNegative = new long[masterAddresses.Length];
            long[] masterFailure = new long[masterAddresses.Length];
            for (int i = 0; i < masterLatencies.Length; i++)
                masterLatencies[i] = new List<double>();

            long answered = 0;
            long negative = 0;
            long failed = 0;
            long fallback = 0;
            long retry = 0;
            long attributed = 0;
            long coalesced = 0;
            for (int i = 0; i < flights.Count; i++)
            {
                ForwardingFlightTrace flight = CreateFlightTrace(flights[i],
                    masterAddresses, conditionalZones, captureEndUs);
                flight.Sequence = i;
                retainedFlights.Add(flight);
                if (retainedFlights.Count > maximumFlights)
                    retainedFlights.Remove(retainedFlights.Min);
                forwardingDurations.Add(flight.ForwardingDurationMs);
                attributed += flight.WaitingClientQueries;
                coalesced += flight.CoalescedClientQueries;
                if (flight.Status == "Answered") answered++;
                else if (flight.Status == "NegativeAnswer") negative++;
                else failed++;
                if (flight.DifferentMasterFallbackUsed) fallback++;
                if (flight.SameMasterRetries > 0) retry++;
                for (int a = 0; a < flights[i].Attempts.Count; a++)
                {
                    AttemptState attempt = flights[i].Attempts[a];
                    int master = attempt.PeerIndex;
                    if (master < 0 || master >= masterAddresses.Length) continue;
                    masterQueries[master]++;
                    if (attempt.ResponseUs > 0)
                    {
                        masterResponses[master]++;
                        masterLatencies[master].Add((attempt.ResponseUs - attempt.QueryUs) / 1000.0);
                        if (attempt.ResponseCode == 0) masterNoError[master]++;
                        else if (attempt.ResponseCode == 3) masterNegative[master]++;
                        else masterFailure[master]++;
                    }
                    else masterNoResponses[master]++;
                }
            }

            List<ForwardingFlightTrace> outputFlights =
                new List<ForwardingFlightTrace>(retainedFlights);
            outputFlights.Sort(delegate(ForwardingFlightTrace first,
                ForwardingFlightTrace second)
            {
                int priority = second.Priority.CompareTo(first.Priority);
                if (priority != 0) return priority;
                int duration = second.ForwardingDurationMs.CompareTo(first.ForwardingDurationMs);
                if (duration != 0) return duration;
                return first.FirstForwardAttemptUtc.CompareTo(second.FirstForwardAttemptUtc);
            });
            int returned = outputFlights.Count;
            ForwardingFlightTrace[] retained = new ForwardingFlightTrace[returned];
            for (int i = 0; i < returned; i++) retained[i] = outputFlights[i];

            ForwardingMasterSummary[] masters = new ForwardingMasterSummary[masterAddresses.Length];
            for (int i = 0; i < masters.Length; i++)
            {
                masters[i] = new ForwardingMasterSummary
                {
                    Address = masterAddresses[i],
                    ConfiguredUnionPosition = i + 1,
                    Queries = masterQueries[i],
                    Responses = masterResponses[i],
                    NoResponseObservations = masterNoResponses[i],
                    NoErrorResponses = masterNoError[i],
                    NegativeResponses = masterNegative[i],
                    FailureResponses = masterFailure[i],
                    ResponseLatency = Metrics(masterLatencies[i])
                };
            }

            long clientQueries = 0;
            long clientResponses = 0;
            for (int i = 0; i < clients.Count; i++)
            {
                clientQueries++;
                if (clients[i].ResponseUs > 0) clientResponses++;
            }
            return new ConditionalForwardingAnalysis
            {
                Server = server,
                ServerAddress = serverAddress,
                ConfiguredMasterUnion = masterAddresses,
                ClientQueriesObserved = clientQueries,
                ClientResponsesObserved = clientResponses,
                ClientTransactionsAttributedToForwarding = attributed,
                ClientTransactionsWithoutObservedForwarding = Math.Max(0, clientQueries - attributed),
                CoalescedClientQueries = coalesced,
                TotalFlights = flights.Count,
                AnsweredFlights = answered,
                NegativeAnswerFlights = negative,
                FailedFlights = failed,
                FlightsUsingDifferentMaster = fallback,
                FlightsWithSameMasterRetry = retry,
                UnmatchedForwardResponses = unmatchedForwardResponses,
                ReturnedFlights = returned,
                OmittedFlights = flights.Count - returned,
                ForwardingDuration = Metrics(forwardingDurations),
                Masters = masters,
                Flights = retained
            };
        }

        private static List<ClientTransactionState> BuildClientTransactions(ForwardTraceData data)
        {
            Dictionary<ClientTraceKey, Queue<ClientTransactionState>> pending =
                new Dictionary<ClientTraceKey, Queue<ClientTransactionState>>();
            List<ClientTransactionState> clients = new List<ClientTransactionState>();
            for (int i = 0; i < data.Events.Length; i++)
            {
                ForwardTraceEvent item = data.Events[i];
                if (item.Kind != ForwardTraceKind.ClientQuery &&
                    item.Kind != ForwardTraceKind.ClientResponse) continue;
                ClientTraceKey key = new ClientTraceKey
                {
                    Port = item.LocalPort,
                    TransactionId = item.TransactionId,
                    Tcp = item.Tcp
                };
                if (item.Kind == ForwardTraceKind.ClientQuery)
                {
                    ClientTransactionState client = new ClientTransactionState
                    {
                        Name = data.Names[item.NameIndex],
                        QueryType = item.QueryType,
                        RequestUs = item.TimestampMicroseconds
                    };
                    clients.Add(client);
                    Queue<ClientTransactionState> queue;
                    if (!pending.TryGetValue(key, out queue))
                    {
                        queue = new Queue<ClientTransactionState>();
                        pending.Add(key, queue);
                    }
                    queue.Enqueue(client);
                }
                else
                {
                    Queue<ClientTransactionState> queue;
                    if (pending.TryGetValue(key, out queue) && queue.Count > 0)
                    {
                        ClientTransactionState client = queue.Dequeue();
                        client.ResponseUs = item.TimestampMicroseconds;
                        client.ResponseCode = item.ResponseCode;
                        if (queue.Count == 0) pending.Remove(key);
                    }
                }
            }
            return clients;
        }

        private static List<AttemptState> BuildAttempts(ForwardTraceData data,
            out long unmatchedResponses)
        {
            unmatchedResponses = 0;
            Dictionary<AttemptTraceKey, Stack<AttemptState>> pending =
                new Dictionary<AttemptTraceKey, Stack<AttemptState>>();
            List<AttemptState> attempts = new List<AttemptState>();
            for (int i = 0; i < data.Events.Length; i++)
            {
                ForwardTraceEvent item = data.Events[i];
                if (item.Kind != ForwardTraceKind.ForwardQuery &&
                    item.Kind != ForwardTraceKind.ForwardResponse) continue;
                AttemptTraceKey key = new AttemptTraceKey
                {
                    PeerIndex = item.PeerIndex,
                    Port = item.LocalPort,
                    TransactionId = item.TransactionId,
                    Tcp = item.Tcp
                };
                if (item.Kind == ForwardTraceKind.ForwardQuery)
                {
                    AttemptState attempt = new AttemptState
                    {
                        Name = data.Names[item.NameIndex],
                        QueryType = item.QueryType,
                        PeerIndex = item.PeerIndex,
                        TransactionId = item.TransactionId,
                        Tcp = item.Tcp,
                        QueryUs = item.TimestampMicroseconds
                    };
                    attempts.Add(attempt);
                    Stack<AttemptState> stack;
                    if (!pending.TryGetValue(key, out stack))
                    {
                        stack = new Stack<AttemptState>();
                        pending.Add(key, stack);
                    }
                    stack.Push(attempt);
                }
                else
                {
                    Stack<AttemptState> stack;
                    if (pending.TryGetValue(key, out stack) && stack.Count > 0)
                    {
                        AttemptState attempt = stack.Pop();
                        attempt.ResponseUs = item.TimestampMicroseconds;
                        attempt.ResponseCode = item.ResponseCode;
                        attempt.Truncated = item.Truncated;
                        if (stack.Count == 0) pending.Remove(key);
                    }
                    else unmatchedResponses++;
                }
            }
            attempts.Sort(delegate(AttemptState first, AttemptState second)
            {
                return first.QueryUs.CompareTo(second.QueryUs);
            });
            return attempts;
        }

        private static List<FlightState> BuildFlights(List<AttemptState> attempts,
            List<ClientTransactionState> clients)
        {
            const long maximumGapUs = 60000000L;
            Dictionary<string, List<long>> responseTimes =
                new Dictionary<string, List<long>>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < clients.Count; i++)
            {
                if (clients[i].ResponseUs <= 0) continue;
                string clientKey = clients[i].Name + "|" + clients[i].QueryType;
                List<long> times;
                if (!responseTimes.TryGetValue(clientKey, out times))
                {
                    times = new List<long>();
                    responseTimes.Add(clientKey, times);
                }
                times.Add(clients[i].ResponseUs);
            }
            Dictionary<string, FlightState> active =
                new Dictionary<string, FlightState>(StringComparer.OrdinalIgnoreCase);
            List<FlightState> flights = new List<FlightState>();
            for (int i = 0; i < attempts.Count; i++)
            {
                AttemptState attempt = attempts[i];
                string key = attempt.Name + "|" + attempt.QueryType;
                FlightState flight;
                bool newFlight = !active.TryGetValue(key, out flight) ||
                    attempt.QueryUs - flight.LastAttemptUs > maximumGapUs ||
                    (flight.TerminalResponseUs > 0 &&
                        attempt.QueryUs > flight.TerminalResponseUs);
                if (!newFlight)
                {
                    List<long> times;
                    if (responseTimes.TryGetValue(key, out times))
                    {
                        for (int r = 0; r < times.Count; r++)
                        {
                            if (times[r] > flight.LastAttemptUs &&
                                times[r] < attempt.QueryUs)
                            {
                                newFlight = true;
                                break;
                            }
                        }
                    }
                }
                if (newFlight)
                {
                    flight = new FlightState
                    {
                        Name = attempt.Name,
                        QueryType = attempt.QueryType,
                        FirstAttemptUs = attempt.QueryUs,
                        LastAttemptUs = attempt.QueryUs
                    };
                    flights.Add(flight);
                    active[key] = flight;
                }
                flight.Attempts.Add(attempt);
                flight.LastAttemptUs = attempt.QueryUs;
                if (attempt.ResponseUs > 0 && !attempt.Truncated &&
                    (attempt.ResponseCode == 0 || attempt.ResponseCode == 3))
                {
                    if (flight.TerminalResponseUs == 0 ||
                        attempt.ResponseUs < flight.TerminalResponseUs)
                        flight.TerminalResponseUs = attempt.ResponseUs;
                }
            }
            return flights;
        }

        private static void AttributeClients(List<ClientTransactionState> clients,
            List<FlightState> flights)
        {
            Dictionary<string, List<FlightState>> byName =
                new Dictionary<string, List<FlightState>>(StringComparer.OrdinalIgnoreCase);
            for (int i = 0; i < flights.Count; i++)
            {
                string key = flights[i].Name + "|" + flights[i].QueryType;
                List<FlightState> list;
                if (!byName.TryGetValue(key, out list))
                {
                    list = new List<FlightState>();
                    byName.Add(key, list);
                }
                list.Add(flights[i]);
            }
            for (int i = 0; i < clients.Count; i++)
            {
                ClientTransactionState client = clients[i];
                string key = client.Name + "|" + client.QueryType;
                List<FlightState> candidates;
                if (!byName.TryGetValue(key, out candidates)) continue;
                FlightState best = null;
                long bestDistance = Int64.MaxValue;
                for (int f = 0; f < candidates.Count; f++)
                {
                    FlightState flight = candidates[f];
                    long effectiveEnd = flight.TerminalResponseUs > 0 ?
                        flight.TerminalResponseUs : flight.LastAttemptUs + 60000000L;
                    if (client.RequestUs > effectiveEnd) continue;
                    if (client.ResponseUs > 0 && client.ResponseUs < flight.FirstAttemptUs)
                        continue;
                    if (flight.FirstAttemptUs - client.RequestUs > 60000000L) continue;
                    long distance = Math.Abs(flight.FirstAttemptUs - client.RequestUs);
                    if (distance < bestDistance)
                    {
                        best = flight;
                        bestDistance = distance;
                    }
                }
                if (best == null) continue;
                best.ClientQueries++;
                if (best.FirstClientRequestUs == 0 ||
                    client.RequestUs < best.FirstClientRequestUs)
                    best.FirstClientRequestUs = client.RequestUs;
                if (client.ResponseUs > 0)
                {
                    best.ClientResponses++;
                    if (best.FirstClientResponseUs == 0 ||
                        client.ResponseUs < best.FirstClientResponseUs)
                        best.FirstClientResponseUs = client.ResponseUs;
                    if (client.ResponseUs > best.LastClientResponseUs)
                        best.LastClientResponseUs = client.ResponseUs;
                    best.FinalClientResponseCode = client.ResponseCode;
                }
            }
        }

        private static ForwardingFlightTrace CreateFlightTrace(FlightState state,
            string[] masterAddresses, string[] zones, long captureEndUs)
        {
            state.Attempts.Sort(delegate(AttemptState first, AttemptState second)
            {
                return first.QueryUs.CompareTo(second.QueryUs);
            });
            HashSet<ushort> distinctMasters = new HashSet<ushort>();
            ForwardingAttemptTrace[] attempts =
                new ForwardingAttemptTrace[state.Attempts.Count];
            AttemptState terminal = null;
            bool anyResponse = false;
            for (int i = 0; i < state.Attempts.Count; i++)
            {
                AttemptState attempt = state.Attempts[i];
                distinctMasters.Add(attempt.PeerIndex);
                if (attempt.ResponseUs > 0) anyResponse = true;
                if (terminal == null && attempt.ResponseUs > 0 &&
                    !attempt.Truncated &&
                    (attempt.ResponseCode == 0 || attempt.ResponseCode == 3))
                    terminal = attempt;
                long waitEnd;
                string outcome;
                if (attempt.ResponseUs > 0)
                {
                    waitEnd = attempt.ResponseUs;
                    outcome = attempt.Truncated ? "Truncated" :
                        ResponseCodeName(attempt.ResponseCode);
                }
                else if (i + 1 < state.Attempts.Count)
                {
                    waitEnd = state.Attempts[i + 1].QueryUs;
                    outcome = "NoResponseBeforeNextAttempt";
                }
                else if (state.FirstClientResponseUs > 0)
                {
                    waitEnd = state.FirstClientResponseUs;
                    outcome = "NoResponseBeforeClientResponse";
                }
                else
                {
                    waitEnd = captureEndUs;
                    outcome = "NoResponseBeforeCaptureEnd";
                }
                string target = attempt.PeerIndex < masterAddresses.Length ?
                    masterAddresses[attempt.PeerIndex] : "Unknown";
                attempts[i] = new ForwardingAttemptTrace
                {
                    AttemptNumber = i + 1,
                    TargetAddress = target,
                    Protocol = attempt.Tcp ? "TCP" : "UDP",
                    TransactionId = attempt.TransactionId,
                    QuerySentUtc = UnixMicrosecondsToUtc(attempt.QueryUs),
                    ResponseReceivedUtc = attempt.ResponseUs > 0 ?
                        (DateTime?)UnixMicrosecondsToUtc(attempt.ResponseUs) : null,
                    ObservedWaitMs = Round(Math.Max(0, waitEnd - attempt.QueryUs) / 1000.0),
                    ResponseCode = attempt.ResponseUs > 0 ? attempt.ResponseCode : -1,
                    ResponseCodeName = attempt.ResponseUs > 0 ?
                        ResponseCodeName(attempt.ResponseCode) : null,
                    Truncated = attempt.Truncated,
                    Outcome = outcome
                };
            }

            long finalUpstreamUs = terminal == null ? 0 : terminal.ResponseUs;
            long forwardEndUs = finalUpstreamUs > 0 ? finalUpstreamUs :
                (state.FirstClientResponseUs > 0 ? state.FirstClientResponseUs : captureEndUs);
            string status;
            if (terminal != null && terminal.ResponseCode == 0) status = "Answered";
            else if (terminal != null && terminal.ResponseCode == 3) status = "NegativeAnswer";
            else if (anyResponse) status = "FailedResponse";
            else status = "NoResponse";
            string responder = terminal != null && terminal.PeerIndex < masterAddresses.Length ?
                masterAddresses[terminal.PeerIndex] : null;
            double preForward = state.FirstClientRequestUs > 0 ?
                (state.FirstAttemptUs - state.FirstClientRequestUs) / 1000.0 : 0.0;
            double postForward = finalUpstreamUs > 0 && state.FirstClientResponseUs > 0 ?
                (state.FirstClientResponseUs - finalUpstreamUs) / 1000.0 : 0.0;
            double serverTurn = state.FirstClientRequestUs > 0 &&
                state.LastClientResponseUs > 0 ?
                (state.LastClientResponseUs - state.FirstClientRequestUs) / 1000.0 : 0.0;
            bool masterFallback = distinctMasters.Count > 1;
            int sameMasterRetries = Math.Max(0, state.Attempts.Count - distinctMasters.Count);
            return new ForwardingFlightTrace
            {
                ConditionalForwarderZone = MatchZone(state.Name, zones),
                QueryName = state.Name,
                QueryType = QueryTypeName(state.QueryType),
                FirstClientQueryReceivedUtc = state.FirstClientRequestUs > 0 ?
                    (DateTime?)UnixMicrosecondsToUtc(state.FirstClientRequestUs) : null,
                FirstForwardAttemptUtc = UnixMicrosecondsToUtc(state.FirstAttemptUs),
                FinalUpstreamResponseUtc = finalUpstreamUs > 0 ?
                    (DateTime?)UnixMicrosecondsToUtc(finalUpstreamUs) : null,
                FirstClientResponseUtc = state.FirstClientResponseUs > 0 ?
                    (DateTime?)UnixMicrosecondsToUtc(state.FirstClientResponseUs) : null,
                LastClientResponseUtc = state.LastClientResponseUs > 0 ?
                    (DateTime?)UnixMicrosecondsToUtc(state.LastClientResponseUs) : null,
                WaitingClientQueries = state.ClientQueries,
                ClientResponses = state.ClientResponses,
                CoalescedClientQueries = Math.Max(0, state.ClientQueries - 1),
                PreForwardDelayMs = Round(preForward),
                ForwardingDurationMs = Round(Math.Max(0, forwardEndUs - state.FirstAttemptUs) / 1000.0),
                PostForwardDelayMs = Round(postForward),
                ObservedServerTurnaroundMs = Round(serverTurn),
                DifferentMasterFallbackUsed = masterFallback,
                DistinctMastersAttempted = distinctMasters.Count,
                SameMasterRetries = sameMasterRetries,
                FinalResponder = responder,
                Status = status,
                FinalClientResponseCode = state.ClientResponses > 0 ?
                    state.FinalClientResponseCode : -1,
                FinalClientResponseCodeName = state.ClientResponses > 0 ?
                    ResponseCodeName(state.FinalClientResponseCode) : null,
                Attempts = attempts,
                Priority = masterFallback ? 4 :
                    ((status == "FailedResponse" || status == "NoResponse") ? 3 :
                    (sameMasterRetries > 0 ? 2 : 1))
            };
        }

        private static string MatchZone(string name, string[] zones)
        {
            string best = null;
            if (zones == null) return null;
            for (int i = 0; i < zones.Length; i++)
            {
                string zone = zones[i].Trim().TrimEnd('.').ToLowerInvariant();
                if (name.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase))
                {
                    if (best == null || zone.Length > best.Length) best = zone;
                }
            }
            return best;
        }

        private static ForwardingLatencySummary Metrics(List<double> values)
        {
            ForwardingLatencySummary result = new ForwardingLatencySummary
            {
                Count = values.Count
            };
            if (values.Count == 0) return result;
            double[] sorted = values.ToArray();
            Array.Sort(sorted);
            double sum = 0.0;
            for (int i = 0; i < sorted.Length; i++) sum += sorted[i];
            result.MinimumMs = Round(sorted[0]);
            result.AverageMs = Round(sum / sorted.Length);
            result.P50Ms = Round(Percentile(sorted, 0.50));
            result.P95Ms = Round(Percentile(sorted, 0.95));
            result.P99Ms = Round(Percentile(sorted, 0.99));
            result.MaximumMs = Round(sorted[sorted.Length - 1]);
            return result;
        }

        private static double Percentile(double[] values, double percentile)
        {
            if (values.Length == 1) return values[0];
            double rank = percentile * (values.Length - 1);
            int lower = (int)Math.Floor(rank);
            int upper = (int)Math.Ceiling(rank);
            if (lower == upper) return values[lower];
            return values[lower] + (values[upper] - values[lower]) * (rank - lower);
        }

        private static long ToUnixMicroseconds(DateTime value)
        {
            DateTime utc = value.Kind == DateTimeKind.Utc ? value : value.ToUniversalTime();
            return (utc.Ticks - new DateTime(1970, 1, 1, 0, 0, 0,
                DateTimeKind.Utc).Ticks) / 10L;
        }

        private static DateTime UnixMicrosecondsToUtc(long value)
        {
            return new DateTime(1970, 1, 1, 0, 0, 0,
                DateTimeKind.Utc).AddTicks(value * 10L);
        }

        private static double Round(double value) { return Math.Round(value, 3); }

        private static string ResponseCodeName(int value)
        {
            switch (value)
            {
                case 0: return "NOERROR";
                case 1: return "FORMERR";
                case 2: return "SERVFAIL";
                case 3: return "NXDOMAIN";
                case 4: return "NOTIMP";
                case 5: return "REFUSED";
                default: return "RCODE" + value;
            }
        }

        private static string QueryTypeName(ushort value)
        {
            switch (value)
            {
                case 1: return "A";
                case 2: return "NS";
                case 5: return "CNAME";
                case 6: return "SOA";
                case 12: return "PTR";
                case 15: return "MX";
                case 16: return "TXT";
                case 28: return "AAAA";
                case 33: return "SRV";
                default: return value.ToString();
            }
        }
    }
}
'@

        if ($TraceConditionalForwarding -and -not $CoordinatedCapture) {
            throw 'TraceConditionalForwarding requires CoordinatedCapture.'
        }

        if ($CoordinatedCapture -and -not ('DnsCoordinatedCaptureV424.CaptureRunner' -as [type])) {
            if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
                throw 'CoordinatedCapture requires Windows on the test client.'
            }
            $npcapDirectory = if ([Environment]::Is64BitProcess) {
                Join-Path $env:SystemRoot 'System32\Npcap'
            } else {
                Join-Path $env:SystemRoot 'SysWOW64\Npcap'
            }
            if (-not [IO.Directory]::Exists($npcapDirectory)) {
                throw "Npcap runtime directory was not found: $npcapDirectory"
            }
            if (($env:Path -split ';') -notcontains $npcapDirectory) {
                $env:Path = $npcapDirectory + ';' + $env:Path
            }
            Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition $coordinatedCaptureTypeDefinition
        }

        if ($TraceConditionalForwarding -and
            -not ('DnsForwardingCaptureV410.ForwardingCaptureRunner' -as [type])) {
            Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition $forwardingCaptureTypeDefinition
        }

        function Get-DnsCaptureSourceAddress {
            param([Parameter(Mandatory)][string]$PeerAddress)
            $peer = $null
            if (-not [IPAddress]::TryParse($PeerAddress, [ref]$peer)) {
                throw "The coordinated-capture peer address is invalid: $PeerAddress"
            }
            $socket = New-Object System.Net.Sockets.Socket @(
                $peer.AddressFamily,
                [System.Net.Sockets.SocketType]::Dgram,
                [System.Net.Sockets.ProtocolType]::Udp
            )
            try {
                $socket.Connect((New-Object System.Net.IPEndPoint -ArgumentList $peer, 53))
                return ([System.Net.IPEndPoint]$socket.LocalEndPoint).Address.ToString()
            } finally {
                $socket.Dispose()
            }
        }

        function Test-DnsCaptureCredentialFailure {
            param([AllowEmptyString()][string]$Message)

            if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
            if ($Message -match '(?i)cannot find the computer|server name cannot be resolved|client cannot connect|network path was not found|connection timed out|actively refused') {
                return $false
            }
            return $Message -match '(?i)access is denied|user name or password is incorrect|logon failure|credentials? (?:were |was )?rejected|authentication failed|unauthorized|0x8009030[ce]'
        }

        function Get-DnsCaptureFallbackReason {
            param([AllowEmptyString()][string]$Message)

            $singleLine = ([string]$Message -replace '\s+', ' ').Trim()
            if ([string]::IsNullOrWhiteSpace($singleLine)) {
                return 'Remote server-side capture setup did not complete.'
            }
            if ($singleLine -match '(?i)cannot find the computer') {
                return 'WinRM/Kerberos could not find the target as an Active Directory computer.'
            }
            if ($singleLine -match '(?i)server name cannot be resolved') {
                return 'WinRM could not resolve the capture target.'
            }
            if ($singleLine -match '(?i)client cannot connect|actively refused') {
                return 'WinRM is not available on the capture target.'
            }
            if ($singleLine -match '(?i)access is denied|unauthorized') {
                return 'The remoting identity was not authorized for server-side capture.'
            }
            if ($singleLine.Length -gt 300) {
                return $singleLine.Substring(0, 297) + '...'
            }
            return $singleLine
        }

        function Convert-DnsCaptureDiagnostics {
            param([Parameter(Mandatory)]$Capture)
            return [pscustomobject]@{
                ComputerName         = $Capture.ComputerName
                LocalAddress         = $Capture.LocalAddress
                PeerAddress          = $Capture.PeerAddress
                AdapterName          = $Capture.AdapterName
                DeviceName           = $Capture.DeviceName
                Filter               = $Capture.Filter
                NpcapVersion         = $Capture.NpcapVersion
                TimestampSource      = $Capture.TimestampSource
                CaptureStartUtc      = $Capture.CaptureStartUtc
                CaptureEndUtc        = $Capture.CaptureEndUtc
                ParsedPackets        = [long]$Capture.ParsedPackets
                QueryPackets         = [long]$Capture.QueryPackets
                ResponsePackets      = [long]$Capture.ResponsePackets
                CompletedPairs       = [long]$Capture.CompletedPairs
                UnmatchedQueries     = [long]$Capture.UnmatchedQueries
                UnmatchedResponses   = [long]$Capture.UnmatchedResponses
                PcapReceived         = [long]$Capture.PcapReceived
                PcapDropped          = [long]$Capture.PcapDropped
                InterfaceDropped     = [long]$Capture.InterfaceDropped
                StatisticsAvailable  = [bool]$Capture.StatisticsAvailable
                PacketLimitReached   = [bool]$Capture.PacketLimitReached
            }
        }

        function Format-FixedText {
            param([AllowNull()][string]$Value, [int]$Width)
            if ($null -eq $Value) { $Value = '' }
            if ($Value.Length -gt $Width) { return $Value.Substring(0, $Width - 1) + '~' }
            return $Value.PadRight($Width)
        }

        function Format-CenteredText {
            param([AllowNull()][string]$Value, [int]$Width)
            if ($null -eq $Value) { $Value = '' }
            if ($Value.Length -gt $Width) { $Value = $Value.Substring(0, $Width - 1) + '~' }
            $leftWidth = [int]([Math]::Floor(($Width - $Value.Length) / 2) + $Value.Length)
            return $Value.PadLeft($leftWidth).PadRight($Width)
        }

        function Get-ShortServerName {
            param([Parameter(Mandatory)][string]$Value)
            $withoutAddress = $Value -replace '\s+\[.*$',''
            $parsed = $null
            if ([IPAddress]::TryParse($withoutAddress, [ref]$parsed)) { return $withoutAddress }
            return ($withoutAddress -split '\.')[0]
        }

        function Format-MetricNumber {
            param($Value, [string]$Pattern = '0.00')
            if ($null -eq $Value) { return '-' }
            return ([double]$Value).ToString($Pattern, [CultureInfo]::InvariantCulture)
        }

        function Format-SignedMetricNumber {
            param($Value)
            if ($null -eq $Value) { return '-' }
            return ([double]$Value).ToString(
                '+0.000;-0.000;0.000', [CultureInfo]::InvariantCulture)
        }

        function Format-AverageExcessShare {
            param($OutboundMetric, $ReturnMetric, [int]$Width = 18)

            if ($null -eq $OutboundMetric -or $null -eq $ReturnMetric -or
                $OutboundMetric.Count -le 0 -or $ReturnMetric.Count -le 0) {
                return (Format-CenteredText -Value '-' -Width $Width)
            }
            $outboundPositive = [Math]::Max(
                0.0, [double]$OutboundMetric.AverageMs)
            $returnPositive = [Math]::Max(
                0.0, [double]$ReturnMetric.AverageMs)
            $totalPositive = $outboundPositive + $returnPositive
            if ($totalPositive -le 0.0) {
                return (Format-CenteredText -Value 'NO POSITIVE EXCESS' `
                    -Width $Width)
            }
            $outboundPercent = [int][Math]::Round(
                100.0 * $outboundPositive / $totalPositive,
                0, [MidpointRounding]::AwayFromZero)
            $returnPercent = 100 - $outboundPercent
            $shareText = 'OUT {0}% / RET {1}%' -f @(
                $outboundPercent
                $returnPercent
            )
            return (Format-CenteredText -Value $shareText -Width $Width)
        }

        function Convert-MetricSnapshot {
            param(
                [Parameter(Mandatory)][DnsPerformanceV420.MetricSnapshot]$Metric,
                [string]$NameProperty,
                [string]$Name,
                [string]$Address,
                [string]$FQDN
            )

            $properties = [ordered]@{}
            if ($NameProperty) { $properties[$NameProperty] = $Name }
            if ($PSBoundParameters.ContainsKey('Address')) { $properties.Address = $Address }
            if ($PSBoundParameters.ContainsKey('FQDN')) { $properties.FQDN = $FQDN }
            foreach ($property in @(
                'Planned','Sent','NotSent','ResponseReceived','ResponseRatePercent','Success',
                'SuccessRatePercent','Timeout','DnsError','OtherFailure','SchedulerMiss',
                'ConcurrencyDrop','TcpFallback','AverageMs','StdDevMs','MinMs','P50Ms',
                'P95Ms','P99Ms','MaxMs','ClientProcessingAverageMs',
                'ClientProcessingP95Ms','ClientProcessingP99Ms','ClientProcessingMaxMs',
                'MaxSchedulerLagMs','Qps'
            )) {
                $properties[$property] = $Metric.$property
            }
            return [pscustomobject]$properties
        }

        function Get-DashboardLines {
            param(
                [Parameter(Mandatory)][DnsPerformanceV420.LiveSnapshot]$Snapshot,
                [Parameter(Mandatory)][DnsPerformanceV420.RunnerProgress]$Progress,
                [Parameter(Mandatory)][string[]]$Names,
                [Parameter(Mandatory)][int]$TargetAggregateQps,
                [Parameter(Mandatory)][int]$PerServerQps,
                [Parameter(Mandatory)][int]$Duration,
                [Parameter(Mandatory)][int]$EndpointCount,
                [Parameter(Mandatory)][long]$Planned,
                [Parameter(Mandatory)][int]$OutstandingLimit
            )

            $now = [datetime]::UtcNow
            $phase = if ($Progress.Phase) { $Progress.Phase } else { 'STARTING' }
            if ($phase -eq 'STARTING' -or $phase -eq 'WARMUP') {
                $warmElapsed = if ($Progress.WarmupStartUtc -eq [datetime]::MinValue) { 0.0 } else {
                    [Math]::Max(0.0, ($now - $Progress.WarmupStartUtc).TotalSeconds)
                }
                return @(
                    ('DNS PERFORMANCE TEST v3.5.3 - {0} - UTC {1:HH:mm:ss}' -f $phase, $now),
                    ('{0} endpoints x {1} QPS/server = {2} target aggregate QPS | {3} names | measured {4}s | warm-up {5}s' -f @(
                        $EndpointCount
                        $PerServerQps
                        $TargetAggregateQps
                        $Names.Count
                        $Duration
                        $Progress.WarmupSeconds
                    )),
                    ('Warm-up elapsed {0:0.0}/{1}s; measurements and CSV rows begin after warm-up.' -f @(
                        [Math]::Min($warmElapsed, [double]$Progress.WarmupSeconds)
                        $Progress.WarmupSeconds
                    ))
                )
            }
            $elapsed = [Math]::Max(0.001, ($now - $Progress.StartUtc).TotalSeconds)
            $scheduleElapsed = [Math]::Min($elapsed, [double]$Duration)
            $sendQps = if ($scheduleElapsed -lt 1.0) { 0.0 } else {
                $Progress.StartedQueries / $scheduleElapsed
            }
            $drop = $Progress.SchedulerMisses + $Progress.ConcurrencyDrops
            $overall = $Snapshot.Overall
            $rollingQpsText = if ($Snapshot.EffectiveWindowSeconds -lt 1.0) { '-' } else {
                Format-MetricNumber $overall.Qps '0.0'
            }
            $lines = New-Object 'System.Collections.Generic.List[string]'
            $lines.Add(('DNS PERFORMANCE TEST v3.5.3 - {0} - UTC {1:HH:mm:ss}' -f $phase, $now))
            $lines.Add(('{0} endpoints x {1} QPS/server = {2} target aggregate QPS | {3} names | {4}s | {5:n0} planned | MaxOutstanding/server {6}' -f @(
                $EndpointCount
                $PerServerQps
                $TargetAggregateQps
                $Names.Count
                $Duration
                $Planned
                $OutstandingLimit
            )))
            $lines.Add(('Elapsed {0,7:0.0}/{1}s | Send QPS {2,8:0.0}/{3} | Rolling completion QPS {4,8} | Sent {5:n0} | Done {6:n0} | Drop {7:n0}' -f @(
                $scheduleElapsed
                $Duration
                $sendQps
                $TargetAggregateQps
                $rollingQpsText
                $Progress.StartedQueries
                $Progress.CompletedQueries
                $drop
            )))
            $lines.Add(('ROLLING SOCKET-OBSERVED LATENCY - all servers/FQDNs, successful responses only, last {0:0.0}s:' -f @(
                $Snapshot.EffectiveWindowSeconds
            )))
            $lines.Add(('AVG {0}  STD {1}  P50 {2}  P95 {3}  P99 {4}  MAX {5}' -f @(
                (Format-MetricNumber $overall.AverageMs)
                (Format-MetricNumber $overall.StdDevMs)
                (Format-MetricNumber $overall.P50Ms)
                (Format-MetricNumber $overall.P95Ms)
                (Format-MetricNumber $overall.P99Ms)
                (Format-MetricNumber $overall.MaxMs)
            )))
            # Mandatory string-array parameters reject empty elements in Windows
            # PowerShell, so use a visible-width separator for the blank row.
            $lines.Add(' ')

            $identityHeader = ('{0,-18} {1,8} {2,7}' -f 'SERVER','COMP QPS','OK%')
            $columnHeader = $identityHeader + (' | {0,7} {1,7} {2,7}' -f 'TIMEOUT','RCODE','OTHER')
            $groupHeader = ''.PadRight($identityHeader.Length) + ' | ' + (Format-CenteredText 'QUERY FAILURES' 23)
            for ($n = 0; $n -lt $Names.Count; $n++) {
                $groupHeader += ' | ' + (Format-CenteredText $Names[$n] 23)
                $columnHeader += (' | {0,7} {1,7} {2,7}' -f 'AVG','STD','P95')
            }
            $lines.Add($groupHeader)
            $lines.Add($columnHeader)
            $lines.Add(('-' * $columnHeader.Length))

            foreach ($server in $Snapshot.Servers) {
                $serverQpsText = if ($Snapshot.EffectiveWindowSeconds -lt 1.0) { '-' } else {
                    Format-MetricNumber $server.Metrics.Qps '0.0'
                }
                $row = ('{0,-18} {1,8} {2,7}' -f @(
                    (Format-FixedText (Get-ShortServerName $server.Server) 18)
                    $serverQpsText
                    (Format-MetricNumber $server.Metrics.SuccessRatePercent '0.00')
                ))
                $row += (' | {0,7} {1,7} {2,7}' -f @(
                    $server.Metrics.Timeout
                    $server.Metrics.DnsError
                    $server.Metrics.OtherFailure
                ))
                for ($n = 0; $n -lt $Names.Count; $n++) {
                    $cell = $server.FqdnMetrics[$n]
                    $averageText = Format-MetricNumber $cell.AverageMs
                    $stdDevText = Format-MetricNumber $cell.StdDevMs
                    $p95Text = Format-MetricNumber $cell.P95Ms
                    $row += (' | {0,7} {1,7} {2,7}' -f $averageText, $stdDevText, $p95Text)
                }
                $lines.Add($row)
            }
            return $lines.ToArray()
        }

        function Clear-DashboardHost {
            param([bool]$IsIse)
            $iseObject = if ($IsIse) {
                Get-Variable psISE -Scope Global -ValueOnly -ErrorAction SilentlyContinue
            } else { $null }
            if ($null -ne $iseObject) {
                $iseObject.CurrentPowerShellTab.ConsolePane.Clear()
            } else {
                Clear-Host
            }
        }

        function Show-Dashboard {
            param(
                [Parameter(Mandatory)]
                [AllowEmptyString()]
                [string[]]$Lines,
                [ValidateSet('Redraw','Append')]
                [string]$Mode,
                [bool]$IsIse
            )
            if ($Mode -eq 'Redraw') {
                Clear-DashboardHost -IsIse $IsIse
            } else {
                Write-Host ''
            }
            foreach ($line in $Lines) { Write-Host $line }
        }

        function Write-MetricTable {
            param(
                [Parameter(Mandatory)][string]$Title,
                [Parameter(Mandatory)]$Rows,
                [Parameter(Mandatory)][string]$NameProperty,
                [int]$NameWidth = 45
            )
            Write-Host ''
            Write-Host $Title -ForegroundColor Cyan

            $nameHeader = if ($NameProperty -eq 'DNS_Server') { 'DNS SERVER' } else { $NameProperty -replace '_',' ' }
            $longestName = [Math]::Max(18, $nameHeader.Length)
            foreach ($row in $Rows) {
                $candidateText = [string]($row.$NameProperty)
                $candidateLength = $candidateText.Length
                if ($candidateLength -gt $longestName) { $longestName = $candidateLength }
            }
            $resolvedNameWidth = [Math]::Min($NameWidth, $longestName)
            $identityHeader = ("{0,-$resolvedNameWidth} {1,10} {2,7}" -f $nameHeader,'SENT','OK%')
            $failureHeader = ('{0,7} {1,7} {2,7}' -f 'TIMEOUT','RCODE','OTHER')
            $latencyHeader = ('{0,9} {1,9} {2,9} {3,9} {4,9} {5,9}' -f @(
                'AVG MS'
                'STD MS'
                'P50 MS'
                'P95 MS'
                'P99 MS'
                'MAX MS'
            ))
            $columnHeader = $identityHeader + ' | ' + $failureHeader + ' | ' + $latencyHeader
            $groupHeader = @(
                ''.PadRight($identityHeader.Length)
                ' | '
                (Format-CenteredText 'QUERY FAILURES' $failureHeader.Length)
                ' | '
                (Format-CenteredText 'SUCCESSFUL SOCKET-OBSERVED LATENCY (MS)' $latencyHeader.Length)
            ) -join ''
            Write-Host $groupHeader
            Write-Host $columnHeader
            Write-Host ('-' * $columnHeader.Length) -ForegroundColor DarkGray
            foreach ($row in $Rows) {
                $identity = ("{0,-$resolvedNameWidth} {1,10} {2,7}" -f @(
                    (Format-FixedText $row.$NameProperty $resolvedNameWidth)
                    ('{0:n0}' -f $row.Sent)
                    (Format-MetricNumber $row.SuccessRatePercent '0.00')
                ))
                $failures = ('{0,7} {1,7} {2,7}' -f @(
                    ('{0:n0}' -f $row.Timeout)
                    ('{0:n0}' -f $row.DnsError)
                    ('{0:n0}' -f $row.OtherFailure)
                ))
                $latency = ('{0,9} {1,9} {2,9} {3,9} {4,9} {5,9}' -f @(
                    (Format-MetricNumber $row.AverageMs)
                    (Format-MetricNumber $row.StdDevMs)
                    (Format-MetricNumber $row.P50Ms)
                    (Format-MetricNumber $row.P95Ms)
                    (Format-MetricNumber $row.P99Ms)
                    (Format-MetricNumber $row.MaxMs)
                ))
                Write-Host ($identity + ' | ' + $failures + ' | ' + $latency)
            }
        }

        function Write-CellMatrix {
            param(
                [Parameter(Mandatory)][string]$Title,
                [Parameter(Mandatory)]$PerServerFqdn,
                [Parameter(Mandatory)][string[]]$ServerNames,
                [Parameter(Mandatory)][string[]]$Names,
                [ValidateSet('AverageP95','P99Success')][string]$Mode
            )
            Write-Host ''
            Write-Host $Title -ForegroundColor Cyan
            $serverWidth = 18
            foreach ($serverName in $ServerNames) {
                $candidateLength = (Get-ShortServerName $serverName).Length
                if ($candidateLength -gt $serverWidth) { $serverWidth = [Math]::Min(24, $candidateLength) }
            }
            $groupHeader = ("{0,-$serverWidth}" -f 'SERVER')
            $metricHeader = ''.PadRight($serverWidth)
            for ($n = 0; $n -lt $Names.Count; $n++) {
                $groupHeader += ' | ' + (Format-CenteredText $Names[$n] 23)
                if ($Mode -eq 'AverageP95') {
                    $metricHeader += (' | {0,7} {1,7} {2,7}' -f 'AVG MS','STD MS','P95 MS')
                } else {
                    $metricHeader += (' | {0,7} {1,7} {2,7}' -f 'P99 MS','MAX MS','OK%')
                }
            }
            Write-Host $groupHeader
            Write-Host $metricHeader
            Write-Host ('-' * $metricHeader.Length) -ForegroundColor DarkGray
            for ($s = 0; $s -lt $ServerNames.Count; $s++) {
                $row = ("{0,-$serverWidth}" -f @(
                    (Format-FixedText (Get-ShortServerName $ServerNames[$s]) $serverWidth)
                ))
                for ($n = 0; $n -lt $Names.Count; $n++) {
                    $metric = $PerServerFqdn[($s * $Names.Count) + $n]
                    if ($Mode -eq 'AverageP95') {
                        $averageText = Format-MetricNumber $metric.AverageMs
                        $stdDevText = Format-MetricNumber $metric.StdDevMs
                        $p95Text = Format-MetricNumber $metric.P95Ms
                        $row += (' | {0,7} {1,7} {2,7}' -f @(
                            $averageText
                            $stdDevText
                            $p95Text
                        ))
                    } else {
                        $p99Text = Format-MetricNumber $metric.P99Ms
                        $maxText = Format-MetricNumber $metric.MaxMs
                        $successText = if ($metric.Sent -gt 0) {
                            Format-MetricNumber $metric.SuccessRatePercent '0.0'
                        } else { '-' }
                        $row += (' | {0,7} {1,7} {2,7}' -f @(
                            $p99Text
                            $maxText
                            $successText
                        ))
                    }
                }
                Write-Host $row
            }
        }

        function Write-ObserverHealth {
            param([Parameter(Mandatory)]$Summary)

            $observer = $Summary.ObserverHealth
            $overall = $Summary.OverallMetrics
            $threshold = [double]$observer.ProcessingThresholdMs
            $pressure = New-Object 'System.Collections.Generic.List[string]'
            $incidentAffectedRounds = [long]0
            $incidentObserverRounds = [long]0
            foreach ($incident in @($Summary.DegradationIncidents)) {
                $incidentAffectedRounds += [long]$incident.AffectedRoundCount
                $incidentObserverRounds += [long]$incident.ObserverSuspectRounds
            }
            if ($overall.SchedulerMiss -gt 0) {
                $pressure.Add(('{0:n0} scheduler miss(es)' -f $overall.SchedulerMiss))
            }
            if ($overall.MaxSchedulerLagMs -ge $Summary.Configuration.SchedulerToleranceMilliseconds) {
                $pressure.Add(('maximum scheduler lag {0:0.000} ms' -f $overall.MaxSchedulerLagMs))
            }
            if ($overall.ClientProcessingMaxMs -ge $threshold) {
                $pressure.Add(('client processing max {0:0.000} ms' -f $overall.ClientProcessingMaxMs))
            }
            if ($observer.ParserMaxQueueDelayMs -ge $threshold) {
                $pressure.Add(('parser queue max {0:0.000} ms' -f $observer.ParserMaxQueueDelayMs))
            }
            if ($observer.ProcessCpuPercent -ge 85.0) {
                $pressure.Add(('process CPU {0:0.0}%' -f $observer.ProcessCpuPercent))
            }

            Write-Host ''
            Write-Host 'OBSERVER HEALTH' -ForegroundColor Cyan
            Write-Host ('Warm-up: {0:0.##}s   Parser workers: {1}   Parsed packets: {2:n0}   Maximum parser queue depth: {3:n0}' -f @(
                $observer.WarmupSeconds
                $observer.ParserWorkerCount
                $observer.ParserProcessedPackets
                $observer.ParserMaxQueueDepth
            ))
            Write-Host ('Parser queue delay ms - Avg: {0}   Max: {1}   Parse duration ms - Avg: {2}   Max: {3}' -f @(
                (Format-MetricNumber $observer.ParserAverageQueueDelayMs '0.000')
                (Format-MetricNumber $observer.ParserMaxQueueDelayMs '0.000')
                (Format-MetricNumber $observer.ParserAverageParseMs '0.000')
                (Format-MetricNumber $observer.ParserMaxParseMs '0.000')
            ))
            Write-Host ('Process CPU: {0:0.0}%   GC collections 0/1/2: {1:n0}/{2:n0}/{3:n0}   Managed/working-set peak: {4:0.0}/{5:0.0} MB' -f @(
                $observer.ProcessCpuPercent
                $observer.Gen0Collections
                $observer.Gen1Collections
                $observer.Gen2Collections
                $observer.MaxManagedMemoryMb
                $observer.MaxWorkingSetMb
            ))
            Write-Host ('Minimum available ThreadPool worker/I/O threads: {0:n0}/{1:n0}   Observer threshold: {2:0.###} ms' -f @(
                $observer.MinAvailableWorkerThreads
                $observer.MinAvailableIoThreads
                $threshold
            ))
            if ($pressure.Count -eq 0) {
                Write-Host 'Assessment: NO MATERIAL CLIENT/OBSERVER PRESSURE DETECTED.' -ForegroundColor Green
            } elseif ($incidentObserverRounds -gt 0) {
                $overlapPercent = if ($incidentAffectedRounds -gt 0) {
                    100.0 * $incidentObserverRounds / $incidentAffectedRounds
                } else { 0.0 }
                Write-Host 'Assessment: CLIENT/OBSERVER PRESSURE OVERLAPPED DNS DEGRADATION.' -ForegroundColor Yellow
                Write-Host ('Overlap: {0:n0}/{1:n0} ({2:0.0}%) affected paired-query rounds. Evidence: {3}.' -f @(
                    $incidentObserverRounds
                    $incidentAffectedRounds
                    $overlapPercent
                    ($pressure -join '; ')
                ))
            } else {
                Write-Host 'Assessment: TRANSIENT CLIENT/OBSERVER DELAY OBSERVED.' -ForegroundColor Gray
                Write-Host ('Evidence: ' + ($pressure -join '; ') + '.')
                if ($Summary.TotalDegradationIncidents -gt 0) {
                    if ($Summary.OmittedDegradationIncidents -gt 0) {
                        Write-Host 'No displayed DNS degradation round overlapped this observer delay; omitted incidents are not represented here.'
                    } else {
                        Write-Host 'No qualifying DNS degradation round overlapped this observer delay.'
                    }
                } else {
                    Write-Host 'No qualifying DNS degradation was detected during the run.'
                }
            }
        }

        function Write-DegradationTable {
            param([Parameter(Mandatory)]$Summary)

            function Format-RoundFraction {
                param([long]$Numerator, [long]$Denominator)
                $percent = if ($Denominator -gt 0) {
                    100.0 * $Numerator / $Denominator
                } else { 0.0 }
                return ('{0:n0}/{1:n0} ({2:0.0}%)' -f $Numerator, $Denominator, $percent)
            }

            function Format-IncidentDuration {
                param([double]$Milliseconds)
                if ($Milliseconds -ge 1000.0) {
                    return ('{0:0.000}s' -f ($Milliseconds / 1000.0))
                }
                return ('{0:0}ms' -f $Milliseconds)
            }

            function Get-IncidentScopeDisplay {
                param([string]$PrimaryScope)
                switch ($PrimaryScope) {
                    'SINGLE SERVER' { return 'Single server' }
                    'MULTI SERVER'  { return 'Multiple servers' }
                    'WIDESPREAD'    { return 'Widespread' }
                    default         { return $PrimaryScope }
                }
            }

            function Get-IncidentPatternLabel {
                param([Parameter(Mandatory)]$Incident)
                $scopeLabel = switch ([string]$Incident.PrimaryScope) {
                    'SINGLE SERVER' { 'SINGLE-SERVER' }
                    'MULTI SERVER'  { 'MULTI-SERVER' }
                    'WIDESPREAD'    { 'WIDESPREAD' }
                    default         { ([string]$Incident.PrimaryScope).Replace(' ', '-') }
                }
                $hasFailures = ($Incident.Timeouts + $Incident.DnsErrors + $Incident.OtherFailures) -gt 0
                $pattern = if ($hasFailures) { 'DNS DEGRADATION' } else { 'LATENCY BURST' }
                return ($scopeLabel + ' ' + $pattern)
            }

            function Get-IncidentOverlapSummary {
                param([Parameter(Mandatory)]$Incident)
                $peerRounds = [long]$Incident.SharedSlowRounds
                $observerRounds = [long]$Incident.ObserverSuspectRounds
                $affectedRounds = [long]$Incident.AffectedRoundCount
                if ($peerRounds -eq 0 -and $observerRounds -eq 0) {
                    return 'No peer latency or client/observer pressure overlapped the affected rounds.'
                }
                if ($peerRounds -gt 0 -and $observerRounds -eq 0) {
                    return ('Peer latency overlapped {0}; no client/observer pressure overlapped.' -f @(
                        (Format-RoundFraction $peerRounds $affectedRounds)
                    ))
                }
                if ($peerRounds -eq 0) {
                    return ('Client/observer pressure overlapped {0}; no peer latency overlapped.' -f @(
                        (Format-RoundFraction $observerRounds $affectedRounds)
                    ))
                }
                return ('Peer latency overlapped {0}; client/observer pressure overlapped {1}.' -f @(
                    (Format-RoundFraction $peerRounds $affectedRounds)
                    (Format-RoundFraction $observerRounds $affectedRounds)
                ))
            }

            $criteria = $Summary.Configuration.DegradationAnalysis
            Write-Host ''
            Write-Host 'DNS LATENCY DEGRADATION' -ForegroundColor Cyan
            if ($Summary.TotalDegradationIncidents -eq 0) {
                Write-Host 'Assessment: NO OBJECTIVE BREACH.' -ForegroundColor Green
                Write-Host 'Isolated maxima remain available in the ordinary summary and CSV.'
            } else {
                $incidentNoun = if ($Summary.TotalDegradationIncidents -eq 1) { 'incident' } else { 'incidents' }
                $spikeNoun = if ($Summary.TotalDegradationEvents -eq 1) { 'spike' } else { 'spikes' }
                Write-Host ('DEGRADATION DETECTED: {0:n0} {1} across {2:n0} qualifying server/FQDN {3}.' -f @(
                    $Summary.TotalDegradationIncidents
                    $incidentNoun
                    $Summary.TotalDegradationEvents
                    $spikeNoun
                )) -ForegroundColor Yellow

                $displayedIncidents = @($Summary.DegradationIncidents)
                if ($Summary.TotalDegradationIncidents -eq 1 -and $displayedIncidents.Count -eq 1) {
                    $primaryIncident = $displayedIncidents[0]
                    $primaryLabel = Get-IncidentPatternLabel $primaryIncident
                    $primaryServers = @($primaryIncident.DNS_Servers | ForEach-Object { Get-ShortServerName $_ }) -join ', '
                    $primaryDuration = Format-IncidentDuration $primaryIncident.DurationMs
                    $primaryFqdnText = if ($primaryIncident.AffectedNameCount -eq $primaryIncident.TotalNames) {
                        'all {0:n0} tested FQDNs' -f $primaryIncident.TotalNames
                    } else {
                        '{0:n0} of {1:n0} tested FQDNs' -f @(
                            $primaryIncident.AffectedNameCount
                            $primaryIncident.TotalNames
                        )
                    }
                    Write-Host ('Assessment: ' + $primaryLabel) -ForegroundColor Yellow
                    Write-Host ('A {0} {1} was measured on {2}, affecting {3}.' -f @(
                        $primaryDuration
                        $(if (($primaryIncident.Timeouts + $primaryIncident.DnsErrors + $primaryIncident.OtherFailures) -gt 0) { 'DNS degradation' } else { 'latency burst' })
                        $primaryServers
                        $primaryFqdnText
                    ))
                    Write-Host (Get-IncidentOverlapSummary $primaryIncident)
                } else {
                    Write-Host 'Assessment: MULTIPLE DNS DEGRADATION INCIDENTS' -ForegroundColor Yellow
                    Write-Host 'Incident cards below show independently qualifying scope and measured overlap evidence.'
                }

                foreach ($incident in $displayedIncidents) {
                    $serverCount = '{0}/{1}' -f $incident.AffectedEndpointCount, $incident.TotalEndpoints
                    $fqdnCount = '{0}/{1}' -f $incident.AffectedNameCount, $incident.TotalNames
                    $impactPercent = if ($incident.EvaluatedQueries -gt 0) {
                        100.0 * $incident.AffectedQueries / $incident.EvaluatedQueries
                    } else { 0.0 }
                    $serverList = @($incident.DNS_Servers | ForEach-Object { Get-ShortServerName $_ }) -join ', '
                    $fqdnList = @($incident.FQDNs) -join ', '
                    $patternLabel = Get-IncidentPatternLabel $incident
                    $scopeDisplay = Get-IncidentScopeDisplay $incident.PrimaryScope
                    $durationText = Format-IncidentDuration $incident.DurationMs
                    $observerPeerText = if ($incident.SharedSlowRounds -gt 0) {
                        Format-RoundFraction $incident.ObserverSharedRounds $incident.SharedSlowRounds
                    } else {
                        'n/a (no peer-overlapped rounds)'
                    }

                    Write-Host ''
                    Write-Host ('INCIDENT {0} - {1}' -f $incident.IncidentNumber, $patternLabel) -ForegroundColor Cyan
                    Write-Host ('Time:       {0:HH:mm:ss.fff} - {1:HH:mm:ss.fff} UTC   Active: {2}' -f @(
                        $incident.StartUtc
                        $incident.EndUtc
                        $durationText
                    ))
                    Write-Host ('Scope:      {0} ({1})   FQDNs: {2}   Pair spikes: {3:n0}' -f @(
                        $scopeDisplay
                        $serverCount
                        $fqdnCount
                        $incident.PairEventCount
                    ))
                    Write-Host ('Objective:  {0}' -f $incident.Objectives)
                    Write-Host ('Impact:     {0:n0} of {1:n0} queries ({2:0.00}%)   Maximum latency: {3:0.000} ms' -f @(
                        $incident.AffectedQueries
                        $incident.EvaluatedQueries
                        $impactPercent
                        $incident.MaxResponseMs
                    ))
                    Write-Host ('Latency:    10-49 ms: {0:n0}   50+ ms: {1:n0}   Maximum scheduler lag: {2:0.000} ms' -f @(
                        $incident.Slow10To49Ms
                        $incident.Slow50MsOrMore
                        $incident.MaxSchedulerLagMs
                    ))
                    Write-Host ('Failures:   Timeout: {0:n0}   DNS RCODE: {1:n0}   Other: {2:n0}' -f @(
                        $incident.Timeouts
                        $incident.DnsErrors
                        $incident.OtherFailures
                    ))
                    Write-Host ('Evidence:   Endpoint-only: {0}   Peer-overlapped: {1}' -f @(
                        (Format-RoundFraction $incident.EndpointOnlyRounds $incident.AffectedRoundCount)
                        (Format-RoundFraction $incident.SharedSlowRounds $incident.AffectedRoundCount)
                    ))
                    Write-Host ('            Majority-overlapped: {0}   Observer-overlapped: {1}' -f @(
                        (Format-RoundFraction $incident.MajoritySlowRounds $incident.AffectedRoundCount)
                        (Format-RoundFraction $incident.ObserverSuspectRounds $incident.AffectedRoundCount)
                    ))
                    Write-Host ('            Peak simultaneous endpoints: {0}/{1}   Observer + peer overlap: {2}' -f @(
                        $incident.PeakAffectedEndpoints
                        $incident.TotalEndpoints
                        $observerPeerText
                    ))
                    Write-Host ('Servers:    ' + $serverList)
                    Write-Host ('FQDNs:      ' + $fqdnList)
                }

                if ($Summary.OmittedDegradationIncidents -gt 0) {
                    $omittedNoun = if ($Summary.OmittedDegradationIncidents -eq 1) { 'incident was' } else { 'incidents were' }
                    Write-Host ''
                    Write-Host ('{0:n0} additional {1} omitted; the most severe {2:n0} are shown.' -f @(
                        $Summary.OmittedDegradationIncidents
                        $omittedNoun
                        $Summary.DegradationIncidents.Count
                    )) -ForegroundColor Yellow
                }
            }

            $observation = $Summary.LargestSuccessfulObservation
            if ($null -ne $observation) {
                Write-Host ''
                Write-Host 'RUN-WIDE MAXIMUM OBSERVATION' -ForegroundColor Cyan
                Write-Host ('Response:    {0:0.000} ms   Server: {1}   FQDN: {2}' -f @(
                    $observation.ResponseTimeMs
                    (Get-ShortServerName $observation.DNS_Server)
                    $observation.FQDN
                ))
                Write-Host ('Time:        Sent {0:yyyy-MM-dd HH:mm:ss.fffffff} UTC   Received {1:yyyy-MM-dd HH:mm:ss.fffffff} UTC' -f @(
                    $observation.StartedUtc
                    $observation.ReceivedUtc
                ))
                Write-Host ('Client:      Processing {0:0.000} ms   End-to-end {1:0.000} ms   Timing source: {2}' -f @(
                    $observation.ClientProcessingDelayMs
                    $observation.EndToEndTimeMs
                    $observation.TimingSource
                ))
                Write-Host ('Parser:      Queue {0:0.000} ms   Parse {1:0.000} ms   Continuation {2:0.000} ms' -f @(
                    $observation.ParserQueueDelayMs
                    $observation.ParseDurationMs
                    $observation.ContinuationDelayMs
                ))
            }

            Write-Host ''
            Write-Host 'INTERPRETATION NOTES' -ForegroundColor Cyan
            if ($Summary.CoordinatedCapture.Enabled) {
                Write-Host 'Packet timing: client packet-observed latency runs from the client request packet to the client response packet and excludes client parsing and processing.' -ForegroundColor Gray
                Write-Host 'Packet timing: combined network time is client packet-observed latency minus server packet turnaround, so it contains outbound and return network time together.' -ForegroundColor Gray
                Write-Host 'Packet timing: each duration is calculated on one host, so synchronized client/server clocks are not required.' -ForegroundColor Gray
                Write-Host 'Directional deltas: positive is slower than the nearby baseline and negative is faster; these are changes, not absolute one-way latency.' -ForegroundColor Gray
                Write-Host 'Directional deltas: outbound and return percentiles are calculated independently and should not be added together.' -ForegroundColor Gray
                Write-Host 'Directional deltas: client/server clock values may differ, but their offset must remain stable within the nearby baseline window.' -ForegroundColor Gray
                Write-Host 'Average excess share: normalizes only positive outbound and return average deltas to 100%; negative values remain visible but do not count as added delay. It is not absolute one-way latency or a trend over the run.' -ForegroundColor Gray
                if ($Summary.CoordinatedCapture.ClientOnlyEndpointCount -gt 0) {
                    Write-Host 'Client-only fallback: normal socket-observed timing remains in the ordinary tables and CSV; server turnaround, combined network time, and directional deltas are unavailable.' -ForegroundColor Gray
                }
            }
            if ($Summary.ConditionalForwarding.Enabled) {
                Write-Host 'Conditional forwarding: no observed forward can mean a cached/local answer; it is not labeled as a forwarding failure.' -ForegroundColor Gray
            }
            Write-Host ('Latency objectives: per server x FQDN, success >=99.9%; successful socket-observed latency <{0:0.##} ms >=99%; <{1:0.##} ms >=99.9%.' -f @(
                $criteria.NormalLatencyThresholdMs
                $criteria.SevereLatencyThresholdMs
            )) -ForegroundColor Gray
            Write-Host ('Degradation detection: complete {0}s sliding windows plus a full-run check, evaluated every 1s with at least {1} violations/objective.' -f @(
                $criteria.WindowSeconds
                $criteria.MinimumViolations
            )) -ForegroundColor Gray
            Write-Host ('Observer correlation: client processing or parser queue >= {0:0.###} ms; scheduler misses or late rounds also count as evidence.' -f @(
                $criteria.ObserverProcessingThresholdMs
            )) -ForegroundColor Gray
            Write-Host 'Impact accounting: counts query failures plus successful responses of at least 10 ms; evaluated is the query count in qualifying buckets.' -ForegroundColor Gray
            Write-Host 'Incident timing: the 10-49 ms and 50+ ms buckets are mutually exclusive; active time ends when a complete one-second bucket is clean.' -ForegroundColor Gray
            Write-Host 'Scope and overlap: describe measured timing only; neither claims a DNS, server, security, load-balancer, or network root cause.' -ForegroundColor Gray
        }

        function Write-OutputSummary {
            param([Parameter(Mandatory)]$Summary)

            if (-not $Summary.CsvOutputPath) { return }

            Write-Host ''
            Write-Host 'OUTPUT' -ForegroundColor Cyan
            Write-Host ('Detailed CSV: ' + $Summary.CsvOutputPath)

            if ($Summary.CoordinatedCapture.Enabled -and
                $null -ne $Summary.CoordinatedCapture.CsvEnrichment) {
                $enrichment = $Summary.CoordinatedCapture.CsvEnrichment
                if ($enrichment.Status -eq 'Complete') {
                    if ($enrichment.ClientOnlyRows -gt 0) {
                        Write-Host ('Packet timing enrichment: Complete   Coordinated: {0:n0}   Client-only: {1:n0}   Unmatched: {2:n0}   Total: {3:n0}' -f @(
                            $enrichment.MatchedRows
                            $enrichment.ClientOnlyRows
                            $enrichment.UnmatchedRows
                            $enrichment.TotalRows
                        ))
                    } else {
                        Write-Host ('Packet timing enrichment: Complete   Matched rows: {0:n0}/{1:n0}' -f @(
                            $enrichment.MatchedRows
                            $enrichment.TotalRows
                        ))
                    }
                } elseif ($enrichment.Status -eq 'Failed') {
                    $failureText = 'Packet timing enrichment: Failed'
                    if (-not [string]::IsNullOrWhiteSpace([string]$enrichment.ErrorMessage)) {
                        $failureText += '   ' + $enrichment.ErrorMessage
                    }
                    Write-Host $failureText -ForegroundColor Yellow
                } else {
                    Write-Host ('Packet timing enrichment: ' + $enrichment.Status)
                }
            }
        }

        function Write-FinalSummary {
            param([Parameter(Mandatory)]$Summary, [bool]$Redraw, [bool]$IsIse)
            if ($Redraw) { Clear-DashboardHost -IsIse $IsIse }
            $overall = $Summary.OverallMetrics
            $timing = $Summary.Timing
            Write-Host 'DNS PERFORMANCE TEST SUMMARY' -ForegroundColor Cyan
            Write-Host ('Endpoints: {0}   Names: {1}   Query type: {2}   Duration: {3}s' -f @(
                $Summary.Configuration.DNS_Server_Endpoints.Count
                $Summary.Configuration.FQDNs.Count
                $Summary.Configuration.QueryType
                $Summary.Configuration.DurationSeconds
            ))
            Write-Host ('Start UTC: {0:yyyy-MM-dd HH:mm:ss.fff}   End UTC: {1:yyyy-MM-dd HH:mm:ss.fff}   Elapsed: {2:0.000}s' -f @(
                $timing.StartUtc
                $timing.EndUtc
                $timing.TotalElapsedSeconds
            ))
            Write-Host ('Target: {0} QPS/server x {1} endpoints = {2} aggregate QPS   Offered aggregate QPS: {3:0.000}' -f @(
                $Summary.Configuration.QueriesPerSecondPerServer
                $Summary.Configuration.DNS_Server_Endpoints.Count
                $Summary.Configuration.TargetAggregateQps
                $timing.OfferedAggregateQps
            ))
            Write-Host ('Completion throughput: {0:0.000} QPS' -f $timing.CompletionThroughputQps)
            Write-Host ('Planned: {0:n0}   Sent: {1:n0}   Not sent: {2:n0}   Scheduler misses: {3:n0}   Concurrency drops: {4:n0}' -f @(
                $overall.Planned
                $overall.Sent
                $overall.NotSent
                $overall.SchedulerMiss
                $overall.ConcurrencyDrop
            ))
            Write-Host ('Responses: {0:n0} ({1:0.000}%)   Successful: {2:n0} ({3:0.000}%)   Timeouts: {4:n0}   DNS RCODE errors: {5:n0}   Other failures: {6:n0}' -f @(
                $overall.ResponseReceived
                $overall.ResponseRatePercent
                $overall.Success
                $overall.SuccessRatePercent
                $overall.Timeout
                $overall.DnsError
                $overall.OtherFailure
            ))
            Write-Host ('Successful socket-observed response latency ms - Min: {0}   Avg: {1}   StdDev: {2}   P50: {3}   P95: {4}   P99: {5}   Max: {6}' -f @(
                (Format-MetricNumber $overall.MinMs '0.000')
                (Format-MetricNumber $overall.AverageMs '0.000')
                (Format-MetricNumber $overall.StdDevMs '0.000')
                (Format-MetricNumber $overall.P50Ms '0.000')
                (Format-MetricNumber $overall.P95Ms '0.000')
                (Format-MetricNumber $overall.P99Ms '0.000')
                (Format-MetricNumber $overall.MaxMs '0.000')
            ))
            Write-Host ('Client processing delay ms - Avg: {0}   P95: {1}   P99: {2}   Max: {3}' -f @(
                (Format-MetricNumber $overall.ClientProcessingAverageMs '0.000')
                (Format-MetricNumber $overall.ClientProcessingP95Ms '0.000')
                (Format-MetricNumber $overall.ClientProcessingP99Ms '0.000')
                (Format-MetricNumber $overall.ClientProcessingMaxMs '0.000')
            ))
            Write-Host ('TCP fallbacks: {0:n0}   Maximum scheduler lag: {1} ms' -f @(
                $overall.TcpFallback
                (Format-MetricNumber $overall.MaxSchedulerLagMs '0.000')
            ))
            if ($Summary.StatusCounts.Count -gt 0) {
                Write-Host ('Status counts: ' + (($Summary.StatusCounts | ForEach-Object { '{0}={1:n0}' -f $_.Status, $_.Count }) -join '; '))
            }
            if ($Summary.RCodeCounts.Count -gt 0) {
                Write-Host ('RCODE counts:  ' + (($Summary.RCodeCounts | ForEach-Object { '{0}={1:n0}' -f $_.RCode, $_.Count }) -join '; '))
            }

            Write-ObserverHealth -Summary $Summary

            Write-MetricTable -Title 'PER-SERVER SUMMARY' -Rows $Summary.PerServerMetrics -NameProperty 'DNS_Server' -NameWidth 40
            if ($Summary.CoordinatedCapture.Enabled) {
                Write-Host ''
                Write-Host 'COORDINATED PACKET TIMING (UDP/53)' -ForegroundColor Cyan
                Write-Host ('Status: {0}   Coordinated: {1:n0}   Client-only: {2:n0}   Matched pairs: {3:n0}   TCP fallbacks excluded: {4:n0}' -f @(
                    $Summary.CoordinatedCapture.Status
                    $Summary.CoordinatedCapture.CoordinatedEndpointCount
                    $Summary.CoordinatedCapture.ClientOnlyEndpointCount
                    $Summary.CoordinatedCapture.MatchedPairs
                    $Summary.CoordinatedCapture.TcpFallbackPairsExcluded
                ))
                $captureIdentityHeader = ('{0,-18} {1,10} {2,8}' -f @(
                    'DNS SERVER'
                    'MATCHED'
                    'COVER%'
                ))
                $captureMetricHeader = ('{0,9} {1,9} {2,10}' -f @(
                    'AVG MS'
                    'STD MS'
                    'P95 MS'
                ))
                $captureStatusHeader = Format-CenteredText 'STATUS' 12
                $captureGroupHeader = @(
                    ''.PadRight($captureIdentityHeader.Length)
                    ' | '
                    (Format-CenteredText 'CLIENT PACKET-OBSERVED LATENCY' $captureMetricHeader.Length)
                    ' | '
                    (Format-CenteredText 'SERVER PACKET TURNAROUND' $captureMetricHeader.Length)
                    ' | '
                    (Format-CenteredText 'COMBINED NETWORK TIME' $captureMetricHeader.Length)
                    ' | '
                    (Format-CenteredText 'EVIDENCE' $captureStatusHeader.Length)
                ) -join ''
                $captureColumnHeader = @(
                    $captureIdentityHeader
                    ' | '
                    $captureMetricHeader
                    ' | '
                    $captureMetricHeader
                    ' | '
                    $captureMetricHeader
                    ' | '
                    $captureStatusHeader
                ) -join ''
                Write-Host $captureGroupHeader -ForegroundColor White
                Write-Host $captureColumnHeader -ForegroundColor White
                Write-Host ('-' * $captureColumnHeader.Length) -ForegroundColor DarkGray
                foreach ($endpoint in $Summary.CoordinatedCapture.Endpoints) {
                    $isClientOnly = $endpoint.Status -eq 'ClientOnly'
                    $matchedDisplay = if ($isClientOnly) {
                        '-'
                    } else { '{0:n0}' -f $endpoint.MatchedPairs }
                    $coverageDisplay = if ($isClientOnly) {
                        '-'
                    } else { '{0:0.000}' -f $endpoint.CoveragePercent }
                    $captureIdentity = ('{0,-18} {1,10} {2,8}' -f @(
                        (Format-FixedText (Get-ShortServerName $endpoint.DNS_Server) 18)
                        $matchedDisplay
                        $coverageDisplay
                    ))
                    if ($isClientOnly) {
                        $clientRoundTrip = Format-CenteredText '-' $captureMetricHeader.Length
                        $serverTurnaround = Format-CenteredText '-' $captureMetricHeader.Length
                        $combinedNetwork = Format-CenteredText '-' $captureMetricHeader.Length
                    } else {
                        $clientRoundTrip = ('{0,9} {1,9} {2,10}' -f @(
                            (Format-MetricNumber $endpoint.ClientWire.AverageMs '0.000')
                            (Format-MetricNumber $endpoint.ClientWire.StandardDeviationMs '0.000')
                            (Format-MetricNumber $endpoint.ClientWire.P95Ms '0.000')
                        ))
                        $serverTurnaround = ('{0,9} {1,9} {2,10}' -f @(
                            (Format-MetricNumber $endpoint.ServerTurnaround.AverageMs '0.000')
                            (Format-MetricNumber $endpoint.ServerTurnaround.StandardDeviationMs '0.000')
                            (Format-MetricNumber $endpoint.ServerTurnaround.P95Ms '0.000')
                        ))
                        $combinedNetwork = ('{0,9} {1,9} {2,10}' -f @(
                            (Format-MetricNumber $endpoint.NetworkRemainder.AverageMs '0.000')
                            (Format-MetricNumber $endpoint.NetworkRemainder.StandardDeviationMs '0.000')
                            (Format-MetricNumber $endpoint.NetworkRemainder.P95Ms '0.000')
                        ))
                    }
                    Write-Host (@(
                        $captureIdentity
                        ' | '
                        $clientRoundTrip
                        ' | '
                        $serverTurnaround
                        ' | '
                        $combinedNetwork
                        ' | '
                        (Format-CenteredText $endpoint.Status $captureStatusHeader.Length)
                    ) -join '')
                }
                foreach ($fallback in @($Summary.CoordinatedCapture.Fallbacks)) {
                    Write-Host ('Capture fallback: ' + $fallback) -ForegroundColor Yellow
                }
                if ($Summary.CoordinatedCapture.Issues.Count -gt 0) {
                    foreach ($issue in $Summary.CoordinatedCapture.Issues) {
                        Write-Host ('Capture issue: ' + $issue) -ForegroundColor Yellow
                    }
                }

                Write-Host ''
                Write-Host 'DIRECTIONAL DELAY CHANGE VS NEARBY BASELINE (MS)' -ForegroundColor Cyan
                $directionalIdentityHeader = ('{0,-18}' -f 'DNS SERVER')
                $directionalMetricHeader = ('{0,9} {1,9} {2,9} {3,9}' -f @(
                    'AVG MS'
                    'STD MS'
                    'P95 MS'
                    'MAX MS'
                ))
                $directionalInterpretationHeader =
                    Format-CenteredText 'AVG EXCESS SHARE' 18
                $directionalGroupHeader = @(
                    ''.PadRight($directionalIdentityHeader.Length)
                    ' | '
                    (Format-CenteredText 'OUTBOUND DELAY DELTA' $directionalMetricHeader.Length)
                    ' | '
                    (Format-CenteredText 'RETURN DELAY DELTA' $directionalMetricHeader.Length)
                    ' | '
                    (Format-CenteredText 'INTERPRETATION' $directionalInterpretationHeader.Length)
                ) -join ''
                $directionalColumnHeader = @(
                    $directionalIdentityHeader
                    ' | '
                    $directionalMetricHeader
                    ' | '
                    $directionalMetricHeader
                    ' | '
                    $directionalInterpretationHeader
                ) -join ''
                Write-Host $directionalGroupHeader -ForegroundColor White
                Write-Host $directionalColumnHeader -ForegroundColor White
                Write-Host ('-' * $directionalColumnHeader.Length) -ForegroundColor DarkGray
                foreach ($endpoint in $Summary.CoordinatedCapture.Endpoints) {
                    $outboundDelta = if ($null -ne $endpoint.OutboundDelayDelta -and
                        $endpoint.OutboundDelayDelta.Count -gt 0) {
                        '{0,9} {1,9} {2,9} {3,9}' -f @(
                            (Format-SignedMetricNumber $endpoint.OutboundDelayDelta.AverageMs)
                            (Format-MetricNumber $endpoint.OutboundDelayDelta.StandardDeviationMs '0.000')
                            (Format-SignedMetricNumber $endpoint.OutboundDelayDelta.P95Ms)
                            (Format-SignedMetricNumber $endpoint.OutboundDelayDelta.MaximumMs)
                        )
                    } else {
                        Format-CenteredText '-' $directionalMetricHeader.Length
                    }
                    $returnDelta = if ($null -ne $endpoint.ReturnDelayDelta -and
                        $endpoint.ReturnDelayDelta.Count -gt 0) {
                        '{0,9} {1,9} {2,9} {3,9}' -f @(
                            (Format-SignedMetricNumber $endpoint.ReturnDelayDelta.AverageMs)
                            (Format-MetricNumber $endpoint.ReturnDelayDelta.StandardDeviationMs '0.000')
                            (Format-SignedMetricNumber $endpoint.ReturnDelayDelta.P95Ms)
                            (Format-SignedMetricNumber $endpoint.ReturnDelayDelta.MaximumMs)
                        )
                    } else {
                        Format-CenteredText '-' $directionalMetricHeader.Length
                    }
                    $averageExcessShare = Format-AverageExcessShare `
                        -OutboundMetric $endpoint.OutboundDelayDelta `
                        -ReturnMetric $endpoint.ReturnDelayDelta `
                        -Width $directionalInterpretationHeader.Length
                    Write-Host (@(
                        ('{0,-18}' -f (Format-FixedText (Get-ShortServerName $endpoint.DNS_Server) 18))
                        ' | '
                        $outboundDelta
                        ' | '
                        $returnDelta
                        ' | '
                        $averageExcessShare
                    ) -join '')
                }
            }
            if ($Summary.ConditionalForwarding.Enabled) {
                Write-Host ''
                Write-Host 'CONDITIONAL FORWARDING TRACE' -ForegroundColor Cyan
                Write-Host ('Status: {0}   Cache changes: none' -f
                    $Summary.ConditionalForwarding.Status)
                $forwardingIdentityHeader = ('{0,-18} {1,9}' -f @(
                    'DNS SERVER'
                    'FLIGHTS'
                ))
                $forwardingOutcomeHeader = ('{0,9} {1,8} {2,9} {3,10}' -f @(
                    'FALLBACK'
                    'FAILED'
                    'NO FWD'
                    'COALESCED'
                ))
                $forwardingLatencyHeader = ('{0,9} {1,9}' -f 'AVG MS','P95 MS')
                $forwardingStatusHeader = Format-CenteredText 'STATUS' 12
                $forwardingGroupHeader = @(
                    ''.PadRight($forwardingIdentityHeader.Length)
                    ' | '
                    (Format-CenteredText 'FORWARDING OUTCOMES' $forwardingOutcomeHeader.Length)
                    ' | '
                    (Format-CenteredText 'FORWARD DURATION' $forwardingLatencyHeader.Length)
                    ' | '
                    (Format-CenteredText 'EVIDENCE' $forwardingStatusHeader.Length)
                ) -join ''
                $forwardingColumnHeader = @(
                    $forwardingIdentityHeader
                    ' | '
                    $forwardingOutcomeHeader
                    ' | '
                    $forwardingLatencyHeader
                    ' | '
                    $forwardingStatusHeader
                ) -join ''
                Write-Host $forwardingGroupHeader -ForegroundColor White
                Write-Host $forwardingColumnHeader -ForegroundColor White
                Write-Host ('-' * $forwardingColumnHeader.Length) -ForegroundColor DarkGray
                foreach ($endpoint in $Summary.ConditionalForwarding.Endpoints) {
                    $analysis = $endpoint.Analysis
                    if ($endpoint.Status -eq 'ClientOnly') {
                        $forwardingIdentity = ('{0,-18} {1,9}' -f @(
                            (Format-FixedText (Get-ShortServerName $endpoint.DNS_Server) 18)
                            '-'
                        ))
                        $forwardingOutcomes =
                            Format-CenteredText '-' $forwardingOutcomeHeader.Length
                        $forwardingLatency =
                            Format-CenteredText '-' $forwardingLatencyHeader.Length
                    } else {
                        $forwardingIdentity = ('{0,-18} {1,9:n0}' -f @(
                            (Format-FixedText (Get-ShortServerName $endpoint.DNS_Server) 18)
                            $(if ($null -ne $analysis) { $analysis.TotalFlights } else { 0 })
                        ))
                        $forwardingOutcomes = ('{0,9:n0} {1,8:n0} {2,9:n0} {3,10:n0}' -f @(
                            $(if ($null -ne $analysis) { $analysis.FlightsUsingDifferentMaster } else { 0 })
                            $(if ($null -ne $analysis) { $analysis.FailedFlights } else { 0 })
                            $(if ($null -ne $analysis) { $analysis.ClientTransactionsWithoutObservedForwarding } else { 0 })
                            $(if ($null -ne $analysis) { $analysis.CoalescedClientQueries } else { 0 })
                        ))
                        $forwardingLatency = if ($null -ne $analysis -and
                            $analysis.ForwardingDuration.Count -gt 0) {
                            '{0,9} {1,9}' -f @(
                                (Format-MetricNumber $analysis.ForwardingDuration.AverageMs '0.000')
                                (Format-MetricNumber $analysis.ForwardingDuration.P95Ms '0.000')
                            )
                        } else {
                            Format-CenteredText '-' $forwardingLatencyHeader.Length
                        }
                    }
                    Write-Host (@(
                        $forwardingIdentity
                        ' | '
                        $forwardingOutcomes
                        ' | '
                        $forwardingLatency
                        ' | '
                        (Format-CenteredText $endpoint.Status $forwardingStatusHeader.Length)
                    ) -join '')
                }
                $notableFlights = @($Summary.ConditionalForwarding.Endpoints |
                    Where-Object { $null -ne $_.Analysis } |
                    ForEach-Object {
                        $serverName = $_.DNS_Server
                        @($_.Analysis.Flights) | Where-Object {
                            $_.DifferentMasterFallbackUsed -or
                            $_.Status -in @('FailedResponse','NoResponse')
                        } | ForEach-Object {
                            [pscustomobject]@{ Server = $serverName; Flight = $_ }
                        }
                    } | Select-Object -First 10)
                if ($notableFlights.Count -gt 0) {
                    Write-Host 'Notable retained flights:' -ForegroundColor DarkGray
                    foreach ($item in $notableFlights) {
                        $path = @($item.Flight.Attempts | ForEach-Object {
                            '{0}({1})' -f $_.TargetAddress, $_.Outcome
                        }) -join ' -> '
                        Write-Host ('  {0}  {1}  {2}  {3} ms  {4}' -f @(
                            (Get-ShortServerName $item.Server)
                            $item.Flight.QueryName
                            $item.Flight.Status
                            (Format-MetricNumber $item.Flight.ForwardingDurationMs '0.000')
                            $path
                        ))
                    }
                }
                foreach ($fallback in @($Summary.ConditionalForwarding.Fallbacks)) {
                    Write-Host ('Forwarding trace fallback: ' + $fallback) -ForegroundColor Yellow
                }
                foreach ($issue in $Summary.ConditionalForwarding.Issues) {
                    Write-Host ('Forwarding trace issue: ' + $issue) -ForegroundColor Yellow
                }
            }
            Write-MetricTable -Title 'PER-FQDN SUMMARY' -Rows $Summary.PerFQDNMetrics -NameProperty 'FQDN' -NameWidth 45
            $latencyMatrixParameters = @{
                Title         = 'SERVER x FQDN LATENCY'
                PerServerFqdn = $Summary.PerServerFQDNMetrics
                ServerNames   = $Summary.Configuration.DNS_Server_Endpoints.Label
                Names         = $Summary.Configuration.FQDNs
                Mode          = 'AverageP95'
            }
            Write-CellMatrix @latencyMatrixParameters

            $tailMatrixParameters = @{
                Title         = 'SERVER x FQDN TAIL/SUCCESS'
                PerServerFqdn = $Summary.PerServerFQDNMetrics
                ServerNames   = $Summary.Configuration.DNS_Server_Endpoints.Label
                Names         = $Summary.Configuration.FQDNs
                Mode          = 'P99Success'
            }
            Write-CellMatrix @tailMatrixParameters
            Write-DegradationTable -Summary $Summary
            Write-OutputSummary -Summary $Summary
        }
    }

    process {
        $normalizedNames = New-Object 'System.Collections.Generic.List[string]'
        $nameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $FQDNs) {
            try { $normalized = [DnsPerformanceV420.DnsWire]::NormalizeName($name) }
            catch { throw "Invalid FQDN '$name': $($_.Exception.Message)" }
            if ($nameSet.Add($normalized)) { $normalizedNames.Add($normalized) }
        }

        $targets = New-Object 'System.Collections.Generic.List[DnsPerformanceV420.DnsTarget]'
        $captureEndpointDefinitions = New-Object 'System.Collections.Generic.List[object]'
        $targetSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($server in $DNSServers) {
            $addresses = @()
            $parsedAddress = $null
            if ([IPAddress]::TryParse($server, [ref]$parsedAddress)) { $addresses = @($parsedAddress) }
            else {
                try { $addresses = @([System.Net.Dns]::GetHostAddresses($server)) }
                catch { throw "Unable to resolve DNS server '$server' before the test: $($_.Exception.Message)" }
            }
            if ($addresses.Count -eq 0) { throw "DNS server '$server' resolved to no addresses." }
            foreach ($address in $addresses) {
                $addressText = $address.ToString()
                if (-not $targetSet.Add($addressText)) { continue }
                $label = if ($addresses.Count -gt 1) { "$server [$addressText]" } else { $server }
                $targets.Add((New-Object DnsPerformanceV420.DnsTarget -ArgumentList $label, $addressText))
                $captureComputer = $server
                if ($null -ne $CaptureComputerMap) {
                    foreach ($mappingKey in @($addressText, $label, $server)) {
                        if ($CaptureComputerMap.ContainsKey($mappingKey)) {
                            $captureComputer = [string]$CaptureComputerMap[$mappingKey]
                            break
                        }
                    }
                }
                if ([string]::IsNullOrWhiteSpace($captureComputer)) {
                    throw "CaptureComputerMap resolved '$label' to an empty remoting computer name."
                }
                $captureEndpointDefinitions.Add([pscustomobject]@{
                    Label           = $label
                    Address         = $addressText
                    OriginalServer  = $server
                    CaptureComputer = $captureComputer
                })
            }
        }
        if ($targets.Count -eq 0) { throw 'No unique DNS server endpoints remain after resolution.' }
        if ($targets.Count -gt 64) { throw 'A maximum of 64 resolved DNS endpoints is supported.' }
        if ($CoordinatedCapture -and $targets.Count -gt 16) {
            throw 'CoordinatedCapture supports a maximum of 16 resolved DNS endpoints per run.'
        }

        $aggregateQps64 = [long]$QueriesPerSecond * $targets.Count
        if ($aggregateQps64 -gt [int]::MaxValue) { throw 'The target aggregate QPS exceeds the supported integer range.' }
        $aggregateQps = [int]$aggregateQps64
        $plannedQueries = [long]$aggregateQps * $DurationSeconds
        if ($plannedQueries -gt $MaximumPlannedQueries) {
            throw "The test would plan $plannedQueries queries, exceeding MaximumPlannedQueries ($MaximumPlannedQueries)."
        }
        $warmupPlannedQueries = [long]$aggregateQps64 * [long]$WarmupSeconds
        if ($warmupPlannedQueries -gt $MaximumPlannedQueries) {
            throw "The warm-up would plan $warmupPlannedQueries queries, exceeding MaximumPlannedQueries ($MaximumPlannedQueries)."
        }
        if ($IncludeDetailedResults -and $plannedQueries -gt $MaximumDetailedResults) {
            throw "IncludeDetailedResults would retain $plannedQueries rows. Use CsvOutputPath or increase MaximumDetailedResults explicitly."
        }

        if ($MaxOutstandingPerServer -eq 0) {
            $calculated = [Math]::Ceiling($QueriesPerSecond * ($TimeoutMilliseconds / 1000.0) * 1.5) + 32
            $MaxOutstandingPerServer = [int][Math]::Max(32, [Math]::Min(32768, $calculated))
        }

        $resolvedCsvPath = $null
        if ($CsvOutputPath) {
            if ([IO.Path]::GetExtension($CsvOutputPath) -ne '.csv') { throw 'CsvOutputPath must use the .csv extension.' }
            $resolvedCsvPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($CsvOutputPath)
            $csvParent = [IO.Path]::GetDirectoryName($resolvedCsvPath)
            if (-not $csvParent -or -not [IO.Directory]::Exists($csvParent)) {
                throw "The CSV parent directory does not exist: $csvParent"
            }
        }

        $options = New-Object DnsPerformanceV420.RunnerOptions
        $options.QueriesPerSecondPerServer = $QueriesPerSecond
        $options.DurationSeconds = $DurationSeconds
        $options.TimeoutMilliseconds = $TimeoutMilliseconds
        $options.MaxOutstandingPerServer = $MaxOutstandingPerServer
        $options.SchedulerToleranceMilliseconds = $SchedulerToleranceMilliseconds
        $options.RecursionDesired = -not $NoRecursion
        $options.UseEdns = -not $NoEdns
        $options.UdpPayloadSize = [uint16]$UdpPayloadSize
        $options.TcpFallback = -not $DisableTcpFallback
        $options.RequireAnswer = -not $AllowNoAnswer
        $options.CsvOutputPath = $resolvedCsvPath
        $options.KeepDetailedResults = [bool]$IncludeDetailedResults
        $options.DegradationWindowSeconds = $DegradationWindowSeconds
        $options.MinimumDegradationSamples = $MinimumDegradationSamples
        $options.MaximumDegradationEvents = $MaximumDegradationEvents
        $options.NormalLatencyThresholdMs = 10.0
        $options.SevereLatencyThresholdMs = 50.0
        $options.WarmupSeconds = $WarmupSeconds
        $options.ProcessingWorkerCount = $ProcessingWorkerCount
        $options.ObserverProcessingThresholdMs = $ObserverProcessingThresholdMilliseconds
        $options.WaitForMeasurementRelease = [bool]$CoordinatedCapture

        $queryTypeCode = [DnsPerformanceV420.DnsWire]::GetQueryTypeCode($QueryType)
        $runner = [DnsPerformanceV420.DnsLoadRunner]::Create(
            $targets.ToArray(), $normalizedNames.ToArray(), $queryTypeCode, $options)
        $cancellation = New-Object System.Threading.CancellationTokenSource
        $runnerTask = $null
        $completion = $null
        $finalSnapshot = $null
        $captureStates = New-Object 'System.Collections.Generic.List[object]'
        $clientOnlyCaptureDefinitions =
            New-Object 'System.Collections.Generic.List[object]'
        $captureArmed = $false
        $csvPacketTimingEnrichment = [pscustomobject]@{
            Status        = if ($resolvedCsvPath -and $CoordinatedCapture) { 'Pending' } else { 'NotRequested' }
            TotalRows     = 0L
            MatchedRows   = 0L
            ClientOnlyRows = 0L
            UnmatchedRows = 0L
            NotSentRows   = 0L
            TcpFallbackRows = 0L
            DirectionalDeltaMethod = $null
            ErrorMessage  = $null
        }
        $coordinatedCaptureSummary = [pscustomobject]@{
            Enabled                     = [bool]$CoordinatedCapture
            Status                      = if ($CoordinatedCapture) { 'Preparing' } else { 'NotRequested' }
            Scope                       = 'UDP port 53 request/response pairs'
            TimestampSource             = if ($CoordinatedCapture) { 'Npcap default host timestamp (microsecond representation)' } else { $null }
            TcpFallbackPairsExcluded    = 0L
            MatchedPairs                = 0L
            CoordinatedEndpointCount    = 0
            ClientOnlyEndpointCount     = 0
            CsvEnrichment               = $csvPacketTimingEnrichment
            Endpoints                   = @()
            Fallbacks                   = @()
            Issues                      = @()
        }
        $conditionalForwardingSummary = [pscustomobject]@{
            Enabled                     = [bool]$TraceConditionalForwarding
            Status                      = if ($TraceConditionalForwarding) { 'Preparing' } else { 'NotRequested' }
            Scope                       = 'Tested DNS questions sent between each DNS server and its matching conditional-forwarder masters'
            CacheMutation               = 'None'
            Endpoints                   = @()
            Fallbacks                   = @()
            Issues                      = @()
        }
        $isIse = ($Host.Name -eq 'Windows PowerShell ISE Host') -or ($null -ne (Get-Variable psISE -Scope Global -ErrorAction SilentlyContinue))
        $outputRedirected = $false
        $inputRedirected = $false
        $executionError = $null
        try {
            if (-not $isIse) {
                $outputRedirected = [Console]::IsOutputRedirected
                $inputRedirected = [Console]::IsInputRedirected
            }
        } catch { }
        $credentialPromptAvailable = [Environment]::UserInteractive -and
            ($isIse -or -not $inputRedirected)
        $effectiveCaptureCredential = $CaptureCredential
        $captureCredentialPrompted = $false
        $dashboardRenderingMode = if ($isIse -or ($Host.Name -eq 'ConsoleHost' -and -not $outputRedirected)) {
            'Redraw'
        } else {
            'Append'
        }

        try {
            if ($CoordinatedCapture) {
                if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
                    throw 'CoordinatedCapture requires Windows on the test client.'
                }
                $estimatedPacketsPerEndpoint = 2L * [long]$QueriesPerSecond * [long]$DurationSeconds
                if ($estimatedPacketsPerEndpoint -gt $CaptureMaximumPacketsPerEndpoint) {
                    Write-Warning ("A fully answered run can produce approximately {0:n0} UDP packets per endpoint, above CaptureMaximumPacketsPerEndpoint ({1:n0}). Coordinated evidence may be incomplete." -f @(
                        $estimatedPacketsPerEndpoint
                        $CaptureMaximumPacketsPerEndpoint
                    ))
                }
                if ($TraceConditionalForwarding) {
                    $estimatedForwardingPacketsPerEndpoint =
                        6L * [long]$QueriesPerSecond * [long]$DurationSeconds
                    if ($estimatedForwardingPacketsPerEndpoint -gt
                        $CaptureMaximumForwardingPacketsPerEndpoint) {
                        Write-Warning ("If every client query is a cache miss and uses one fully observed fallback, the conditional-forwarding trace can observe approximately {0:n0} client/upstream DNS packets per endpoint, above CaptureMaximumForwardingPacketsPerEndpoint ({1:n0}). Trace evidence may be incomplete." -f @(
                            $estimatedForwardingPacketsPerEndpoint
                            $CaptureMaximumForwardingPacketsPerEndpoint
                        ))
                    }
                }
                Write-Host ('Preparing coordinated Npcap capture for {0} DNS endpoint(s)...' -f $targets.Count) -ForegroundColor Cyan
                foreach ($definition in $captureEndpointDefinitions) {
                    $endpointSetupTimer = [Diagnostics.Stopwatch]::StartNew()
                    $captureDurationSeconds = $DurationSeconds +
                        [int][Math]::Ceiling($TimeoutMilliseconds / 1000.0) + $CaptureGraceSeconds
                    $clientAddress = Get-DnsCaptureSourceAddress `
                        -PeerAddress $definition.Address
                    $localCaptureProbe = $null
                    try {
                        $localCaptureProbe =
                            [DnsCoordinatedCaptureV424.CaptureRunner]::Open(
                                $clientAddress, $definition.Address, 64, 1, 1)
                        if ($null -eq $localCaptureProbe.ReadyInfo) {
                            throw 'Local Npcap access verification returned no readiness record.'
                        }
                    } catch {
                        throw "Client Npcap preflight failed for $($definition.Label) [$($definition.Address)]: $($_.Exception.Message)"
                    } finally {
                        if ($null -ne $localCaptureProbe) {
                            $localCaptureProbe.Dispose()
                        }
                    }
                    $preflightScript = {
                        param($TypeDefinition, $ForwardingTypeDefinition, $TraceForwarding,
                            $ServerAddress, $ClientAddress)
                        $npcapDirectory = if ([Environment]::Is64BitProcess) {
                            Join-Path $env:SystemRoot 'System32\Npcap'
                        } else {
                            Join-Path $env:SystemRoot 'SysWOW64\Npcap'
                        }
                        if (-not [IO.Directory]::Exists($npcapDirectory)) {
                            throw "Npcap runtime directory was not found: $npcapDirectory"
                        }
                        if (($env:Path -split ';') -notcontains $npcapDirectory) {
                            $env:Path = $npcapDirectory + ';' + $env:Path
                        }
                        if (-not ('DnsCoordinatedCaptureV424.CaptureRunner' -as [type])) {
                            Add-Type -Language CSharp -ErrorAction Stop -TypeDefinition $TypeDefinition
                        }
                        $captureProbe = $null
                        try {
                            $captureProbe =
                                [DnsCoordinatedCaptureV424.CaptureRunner]::Open(
                                    $ServerAddress, $ClientAddress, 64, 1, 1)
                            $captureProbeReady = $captureProbe.ReadyInfo
                            if ($null -eq $captureProbeReady) {
                                throw 'Remote Npcap access verification returned no readiness record.'
                            }
                        } finally {
                            if ($null -ne $captureProbe) { $captureProbe.Dispose() }
                        }
                        $conditionalForwarders = @()
                        if ($TraceForwarding) {
                            if (-not ('DnsForwardingCaptureV410.ForwardingCaptureRunner' -as [type])) {
                                Add-Type -Language CSharp -ErrorAction Stop `
                                    -TypeDefinition $ForwardingTypeDefinition
                            }
                            $conditionalForwarders = @(Get-DnsServerZone -ErrorAction Stop |
                                Where-Object { [string]$_.ZoneType -eq 'Forwarder' } |
                                ForEach-Object {
                                    $zoneName = if ($null -ne $_.PSObject.Properties['ZoneName']) {
                                        [string]$_.ZoneName
                                    } else { [string]$_.Name }
                                    [pscustomobject]@{
                                        ZoneName         = $zoneName.Trim().TrimEnd('.').ToLowerInvariant()
                                        MasterServers    = @($_.MasterServers | ForEach-Object { $_.ToString() })
                                        ForwarderTimeout = if ($null -ne $_.PSObject.Properties['ForwarderTimeout']) {
                                            $_.ForwarderTimeout
                                        } else { $null }
                                    }
                                })
                        }
                        [pscustomobject]@{
                            ComputerName          = $env:COMPUTERNAME
                            NpcapPath              = $npcapDirectory
                            HelperLoaded           = $true
                            CaptureAccessVerified  = $true
                            CaptureAdapterName     = $captureProbeReady.AdapterName
                            ConditionalForwarders  = @($conditionalForwarders)
                        }
                    }

                    $remoteSession = $null
                    $preflight = $null
                    $setupFailureMessage = $null
                    while ($null -eq $preflight) {
                        if ($endpointSetupTimer.Elapsed.TotalSeconds -ge
                            $CaptureStartupTimeoutSeconds) {
                            $setupFailureMessage =
                                "Remote capture setup exceeded CaptureStartupTimeoutSeconds ($CaptureStartupTimeoutSeconds)."
                            break
                        }
                        $remainingMilliseconds = [int][Math]::Max(1000, [Math]::Floor(
                            ($CaptureStartupTimeoutSeconds -
                                $endpointSetupTimer.Elapsed.TotalSeconds) * 1000.0))
                        $sessionOptionParameters = @{
                            OpenTimeout      = $remainingMilliseconds
                            OperationTimeout = [int][Math]::Min([int]::MaxValue,
                                ([long]$captureDurationSeconds + 60L) * 1000L)
                        }
                        $sessionOptions = New-PSSessionOption @sessionOptionParameters
                        $sessionParameters = @{
                            ComputerName  = $definition.CaptureComputer
                            SessionOption = $sessionOptions
                            ErrorAction   = 'Stop'
                        }
                        if ($null -ne $effectiveCaptureCredential) {
                            $sessionParameters.Credential = $effectiveCaptureCredential
                        }
                        if ($CaptureUseSSL) { $sessionParameters.UseSSL = $true }
                        try {
                            $remoteSession = New-PSSession @sessionParameters
                            $preflightOutput = @(Invoke-Command -Session $remoteSession `
                                -ScriptBlock $preflightScript -ArgumentList @(
                                    $coordinatedCaptureTypeDefinition
                                    $forwardingCaptureTypeDefinition
                                    [bool]$TraceConditionalForwarding
                                    $definition.Address
                                    $clientAddress
                                ) -ErrorAction Stop)
                            $preflight = $preflightOutput | Select-Object -Last 1
                            if ($null -eq $preflight -or
                                -not $preflight.CaptureAccessVerified) {
                                throw 'Remote Npcap access verification returned no readiness record.'
                            }
                        } catch {
                            $setupFailure = $_
                            $setupFailureMessage = $setupFailure.Exception.Message
                            $preflight = $null
                            if ($null -ne $remoteSession) {
                                Remove-PSSession -Session $remoteSession `
                                    -ErrorAction SilentlyContinue
                                $remoteSession = $null
                            }
                            $isCredentialFailure = Test-DnsCaptureCredentialFailure `
                                -Message $setupFailureMessage
                            if ($isCredentialFailure -and
                                -not $captureCredentialPrompted -and
                                $credentialPromptAvailable) {
                                $captureCredentialPrompted = $true
                                Write-Warning ("Coordinated-capture setup using the current remoting credentials failed on '{0}' for {1}: {2}" -f @(
                                    $definition.CaptureComputer
                                    $definition.Label
                                    $setupFailure.Exception.Message
                                ))
                                Write-Host 'Enter alternate credentials to retry, or cancel if the failure is not credential-related.' -ForegroundColor Yellow
                                $alternateCredential = $null
                                $endpointSetupTimer.Stop()
                                try {
                                    $alternateCredential = Get-Credential -Message `
                                        ("Credentials for coordinated capture on {0}" -f `
                                            $definition.CaptureComputer)
                                } catch { }
                                finally { $endpointSetupTimer.Start() }
                                if ($null -ne $alternateCredential) {
                                    $effectiveCaptureCredential = $alternateCredential
                                    $setupFailureMessage = $null
                                    continue
                                }
                            }
                            break
                        }
                    }

                    if ($null -eq $preflight) {
                        if ($null -ne $remoteSession) {
                            Remove-PSSession -Session $remoteSession `
                                -ErrorAction SilentlyContinue
                            $remoteSession = $null
                        }
                        $fallbackReason = Get-DnsCaptureFallbackReason `
                            -Message $setupFailureMessage
                        $clientOnlyCaptureDefinitions.Add([pscustomobject]@{
                            Label           = $definition.Label
                            Address         = $definition.Address
                            CaptureComputer = $definition.CaptureComputer
                            Reason          = $fallbackReason
                        })
                        Write-Warning ("Server-side capture is unavailable on '{0}' for {1}; continuing with normal client-side timing only. {2}" -f @(
                            $definition.CaptureComputer
                            $definition.Label
                            $fallbackReason
                        ))
                        continue
                    }

                    $state = [pscustomobject]@{
                        Id             = [Guid]::NewGuid().ToString('N')
                        Label          = $definition.Label
                        Address        = $definition.Address
                        RemoteComputer = $definition.CaptureComputer
                        ClientAddress  = $clientAddress
                        Session        = $remoteSession
                        OpenJob        = $null
                        RunJob         = $null
                        LocalSession   = $null
                        LocalTask      = $null
                        ClientReady    = $null
                        ServerReady    = $null
                        ForwardingReady = $null
                        ClientResult   = $null
                        ServerResult   = $null
                        RemoteCaptureBytes = $null
                        ConditionalForwarders = @()
                        ForwardingZoneNames = @()
                        ForwardingMasterAddresses = @()
                    }
                    $captureStates.Add($state)
                    if ($TraceConditionalForwarding) {
                        $matchingZones = New-Object 'System.Collections.Generic.List[object]'
                        $masterAddresses = New-Object 'System.Collections.Generic.List[string]'
                        $seenMasters = New-Object 'System.Collections.Generic.HashSet[string]' `
                            ([StringComparer]::OrdinalIgnoreCase)
                        $seenZones = New-Object 'System.Collections.Generic.HashSet[string]' `
                            ([StringComparer]::OrdinalIgnoreCase)
                        foreach ($testName in $normalizedNames) {
                            $bestZone = $null
                            foreach ($zone in @($preflight.ConditionalForwarders)) {
                                $zoneName = [string]$zone.ZoneName
                                if ($testName -eq $zoneName -or
                                    $testName.EndsWith('.' + $zoneName,
                                        [StringComparison]::OrdinalIgnoreCase)) {
                                    if ($null -eq $bestZone -or
                                        $zoneName.Length -gt
                                            ([string]$bestZone.ZoneName).Length) {
                                        $bestZone = $zone
                                    }
                                }
                            }
                            if ($null -eq $bestZone -or
                                -not $seenZones.Add([string]$bestZone.ZoneName)) {
                                continue
                            }
                            $matchingZones.Add([pscustomobject]@{
                                ZoneName         = [string]$bestZone.ZoneName
                                MasterServers    = @($bestZone.MasterServers)
                                ForwarderTimeout = $bestZone.ForwarderTimeout
                            })
                            foreach ($master in @($bestZone.MasterServers)) {
                                $masterText = [string]$master
                                if ($seenMasters.Add($masterText)) {
                                    $masterAddresses.Add($masterText)
                                }
                            }
                        }
                        $state.ConditionalForwarders =
                            [object[]]($matchingZones.ToArray())
                        $state.ForwardingZoneNames = [string[]]@(
                            $matchingZones.ToArray() |
                                ForEach-Object { $_.ZoneName }
                        )
                        $state.ForwardingMasterAddresses =
                            [string[]]($masterAddresses.ToArray())
                    }
                }
            }

            $runnerTask = $runner.RunAsync($cancellation.Token)
            $live = $runner.GetLiveSnapshot($RollingWindowSeconds)
            $dashboardParameters = @{
                Snapshot           = $live
                Progress           = $runner.Progress
                Names              = $normalizedNames.ToArray()
                TargetAggregateQps = $aggregateQps
                PerServerQps       = $QueriesPerSecond
                Duration           = $DurationSeconds
                EndpointCount      = $targets.Count
                Planned            = $plannedQueries
                OutstandingLimit   = $MaxOutstandingPerServer
            }
            $lines = Get-DashboardLines @dashboardParameters
            Show-Dashboard -Lines $lines -Mode $dashboardRenderingMode -IsIse $isIse -ErrorAction Stop
            $displayTimer = [Diagnostics.Stopwatch]::StartNew()
            while (-not $runnerTask.IsCompleted) {
                if ($CoordinatedCapture -and -not $captureArmed -and
                    $runner.Progress.Phase -eq 'ARMING') {
                    $armingTimer = [Diagnostics.Stopwatch]::StartNew()
                    foreach ($state in $captureStates) {
                        try {
                            $state.LocalSession = [DnsCoordinatedCaptureV424.CaptureRunner]::Open(
                                $state.ClientAddress, $state.Address, 128, 8,
                                $CaptureMaximumPacketsPerEndpoint)
                            $state.ClientReady = $state.LocalSession.ReadyInfo
                        } catch {
                            throw "Client Npcap capture could not open for $($state.Label) [$($state.Address)]: $($_.Exception.Message)"
                        }
                    }

                    $remoteOpenScript = {
                        param($CaptureId, $ServerAddress, $ClientAddress, $MaximumPackets,
                            $ForwardingSettings)
                        if ($null -eq $global:DnsCoordinatedCaptureSessions) {
                            $global:DnsCoordinatedCaptureSessions = @{}
                        }
                        $pairCapture = [DnsCoordinatedCaptureV424.CaptureRunner]::Open(
                            $ServerAddress, $ClientAddress, 128, 8, $MaximumPackets)
                        $forwardingCapture = $null
                        try {
                            if ($ForwardingSettings.Enabled -and
                                @($ForwardingSettings.MasterAddresses).Count -gt 0) {
                                $serverInterface = @(Get-NetIPAddress -IPAddress $ServerAddress `
                                    -ErrorAction Stop | Select-Object -First 1).InterfaceIndex
                                $forwardingLocalAddresses =
                                    New-Object 'System.Collections.Generic.List[string]'
                                $seenForwardingLocalAddresses =
                                    New-Object 'System.Collections.Generic.HashSet[string]' `
                                        ([StringComparer]::OrdinalIgnoreCase)
                                foreach ($masterAddress in @($ForwardingSettings.MasterAddresses)) {
                                    $peer = [IPAddress]::Parse([string]$masterAddress)
                                    $routeSocket = New-Object System.Net.Sockets.Socket @(
                                        $peer.AddressFamily,
                                        [System.Net.Sockets.SocketType]::Dgram,
                                        [System.Net.Sockets.ProtocolType]::Udp
                                    )
                                    try {
                                        $routeSocket.Connect((New-Object System.Net.IPEndPoint `
                                            -ArgumentList $peer, 53))
                                        $sourceAddress = ([IPEndPoint]$routeSocket.LocalEndPoint).Address.ToString()
                                        $sourceInterface = @(Get-NetIPAddress -IPAddress $sourceAddress `
                                            -ErrorAction Stop | Select-Object -First 1).InterfaceIndex
                                        if ($sourceInterface -ne $serverInterface) {
                                            throw "Conditional-forwarder master $masterAddress routes through interface $sourceInterface ($sourceAddress), but the DNS endpoint $ServerAddress is on interface $serverInterface. Multi-adapter forwarding capture is not supported in this revision."
                                        }
                                        if ($seenForwardingLocalAddresses.Add($sourceAddress)) {
                                            $forwardingLocalAddresses.Add($sourceAddress)
                                        }
                                    } finally {
                                        $routeSocket.Dispose()
                                    }
                                }
                                $forwardingCapture =
                                    [DnsForwardingCaptureV410.ForwardingCaptureRunner]::Open(
                                        $ServerAddress, $ClientAddress,
                                        [string[]]($forwardingLocalAddresses.ToArray()),
                                        [string[]]($ForwardingSettings.MasterAddresses),
                                        [string[]]($ForwardingSettings.TestNames),
                                        384, 8, $ForwardingSettings.MaximumPackets)
                            }
                            $entry = [pscustomobject]@{
                                PairCapture       = $pairCapture
                                ForwardingCapture = $forwardingCapture
                            }
                            $global:DnsCoordinatedCaptureSessions[$CaptureId] = $entry
                            return [pscustomobject]@{
                                PairReady       = $pairCapture.ReadyInfo
                                ForwardingReady = if ($null -ne $forwardingCapture) {
                                    $forwardingCapture.ReadyInfo
                                } else { $null }
                            }
                        } catch {
                            if ($null -ne $forwardingCapture) {
                                try { $forwardingCapture.Dispose() } catch { }
                            }
                            try { $pairCapture.Dispose() } catch { }
                            throw
                        }
                    }
                    foreach ($state in $captureStates) {
                        $forwardingOpenSettings = [pscustomobject]@{
                            Enabled         = [bool]$TraceConditionalForwarding
                            MasterAddresses = [string[]]$state.ForwardingMasterAddresses
                            TestNames       = [string[]]($normalizedNames.ToArray())
                            MaximumPackets  = $CaptureMaximumForwardingPacketsPerEndpoint
                        }
                        $state.OpenJob = Invoke-Command -Session $state.Session -AsJob `
                            -ScriptBlock $remoteOpenScript -ArgumentList @(
                                $state.Id, $state.Address, $state.ClientAddress,
                                $CaptureMaximumPacketsPerEndpoint,
                                $forwardingOpenSettings) -ErrorAction Stop
                    }
                    while (@($captureStates | Where-Object { $_.OpenJob.State -notin @('Completed','Failed','Stopped') }).Count -gt 0) {
                        if ($armingTimer.Elapsed.TotalSeconds -ge $CaptureStartupTimeoutSeconds) {
                            throw "Npcap handles did not arm on every endpoint within CaptureStartupTimeoutSeconds ($CaptureStartupTimeoutSeconds)."
                        }
                        Start-Sleep -Milliseconds 50
                    }
                    foreach ($state in $captureStates) {
                        if ($state.OpenJob.State -ne 'Completed') {
                            $reason = if ($null -ne $state.OpenJob.JobStateInfo.Reason) {
                                $state.OpenJob.JobStateInfo.Reason.Message
                            } else { 'The remote capture-open job did not complete.' }
                            throw "Server Npcap capture could not open on '$($state.RemoteComputer)' for $($state.Label): $reason"
                        }
                        $readyOutput = @(Receive-Job -Job $state.OpenJob -ErrorAction Stop)
                        $readyRecord = $readyOutput | Select-Object -Last 1
                        $state.ServerReady = $readyRecord.PairReady
                        $state.ForwardingReady = $readyRecord.ForwardingReady
                        Remove-Job -Job $state.OpenJob -Force -ErrorAction SilentlyContinue
                        $state.OpenJob = $null
                        if ($null -eq $state.ServerReady) {
                            throw "Server Npcap capture on '$($state.RemoteComputer)' returned no readiness record for $($state.Label)."
                        }
                    }

                    $remoteRunScript = {
                        param($CaptureId, $CaptureDurationSeconds)
                        $entry = $global:DnsCoordinatedCaptureSessions[$CaptureId]
                        if ($null -eq $entry) { throw "Capture session '$CaptureId' was not found." }
                        $capture = $entry.PairCapture
                        $forwardingCapture = $entry.ForwardingCapture
                        $captureTask = $null
                        $forwardingTask = $null
                        try {
                            $captureTask = $capture.RunAsync($CaptureDurationSeconds)
                            if ($null -ne $forwardingCapture) {
                                $forwardingTask = $forwardingCapture.RunAsync($CaptureDurationSeconds)
                            }
                            while (-not $captureTask.IsCompleted -or
                                ($null -ne $forwardingTask -and -not $forwardingTask.IsCompleted)) {
                                Start-Sleep -Milliseconds 100
                            }
                            $result = $captureTask.GetAwaiter().GetResult()
                            $forwardingResult = if ($null -ne $forwardingTask) {
                                $forwardingTask.GetAwaiter().GetResult()
                            } else { $null }
                            return [pscustomobject]@{
                                ComputerName          = $result.ComputerName
                                LocalAddress          = $result.LocalAddress
                                PeerAddress           = $result.PeerAddress
                                AdapterName           = $result.AdapterName
                                DeviceName            = $result.DeviceName
                                Filter                = $result.Filter
                                NpcapVersion          = $result.NpcapVersion
                                TimestampSource       = $result.TimestampSource
                                CaptureStartUtc       = $result.CaptureStartUtc
                                CaptureEndUtc         = $result.CaptureEndUtc
                                ParsedPackets         = $result.ParsedPackets
                                QueryPackets          = $result.QueryPackets
                                ResponsePackets       = $result.ResponsePackets
                                CompletedPairs        = $result.CompletedPairs
                                UnmatchedQueries      = $result.UnmatchedQueries
                                UnmatchedResponses    = $result.UnmatchedResponses
                                PcapReceived          = $result.PcapReceived
                                PcapDropped           = $result.PcapDropped
                                InterfaceDropped      = $result.InterfaceDropped
                                StatisticsAvailable   = $result.StatisticsAvailable
                                PacketLimitReached    = $result.PacketLimitReached
                                CompressedPairsBase64 = [Convert]::ToBase64String($result.CompressedPairs)
                                ForwardingEnabled     = $null -ne $forwardingResult
                                ForwardingComputerName = if ($null -ne $forwardingResult) { $forwardingResult.ComputerName } else { $null }
                                ForwardingLocalAddress = if ($null -ne $forwardingResult) { $forwardingResult.LocalAddress } else { $null }
                                ForwardingClientAddress = if ($null -ne $forwardingResult) { $forwardingResult.ClientAddress } else { $null }
                                ForwardingLocalAddresses = if ($null -ne $forwardingResult) { @($forwardingResult.ForwardingLocalAddresses) } else { @() }
                                ForwardingMasterAddresses = if ($null -ne $forwardingResult) { @($forwardingResult.MasterAddresses) } else { @() }
                                ForwardingAdapterName = if ($null -ne $forwardingResult) { $forwardingResult.AdapterName } else { $null }
                                ForwardingDeviceName = if ($null -ne $forwardingResult) { $forwardingResult.DeviceName } else { $null }
                                ForwardingFilter = if ($null -ne $forwardingResult) { $forwardingResult.Filter } else { $null }
                                ForwardingNpcapVersion = if ($null -ne $forwardingResult) { $forwardingResult.NpcapVersion } else { $null }
                                ForwardingTimestampSource = if ($null -ne $forwardingResult) { $forwardingResult.TimestampSource } else { $null }
                                ForwardingCaptureStartUtc = if ($null -ne $forwardingResult) { $forwardingResult.CaptureStartUtc } else { $null }
                                ForwardingCaptureEndUtc = if ($null -ne $forwardingResult) { $forwardingResult.CaptureEndUtc } else { $null }
                                ForwardingCapturedPackets = if ($null -ne $forwardingResult) { $forwardingResult.CapturedPackets } else { 0L }
                                ForwardingParsedDnsPackets = if ($null -ne $forwardingResult) { $forwardingResult.ParsedDnsPackets } else { 0L }
                                ForwardingRelevantEvents = if ($null -ne $forwardingResult) { $forwardingResult.RelevantEvents } else { 0L }
                                ForwardingUnparsedDnsPackets = if ($null -ne $forwardingResult) { $forwardingResult.UnparsedDnsPackets } else { 0L }
                                ForwardingPcapReceived = if ($null -ne $forwardingResult) { $forwardingResult.PcapReceived } else { 0L }
                                ForwardingPcapDropped = if ($null -ne $forwardingResult) { $forwardingResult.PcapDropped } else { 0L }
                                ForwardingInterfaceDropped = if ($null -ne $forwardingResult) { $forwardingResult.InterfaceDropped } else { 0L }
                                ForwardingStatisticsAvailable = if ($null -ne $forwardingResult) { $forwardingResult.StatisticsAvailable } else { $false }
                                ForwardingPacketLimitReached = if ($null -ne $forwardingResult) { $forwardingResult.PacketLimitReached } else { $false }
                                ForwardingCompressedEventsBase64 = if ($null -ne $forwardingResult) {
                                    [Convert]::ToBase64String($forwardingResult.CompressedEvents)
                                } else { $null }
                            }
                        } finally {
                            $capture.RequestStop()
                            if ($null -ne $forwardingCapture) { $forwardingCapture.RequestStop() }
                            if ($null -ne $captureTask -and -not $captureTask.IsCompleted) {
                                try { $null = $captureTask.Wait(2000) } catch { }
                            }
                            if ($null -ne $forwardingTask -and -not $forwardingTask.IsCompleted) {
                                try { $null = $forwardingTask.Wait(2000) } catch { }
                            }
                            $capture.Dispose()
                            if ($null -ne $forwardingCapture) { $forwardingCapture.Dispose() }
                            $global:DnsCoordinatedCaptureSessions.Remove($CaptureId)
                        }
                    }
                    foreach ($state in $captureStates) {
                        $state.RunJob = Invoke-Command -Session $state.Session -AsJob `
                            -ScriptBlock $remoteRunScript -ArgumentList @(
                                $state.Id, $captureDurationSeconds) -ErrorAction Stop
                        $state.LocalTask = $state.LocalSession.RunAsync($captureDurationSeconds)
                    }
                    $runner.ReleaseMeasurementGate()
                    $captureArmed = $true
                    $coordinatedCaptureSummary.Status = 'Capturing'
                }
                if ($displayTimer.Elapsed.TotalSeconds -ge $DisplayIntervalSeconds) {
                    $live = $runner.GetLiveSnapshot($RollingWindowSeconds)
                    $dashboardParameters.Snapshot = $live
                    $dashboardParameters.Progress = $runner.Progress
                    $lines = Get-DashboardLines @dashboardParameters
                    Show-Dashboard -Lines $lines -Mode $dashboardRenderingMode -IsIse $isIse -ErrorAction Stop
                    $displayTimer.Restart()
                }
                Start-Sleep -Milliseconds 50
            }
            $completion = $runnerTask.GetAwaiter().GetResult()
            $finalSnapshot = $runner.GetFinalSnapshot()
            if ($CoordinatedCapture) {
                if (-not $captureArmed) {
                    throw 'The DNS runner completed without entering the coordinated-capture measurement phase.'
                }
                $captureWaitTimer = [Diagnostics.Stopwatch]::StartNew()
                $captureWaitLimitSeconds = [int][Math]::Ceiling($TimeoutMilliseconds / 1000.0) +
                    $CaptureGraceSeconds + 30
                while (@($captureStates | Where-Object {
                    (-not $_.LocalTask.IsCompleted) -or
                    ($_.RunJob.State -notin @('Completed','Failed','Stopped'))
                }).Count -gt 0) {
                    if ($captureWaitTimer.Elapsed.TotalSeconds -ge $captureWaitLimitSeconds) {
                        throw "Coordinated capture did not finish within $captureWaitLimitSeconds seconds after the DNS runner completed."
                    }
                    Start-Sleep -Milliseconds 100
                }

                $endpointCaptureSummaries = New-Object 'System.Collections.Generic.List[object]'
                $captureIssues = New-Object 'System.Collections.Generic.List[string]'
                $captureFallbacks = New-Object 'System.Collections.Generic.List[string]'
                $forwardingEndpointSummaries = New-Object 'System.Collections.Generic.List[object]'
                $forwardingIssues = New-Object 'System.Collections.Generic.List[string]'
                $forwardingFallbacks = New-Object 'System.Collections.Generic.List[string]'
                $totalMatchedPairs = 0L
                foreach ($state in $captureStates) {
                    $state.ClientResult = $state.LocalTask.GetAwaiter().GetResult()
                    if ($state.RunJob.State -ne 'Completed') {
                        $reason = if ($null -ne $state.RunJob.JobStateInfo.Reason) {
                            $state.RunJob.JobStateInfo.Reason.Message
                        } else { 'The remote capture job did not complete.' }
                        throw "Server capture failed on '$($state.RemoteComputer)' for $($state.Label): $reason"
                    }
                    $serverOutput = @(Receive-Job -Job $state.RunJob -ErrorAction Stop)
                    $state.ServerResult = $serverOutput | Where-Object {
                        $null -ne $_.PSObject.Properties['CompressedPairsBase64']
                    } | Select-Object -Last 1
                    if ($null -eq $state.ServerResult) {
                        throw "Server capture on '$($state.RemoteComputer)' returned no result for $($state.Label)."
                    }
                    $remoteCaptureBytes = [Convert]::FromBase64String(
                        [string]$state.ServerResult.CompressedPairsBase64)
                    $state.RemoteCaptureBytes = [byte[]]$remoteCaptureBytes
                    $analysis = [DnsCoordinatedCaptureV424.CaptureAnalyzer]::Analyze(
                        $state.Label, $state.Address,
                        [byte[]]$state.ClientResult.CompressedPairs,
                        $remoteCaptureBytes,
                        $CaptureSlowTransactionThresholdMilliseconds,
                        $CaptureMaximumSlowTransactions)
                    $totalMatchedPairs += [long]$analysis.MatchedPairs

                    $endpointIssues = New-Object 'System.Collections.Generic.List[string]'
                    if ($state.ClientResult.PacketLimitReached -or $state.ServerResult.PacketLimitReached) {
                        $endpointIssues.Add('Capture packet safety limit reached.')
                    }
                    if (-not $state.ClientResult.StatisticsAvailable -or
                        -not $state.ServerResult.StatisticsAvailable) {
                        $endpointIssues.Add('Npcap drop statistics were unavailable at one or both capture points.')
                    }
                    if ([long]$state.ClientResult.PcapDropped -gt 0 -or
                        [long]$state.ClientResult.InterfaceDropped -gt 0) {
                        $endpointIssues.Add('Client Npcap reported dropped packets.')
                    }
                    if ([long]$state.ServerResult.PcapDropped -gt 0 -or
                        [long]$state.ServerResult.InterfaceDropped -gt 0) {
                        $endpointIssues.Add('Server Npcap reported dropped packets.')
                    }
                    if ([long]$analysis.UnmatchedLocalPairs -gt 0 -or
                        [long]$analysis.UnmatchedServerPairs -gt 0) {
                        $endpointIssues.Add('Some completed UDP pairs could not be matched across capture points.')
                    }
                    foreach ($issue in $endpointIssues) {
                        $captureIssues.Add("$($state.Label): $issue")
                    }
                    $endpointCaptureSummaries.Add([pscustomobject]@{
                        DNS_Server             = $state.Label
                        Address                = $state.Address
                        CaptureComputer        = $state.RemoteComputer
                        CaptureMode            = 'Coordinated'
                        Status                 = if ($endpointIssues.Count -eq 0) { 'Complete' } else { 'Incomplete' }
                        CoveragePercent        = $analysis.CoveragePercent
                        MatchedPairs           = $analysis.MatchedPairs
                        UnmatchedClientPairs   = $analysis.UnmatchedLocalPairs
                        UnmatchedServerPairs   = $analysis.UnmatchedServerPairs
                        NegativeNetworkSamples = $analysis.NegativeNetworkRemainders
                        ClientWire             = $analysis.ClientWire
                        ClientPacketObservedLatency = $analysis.ClientWire
                        ServerTurnaround       = $analysis.ServerTurnaround
                        NetworkRemainder       = $analysis.NetworkRemainder
                        CombinedNetworkTime    = $analysis.NetworkRemainder
                        OutboundDelayDelta     = $analysis.OutboundDelayDelta
                        ReturnDelayDelta       = $analysis.ReturnDelayDelta
                        DirectionalDeltaMethod = $analysis.DirectionalDeltaMethod
                        SlowTransactions       = @($analysis.SlowTransactions)
                        ClientCapture          = Convert-DnsCaptureDiagnostics -Capture $state.ClientResult
                        ServerCapture          = Convert-DnsCaptureDiagnostics -Capture $state.ServerResult
                        Issues                 = [string[]]($endpointIssues.ToArray())
                    })

                    if ($TraceConditionalForwarding) {
                        if ($state.ForwardingMasterAddresses.Count -eq 0) {
                            $forwardingEndpointSummaries.Add([pscustomobject]@{
                                DNS_Server            = $state.Label
                                Address               = $state.Address
                                CaptureComputer       = $state.RemoteComputer
                                Status                = 'NoMatchingCF'
                                ConditionalForwarders = @()
                                Analysis              = $null
                                Capture               = $null
                                Issues                = @()
                            })
                        } elseif (-not [bool]$state.ServerResult.ForwardingEnabled -or
                            [string]::IsNullOrWhiteSpace(
                                [string]$state.ServerResult.ForwardingCompressedEventsBase64)) {
                            $forwardingIssue = 'A matching conditional forwarder was found, but the forwarding capture returned no evidence payload.'
                            $forwardingIssues.Add("$($state.Label): $forwardingIssue")
                            $forwardingEndpointSummaries.Add([pscustomobject]@{
                                DNS_Server            = $state.Label
                                Address               = $state.Address
                                CaptureComputer       = $state.RemoteComputer
                                Status                = 'Incomplete'
                                ConditionalForwarders = @($state.ConditionalForwarders)
                                Analysis              = $null
                                Capture               = $null
                                Issues                = @($forwardingIssue)
                            })
                        } else {
                            $forwardingBytes = [Convert]::FromBase64String(
                                [string]$state.ServerResult.ForwardingCompressedEventsBase64)
                            $forwardingAnalysis =
                                [DnsForwardingCaptureV410.ForwardingCaptureAnalyzer]::Analyze(
                                    $state.Label, $state.Address,
                                    [string[]]($state.ForwardingMasterAddresses),
                                    [string[]]($state.ForwardingZoneNames),
                                    [byte[]]$forwardingBytes,
                                    [datetime]$state.ServerResult.ForwardingCaptureEndUtc,
                                    $CaptureMaximumForwardingFlights)
                            $endpointForwardingIssues =
                                New-Object 'System.Collections.Generic.List[string]'
                            if ([bool]$state.ServerResult.ForwardingPacketLimitReached) {
                                $endpointForwardingIssues.Add(
                                    'Forwarding capture packet safety limit reached.')
                            }
                            if (-not [bool]$state.ServerResult.ForwardingStatisticsAvailable) {
                                $endpointForwardingIssues.Add(
                                    'Npcap forwarding-capture drop statistics were unavailable.')
                            }
                            if ([long]$state.ServerResult.ForwardingPcapDropped -gt 0 -or
                                [long]$state.ServerResult.ForwardingInterfaceDropped -gt 0) {
                                $endpointForwardingIssues.Add(
                                    'Npcap reported dropped forwarding-capture packets.')
                            }
                            if ([long]$forwardingAnalysis.UnmatchedForwardResponses -gt 0) {
                                $endpointForwardingIssues.Add(
                                    'Some upstream responses could not be matched to an observed upstream query.')
                            }
                            foreach ($forwardingIssue in $endpointForwardingIssues) {
                                $forwardingIssues.Add("$($state.Label): $forwardingIssue")
                            }
                            $forwardingEndpointSummaries.Add([pscustomobject]@{
                                DNS_Server            = $state.Label
                                Address               = $state.Address
                                CaptureComputer       = $state.RemoteComputer
                                Status                = if ($endpointForwardingIssues.Count -eq 0) {
                                    'Complete'
                                } else { 'Incomplete' }
                                ConditionalForwarders = @($state.ConditionalForwarders)
                                Analysis              = $forwardingAnalysis
                                Capture               = [pscustomobject]@{
                                    ComputerName          = $state.ServerResult.ForwardingComputerName
                                    LocalAddress          = $state.ServerResult.ForwardingLocalAddress
                                    ClientAddress         = $state.ServerResult.ForwardingClientAddress
                                    ForwardingLocalAddresses = @($state.ServerResult.ForwardingLocalAddresses)
                                    MasterAddresses       = @($state.ServerResult.ForwardingMasterAddresses)
                                    AdapterName           = $state.ServerResult.ForwardingAdapterName
                                    DeviceName            = $state.ServerResult.ForwardingDeviceName
                                    Filter                = $state.ServerResult.ForwardingFilter
                                    NpcapVersion          = $state.ServerResult.ForwardingNpcapVersion
                                    TimestampSource       = $state.ServerResult.ForwardingTimestampSource
                                    CaptureStartUtc       = $state.ServerResult.ForwardingCaptureStartUtc
                                    CaptureEndUtc         = $state.ServerResult.ForwardingCaptureEndUtc
                                    CapturedPackets       = [long]$state.ServerResult.ForwardingCapturedPackets
                                    ParsedDnsPackets      = [long]$state.ServerResult.ForwardingParsedDnsPackets
                                    RelevantEvents        = [long]$state.ServerResult.ForwardingRelevantEvents
                                    NonDnsOrUnparsedPackets = [long]$state.ServerResult.ForwardingUnparsedDnsPackets
                                    PcapReceived          = [long]$state.ServerResult.ForwardingPcapReceived
                                    PcapDropped           = [long]$state.ServerResult.ForwardingPcapDropped
                                    InterfaceDropped      = [long]$state.ServerResult.ForwardingInterfaceDropped
                                    StatisticsAvailable   = [bool]$state.ServerResult.ForwardingStatisticsAvailable
                                    PacketLimitReached    = [bool]$state.ServerResult.ForwardingPacketLimitReached
                                }
                                Issues                =
                                    [string[]]($endpointForwardingIssues.ToArray())
                            })
                        }
                    }
                    Remove-Job -Job $state.RunJob -Force -ErrorAction SilentlyContinue
                    $state.RunJob = $null
                }
                foreach ($definition in $clientOnlyCaptureDefinitions) {
                    $fallbackIssue =
                        'Server-side packet capture unavailable; normal client-side socket timing was retained. ' +
                        $definition.Reason
                    $captureFallbacks.Add("$($definition.Label): $fallbackIssue")
                    $endpointCaptureSummaries.Add([pscustomobject]@{
                        DNS_Server             = $definition.Label
                        Address                = $definition.Address
                        CaptureComputer        = $definition.CaptureComputer
                        CaptureMode            = 'ClientOnly'
                        Status                 = 'ClientOnly'
                        CoveragePercent        = $null
                        MatchedPairs           = $null
                        UnmatchedClientPairs   = $null
                        UnmatchedServerPairs   = $null
                        NegativeNetworkSamples = $null
                        ClientWire             = $null
                        ClientPacketObservedLatency = $null
                        ServerTurnaround       = $null
                        NetworkRemainder       = $null
                        CombinedNetworkTime    = $null
                        OutboundDelayDelta     = $null
                        ReturnDelayDelta       = $null
                        DirectionalDeltaMethod = $null
                        SlowTransactions       = @()
                        ClientCapture          = $null
                        ServerCapture          = $null
                        Issues                 = @($fallbackIssue)
                    })
                    if ($TraceConditionalForwarding) {
                        $forwardingIssue =
                            'Server-side conditional-forwarding trace is unavailable because this endpoint is using client-only timing.'
                        $forwardingFallbacks.Add("$($definition.Label): $forwardingIssue")
                        $forwardingEndpointSummaries.Add([pscustomobject]@{
                            DNS_Server            = $definition.Label
                            Address               = $definition.Address
                            CaptureComputer       = $definition.CaptureComputer
                            Status                = 'ClientOnly'
                            ConditionalForwarders = @()
                            Analysis              = $null
                            Capture               = $null
                            Issues                = @($forwardingIssue)
                        })
                    }
                }
                if ($resolvedCsvPath) {
                    try {
                        $csvCaptureEndpoints =
                            New-Object 'System.Collections.Generic.List[DnsCoordinatedCaptureV424.CaptureCsvEndpoint]'
                        foreach ($state in $captureStates) {
                            $csvCaptureEndpoint =
                                New-Object DnsCoordinatedCaptureV424.CaptureCsvEndpoint
                            $csvCaptureEndpoint.ServerAddress = [string]$state.Address
                            $csvCaptureEndpoint.ClientPairs =
                                [byte[]]$state.ClientResult.CompressedPairs
                            $csvCaptureEndpoint.ServerPairs =
                                [byte[]]$state.RemoteCaptureBytes
                            $csvCaptureEndpoint.ClientOnly = $false
                            $csvCaptureEndpoints.Add($csvCaptureEndpoint)
                        }
                        foreach ($definition in $clientOnlyCaptureDefinitions) {
                            $csvCaptureEndpoint =
                                New-Object DnsCoordinatedCaptureV424.CaptureCsvEndpoint
                            $csvCaptureEndpoint.ServerAddress =
                                [string]$definition.Address
                            $csvCaptureEndpoint.ClientPairs = [byte[]]@()
                            $csvCaptureEndpoint.ServerPairs = [byte[]]@()
                            $csvCaptureEndpoint.ClientOnly = $true
                            $csvCaptureEndpoints.Add($csvCaptureEndpoint)
                        }
                        $csvEnrichmentResult =
                            [DnsCoordinatedCaptureV424.CaptureCsvEnricher]::Enrich(
                                $resolvedCsvPath, $csvCaptureEndpoints.ToArray())
                        $csvPacketTimingEnrichment = [pscustomobject]@{
                            Status                 = 'Complete'
                            TotalRows              = [long]$csvEnrichmentResult.TotalRows
                            MatchedRows            = [long]$csvEnrichmentResult.MatchedRows
                            ClientOnlyRows         = [long]$csvEnrichmentResult.ClientOnlyRows
                            UnmatchedRows          = [long]$csvEnrichmentResult.UnmatchedRows
                            NotSentRows            = [long]$csvEnrichmentResult.NotSentRows
                            TcpFallbackRows        = [long]$csvEnrichmentResult.TcpFallbackRows
                            DirectionalDeltaMethod = $csvEnrichmentResult.DirectionalDeltaMethod
                            ErrorMessage           = $null
                        }
                    } catch {
                        $csvEnrichmentMessage =
                            "Detailed CSV Npcap enrichment failed; the original workload CSV was preserved: $($_.Exception.Message)"
                        $captureIssues.Add($csvEnrichmentMessage)
                        Write-Warning $csvEnrichmentMessage
                        $csvPacketTimingEnrichment = [pscustomobject]@{
                            Status                 = 'Failed'
                            TotalRows              = 0L
                            MatchedRows            = 0L
                            ClientOnlyRows         = 0L
                            UnmatchedRows          = 0L
                            NotSentRows            = 0L
                            TcpFallbackRows        = 0L
                            DirectionalDeltaMethod = $null
                            ErrorMessage           = $_.Exception.Message
                        }
                    }
                }
                $coordinatedEndpointCount = $captureStates.Count
                $clientOnlyEndpointCount = $clientOnlyCaptureDefinitions.Count
                $orderedEndpointCaptureSummaries = [object[]]@(
                    foreach ($definition in $captureEndpointDefinitions) {
                        $endpointCaptureSummaries |
                            Where-Object { $_.Address -eq $definition.Address } |
                            Select-Object -First 1
                    }
                )
                $incompleteCoordinatedEndpointCount = @(
                    $orderedEndpointCaptureSummaries |
                        Where-Object { $_.Status -eq 'Incomplete' }
                ).Count
                $coordinatedCaptureSummary = [pscustomobject]@{
                    Enabled                    = $true
                    Status                     = if ($incompleteCoordinatedEndpointCount -gt 0) {
                        'Incomplete'
                    } elseif ($clientOnlyEndpointCount -gt 0 -and
                        $coordinatedEndpointCount -gt 0) {
                        'Mixed'
                    } elseif ($clientOnlyEndpointCount -gt 0) {
                        'ClientOnly'
                    } else { 'Complete' }
                    Scope                      = 'UDP port 53 request/response pairs; TCP fallbacks are excluded'
                    TimestampSource            = 'Npcap default host timestamp (microsecond representation)'
                    ClockSynchronizationNeeded = $false
                    DirectionalClockRequirement = 'Clock offset need not be zero, but it must remain stable within the nearby baseline window'
                    DirectionalDeltaMethod      = 'Same-endpoint actual P10 combined-network transaction in a nearby approximately 11-second window; deltas are not absolute one-way latency'
                    TcpFallbackPairsExcluded   = [long]$finalSnapshot.Overall.TcpFallback
                    MatchedPairs               = $totalMatchedPairs
                    CoordinatedEndpointCount   = $coordinatedEndpointCount
                    ClientOnlyEndpointCount    = $clientOnlyEndpointCount
                    CsvEnrichment              = $csvPacketTimingEnrichment
                    Endpoints                  = $orderedEndpointCaptureSummaries
                    Fallbacks                  = [string[]]($captureFallbacks.ToArray())
                    Issues                     = [string[]]($captureIssues.ToArray())
                }
                if ($TraceConditionalForwarding) {
                    $orderedForwardingEndpointSummaries = [object[]]@(
                        foreach ($definition in $captureEndpointDefinitions) {
                            $forwardingEndpointSummaries |
                                Where-Object { $_.Address -eq $definition.Address } |
                                Select-Object -First 1
                        }
                    )
                    $matchingEndpointCount = @($orderedForwardingEndpointSummaries |
                        Where-Object { $_.Status -notin @(
                            'NoMatchingCF','ClientOnly') }).Count
                    $clientOnlyForwardingCount = @($orderedForwardingEndpointSummaries |
                        Where-Object { $_.Status -eq 'ClientOnly' }).Count
                    $incompleteForwardingCount = @($orderedForwardingEndpointSummaries |
                        Where-Object { $_.Status -eq 'Incomplete' }).Count
                    $conditionalForwardingSummary = [pscustomobject]@{
                        Enabled                     = $true
                        Status                      = if ($incompleteForwardingCount -gt 0) {
                            'Incomplete'
                        } elseif ($clientOnlyForwardingCount -gt 0 -and
                            $matchingEndpointCount -gt 0) {
                            'Mixed'
                        } elseif ($clientOnlyForwardingCount -gt 0) {
                            'ClientOnly'
                        } elseif ($matchingEndpointCount -eq 0) {
                            'NoMatchingCF'
                        } else { 'Complete' }
                        Scope                       = 'Exact tested DNS questions on client-facing and conditional-forwarder paths; CNAME-derived child lookups are outside this trace'
                        CacheMutation               = 'None; cached answers can legitimately have no observed forwarding flight'
                        Endpoints                   = $orderedForwardingEndpointSummaries
                        Fallbacks                   = [string[]]($forwardingFallbacks.ToArray())
                        Issues                      = [string[]]($forwardingIssues.ToArray())
                    }
                }
            }
        } catch {
            $executionError = $_
        } finally {
            if ($null -ne $runnerTask -and -not $runnerTask.IsCompleted) {
                $cancellation.Cancel()
                try { $runnerTask.Wait(3000) } catch { }
            }
            $cancellation.Dispose()
            if ($null -ne $runner) { $runner.Dispose() }
            foreach ($state in $captureStates) {
                if ($null -ne $state.LocalSession) {
                    try { $state.LocalSession.RequestStop() } catch { }
                    if ($null -ne $state.LocalTask -and -not $state.LocalTask.IsCompleted) {
                        try { $null = $state.LocalTask.Wait(2000) } catch { }
                    }
                    try { $state.LocalSession.Dispose() } catch { }
                }
                foreach ($job in @($state.OpenJob, $state.RunJob)) {
                    if ($null -eq $job) { continue }
                    if ($job.State -notin @('Completed','Failed','Stopped')) {
                        Stop-Job -Job $job -ErrorAction SilentlyContinue
                    }
                    Remove-Job -Job $job -Force -ErrorAction SilentlyContinue
                }
                if ($null -ne $state.Session) {
                    try {
                        $null = Invoke-Command -Session $state.Session -ArgumentList $state.Id `
                            -ErrorAction SilentlyContinue -ScriptBlock {
                                param($CaptureId)
                                if ($null -ne $global:DnsCoordinatedCaptureSessions -and
                                    $global:DnsCoordinatedCaptureSessions.ContainsKey($CaptureId)) {
                                    $entry = $global:DnsCoordinatedCaptureSessions[$CaptureId]
                                    foreach ($capture in @(
                                        $entry.PairCapture, $entry.ForwardingCapture)) {
                                        if ($null -eq $capture) { continue }
                                        $capture.RequestStop()
                                        $capture.Dispose()
                                    }
                                    $global:DnsCoordinatedCaptureSessions.Remove($CaptureId)
                                }
                            }
                    } catch { }
                    Remove-PSSession -Session $state.Session -ErrorAction SilentlyContinue
                }
            }
        }

        if ($null -ne $executionError) {
            $PSCmdlet.ThrowTerminatingError($executionError)
        }

        if ($null -eq $completion -or $null -eq $finalSnapshot -or $null -eq $finalSnapshot.Overall) {
            throw 'The DNS test ended without a valid completion snapshot; no summary was generated.'
        }

        $overallMetrics = Convert-MetricSnapshot $finalSnapshot.Overall
        $perServerMetrics = foreach ($item in $finalSnapshot.PerServer) {
            Convert-MetricSnapshot -Metric $item.Metrics -NameProperty 'DNS_Server' -Name $item.Name -Address $item.Address
        }
        $perFqdnMetrics = foreach ($item in $finalSnapshot.PerFqdn) {
            Convert-MetricSnapshot -Metric $item.Metrics -NameProperty 'FQDN' -Name $item.Name
        }
        $perServerFqdnMetrics = foreach ($item in $finalSnapshot.PerServerFqdn) {
            $metricParameters = @{
                Metric       = $item.Metrics
                NameProperty = 'DNS_Server'
                Name         = $item.Server
                Address      = $item.ServerAddress
                FQDN         = $item.QueryName
            }
            Convert-MetricSnapshot @metricParameters
        }
        $statusMetrics = foreach ($item in $finalSnapshot.StatusCounts) {
            [pscustomobject]@{ Status = $item.Name; Count = $item.Count }
        }
        $rcodeMetrics = foreach ($item in $finalSnapshot.RCodeCounts) {
            [pscustomobject]@{ RCode = $item.Name; Count = $item.Count }
        }
        $degradationEvents = foreach ($item in $finalSnapshot.DegradationEvents) {
            [pscustomobject]@{
                StartUtc              = $item.StartUtc
                EndUtc                = $item.EndUtc
                DurationMs            = $item.DurationMs
                DNS_Server            = $item.Server
                Address               = $item.ServerAddress
                FQDN                  = $item.QueryName
                Scope                 = $item.Scope
                Attribution           = $item.Attribution
                Objectives            = $item.Objectives
                Sent                  = $item.Sent
                Bad                   = $item.Bad
                EvaluatedQueries      = $item.Sent
                AffectedQueries       = $item.Bad
                AvailabilityFailures  = $item.AvailabilityFailures
                Timeouts              = $item.Timeouts
                DnsErrors             = $item.DnsErrors
                OtherFailures         = $item.OtherFailures
                NormalSlow            = $item.NormalSlow
                SevereSlow            = $item.SevereSlow
                Slow10To49Ms          = $item.NormalSlow - $item.SevereSlow
                Slow50MsOrMore        = $item.SevereSlow
                BadPercent            = $item.BadPercent
                MaxResponseMs         = $item.MaxResponseMs
                MaxSchedulerLagMs     = $item.MaxSchedulerLagMs
                AffectedEndpoints     = $item.AffectedEndpoints
                PeakAffectedEndpoints = $item.PeakAffectedEndpoints
                TotalEndpoints        = $item.TotalEndpoints
                AffectedRoundCount     = $item.EndpointOnlyRounds + $item.SharedSlowRounds
                ObserverSuspectRounds = $item.ObserverSuspectRounds
                SharedSlowRounds      = $item.SharedSlowRounds
                EndpointOnlyRounds    = $item.EndpointOnlyRounds
            }
        }
        $degradationIncidents = foreach ($incident in $finalSnapshot.DegradationIncidents) {
            $pairDetails = foreach ($item in $incident.PairEvents) {
                [pscustomobject]@{
                    StartUtc              = $item.StartUtc
                    EndUtc                = $item.EndUtc
                    DurationMs            = $item.DurationMs
                    DNS_Server            = $item.Server
                    Address               = $item.ServerAddress
                    FQDN                  = $item.QueryName
                    Scope                 = $item.Scope
                    Attribution           = $item.Attribution
                    Objectives            = $item.Objectives
                    EvaluatedQueries      = $item.Sent
                    AffectedQueries       = $item.Bad
                    AvailabilityFailures  = $item.AvailabilityFailures
                    Timeouts              = $item.Timeouts
                    DnsErrors             = $item.DnsErrors
                    OtherFailures         = $item.OtherFailures
                    Slow10To49Ms          = $item.NormalSlow - $item.SevereSlow
                    Slow50MsOrMore        = $item.SevereSlow
                    MaxResponseMs         = $item.MaxResponseMs
                    MaxSchedulerLagMs     = $item.MaxSchedulerLagMs
                    PeakAffectedEndpoints = $item.PeakAffectedEndpoints
                    TotalEndpoints        = $item.TotalEndpoints
                    AffectedRoundCount     = $item.EndpointOnlyRounds + $item.SharedSlowRounds
                    ObserverSuspectRounds = $item.ObserverSuspectRounds
                    SharedSlowRounds      = $item.SharedSlowRounds
                    EndpointOnlyRounds    = $item.EndpointOnlyRounds
                }
            }
            [pscustomobject]@{
                IncidentNumber           = $incident.IncidentNumber
                StartUtc                 = $incident.StartUtc
                EndUtc                   = $incident.EndUtc
                DurationMs               = $incident.DurationMs
                PrimaryScope             = $incident.PrimaryScope
                Correlation              = $incident.Correlation
                ClientEvidence           = $incident.ClientEvidence
                Objectives               = $incident.Objectives
                DNS_Servers              = @($incident.Servers)
                ServerAddresses          = @($incident.ServerAddresses)
                FQDNs                    = @($incident.QueryNames)
                QualifyingServerCount    = $incident.AffectedEndpointCount
                QualifyingFqdnCount      = $incident.AffectedNameCount
                AffectedEndpointCount    = $incident.AffectedEndpointCount
                TotalEndpoints           = $incident.TotalEndpoints
                AffectedNameCount        = $incident.AffectedNameCount
                TotalNames               = $incident.TotalNames
                PairEventCount           = $incident.PairEventCount
                EvaluatedQueries         = $incident.EvaluatedQueries
                AffectedQueries          = $incident.AffectedQueries
                AvailabilityFailures     = $incident.AvailabilityFailures
                Timeouts                 = $incident.Timeouts
                DnsErrors                = $incident.DnsErrors
                OtherFailures            = $incident.OtherFailures
                Slow10To49Ms             = $incident.NormalSlow - $incident.SevereSlow
                Slow50MsOrMore           = $incident.SevereSlow
                MaxResponseMs            = $incident.MaxResponseMs
                MaxSchedulerLagMs        = $incident.MaxSchedulerLagMs
                AffectedRoundCount       = $incident.AffectedRoundCount
                PeakAffectedEndpoints    = $incident.PeakAffectedEndpoints
                ObserverSuspectRounds    = $incident.ObserverSuspectRounds
                ObserverSharedRounds     = $incident.ObserverSharedRounds
                SharedSlowRounds         = $incident.SharedSlowRounds
                MajoritySlowRounds       = $incident.MajoritySlowRounds
                EndpointOnlyRounds       = $incident.EndpointOnlyRounds
                PairEvents               = @($pairDetails)
            }
        }
        $largestObservation = $null
        if ($null -ne $finalSnapshot.LargestSuccessfulObservation) {
            $item = $finalSnapshot.LargestSuccessfulObservation
            $largestObservation = [pscustomobject]@{
                Sequence                 = $item.Sequence
                ScheduledUtc             = $item.ScheduledUtc
                StartedUtc               = $item.StartedUtc
                ReceivedUtc              = $item.ReceivedUtc
                CompletedUtc             = $item.CompletedUtc
                DNS_Server               = $item.Server
                Address                  = $item.ServerAddress
                FQDN                     = $item.QueryName
                QueryType                = $item.QueryType
                ResponseTimeMs           = $item.ResponseTimeMs
                ClientProcessingDelayMs  = $item.ClientProcessingDelayMs
                ParserQueueDelayMs       = $item.ParserQueueDelayMs
                ParseDurationMs          = $item.ParseDurationMs
                ContinuationDelayMs      = $item.ContinuationDelayMs
                EndToEndTimeMs            = $item.EndToEndTimeMs
                TimingSource              = $item.TimingSource
            }
        }

        $totalElapsed = ($completion.EndUtc - $completion.StartUtc).TotalSeconds
        $scheduleElapsed = ($completion.SchedulingEndUtc - $completion.StartUtc).TotalSeconds
        $summary = [pscustomobject]@{
            Configuration = [pscustomobject]@{
                FQDNs                           = $normalizedNames.ToArray()
                DNS_Server_Endpoints            = @($targets | ForEach-Object { [pscustomobject]@{ Label = $_.Label; Address = $_.Address } })
                QueryType                       = $QueryType
                QueriesPerSecondPerServer       = $QueriesPerSecond
                TargetAggregateQps              = $aggregateQps
                DurationSeconds                 = $DurationSeconds
                TimeoutMilliseconds             = $TimeoutMilliseconds
                MaxOutstandingPerServer         = $MaxOutstandingPerServer
                SchedulerToleranceMilliseconds  = $SchedulerToleranceMilliseconds
                DisplayIntervalSeconds          = $DisplayIntervalSeconds
                RollingWindowSeconds            = $RollingWindowSeconds
                WarmupSeconds                   = $WarmupSeconds
                ProcessingWorkerCount           = $finalSnapshot.Observer.ParserWorkerCount
                ObserverProcessingThresholdMs   = $ObserverProcessingThresholdMilliseconds
                DashboardRenderingMode          = $dashboardRenderingMode
                RecursionDesired                = -not $NoRecursion
                EDNS                            = -not $NoEdns
                UdpPayloadSize                  = if ($NoEdns) { $null } else { $UdpPayloadSize }
                TcpFallback                     = -not $DisableTcpFallback
                RequireAnswer                   = -not $AllowNoAnswer
                SchedulingMode                  = 'PairedRoundRobin'
                PercentileMethod                = 'Bounded histogram; 0.01 ms bins below 10 ms'
                LatencyDefinition               = 'Socket-observed: UDP send-to-Socket.Receive return; TCP send-to-final-read completion'
                CoordinatedCapture              = [pscustomobject]@{
                    Enabled                     = [bool]$CoordinatedCapture
                    CaptureComputerMap          = $CaptureComputerMap
                    UseSSL                      = [bool]$CaptureUseSSL
                    StartupTimeoutSeconds       = $CaptureStartupTimeoutSeconds
                    GraceSeconds                = $CaptureGraceSeconds
                    MaximumPacketsPerEndpoint   = $CaptureMaximumPacketsPerEndpoint
                    SlowTransactionThresholdMs  = $CaptureSlowTransactionThresholdMilliseconds
                    MaximumSlowTransactions     = $CaptureMaximumSlowTransactions
                }
                ConditionalForwarding            = [pscustomobject]@{
                    Enabled                     = [bool]$TraceConditionalForwarding
                    MaximumPacketsPerEndpoint   = $CaptureMaximumForwardingPacketsPerEndpoint
                    MaximumRetainedFlights      = $CaptureMaximumForwardingFlights
                    CacheMutation               = 'None'
                    MultiAdapterEgressSupported = $false
                }
                DegradationAnalysis             = [pscustomobject]@{
                    WindowSeconds               = $DegradationWindowSeconds
                    EvaluationStepSeconds        = 1
                    FullRunCheck                  = $true
                    AvailabilityObjectivePercent = 99.9
                    NormalLatencyThresholdMs     = 10.0
                    NormalObjectivePercent       = 99.0
                    SevereLatencyThresholdMs     = 50.0
                    SevereObjectivePercent       = 99.9
                    MinimumViolations            = $MinimumDegradationSamples
                    MaximumEvents                = $MaximumDegradationEvents
                    MaximumIncidents             = $MaximumDegradationEvents
                    ObserverProcessingThresholdMs = $ObserverProcessingThresholdMilliseconds
                    DisplaySpikeCleanBucketSeconds = 1
                    IncidentCorrelationGapMs     = 100.0
                    PrimaryScopeBasis            = 'Independently qualifying servers'
                    PairedRoundEvidenceAffectsPrimaryScope = $false
                }
            }
            Timing = [pscustomobject]@{
                StartUtc                = $completion.StartUtc
                SchedulingEndUtc        = $completion.SchedulingEndUtc
                EndUtc                  = $completion.EndUtc
                SchedulingElapsedSeconds = [Math]::Round($scheduleElapsed, 3)
                TotalElapsedSeconds     = [Math]::Round($totalElapsed, 3)
                OfferedAggregateQps     = [Math]::Round($completion.StartedQueries / [double]$DurationSeconds, 3)
                CompletionThroughputQps = [Math]::Round($completion.StartedQueries / [Math]::Max(0.001, $totalElapsed), 3)
            }
            OverallMetrics       = $overallMetrics
            PerServerMetrics     = @($perServerMetrics)
            PerFQDNMetrics       = @($perFqdnMetrics)
            PerServerFQDNMetrics = @($perServerFqdnMetrics)
            StatusCounts         = @($statusMetrics)
            RCodeCounts          = @($rcodeMetrics)
            DegradationEvents    = @($degradationEvents)
            TotalDegradationEvents = $finalSnapshot.TotalDegradationEvents
            OmittedDegradationEvents = $finalSnapshot.OmittedDegradationEvents
            DegradationPairEvents = @($degradationEvents)
            TotalDegradationPairEvents = $finalSnapshot.TotalDegradationEvents
            OmittedDegradationPairEvents = $finalSnapshot.OmittedDegradationEvents
            DegradationIncidents = @($degradationIncidents)
            TotalDegradationIncidents = $finalSnapshot.TotalDegradationIncidents
            OmittedDegradationIncidents = $finalSnapshot.OmittedDegradationIncidents
            LargestSuccessfulObservation = $largestObservation
            CoordinatedCapture   = $coordinatedCaptureSummary
            ConditionalForwarding = $conditionalForwardingSummary
            ObserverHealth       = [pscustomobject]@{
                WarmupSeconds             = $finalSnapshot.Observer.WarmupSeconds
                ParserWorkerCount         = $finalSnapshot.Observer.ParserWorkerCount
                ParserProcessedPackets    = $finalSnapshot.Observer.ParserProcessedPackets
                ParserMaxQueueDepth       = $finalSnapshot.Observer.ParserMaxQueueDepth
                ParserAverageQueueDelayMs = $finalSnapshot.Observer.ParserAverageQueueDelayMs
                ParserMaxQueueDelayMs     = $finalSnapshot.Observer.ParserMaxQueueDelayMs
                ParserAverageParseMs      = $finalSnapshot.Observer.ParserAverageParseMs
                ParserMaxParseMs          = $finalSnapshot.Observer.ParserMaxParseMs
                ProcessCpuPercent         = $finalSnapshot.Observer.ProcessCpuPercent
                Gen0Collections           = $finalSnapshot.Observer.Gen0Collections
                Gen1Collections           = $finalSnapshot.Observer.Gen1Collections
                Gen2Collections           = $finalSnapshot.Observer.Gen2Collections
                MaxManagedMemoryMb        = $finalSnapshot.Observer.MaxManagedMemoryMb
                MaxWorkingSetMb           = $finalSnapshot.Observer.MaxWorkingSetMb
                MinAvailableWorkerThreads = $finalSnapshot.Observer.MinAvailableWorkerThreads
                MinAvailableIoThreads     = $finalSnapshot.Observer.MinAvailableIoThreads
                ProcessingThresholdMs     = $finalSnapshot.Observer.ProcessingThresholdMs
            }
            CsvOutputPath        = $resolvedCsvPath
            DetailedResults      = if ($IncludeDetailedResults) { @($finalSnapshot.DetailedResults) } else { $null }
        }

        Write-FinalSummary -Summary $summary -Redraw ($dashboardRenderingMode -eq 'Redraw') -IsIse $isIse
        return $summary
    }
}
