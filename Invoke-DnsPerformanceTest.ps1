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
        is five seconds, evaluated once per second for each server-by-FQDN pair.

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
        Optional streaming CSV containing one row per planned query. Large tests can
        produce very large files; rows are written during the test instead of retained.

    .PARAMETER IncludeDetailedResults
        Return individual query rows in memory. This is rejected when the planned count
        exceeds MaximumDetailedResults. CSV is preferred for large tests.

    .PARAMETER MaximumDetailedResults
        Safety limit for rows retained by IncludeDetailedResults.

    .PARAMETER MaximumPlannedQueries
        Safety limit applied independently to the measured query plan and the
        warm-up query plan. The function stops before sending any queries when
        either phase would exceed this value.

    .EXAMPLE
        $result = Invoke-DnsPerformanceTest `
            -FQDNs 'app1.contoso.com','app2.contoso.com','www.microsoft.com' `
            -DNSServers 'dns01.contoso.com','dns02.contoso.com' `
            -QueriesPerSecond 200 -DurationSeconds 120

    .EXAMPLE
        $result = Invoke-DnsPerformanceTest `
            -FQDNs $names -DNSServers $servers -QueriesPerSecond 200 `
            -DurationSeconds 1800 -DisplayIntervalSeconds 5 `
            -CsvOutputPath 'C:\Temp\DnsPerformance.csv'

    .OUTPUTS
        PSCustomObject containing configuration, timing, cumulative metrics, status
        counts, RCODE counts, observer-health evidence, DNS latency incidents with
        independently qualifying scope and paired-round evidence, their server-by-FQDN
        pair details, and optional detailed results.

    .NOTES
        Name: Invoke-DnsPerformanceTest
        Version: 3.5.0
        PowerShell: Windows PowerShell 5.1 (including ISE) or PowerShell 7+

        This is a controlled production probe. Confirm that the requested aggregate
        rate is acceptable before running against production infrastructure.

        DNS LATENCY DEGRADATION uses fixed objectives for known-cached names, applied
        independently to each server-by-FQDN pair in sliding windows and across the
        complete run:
          * at least 99.9% successful DNS answers;
          * at least 99% of successful answers below 10 ms; and
          * at least 99.9% of successful answers below 50 ms.

        A window must contain at least MinimumDegradationSamples violations of an
        objective before it qualifies. The 10 ms and 50 ms grades are intentionally
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
        [long]$MaximumPlannedQueries = 10000000
    )

    begin {
        if (-not ('DnsPerformanceV350.DnsLoadRunner' -as [type])) {
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

namespace DnsPerformanceV350
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
        // Retained as an alias for callers of earlier versions. In v3.5.0 this
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
                    writer.WriteLine("Sequence,ScheduledUtc,StartedUtc,ReceivedUtc,CompletedUtc,Server,ServerAddress,QueryName,QueryType,Status,Sent,ResponseReceived,Success,TcpFallbackUsed,Truncated,AnswerCount,RCode,RCodeName,ResponseTimeMs,ClientProcessingDelayMs,ParserQueueDelayMs,ParseDurationMs,ContinuationDelayMs,EndToEndTimeMs,TimingSource,SchedulerLagMs,ErrorMessage");
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
                            Csv(result.Server), Csv(result.ServerAddress), Csv(result.QueryName), Csv(result.QueryType), Csv(result.Status),
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
            PendingResponse pendingResponse;
            Reserve(queryName, queryType, out id, out pendingResponse);
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

        private void Reserve(string queryName, ushort queryType,
            out ushort id, out PendingResponse response)
        {
            lock (pendingSync)
            {
                for (int attempt = 0; attempt < 65536; attempt++)
                {
                    id = unchecked((ushort)++nextTransactionId);
                    if (!pending.ContainsKey(id))
                    {
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
        private RunnerCompletion completion;
        private int started;
        private int disposed;

        public RunnerProgress Progress { get; private set; }
        public RunnerCompletion Completion { get { return completion; } }

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
            try { store.DisposeCsv(); }
            finally { parserPool.Dispose(); }
        }
    }
}
'@
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

        function Convert-MetricSnapshot {
            param(
                [Parameter(Mandatory)][DnsPerformanceV350.MetricSnapshot]$Metric,
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
                [Parameter(Mandatory)][DnsPerformanceV350.LiveSnapshot]$Snapshot,
                [Parameter(Mandatory)][DnsPerformanceV350.RunnerProgress]$Progress,
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
                    ('DNS PERFORMANCE TEST v3.5.0 - {0} - UTC {1:HH:mm:ss}' -f $phase, $now),
                    ('{0} endpoints x {1} QPS/server = {2} target aggregate QPS | {3} names | measured {4}s | warm-up {5}s' -f `
                        $EndpointCount, $PerServerQps, $TargetAggregateQps, $Names.Count, $Duration, $Progress.WarmupSeconds),
                    ('Warm-up elapsed {0:0.0}/{1}s; measurements and CSV rows begin after warm-up.' -f `
                        [Math]::Min($warmElapsed, [double]$Progress.WarmupSeconds), $Progress.WarmupSeconds)
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
            $lines.Add(('DNS PERFORMANCE TEST v3.5.0 - {0} - UTC {1:HH:mm:ss}' -f $phase, $now))
            $lines.Add(('{0} endpoints x {1} QPS/server = {2} target aggregate QPS | {3} names | {4}s | {5:n0} planned | MaxOutstanding/server {6}' -f `
                $EndpointCount, $PerServerQps, $TargetAggregateQps, $Names.Count, $Duration, $Planned, $OutstandingLimit))
            $lines.Add(('Elapsed {0,7:0.0}/{1}s | Send QPS {2,8:0.0}/{3} | Rolling completion QPS {4,8} | Sent {5:n0} | Done {6:n0} | Drop {7:n0}' -f `
                $scheduleElapsed, $Duration, $sendQps, $TargetAggregateQps, $rollingQpsText,
                $Progress.StartedQueries, $Progress.CompletedQueries, $drop))
            $lines.Add(('ROLLING SOCKET-OBSERVED LATENCY - all servers/FQDNs, successful responses only, last {0:0.0}s:' -f `
                $Snapshot.EffectiveWindowSeconds))
            $lines.Add(('AVG {0}  STD {1}  P50 {2}  P95 {3}  P99 {4}  MAX {5}' -f `
                (Format-MetricNumber $overall.AverageMs),
                (Format-MetricNumber $overall.StdDevMs), (Format-MetricNumber $overall.P50Ms),
                (Format-MetricNumber $overall.P95Ms), (Format-MetricNumber $overall.P99Ms),
                (Format-MetricNumber $overall.MaxMs)))
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
                $row = ('{0,-18} {1,8} {2,7}' -f `
                    (Format-FixedText (Get-ShortServerName $server.Server) 18),
                    $serverQpsText,
                    (Format-MetricNumber $server.Metrics.SuccessRatePercent '0.00'))
                $row += (' | {0,7} {1,7} {2,7}' -f `
                    $server.Metrics.Timeout, $server.Metrics.DnsError, $server.Metrics.OtherFailure)
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
            foreach ($row in @($Rows)) {
                $candidateText = [string]($row.$NameProperty)
                $candidateLength = $candidateText.Length
                if ($candidateLength -gt $longestName) { $longestName = $candidateLength }
            }
            $resolvedNameWidth = [Math]::Min($NameWidth, $longestName)
            $identityHeader = ("{0,-$resolvedNameWidth} {1,10} {2,7}" -f $nameHeader,'SENT','OK%')
            $failureHeader = ('{0,7} {1,7} {2,7}' -f 'TIMEOUT','RCODE','OTHER')
            $latencyHeader = ('{0,9} {1,9} {2,9} {3,9} {4,9} {5,9}' -f `
                'AVG MS','STD MS','P50 MS','P95 MS','P99 MS','MAX MS')
            $columnHeader = $identityHeader + ' | ' + $failureHeader + ' | ' + $latencyHeader
            $groupHeader = ''.PadRight($identityHeader.Length) + ' | ' + `
                (Format-CenteredText 'QUERY FAILURES' $failureHeader.Length) + ' | ' + `
                (Format-CenteredText 'SUCCESSFUL SOCKET-OBSERVED LATENCY (MS)' $latencyHeader.Length)
            Write-Host $groupHeader
            Write-Host $columnHeader
            Write-Host ('-' * $columnHeader.Length) -ForegroundColor DarkGray
            foreach ($row in $Rows) {
                $identity = ("{0,-$resolvedNameWidth} {1,10} {2,7}" -f `
                    (Format-FixedText $row.$NameProperty $resolvedNameWidth),
                    ('{0:n0}' -f $row.Sent),
                    (Format-MetricNumber $row.SuccessRatePercent '0.00'))
                $failures = ('{0,7} {1,7} {2,7}' -f `
                    ('{0:n0}' -f $row.Timeout), ('{0:n0}' -f $row.DnsError),
                    ('{0:n0}' -f $row.OtherFailure))
                $latency = ('{0,9} {1,9} {2,9} {3,9} {4,9} {5,9}' -f `
                    (Format-MetricNumber $row.AverageMs), (Format-MetricNumber $row.StdDevMs),
                    (Format-MetricNumber $row.P50Ms), (Format-MetricNumber $row.P95Ms),
                    (Format-MetricNumber $row.P99Ms), (Format-MetricNumber $row.MaxMs))
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
                $row = ("{0,-$serverWidth}" -f `
                    (Format-FixedText (Get-ShortServerName $ServerNames[$s]) $serverWidth))
                for ($n = 0; $n -lt $Names.Count; $n++) {
                    $metric = $PerServerFqdn[($s * $Names.Count) + $n]
                    if ($Mode -eq 'AverageP95') {
                        $averageText = Format-MetricNumber $metric.AverageMs
                        $stdDevText = Format-MetricNumber $metric.StdDevMs
                        $p95Text = Format-MetricNumber $metric.P95Ms
                        $row += (' | {0,7} {1,7} {2,7}' -f `
                            $averageText, $stdDevText, $p95Text)
                    } else {
                        $p99Text = Format-MetricNumber $metric.P99Ms
                        $maxText = Format-MetricNumber $metric.MaxMs
                        $successText = if ($metric.Sent -gt 0) {
                            Format-MetricNumber $metric.SuccessRatePercent '0.0'
                        } else { '-' }
                        $row += (' | {0,7} {1,7} {2,7}' -f `
                            $p99Text, $maxText, $successText)
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
            if ($overall.SchedulerMiss -gt 0) {
                $pressure.Add(('{0:n0} scheduler miss(es)' -f $overall.SchedulerMiss))
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
            Write-Host ('Warm-up: {0:0.##}s   Parser workers: {1}   Parsed packets: {2:n0}   Maximum parser queue depth: {3:n0}' -f `
                $observer.WarmupSeconds, $observer.ParserWorkerCount,
                $observer.ParserProcessedPackets, $observer.ParserMaxQueueDepth)
            Write-Host ('Parser queue delay ms - Avg: {0}   Max: {1}   Parse duration ms - Avg: {2}   Max: {3}' -f `
                (Format-MetricNumber $observer.ParserAverageQueueDelayMs '0.000'),
                (Format-MetricNumber $observer.ParserMaxQueueDelayMs '0.000'),
                (Format-MetricNumber $observer.ParserAverageParseMs '0.000'),
                (Format-MetricNumber $observer.ParserMaxParseMs '0.000'))
            Write-Host ('Process CPU: {0:0.0}%   GC collections 0/1/2: {1:n0}/{2:n0}/{3:n0}   Managed/working-set peak: {4:0.0}/{5:0.0} MB' -f `
                $observer.ProcessCpuPercent, $observer.Gen0Collections,
                $observer.Gen1Collections, $observer.Gen2Collections,
                $observer.MaxManagedMemoryMb, $observer.MaxWorkingSetMb)
            Write-Host ('Minimum available ThreadPool worker/I/O threads: {0:n0}/{1:n0}   Observer threshold: {2:0.###} ms' -f `
                $observer.MinAvailableWorkerThreads, $observer.MinAvailableIoThreads, $threshold)
            if ($pressure.Count -eq 0) {
                Write-Host 'Assessment: NO MATERIAL CLIENT/OBSERVER PRESSURE DETECTED.' -ForegroundColor Green
            } else {
                Write-Host ('Assessment: CLIENT/OBSERVER PRESSURE EVIDENCE - ' + ($pressure -join '; ') + '.') -ForegroundColor Yellow
                Write-Host 'This evidence affects attribution only when it overlaps a degraded paired-query round.'
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

            $criteria = $Summary.Configuration.DegradationAnalysis
            Write-Host ''
            Write-Host 'DNS LATENCY DEGRADATION' -ForegroundColor Cyan
            Write-Host ('Objectives per server x FQDN: success >=99.9%; successful socket-observed latency <{0:0.##} ms >=99%; <{1:0.##} ms >=99.9%' -f `
                $criteria.NormalLatencyThresholdMs, $criteria.SevereLatencyThresholdMs)
            Write-Host ('Evaluation: {0}s sliding windows + full-run check, checked every 1s, minimum {1} violations/objective' -f `
                $criteria.WindowSeconds, $criteria.MinimumViolations)
            Write-Host ('Observer correlation threshold: client processing or parser queue >= {0:0.###} ms; scheduler misses/late rounds also count as observer evidence.' -f `
                $criteria.ObserverProcessingThresholdMs)

            $observation = $Summary.LargestSuccessfulObservation
            if ($null -ne $observation) {
                Write-Host ('Highest successful socket-observed response: {0:0.000} ms | {1} | {2}' -f `
                    $observation.ResponseTimeMs,
                    (Get-ShortServerName $observation.DNS_Server), $observation.FQDN)
                Write-Host ('  Sent UTC {0:yyyy-MM-dd HH:mm:ss.fffffff} | Received UTC {1:yyyy-MM-dd HH:mm:ss.fffffff} | Client processing {2:0.000} ms | End-to-end {3:0.000} ms' -f `
                    $observation.StartedUtc, $observation.ReceivedUtc,
                    $observation.ClientProcessingDelayMs, $observation.EndToEndTimeMs)
                Write-Host ('  Parser queue {0:0.000} ms | Parse {1:0.000} ms | Continuation {2:0.000} ms | Timing source: {3}' -f `
                    $observation.ParserQueueDelayMs, $observation.ParseDurationMs,
                    $observation.ContinuationDelayMs, $observation.TimingSource)
            }

            if ($Summary.TotalDegradationIncidents -eq 0) {
                Write-Host 'NO OBJECTIVE BREACH - isolated maxima remain available in the summary and CSV.' -ForegroundColor Green
                return
            }

            Write-Host ('DEGRADATION DETECTED: {0:n0} incident(s) across {1:n0} qualifying server/FQDN spike(s).' -f `
                $Summary.TotalDegradationIncidents, $Summary.TotalDegradationEvents) -ForegroundColor Yellow
            Write-Host 'PRIMARY SCOPE counts servers whose server/FQDN cells independently breached an objective.'
            Write-Host 'Paired-round evidence reports simultaneous peer latency and observer overlap separately; it does not change primary scope.'

            $header = (Format-FixedText 'ID' 3) + ' ' + (Format-FixedText 'START UTC' 12) + ' ' + `
                (Format-FixedText 'END UTC' 12) + (' {0,9} ' -f 'ACTIVE MS') + `
                (Format-FixedText 'PRIMARY SCOPE' 14) + `
                (' {0,8} {1,7} {2,10} {3,10} {4,8} {5,10} {6,7} {7,10} {8,8} {9,14} {10,16}' -f `
                    'SERVERS','FQDNS','AFFECTED','EVALUATED','TIMEOUT','DNS RCODE','OTHER',
                    '10-49 MS','50+ MS','MAX LATENCY MS','MAX SCHED LAG MS')
            Write-Host $header
            Write-Host ('-' * $header.Length) -ForegroundColor DarkGray
            foreach ($incident in $Summary.DegradationIncidents) {
                $serverCount = ('{0}/{1}' -f $incident.AffectedEndpointCount, $incident.TotalEndpoints)
                $fqdnCount = ('{0}/{1}' -f $incident.AffectedNameCount, $incident.TotalNames)
                $row = (Format-FixedText ([string]$incident.IncidentNumber) 3) + ' ' + `
                    (Format-FixedText ($incident.StartUtc.ToString('HH:mm:ss.fff')) 12) + ' ' + `
                    (Format-FixedText ($incident.EndUtc.ToString('HH:mm:ss.fff')) 12) + `
                    (' {0,9:0} ' -f $incident.DurationMs) + `
                    (Format-FixedText $incident.PrimaryScope 14) + `
                    (' {0,8} {1,7} {2,10:n0} {3,10:n0} {4,8:n0} {5,10:n0} {6,7:n0} {7,10:n0} {8,8:n0} {9,14:0.000} {10,16:0.000}' -f `
                        $serverCount, $fqdnCount, $incident.AffectedQueries,
                        $incident.EvaluatedQueries, $incident.Timeouts, $incident.DnsErrors,
                        $incident.OtherFailures, $incident.Slow10To49Ms,
                        $incident.Slow50MsOrMore, $incident.MaxResponseMs,
                        $incident.MaxSchedulerLagMs)
                Write-Host $row
                $serverList = @($incident.DNS_Servers | ForEach-Object { Get-ShortServerName $_ }) -join ', '
                Write-Host ('  Incident {0} pair spikes: {1:n0} | Servers: {2}' -f `
                    $incident.IncidentNumber, $incident.PairEventCount, $serverList)
                Write-Host ('  FQDNs: ' + (@($incident.FQDNs) -join ', '))
                Write-Host ('  Paired-round evidence: endpoint-only {0}; peer-overlapped {1}; majority-overlapped {2}.' -f `
                    (Format-RoundFraction $incident.EndpointOnlyRounds $incident.AffectedRoundCount),
                    (Format-RoundFraction $incident.SharedSlowRounds $incident.AffectedRoundCount),
                    (Format-RoundFraction $incident.MajoritySlowRounds $incident.AffectedRoundCount))
                Write-Host ('  Observer overlap: {0} degraded rounds; {1} peer-overlapped rounds; peak simultaneous endpoints {2}/{3}.' -f `
                    (Format-RoundFraction $incident.ObserverSuspectRounds $incident.AffectedRoundCount),
                    (Format-RoundFraction $incident.ObserverSharedRounds $incident.SharedSlowRounds),
                    $incident.PeakAffectedEndpoints, $incident.TotalEndpoints)
            }
            if ($Summary.OmittedDegradationIncidents -gt 0) {
                Write-Host ('{0:n0} additional incident(s) omitted; the most severe {1:n0} are shown.' -f `
                    $Summary.OmittedDegradationIncidents, $Summary.DegradationIncidents.Count) -ForegroundColor Yellow
            }
            Write-Host 'AFFECTED is query failures plus successful responses of at least 10 ms.'
            Write-Host 'EVALUATED is the query count in the qualifying per-server/FQDN evaluation buckets.'
            Write-Host '10-49 MS and 50+ MS are mutually exclusive successful-response counts; failure columns are separate.'
            Write-Host 'ACTIVE MS uses the first and last violating observations and ends when a complete one-second bucket is clean.'
            Write-Host 'Primary scope and paired-round evidence describe measured timing only; neither claims a DNS, server, security, load-balancer, or network root cause.'
        }

        function Write-FinalSummary {
            param([Parameter(Mandatory)]$Summary, [bool]$Redraw, [bool]$IsIse)
            if ($Redraw) { Clear-DashboardHost -IsIse $IsIse }
            $overall = $Summary.OverallMetrics
            $timing = $Summary.Timing
            Write-Host 'DNS PERFORMANCE TEST SUMMARY' -ForegroundColor Cyan
            Write-Host ('Endpoints: {0}   Names: {1}   Query type: {2}   Duration: {3}s' -f `
                $Summary.Configuration.DNS_Server_Endpoints.Count, $Summary.Configuration.FQDNs.Count,
                $Summary.Configuration.QueryType, $Summary.Configuration.DurationSeconds)
            Write-Host ('Start UTC: {0:yyyy-MM-dd HH:mm:ss.fff}   End UTC: {1:yyyy-MM-dd HH:mm:ss.fff}   Elapsed: {2:0.000}s' -f `
                $timing.StartUtc, $timing.EndUtc, $timing.TotalElapsedSeconds)
            Write-Host ('Target: {0} QPS/server x {1} endpoints = {2} aggregate QPS   Offered aggregate QPS: {3:0.000}' -f `
                $Summary.Configuration.QueriesPerSecondPerServer,
                $Summary.Configuration.DNS_Server_Endpoints.Count,
                $Summary.Configuration.TargetAggregateQps, $timing.OfferedAggregateQps)
            Write-Host ('Completion throughput: {0:0.000} QPS' -f $timing.CompletionThroughputQps)
            Write-Host ('Planned: {0:n0}   Sent: {1:n0}   Not sent: {2:n0}   Scheduler misses: {3:n0}   Concurrency drops: {4:n0}' -f `
                $overall.Planned, $overall.Sent, $overall.NotSent, $overall.SchedulerMiss, $overall.ConcurrencyDrop)
            Write-Host ('Responses: {0:n0} ({1:0.000}%)   Successful: {2:n0} ({3:0.000}%)   Timeouts: {4:n0}   DNS RCODE errors: {5:n0}   Other failures: {6:n0}' -f `
                $overall.ResponseReceived, $overall.ResponseRatePercent, $overall.Success,
                $overall.SuccessRatePercent, $overall.Timeout, $overall.DnsError, $overall.OtherFailure)
            Write-Host ('Successful socket-observed response latency ms - Min: {0}   Avg: {1}   StdDev: {2}   P50: {3}   P95: {4}   P99: {5}   Max: {6}' -f `
                (Format-MetricNumber $overall.MinMs '0.000'), (Format-MetricNumber $overall.AverageMs '0.000'),
                (Format-MetricNumber $overall.StdDevMs '0.000'), (Format-MetricNumber $overall.P50Ms '0.000'),
                (Format-MetricNumber $overall.P95Ms '0.000'), (Format-MetricNumber $overall.P99Ms '0.000'),
                (Format-MetricNumber $overall.MaxMs '0.000'))
            Write-Host ('Client processing delay ms - Avg: {0}   P95: {1}   P99: {2}   Max: {3}' -f `
                (Format-MetricNumber $overall.ClientProcessingAverageMs '0.000'),
                (Format-MetricNumber $overall.ClientProcessingP95Ms '0.000'),
                (Format-MetricNumber $overall.ClientProcessingP99Ms '0.000'),
                (Format-MetricNumber $overall.ClientProcessingMaxMs '0.000'))
            Write-Host ('TCP fallbacks: {0:n0}   Maximum scheduler lag: {1} ms' -f `
                $overall.TcpFallback, (Format-MetricNumber $overall.MaxSchedulerLagMs '0.000'))
            if ($Summary.StatusCounts.Count -gt 0) {
                Write-Host ('Status counts: ' + (($Summary.StatusCounts | ForEach-Object { '{0}={1:n0}' -f $_.Status, $_.Count }) -join '; '))
            }
            if ($Summary.RCodeCounts.Count -gt 0) {
                Write-Host ('RCODE counts:  ' + (($Summary.RCodeCounts | ForEach-Object { '{0}={1:n0}' -f $_.RCode, $_.Count }) -join '; '))
            }

            Write-ObserverHealth -Summary $Summary

            Write-MetricTable -Title 'PER-SERVER SUMMARY' -Rows $Summary.PerServerMetrics -NameProperty 'DNS_Server' -NameWidth 40
            Write-MetricTable -Title 'PER-FQDN SUMMARY' -Rows $Summary.PerFQDNMetrics -NameProperty 'FQDN' -NameWidth 45
            Write-CellMatrix -Title 'SERVER x FQDN LATENCY' `
                -PerServerFqdn $Summary.PerServerFQDNMetrics `
                -ServerNames $Summary.Configuration.DNS_Server_Endpoints.Label `
                -Names $Summary.Configuration.FQDNs -Mode AverageP95
            Write-CellMatrix -Title 'SERVER x FQDN TAIL/SUCCESS' `
                -PerServerFqdn $Summary.PerServerFQDNMetrics `
                -ServerNames $Summary.Configuration.DNS_Server_Endpoints.Label `
                -Names $Summary.Configuration.FQDNs -Mode P99Success
            if ($Summary.CsvOutputPath) { Write-Host ''; Write-Host ('Detailed CSV: ' + $Summary.CsvOutputPath) }
            Write-DegradationTable -Summary $Summary
        }
    }

    process {
        $normalizedNames = New-Object 'System.Collections.Generic.List[string]'
        $nameSet = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        foreach ($name in $FQDNs) {
            try { $normalized = [DnsPerformanceV350.DnsWire]::NormalizeName($name) }
            catch { throw "Invalid FQDN '$name': $($_.Exception.Message)" }
            if ($nameSet.Add($normalized)) { $normalizedNames.Add($normalized) }
        }

        $targets = New-Object 'System.Collections.Generic.List[DnsPerformanceV350.DnsTarget]'
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
                $targets.Add((New-Object DnsPerformanceV350.DnsTarget -ArgumentList $label, $addressText))
            }
        }
        if ($targets.Count -eq 0) { throw 'No unique DNS server endpoints remain after resolution.' }
        if ($targets.Count -gt 64) { throw 'A maximum of 64 resolved DNS endpoints is supported.' }

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

        $options = New-Object DnsPerformanceV350.RunnerOptions
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

        $queryTypeCode = [DnsPerformanceV350.DnsWire]::GetQueryTypeCode($QueryType)
        $runner = [DnsPerformanceV350.DnsLoadRunner]::Create(
            $targets.ToArray(), $normalizedNames.ToArray(), $queryTypeCode, $options)
        $cancellation = New-Object System.Threading.CancellationTokenSource
        $runnerTask = $null
        $completion = $null
        $finalSnapshot = $null
        $isIse = ($Host.Name -eq 'Windows PowerShell ISE Host') -or ($null -ne (Get-Variable psISE -Scope Global -ErrorAction SilentlyContinue))
        $outputRedirected = $false
        try {
            if (-not $isIse) { $outputRedirected = [Console]::IsOutputRedirected }
        } catch { }
        $dashboardRenderingMode = if ($isIse -or ($Host.Name -eq 'ConsoleHost' -and -not $outputRedirected)) {
            'Redraw'
        } else {
            'Append'
        }

        try {
            $runnerTask = $runner.RunAsync($cancellation.Token)
            $live = $runner.GetLiveSnapshot($RollingWindowSeconds)
            $lines = Get-DashboardLines -Snapshot $live -Progress $runner.Progress `
                -Names $normalizedNames.ToArray() -TargetAggregateQps $aggregateQps `
                -PerServerQps $QueriesPerSecond -Duration $DurationSeconds `
                -EndpointCount $targets.Count -Planned $plannedQueries `
                -OutstandingLimit $MaxOutstandingPerServer
            Show-Dashboard -Lines $lines -Mode $dashboardRenderingMode -IsIse $isIse -ErrorAction Stop
            $displayTimer = [Diagnostics.Stopwatch]::StartNew()
            while (-not $runnerTask.IsCompleted) {
                if ($displayTimer.Elapsed.TotalSeconds -ge $DisplayIntervalSeconds) {
                    $live = $runner.GetLiveSnapshot($RollingWindowSeconds)
                    $lines = Get-DashboardLines -Snapshot $live -Progress $runner.Progress `
                        -Names $normalizedNames.ToArray() -TargetAggregateQps $aggregateQps `
                        -PerServerQps $QueriesPerSecond -Duration $DurationSeconds `
                        -EndpointCount $targets.Count -Planned $plannedQueries `
                        -OutstandingLimit $MaxOutstandingPerServer
                    Show-Dashboard -Lines $lines -Mode $dashboardRenderingMode -IsIse $isIse -ErrorAction Stop
                    $displayTimer.Restart()
                }
                Start-Sleep -Milliseconds 50
            }
            $completion = $runnerTask.GetAwaiter().GetResult()
            $finalSnapshot = $runner.GetFinalSnapshot()
        } finally {
            if ($null -ne $runnerTask -and -not $runnerTask.IsCompleted) {
                $cancellation.Cancel()
                try { $runnerTask.Wait(3000) } catch { }
            }
            $cancellation.Dispose()
            if ($null -ne $runner) { $runner.Dispose() }
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
            Convert-MetricSnapshot -Metric $item.Metrics -NameProperty 'DNS_Server' `
                -Name $item.Server -Address $item.ServerAddress -FQDN $item.QueryName
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
