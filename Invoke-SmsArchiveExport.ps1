<#
.SYNOPSIS
    High-performance .NET-based class for processing massive SMS Backup & Restore XML files.
.DESCRIPTION
    Encapsulates logic to stream 10GB+ XML files using XmlReader and StreamWriter.
    Includes features from smsviewer for better normalization, and
    uses Chart.js for visual summaries.

    Alignment is always driven by msg_box on the source phone:
        msg_box = 2  -> Sent     -> right
        msg_box = 1  -> Received -> left

    Sent messages can be labeled with OwnerName when the backup phone owner
    should be explicit in the on-screen archive and printed scrapbook output.
    If OwnerName is omitted, sent messages remain unlabeled as before.

    PhoneNumber accepts an array of strings, hashtables, or a mix of both.
    Hashtable entries must contain a 'Number' key and may contain optional
    'Name' and 'Color' keys:

        "7701234567"
        @{ Number = "7701234567"; Name = "Ryan" }
        @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }

    Key priority rules:
        Name  — Used as the sender label on received messages. Takes priority
                over contact_name values in the XML.
        Color — Sets the initial received-bubble background color for this
                participant. Must be a valid CSS hex color (e.g. "#1a73e8").
                If omitted, the default grey (#e4e6eb) is used. All bubble
                colors — including the sent (owner) color — can be changed
                live in the rendered HTML via per-participant color pickers.

    The array length drives mode automatically:

        1 entry   — 1:1 mode. Only SMS/MMS threads with exactly two participants
                    where the supplied number is one of them are included.

        2+ entries — Group mode. Only MMS threads whose participant list contains
                     all supplied numbers are included. The participant check
                     counts unique normalized real phone numbers and tolerates
                     either target count or target count plus one to handle SMS
                     Backup & Restore owner placeholders / omitted owner addr
                     nodes. 1:1 SMS threads are excluded unconditionally.

    Sender labels on received messages use a stable per-contact color derived
    from the addr type=137 (FROM) node so each participant is visually distinct.

.PARAMETER Path
    Full or relative path to the SMS Backup & Restore XML file to process.
    Must exist and be readable. Files in excess of 10GB are supported via streaming.

.PARAMETER PhoneNumber
    One or more phone numbers identifying the conversation to extract. Accepts
    strings, hashtables with 'Number', optional 'Name', and optional 'Color'
    keys, or a mix of both. The count drives mode: 1 entry = 1:1 mode, 2+ = group.

    Formatting is flexible — values are normalized before matching:
        "7701234567", "770-123-4567", "+1 (770) 123-4567" all resolve identically.

    Name  — Overrides the sender label shown in the HTML output.
    Color — Sets the initial bubble background color for this participant.
            Valid CSS hex format: "#rrggbb". Changeable live in the HTML.

.PARAMETER OwnerName
    Optional display name for the backup phone owner. When supplied, this label
    appears on sent messages, in the participant/color controls, and in scrapbook
    print output. When omitted, sent messages remain unlabeled and the sent-message
    color control is labeled "Sent Messages".

.PARAMETER ContactFilter
    Filters messages by whether the sender has a resolved contact name in the backup.
    "All"     — No filter applied. Default.
    "Named"   — Include only messages where contact_name is populated and not "(Unknown)".
    "Unknown" — Include only messages where contact_name is empty or "(Unknown)".

.PARAMETER Keyword
    A string or .NET regular expression matched against message body text.
    Only messages whose body contains a match are included.

.PARAMETER StartDate
    Inclusive lower bound on message date. Defaults to [datetime]::MinValue.

.PARAMETER EndDate
    Inclusive upper bound on message date. Defaults to [datetime]::MaxValue.

.PARAMETER OutPath
    Full path for the generated HTML output file. If omitted the file is written
    to the same directory as the source XML named SMS_Export_yyyyMMdd_HHmm.html.

.OUTPUTS
    PSCustomObject:
        Success    [bool]     — True if export completed without error.
        Matched    [int]      — Number of messages written to the output file.
        OutputPath [string]   — Resolved path of the generated HTML file.
        Duration   [TimeSpan] — Wall-clock time elapsed during processing.

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 1 — 1:1 thread, number only
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @("7701234567")
        OutPath     = "C:\Reports\Thread_Ryan.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 2 — 1:1 thread, number with friendly name
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan" }
        )
        OutPath     = "C:\Reports\Thread_Ryan.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 3 — 1:1 thread, custom bubble color baked into HTML
    # -----------------------------------------------------------------------
    # Received bubbles open pre-colored #1a73e8 (Google blue). The color picker
    # in the rendered HTML can override this at any time without re-exporting.

    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
        )
        OutPath     = "C:\Reports\Thread_Ryan.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 4 — Group chat, numbers only
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @("7701234567", "4045559876")
        OutPath     = "C:\Reports\Group_Ryan_Dad.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 5 — Group chat, all entries with friendly names and colors
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
            @{ Number = "4045559876"; Name = "Dad";  Color = "#e67e22" }
        )
        OutPath     = "C:\Reports\Group_Ryan_Dad.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 6 — Group chat, mixed strings and hashtables
    # -----------------------------------------------------------------------
    # Name and Color are optional per entry. Entries without a Color fall back
    # to the default grey (#e4e6eb). Entries without a Name fall back to
    # contact_name from the XML, then the raw number.

    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
            "4045559876"
        )
        OutPath     = "C:\Reports\Group_Ryan_Dad.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 7 — Date range filter
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
            @{ Number = "4045559876"; Name = "Dad";  Color = "#e67e22" }
        )
        StartDate   = "2024-01-01"
        EndDate     = "2024-12-31"
        OutPath     = "C:\Reports\Group_2024.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 8 — Keyword filter with regex
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan" }
            @{ Number = "4045559876"; Name = "Dad"  }
        )
        Keyword     = "dinner|lunch|restaurant"
        OutPath     = "C:\Reports\Group_Food.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 9 — All filters combined
    # -----------------------------------------------------------------------
    $Params = @{
        Path          = "C:\Backups\sms-20260428.xml"
        PhoneNumber   = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
            @{ Number = "4045559876"; Name = "Dad";  Color = "#e67e22" }
        )
        ContactFilter = "Named"
        Keyword       = "Christmas|Thanksgiving"
        StartDate     = "2020-01-01"
        EndDate       = "2025-12-31"
        OutPath       = "C:\Reports\Holidays.html"
    }
    Invoke-SmsArchiveExport @Params

.EXAMPLE
    # -----------------------------------------------------------------------
    # EXAMPLE 10 — Capturing and inspecting the return object
    # -----------------------------------------------------------------------
    $Params = @{
        Path        = "C:\Backups\sms-20260428.xml"
        PhoneNumber = @(
            @{ Number = "7701234567"; Name = "Ryan"; Color = "#1a73e8" }
            @{ Number = "4045559876"; Name = "Dad";  Color = "#e67e22" }
        )
        OutPath     = "C:\Reports\Group_Ryan_Dad.html"
    }
    $Result = Invoke-SmsArchiveExport @Params

    if ($Result.Success) {
        Write-Host "$($Result.Matched) messages exported in $($Result.Duration.TotalSeconds)s"
        Write-Host "Output: $($Result.OutputPath)"
    }

.NOTES
    Author      : Ryan Whitlock
    Format      : SMS Backup & Restore for Android (XML)
    Tested on   : PowerShell 5.1, PowerShell 7.x
    Performance : ~5,000 messages/sec on spinning disk; faster on SSD.

    HTML INTERACTIVE FEATURES (no re-export required):
    The rendered HTML file includes a collapsible "Filters & Appearance" panel:
        - Keyword / Regex search  — live filter with yellow highlight on matches.
                                    Accepts any .NET/JS-compatible regular expression.
        - Full matching days      — Optional. When enabled, a keyword match shows
                                    the entire calendar day containing that match.
                                    Useful for birthdays, holidays, and days with
                                    photo-only MMS messages near matching text.
        - Date range pickers      — From / To inputs default to the full span of
                                    messages in the export. Change either to narrow
                                    the visible window.
        - Participant toggles     — Per-sender checkbox to show or hide that person's
                                    messages entirely. Useful for isolating one speaker
                                    in a group thread.
        - Bubble color pickers    — One color swatch per participant plus one for the
                                    backup owner/sent messages. Colors update live.
                                    The sent message text color auto-adjusts for
                                    contrast when you pick a light background.
        - Owner labels            — Optional. When OwnerName is supplied, sent
                                    messages are labeled with that name so the
                                    scrapbook clearly shows who wrote them.
                                    When omitted, sent messages remain unlabeled.
        - Message counter         — Live "X of Y messages" badge updates with every
                                    filter change and includes the current
                                    scrapbook-selection count.
        - Monthly chart navigation — Clicking a bar scrolls to the first message
                                    in that month, making long archives easier
                                    to browse.
        - Scrapbook selection     — Each message has an "Add to Scrapbook"
                                    checkbox. Use it to choose the messages that
                                    should appear in the scrapbook printout.
        - Scrapbook printing      — The Print Scrapbook button prints only the
                                    messages selected for the scrapbook. The chart,
                                    filter details, controls, and selection
                                    checkboxes are hidden automatically in print.
        - Reset buttons           — The main Reset button restores date range,
                                    clears keyword, un-hides all senders, and
                                    exits Scrapbook Only review mode. It leaves
                                    scrapbook selections as-is. Each participant
                                    color picker has its own Reset button that
                                    restores that participant's exported default
                                    bubble color.

    PHONE MATCHING NOTE:
    The normalizer strips leading zeros and common country code prefixes.
    If a known contact returns zero results, try passing just the last
    7 or 10 digits to widen the match.

    KEYWORD NOTE:
    The Keyword parameter (PS-side) is evaluated as a .NET regular expression via
    PowerShell's -match operator. The HTML keyword filter uses the browser's JS
    RegExp engine. Both accept the same regex syntax in practice. Literal strings
    containing special regex characters (. * + ? [ ] { } ( ) ^ $ | \) should be
    escaped with backslashes or wrapped with [regex]::Escape() on the PS side.

    In the rendered HTML, the "Show full days with search matches" checkbox
    changes keyword filtering from exact-message matches to whole-day matches.
    If one visible message on a calendar day matches the keyword, all messages
    from that same day are shown so photo-only MMS messages and nearby replies
    are easier to find.

    GROUP MODE PARTICIPANT COUNT NOTE:
    MMS participant checks count unique normalized real phone numbers, not raw
    addr nodes. Group mode requires all supplied targets to be present and allows
    the unique participant count to be either TargetPhones.Length or
    TargetPhones.Length + 1. This handles backups where the owner is omitted or
    represented by a placeholder. Without an explicit OwnerPhoneNumber parameter,
    group matching is strict enough for practical use but cannot mathematically
    prove the extra participant is the owner.
#>
class SmsArchiveProcessor {
    [string[]]$TargetPhones
    [string[]]$NormalizedTargets
    [string[]]$EscapedTargets
    [string]$Path
    [string]$ContactFilter = "All"
    [string]$Keyword
    [string]$OwnerName = ""
    [datetime]$StartDate = [datetime]::MinValue
    [datetime]$EndDate   = [datetime]::MaxValue
    [long]$FileSize      = 0
    [bool]$GroupMode     = $false

    [System.Collections.Generic.List[PSCustomObject]]$MessageList
    [System.Collections.Specialized.OrderedDictionary]$Stats
    [System.Collections.Generic.Dictionary[string,string]]$SenderColorMap

    # Supplied friendly names keyed on normalized number. Populated at
    # construction time from hashtable entries in the PhoneNumber parameter.
    # Consulted first when building sender labels; falls back to contact_name
    # from the XML, then raw address.
    [System.Collections.Generic.Dictionary[string,string]]$DisplayNameMap

    # Supplied initial bubble colors keyed on normalized number. Populated at
    # construction time from 'Color' keys in PhoneNumber hashtable entries.
    # Sets the inline background-color style on each received message div.
    # When absent for a given sender the default grey (#e4e6eb) is used.
    # All colors can be overridden live in the HTML via the color picker panel.
    [System.Collections.Generic.Dictionary[string,string]]$DisplayColorMap

    # Fixed palette assigned round-robin as new senders are first encountered.
    # Chosen to be legible against the light grey received-bubble background.
    hidden [string[]]$ColorPalette = @(
        '#c0392b',  # red
        '#8e44ad',  # purple
        '#16a085',  # teal
        '#d35400',  # orange
        '#27ae60',  # green
        '#2980b9'   # blue
    )

    SmsArchiveProcessor([string]$XmlPath, [object[]]$Phones) {
        if (-not (Test-Path $XmlPath)) {
            throw "Source XML file not found at $XmlPath"
        }

        $this.Path            = $XmlPath
        $this.FileSize        = (Get-Item $XmlPath).Length
        $this.MessageList     = New-Object 'System.Collections.Generic.List[PSCustomObject]'
        $this.Stats           = New-Object System.Collections.Specialized.OrderedDictionary
        $this.SenderColorMap  = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $this.DisplayNameMap  = New-Object 'System.Collections.Generic.Dictionary[string,string]'
        $this.DisplayColorMap = New-Object 'System.Collections.Generic.Dictionary[string,string]'

        # Unpack each entry: strings are treated as number-only; hashtables
        # must contain a 'Number' key and may contain optional 'Name' and
        # 'Color' keys. All derived forms are computed once here rather than
        # per-message.
        $RawNumbers = [System.Collections.Generic.List[string]]::new()

        foreach ($Entry in $Phones) {
            if ($Entry -is [hashtable]) {
                if (-not $Entry.ContainsKey('Number')) {
                    throw "PhoneNumber hashtable entry is missing required 'Number' key: $Entry"
                }
                $Raw  = [string]$Entry['Number']
                $Norm = $this.NormalizePhone($Raw)
                $RawNumbers.Add($Raw)

                if ($Entry.ContainsKey('Name') -and -not [string]::IsNullOrEmpty($Entry['Name'])) {
                    $this.DisplayNameMap[$Norm] = [string]$Entry['Name']
                }

                # Optional Color key: must be a CSS hex color, e.g. "#1a73e8".
                # Applied as the initial received-bubble background in the HTML.
                if ($Entry.ContainsKey('Color') -and -not [string]::IsNullOrEmpty($Entry['Color'])) {
                    $Color = [string]$Entry['Color']

                    if (-not $this.IsValidHexColor($Color)) {
                        throw "Invalid Color value '$Color' for phone number '$Raw'. Expected format is '#rrggbb'."
                    }

                    $this.DisplayColorMap[$Norm] = $Color
                }
            } else {
                $Raw  = [string]$Entry
                $RawNumbers.Add($Raw)
            }
        }

        $this.TargetPhones      = $RawNumbers.ToArray()
        $this.NormalizedTargets = $this.TargetPhones | ForEach-Object { $this.NormalizePhone($_) }
        $this.EscapedTargets    = $this.NormalizedTargets | ForEach-Object { [regex]::Escape($_) }
        $this.GroupMode         = $this.TargetPhones.Length -gt 1
    }

    # Enhanced normalization logic adapted from smsviewer/script.js.
    hidden [string] NormalizePhone([string]$Phone) {
        if ([string]::IsNullOrEmpty($Phone)) { return "" }
        $Clean = $Phone -replace '[^\d]', ''
        if ([string]::IsNullOrEmpty($Clean)) { return "" }
        if ($Clean -match '^00(.+)$') { $Clean = $Matches[1] }
        if ($Clean.Length -eq 11 -and $Clean.StartsWith('1')) { $Clean = $Clean.Substring(1) }
        $Clean = $Clean -replace '^0', ''
        return $Clean
    }

    # Validates the optional PhoneNumber hashtable Color value before it is
    # embedded into CSS and HTML color input controls.
    hidden [bool] IsValidHexColor([string]$Color) {
        return ($Color -match '^#[0-9A-Fa-f]{6}$')
    }

    hidden [string] GetSenderColor([string]$NormalizedAddr) {
        if (-not $this.SenderColorMap.ContainsKey($NormalizedAddr)) {
            $Index = $this.SenderColorMap.Count % $this.ColorPalette.Length
            $this.SenderColorMap[$NormalizedAddr] = $this.ColorPalette[$Index]
        }
        return $this.SenderColorMap[$NormalizedAddr]
    }

    hidden [string] ResolveSenderName([string]$NormalizedAddr, [string]$XmlContactName, [string]$RawAddr) {
        if ($this.DisplayNameMap.ContainsKey($NormalizedAddr)) { return $this.DisplayNameMap[$NormalizedAddr] }
        if (-not [string]::IsNullOrEmpty($XmlContactName) -and $XmlContactName -ne "(Unknown)") { return $XmlContactName }
        return $RawAddr
    }

    [PSCustomObject] ExportHtml([string]$OutputPath) {
        $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $Reader    = [System.Xml.XmlReader]::Create($this.Path)

        try {
            while ($Reader.Read()) {
                if ($Reader.NodeType -eq [System.Xml.XmlNodeType]::Element -and
                    ($Reader.Name -eq "sms" -or $Reader.Name -eq "mms")) {
                    $this.ProcessNode($Reader)

                    if ($this.MessageList.Count % 5000 -eq 0 -and $this.MessageList.Count -ne 0) {
                        Write-Progress -Activity "Parsing Archive" `
                                       -Status "Loaded $($this.MessageList.Count) messages..."
                    }
                }
            }

            Write-Progress -Activity "Parsing Archive" -Completed

            # NOTE: Stats and SenderColorMap must be fully populated before
            # WriteHeader is called — it embeds chart data and the participants
            # JS constant inline. Do not reorder these calls.
            $Writer = New-Object System.IO.StreamWriter($OutputPath, $false, [System.Text.Encoding]::UTF8)
            try {
                $this.WriteHeader($Writer)
                $Sorted = $this.MessageList | Sort-Object Date
                foreach ($Msg in $Sorted) { $Writer.WriteLine($Msg.Html) }
                $this.WriteFooter($Writer)
            } finally {
                $Writer.Dispose()
            }

            return [PSCustomObject]@{
                Success    = $true
                Matched    = $this.MessageList.Count
                OutputPath = $OutputPath
                Duration   = $Stopwatch.Elapsed
            }
        } finally {
            $Reader.Dispose()
            $Stopwatch.Stop()
        }
    }

    hidden [void] ProcessNode([System.Xml.XmlReader]$Reader) {
        $Addr        = $Reader.GetAttribute("address")
        $Body        = $Reader.GetAttribute("body")
        $UnixMs      = [long]$Reader.GetAttribute("date")
        $ReadDate    = $Reader.GetAttribute("readable_date")
        $ContactName = $Reader.GetAttribute("contact_name")
        $MsgDate     = [datetimeoffset]::FromUnixTimeMilliseconds($UnixMs).DateTime
        $IsMms       = $Reader.Name -eq "mms"

        if ($MsgDate -lt $this.StartDate -or $MsgDate -gt $this.EndDate) { return }
        if ($this.GroupMode -and -not $IsMms) { return }

        if ($this.ContactFilter -ne "All") {
            $IsNamed = (
                -not [string]::IsNullOrEmpty($ContactName) -and
                $ContactName -ne "(Unknown)"
            )
            if ($this.ContactFilter -eq "Named"   -and -not $IsNamed) { return }
            if ($this.ContactFilter -eq "Unknown" -and $IsNamed)      { return }
        }

        $IsSentByOwner = (
            $Reader.GetAttribute("type")    -eq "2" -or
            $Reader.GetAttribute("msg_box") -eq "2"
        )

        $MediaHtml   = ""
        $FromNorm    = ""
        $FromXmlName = ""
        $FromRawAddr = ""

        $MatchedTargets           = New-Object 'System.Collections.Generic.HashSet[int]'
        $UniqueParticipantNumbers = New-Object 'System.Collections.Generic.HashSet[string]'
        $ParticipantCount         = 0

        if ($IsMms) {
            $SubReader = $Reader.ReadSubtree()

            try {
                while ($SubReader.Read()) {
                    if ($SubReader.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }

                    if ($SubReader.Name -eq "part") {
                        $CT = $SubReader.GetAttribute("ct")

                        if ($CT -eq "text/plain") {
                            $PartText = $SubReader.GetAttribute("text")
                            if (-not [string]::IsNullOrEmpty($PartText) -and $PartText -ne $Body) {
                                $Body += $PartText
                            }
                        } elseif ($CT -like "image/*") {
                            $Base = $SubReader.GetAttribute("data")
                            if (-not [string]::IsNullOrEmpty($Base)) {
                                $MediaHtml += "<img src='data:$CT;base64,$Base' class='img-fluid rounded mt-2 d-block' style='max-height:400px;'>"
                            }
                        }
                    }

                    if ($SubReader.Name -eq "addr") {
                        $AddrVal  = $SubReader.GetAttribute("address")
                        $AddrName = $SubReader.GetAttribute("contact_name")
                        $AddrType = $SubReader.GetAttribute("type")
                        $NormAddr = $this.NormalizePhone($AddrVal)

                        if (-not [string]::IsNullOrEmpty($NormAddr)) {
                            [void]$UniqueParticipantNumbers.Add($NormAddr)
                        }

                        if ($AddrType -eq "137") {
                            $FromNorm    = $NormAddr
                            $FromXmlName = $AddrName
                            $FromRawAddr = $AddrVal
                        }

                        for ($i = 0; $i -lt $this.EscapedTargets.Length; $i++) {
                            if ($NormAddr -match $this.EscapedTargets[$i]) {
                                [void]$MatchedTargets.Add($i)
                            }
                        }
                    }
                }
            } finally {
                $SubReader.Dispose()
            }

            $ParticipantCount = $UniqueParticipantNumbers.Count
        } else {
            $NormAddr = $this.NormalizePhone($Addr)
            if (-not [string]::IsNullOrEmpty($NormAddr)) { [void]$UniqueParticipantNumbers.Add($NormAddr) }
            for ($i = 0; $i -lt $this.EscapedTargets.Length; $i++) {
                if ($NormAddr -match $this.EscapedTargets[$i]) { [void]$MatchedTargets.Add($i) }
            }
            $ParticipantCount = 2
        }

        $AllTargetsMatched = ($MatchedTargets.Count -eq $this.EscapedTargets.Length)

        if ($this.GroupMode) {
            $ExactCount = (
                $ParticipantCount -ge $this.EscapedTargets.Length -and
                $ParticipantCount -le $this.EscapedTargets.Length + 1
            )
        } else {
            $ExactCount = ($ParticipantCount -ge 1 -and $ParticipantCount -le 2)
        }

        if (-not $AllTargetsMatched -or -not $ExactCount) { return }
        if (-not [string]::IsNullOrEmpty($this.Keyword) -and $Body -notmatch $this.Keyword) { return }

        $Css = if ($IsSentByOwner) { "sent" } else { "received" }

        $SenderLabelHtml = ""

        if ($IsSentByOwner) {
            # Sent messages belong to the backup phone owner. Labeling them avoids
            # ambiguity in the scrapbook output, especially when the archive is
            # printed or shared without the on-screen left/right chat context.
            if (-not [string]::IsNullOrWhiteSpace($this.OwnerName)) {
                $SafeOwnerName = [System.Net.WebUtility]::HtmlEncode($this.OwnerName)
                $SenderLabelHtml = "<span class='sender-name owner-sender-name'>$SafeOwnerName</span>"
            }
        } else {
            $LabelText  = ""
            $LabelColor = "#555"

            if ($IsMms -and -not [string]::IsNullOrEmpty($FromNorm)) {
                $LabelText  = [System.Net.WebUtility]::HtmlEncode(
                    $this.ResolveSenderName($FromNorm, $FromXmlName, $FromRawAddr)
                )
                $LabelColor = $this.GetSenderColor($FromNorm)
            } else {
                $NormAddr   = $this.NormalizePhone($Addr)
                $LabelText  = [System.Net.WebUtility]::HtmlEncode(
                    $this.ResolveSenderName($NormAddr, $ContactName, $Addr)
                )
                $LabelColor = $this.GetSenderColor($NormAddr)
            }

            if (-not [string]::IsNullOrEmpty($LabelText)) {
                $SenderLabelHtml = "<span class='sender-name' style='color:$LabelColor'>$LabelText</span>"
            }
        }

        $Key = $MsgDate.ToString("yyyy-MM")
        $this.Stats[$Key] = [int]$this.Stats[$Key] + 1

        # -----------------------------------------------------------------------
        # Resolve the normalized sender identifier used for data-sender and the
        # initial bubble color. This is separate from the label-color logic above
        # so that received-bubble color and sender-name color can diverge.
        #
        #   __owner__  — sent by the backup phone owner (right-side bubbles)
        #   <norm>     — normalized phone number of the received-message sender
        # -----------------------------------------------------------------------
        $ResolvedSenderNorm = if ($IsSentByOwner) {
            "__owner__"
        } elseif ($IsMms -and -not [string]::IsNullOrEmpty($FromNorm)) {
            $FromNorm
        } else {
            $this.NormalizePhone($Addr)
        }

        # Initial bubble background color. PS-supplied Color key takes priority;
        # falls back to messenger blue for sent, light grey for received.
        # The HTML color picker can override this at any time without re-exporting.
        $BubbleColor = if ($IsSentByOwner) {
            "#0084ff"
        } elseif ($this.DisplayColorMap.ContainsKey($ResolvedSenderNorm)) {
            $this.DisplayColorMap[$ResolvedSenderNorm]
        } else {
            "#e4e6eb"
        }

        # "$Body" coerces $null to "" so HtmlEncode never receives a null argument.
        $SafeBody = [System.Net.WebUtility]::HtmlEncode("$Body")

        # data-text stores the body as a single-quote-safe, newline-encoded attribute
        # value so the in-HTML JS filter can search and highlight without needing to
        # re-parse the rendered HTML. The browser decodes the entities back to plain
        # text when JS reads dataset.text, enabling accurate regex matching.
        $DataText = ([System.Net.WebUtility]::HtmlEncode("$Body") `
                      -replace "'",          "&#39;") `
                      -replace "`r`n|`r|`n", "&#10;"

        $DateAttr = $MsgDate.ToString("yyyy-MM-ddTHH:mm:ss")

        # msg-body span is the only mutable message-text region: the JS keyword
        # highlighter rewrites its innerHTML to wrap matches in <mark> tags and
        # restores it when the keyword is cleared. Media, metadata, and scrapbook
        # controls are outside the span and are not touched by the highlighter.
        #
        # The scrapbook checkbox lets the user choose which messages should appear
        # in the scrapbook printout. It is intentionally simple and task-focused.
        $ScrapbookControlHtml = "<label class='scrapbook-control screen-only'><input type='checkbox' class='form-check-input scrapbook-toggle' aria-label='Add this message to scrapbook printout'><span class='scrapbook-label'>Add to Scrapbook</span></label>"
        $Html = "<div class='msg $Css' data-sender='$ResolvedSenderNorm' data-date='$DateAttr' data-text='$DataText' data-scrapbook='false' style='background-color:$BubbleColor;'>$ScrapbookControlHtml$SenderLabelHtml<span class='msg-body'>$SafeBody</span> $MediaHtml <span class='meta'>$ReadDate</span></div>"

        $this.MessageList.Add(
            [PSCustomObject]@{
                Date = $MsgDate
                Html = $Html
            }
        )
    }

    hidden [void] WriteHeader([System.IO.StreamWriter]$Writer) {
        $Labels     = ($this.Stats.Keys   | ForEach-Object { "'$_'" }) -join ","
        $DataValues = ($this.Stats.Values | ForEach-Object { $_ })    -join ","
        $ModeLabel  = if ($this.GroupMode) { "Group Chat" } else { "1:1 Thread" }

        $NumberList = ($this.TargetPhones | ForEach-Object {
            $Norm = $this.NormalizePhone($_)
            if ($this.DisplayNameMap.ContainsKey($Norm)) {
                "$($this.DisplayNameMap[$Norm]) ($_)"
            } else { $_ }
        }) -join ", "

        # Encode user-controlled display values before placing them in HTML.
        # JavaScript data structures are handled separately via ConvertTo-Json.
        $SafeNumberList = [System.Net.WebUtility]::HtmlEncode($NumberList)
        $KeywordDisplay = if ($this.Keyword) { $this.Keyword } else { "None" }
        $SafeKeywordDisplay = [System.Net.WebUtility]::HtmlEncode($KeywordDisplay)

        # -----------------------------------------------------------------------
        # Compute exact date bounds from the exported messages for the HTML date
        # picker defaults. This is more precise than deriving the range from the
        # monthly chart buckets.
        # -----------------------------------------------------------------------
        $DateMin = ""
        $DateMax = ""
        if ($this.MessageList.Count -gt 0) {
            $SortedDates = $this.MessageList | Sort-Object Date
            $DateMin = $SortedDates[0].Date.ToString("yyyy-MM-dd")
            $DateMax = $SortedDates[-1].Date.ToString("yyyy-MM-dd")
        }

        # -----------------------------------------------------------------------
        # Build the participants JS constant as JSON instead of hand-concatenating
        # JavaScript object literals. This avoids edge-case escaping bugs in names
        # that contain quotes, backslashes, newlines, or script-like text.
        #
        # The owner entry is always first so the OwnerName/sent-message color
        # picker appears at the left of the participant row.
        # -----------------------------------------------------------------------
        $Participants = New-Object 'System.Collections.Generic.List[System.Object]'
        $OwnerParticipantLabel = if ([string]::IsNullOrWhiteSpace($this.OwnerName)) {
            "Sent Messages"
        } else {
            "$($this.OwnerName) (Sent)"
        }

        [void]$Participants.Add([ordered]@{
            norm   = "__owner__"
            label  = $OwnerParticipantLabel
            bubble = "#0084ff"
            lc     = "#0084ff"
        })

        foreach ($KV in $this.SenderColorMap.GetEnumerator()) {
            $Norm   = $KV.Key
            $Lc     = $KV.Value
            $Name   = if ($this.DisplayNameMap.ContainsKey($Norm)) { $this.DisplayNameMap[$Norm] } else { $Norm }
            $Bubble = if ($this.DisplayColorMap.ContainsKey($Norm)) { $this.DisplayColorMap[$Norm] } else { "#e4e6eb" }

            [void]$Participants.Add([ordered]@{
                norm   = $Norm
                label  = $Name
                bubble = $Bubble
                lc     = $Lc
            })
        }

        $ParticipantsJson = ConvertTo-Json -InputObject @($Participants.ToArray()) -Compress -Depth 4

        # Prevent any literal </script> sequence inside participant labels from
        # prematurely closing the inline script element.
        $ParticipantsJson = $ParticipantsJson -replace '</', '<\/'

        # -----------------------------------------------------------------------
        # HTML HEAD
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'>")
        $Writer.WriteLine("<title>Archive: $SafeNumberList</title>")
        $Writer.WriteLine("<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css' rel='stylesheet'>")
        $Writer.WriteLine("<script src='https://cdn.jsdelivr.net/npm/chart.js'></script>")
        $Writer.WriteLine("<style>")
        $Writer.WriteLine("body{background:#f0f2f5;padding:40px;font-family:'Segoe UI',system-ui,sans-serif;}")
        $Writer.WriteLine(".chat-card{max-width:900px;margin:auto;background:white;padding:35px;border-radius:20px;box-shadow:0 4px 20px rgba(0,0,0,.08);}")
        $Writer.WriteLine(".filter-banner{background:#e7f3ff;border-radius:12px;padding:15px;margin-bottom:25px;border-left:6px solid #0084ff;}")
        # Background on .sent and .received is intentionally omitted. Each message
        # div carries its own inline background-color so the JS color pickers work
        # without fighting CSS specificity. color:white on .sent is the default text
        # color and is overridden inline by the contrast check when the picker changes.
        $Writer.WriteLine(".msg{margin:12px 0;padding:14px;border-radius:20px;clear:both;max-width:75%;font-size:15px;position:relative;transition:background-color .15s,color .15s;}")
        $Writer.WriteLine(".received{float:left;border-bottom-left-radius:4px;}")
        $Writer.WriteLine(".sent{float:right;border-bottom-right-radius:4px;color:white;}")
        $Writer.WriteLine(".meta{font-size:11px;display:block;opacity:.7;margin-top:8px;font-weight:500;}")
        $Writer.WriteLine(".sender-name{font-size:12px;font-weight:700;display:block;margin-bottom:5px;}")
        $Writer.WriteLine(".owner-sender-name{color:inherit;}")
        $Writer.WriteLine(".chart-container{height:250px;margin-bottom:30px;}")
        $Writer.WriteLine(".doc-title{border-bottom:2px solid #0084ff;padding-bottom:15px;margin-bottom:25px;color:#333;}")
        $Writer.WriteLine("mark.kw-hl{background:#fff176;border-radius:3px;padding:0 2px;color:inherit;}")
        $Writer.WriteLine(".pax-item{display:flex;align-items:center;gap:8px;padding:7px 12px;background:#f8f9fa;border:1px solid #dee2e6;border-radius:10px;white-space:nowrap;}")
        $Writer.WriteLine(".color-swatch{width:28px;height:28px;border-radius:50%;border:2px solid #ccc;padding:2px;cursor:pointer;flex-shrink:0;}")
        $Writer.WriteLine(".color-reset{padding:2px 8px;font-size:11px;line-height:1.3;}")
        $Writer.WriteLine(".scrapbook-control{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:700;margin-bottom:6px;opacity:.78;user-select:none;}")
        $Writer.WriteLine(".scrapbook-control input{margin-top:0;}")
        $Writer.WriteLine(".msg.scrapbook-selected{outline:2px solid #f0ad4e;box-shadow:0 0 0 4px rgba(240,173,78,.18);}")
        $Writer.WriteLine(".msg.nav-flash{outline:3px solid #ffc107;box-shadow:0 0 0 5px rgba(255,193,7,.25);}")
        $Writer.WriteLine(".print-title{display:none;}")
        $Writer.WriteLine(".print-help{font-size:12px;color:#666;}")
        $Writer.WriteLine(".keyword-helper{font-size:11px;color:#666;margin-top:4px;}")
        $Writer.WriteLine("#controls-header{cursor:pointer;user-select:none;}")
        $Writer.WriteLine("@media print{")
        $Writer.WriteLine("  @page{size:letter portrait;margin:.55in;}")
        $Writer.WriteLine("  html,body{background:white!important;padding:0!important;margin:0!important;-webkit-print-color-adjust:exact;print-color-adjust:exact;}")
        $Writer.WriteLine("  .chat-card{max-width:none!important;margin:0!important;padding:0!important;box-shadow:none!important;border-radius:0!important;background:white!important;}")
        $Writer.WriteLine("  .filter-banner,.chart-container,.doc-title,.card,hr.my-4,.text-muted.border-top,.screen-only{display:none!important;}")
        $Writer.WriteLine("  .print-title{display:block!important;text-align:center;font-family:Georgia,'Times New Roman',serif;font-size:22pt;font-weight:700;margin:0 0 18pt 0;color:#222;}")
        $Writer.WriteLine("  .print-title:empty{display:none!important;}")
        $Writer.WriteLine("  body.print-scrapbook-mode .msg:not(.scrapbook-selected){display:none!important;}")
        $Writer.WriteLine("  .msg{break-inside:avoid;page-break-inside:avoid;max-width:78%!important;margin:8pt 0!important;padding:10pt 12pt!important;font-size:12.5pt!important;line-height:1.35!important;box-shadow:none!important;-webkit-print-color-adjust:exact;print-color-adjust:exact;}")
        $Writer.WriteLine("  .sender-name{font-size:10.5pt!important;margin-bottom:4pt!important;}")
        $Writer.WriteLine("  .meta{font-size:8.5pt!important;margin-top:6pt!important;opacity:.75!important;}")
        $Writer.WriteLine("  img{max-width:100%!important;max-height:4.5in!important;break-inside:avoid;page-break-inside:avoid;}")
        $Writer.WriteLine("}")
        $Writer.WriteLine("</style></head><body><div class='chat-card'>")

        # -----------------------------------------------------------------------
        # Page title
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<h1 class='doc-title'>SMS Archive &mdash; $($ModeLabel): $SafeNumberList</h1>")
        $Writer.WriteLine("<h1 class='print-title' id='print-title-output'></h1>")

        # -----------------------------------------------------------------------
        # Static archive-context banner (reflects original PS parameters)
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<div class='filter-banner'>")
        $Writer.WriteLine("<h5 class='mb-1 text-primary'>Archive Context</h5>")
        $Writer.WriteLine("<div class='row small'>")
        $Writer.WriteLine("<div class='col-md-4'><strong>Mode:</strong> $ModeLabel</div>")
        $Writer.WriteLine("<div class='col-md-4'><strong>Participants:</strong> $SafeNumberList</div>")
        $Writer.WriteLine("<div class='col-md-4'><strong>Date Scope:</strong> $($this.StartDate.ToShortDateString()) to $($this.EndDate.ToShortDateString())</div>")
        $Writer.WriteLine("<div class='col-md-4'><strong>Keyword:</strong> $SafeKeywordDisplay</div>")
        $Writer.WriteLine("</div></div>")

        # -----------------------------------------------------------------------
        # Monthly message chart
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<div class='chart-container'><canvas id='msgChart'></canvas></div>")

        # -----------------------------------------------------------------------
        # Interactive controls card, collapsible and open by default
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<div class='card mb-4 border-0 shadow-sm'>")
        $Writer.WriteLine("<div class='card-header bg-white d-flex justify-content-between align-items-center py-2' id='controls-header' onclick='toggleControls()'>")
        $Writer.WriteLine("<span class='fw-semibold text-primary'>&#9776;&nbsp; Filters &amp; Appearance</span>")
        $Writer.WriteLine("<span id='ctrl-chev' style='font-size:11px;color:#888'>&#9650; collapse</span>")
        $Writer.WriteLine("</div>")
        $Writer.WriteLine("<div class='card-body' id='controls-body'>")

        # Row 1: keyword + date range + reset
        $Writer.WriteLine("<div class='row g-2 mb-3'>")
        $Writer.WriteLine("  <div class='col-md-4'><label class='form-label small fw-semibold mb-1'>Keyword / Regex</label><input type='text' class='form-control form-control-sm' id='kw-input' placeholder='Search messages...'><div class='form-check mt-1'><input class='form-check-input' type='checkbox' id='full-day-match' checked><label class='form-check-label small' for='full-day-match'>Show full days with search matches</label></div><div class='keyword-helper'>Helpful for birthdays, holidays, and days with photos.</div></div>")
        $Writer.WriteLine("  <div class='col-md-3'><label class='form-label small fw-semibold mb-1'>From</label><input type='date' class='form-control form-control-sm' id='date-from'></div>")
        $Writer.WriteLine("  <div class='col-md-3'><label class='form-label small fw-semibold mb-1'>To</label><input type='date' class='form-control form-control-sm' id='date-to'></div>")
        $Writer.WriteLine("  <div class='col-md-2 d-flex align-items-end'><button class='btn btn-sm btn-outline-secondary w-100' onclick='resetFilters()'>Reset</button></div>")
        $Writer.WriteLine("</div>")

        # Row 2: per-participant toggle + color picker (built by JS from participants[])
        $Writer.WriteLine("<div class='mb-3'>")
        $Writer.WriteLine("  <label class='form-label small fw-semibold d-block mb-2'>Participants &amp; Bubble Colors</label>")
        $Writer.WriteLine("  <div class='d-flex flex-wrap gap-2' id='pax-controls'></div>")
        $Writer.WriteLine("</div>")

        # Row 3: live message count
        $Writer.WriteLine("<div class='text-end'>")
        $Writer.WriteLine("  <span class='badge bg-primary' style='font-size:.85rem;' id='msg-count'>&mdash;</span>")
        $Writer.WriteLine("</div>")

        # Row 4: scrapbook print workflow. The wording is intentionally simple:
        # the user chooses messages for the scrapbook, reviews them, then prints.
        $Writer.WriteLine("<hr class='my-3'>")
        $Writer.WriteLine("<div class='row g-2 align-items-end'>")
        $Writer.WriteLine("  <div class='col-md-5'>")
        $Writer.WriteLine("    <label class='form-label small fw-semibold mb-1'>Print Title (optional)</label>")
        $Writer.WriteLine("    <input type='text' class='form-control form-control-sm' id='print-title-input' placeholder='Leave blank for no printed title'>")
        $Writer.WriteLine("  </div>")
        $Writer.WriteLine("  <div class='col-md-7 d-flex flex-wrap gap-2 align-items-end'>")
        $Writer.WriteLine("    <button type='button' class='btn btn-sm btn-outline-primary' id='scrapbook-only-btn' onclick='toggleScrapbookOnly()'>Show Scrapbook Only</button>")
        $Writer.WriteLine("    <button type='button' class='btn btn-sm btn-primary' onclick='printScrapbook()'>Print Scrapbook</button>")
        $Writer.WriteLine("    <button type='button' class='btn btn-sm btn-outline-secondary' onclick='uncheckAllScrapbookMessages()'>Uncheck All Scrapbook Messages</button>")
        $Writer.WriteLine("    <span class='badge bg-warning text-dark align-self-center' id='scrapbook-count'>Scrapbook: 0 messages selected</span>")
        $Writer.WriteLine("  </div>")
        $Writer.WriteLine("</div>")
        $Writer.WriteLine("<div class='print-help mt-2'>Choose the messages you want in the scrapbook.</div>")

        $Writer.WriteLine("</div></div>") # end card-body / card

        $Writer.WriteLine("<hr class='my-4'>")

        # -----------------------------------------------------------------------
        # JavaScript
        #
        # Data constants are injected via $Writer.WriteLine so PS variable
        # interpolation applies. All function definitions follow in a single-quoted
        # PS here-string (@' ... '@) so they are written literally with no PS
        # variable expansion. Only the JS runtime interprets them.
        # -----------------------------------------------------------------------
        $Writer.WriteLine("<script>")

        # Chart data (injected by PS)
        $Writer.WriteLine("const chartLabels=[$Labels]; const chartData=[$DataValues];")

        # Participants array (generated through ConvertTo-Json for safe escaping)
        $Writer.WriteLine("const participants=$ParticipantsJson;")

        # Date bounds for picker defaults (injected by PS)
        $Writer.WriteLine("const dateMin='$DateMin'; const dateMax='$DateMax';")

        # All function definitions, single-quoted here-string with no PS expansion.
        $Writer.WriteLine(@'
var filterTimer = null;
var msgChart = null;
var scrapbookOnly = false;
var previousScrapbookOnly = null;

document.addEventListener('DOMContentLoaded', function () {
  initChart();
  buildPaxControls();
  initScrapbookControls();
  document.getElementById('date-from').value = dateMin;
  document.getElementById('date-to').value   = dateMax;
  document.getElementById('kw-input').addEventListener('input', function () {
    clearTimeout(filterTimer);
    filterTimer = setTimeout(applyFilters, 300);
  });
  document.getElementById('full-day-match').addEventListener('change', applyFilters);
  document.getElementById('date-from').addEventListener('change', applyFilters);
  document.getElementById('date-to').addEventListener('change', applyFilters);
  applyFilters();
});

window.addEventListener('afterprint', function () {
  document.body.classList.remove('print-scrapbook-mode');

  if (previousScrapbookOnly !== null) {
    scrapbookOnly = previousScrapbookOnly;
    previousScrapbookOnly = null;
    updateScrapbookOnlyButton();
    applyFilters();
  }
});

// ---- Chart ----

function initChart() {
  var canvas = document.getElementById('msgChart');
  var ctx = canvas.getContext('2d');

  msgChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: chartLabels,
      datasets: [{
        label: 'Messages',
        data: chartData,
        backgroundColor: '#0084ff',
        borderRadius: 5
      }]
    },
    options: {
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            title: function (items) {
              return items.length ? 'Jump to ' + items[0].label : '';
            }
          }
        }
      },
      scales: { y: { beginAtZero: true } },
      onHover: function (event, elements) {
        var target = event && event.native ? event.native.target : canvas;
        target.style.cursor = elements.length ? 'pointer' : 'default';
      },
      onClick: function (event, elements) {
        if (!elements.length) {
          return;
        }

        var index = elements[0].index;
        var month = chartLabels[index];
        scrollToMonth(month);
      }
    }
  });
}

function scrollToMonth(month) {
  applyFilters();

  var messages = Array.prototype.slice.call(document.querySelectorAll('.msg'));
  var target = messages.find(function (m) {
    return m.style.display !== 'none' &&
           (m.dataset.date || '').slice(0, 7) === month;
  });

  if (!target) {
    alert('No visible messages were found in ' + month + '. Clear or widen the filters and try again.');
    return;
  }

  target.scrollIntoView({ behavior: 'smooth', block: 'center' });
  flashMessage(target);
}

function flashMessage(el) {
  el.classList.add('nav-flash');
  setTimeout(function () {
    el.classList.remove('nav-flash');
  }, 1800);
}

// ---- Participant controls (checkboxes + color pickers) ----

function buildPaxControls() {
  var c = document.getElementById('pax-controls');

  participants.forEach(function (p) {
    var d = document.createElement('div');
    d.className = 'pax-item';

    d.innerHTML =
      '<input type="checkbox" class="form-check-input sender-toggle" data-sender="' + escAttr(p.norm) + '" checked>' +
      '<span class="small fw-medium">' + escHtml(p.label) + '</span>' +
      '<input type="color" class="color-swatch" data-sender="' + escAttr(p.norm) + '" value="' + escAttr(p.bubble) + '" title="Bubble color">' +
      '<button type="button" class="btn btn-sm btn-outline-secondary color-reset" data-sender="' + escAttr(p.norm) + '" title="Reset this bubble color">Reset</button>';

    c.appendChild(d);

    // Apply the initial color baked in from PS.
    // For participants, this is either the PhoneNumber Color value or default grey.
    // For the owner, this is the default sent-message blue.
    applyBubbleColor(p.norm, p.bubble);
  });

  // Single delegated listener covers sender toggles, color picker commits,
  // and per-participant color reset buttons.
  c.addEventListener('change', function (e) {
    if (e.target.classList.contains('sender-toggle')) {
      applyFilters();
    }

    if (e.target.type === 'color') {
      applyBubbleColor(e.target.dataset.sender, e.target.value);
    }
  });

  // input fires continuously while dragging the color picker.
  c.addEventListener('input', function (e) {
    if (e.target.type === 'color') {
      applyBubbleColor(e.target.dataset.sender, e.target.value);
    }
  });

  c.addEventListener('click', function (e) {
    if (e.target.classList.contains('color-reset')) {
      resetBubbleColor(e.target.dataset.sender);
    }
  });
}

// Reset one participant's bubble color back to the original value from
// the generated participants[] constant. This original value is the color
// baked into the HTML at export time.
function resetBubbleColor(norm) {
  var p = participants.find(function (item) {
    return item.norm === norm;
  });

  if (!p) {
    return;
  }

  var picker = document.querySelector('.color-swatch[data-sender="' + cssEscape(norm) + '"]');

  if (picker) {
    picker.value = p.bubble;
  }

  applyBubbleColor(norm, p.bubble);
}

// Apply a background color to every message div for a given sender norm.
// For the owner (__owner__), the text color is adjusted for contrast so
// white text stays readable on light-colored sent bubbles.
function applyBubbleColor(norm, color) {
  document.querySelectorAll('.msg[data-sender="' + cssEscape(norm) + '"]').forEach(function (el) {
    el.style.backgroundColor = color;
    if (norm === '__owner__') { el.style.color = contrastColor(color); }
  });
}

// WCAG relative luminance, returns dark or light text color for contrast.
function contrastColor(hex) {
  if (!hex || hex.length < 7) { return '#333333'; }
  var r = parseInt(hex.slice(1, 3), 16);
  var g = parseInt(hex.slice(3, 5), 16);
  var b = parseInt(hex.slice(5, 7), 16);
  return (0.299 * r + 0.587 * g + 0.114 * b) / 255 > 0.5 ? '#333333' : '#ffffff';
}

// ---- Scrapbook selection ----

function initScrapbookControls() {
  document.querySelectorAll('.scrapbook-toggle').forEach(function (cb) {
    cb.addEventListener('change', function () {
      setMessageScrapbookState(cb.closest('.msg'), cb.checked, false);
    });
  });

  updateScrapbookCount();
}

function setMessageScrapbookState(message, selected, skipApply) {
  if (!message) {
    return;
  }

  message.classList.toggle('scrapbook-selected', selected);
  message.dataset.scrapbook = selected ? 'true' : 'false';

  var label = message.querySelector('.scrapbook-label');
  if (label) {
    label.textContent = selected ? 'Added to Scrapbook' : 'Add to Scrapbook';
  }

  updateScrapbookCount();

  if (!skipApply) {
    applyFilters();
  }
}

function getSelectedMessages() {
  return Array.prototype.slice.call(document.querySelectorAll('.msg.scrapbook-selected'));
}

function updateScrapbookCount() {
  var selectedCount = getSelectedMessages().length;
  var el = document.getElementById('scrapbook-count');

  if (el) {
    el.textContent = 'Scrapbook: ' + selectedCount.toLocaleString() + (selectedCount === 1 ? ' message selected' : ' messages selected');
  }

  return selectedCount;
}

function updateScrapbookOnlyButton() {
  var btn = document.getElementById('scrapbook-only-btn');

  if (!btn) {
    return;
  }

  btn.textContent = scrapbookOnly ? 'Show All Matching' : 'Show Scrapbook Only';
  btn.classList.toggle('btn-outline-primary', !scrapbookOnly);
  btn.classList.toggle('btn-primary', scrapbookOnly);
}

function toggleScrapbookOnly() {
  if (!scrapbookOnly && getSelectedMessages().length === 0) {
    alert('No messages are selected for the scrapbook yet. Check "Add to Scrapbook" on the messages you want to review or print.');
    return;
  }

  scrapbookOnly = !scrapbookOnly;
  updateScrapbookOnlyButton();
  applyFilters();
}

function uncheckAllScrapbookMessages() {
  var selected = getSelectedMessages();

  if (selected.length === 0) {
    alert('No messages are currently selected for the scrapbook.');
    return;
  }

  if (!confirm('Uncheck all messages selected for the scrapbook?')) {
    return;
  }

  selected.forEach(function (m) {
    var cb = m.querySelector('.scrapbook-toggle');
    if (cb) {
      cb.checked = false;
    }
    setMessageScrapbookState(m, false, true);
  });

  scrapbookOnly = false;
  updateScrapbookOnlyButton();
  applyFilters();
}

function printScrapbook() {
  var selected = getSelectedMessages();

  if (selected.length === 0) {
    alert('No messages are selected for the scrapbook yet. Check "Add to Scrapbook" on the messages you want to print.');
    return;
  }

  var titleInput = document.getElementById('print-title-input');
  var titleOut = document.getElementById('print-title-output');
  var title = titleInput ? titleInput.value.trim() : '';

  if (titleOut) {
    titleOut.textContent = title;
  }

  previousScrapbookOnly = scrapbookOnly;
  document.body.classList.add('print-scrapbook-mode');
  scrapbookOnly = true;
  updateScrapbookOnlyButton();
  applyFilters();

  setTimeout(function () {
    window.print();
  }, 50);
}

// ---- Filtering ----

function applyFilters() {
  var kw = (document.getElementById('kw-input').value || '').trim();
  var kwRe = null;
  if (kw) { try { kwRe = new RegExp(kw, 'i'); } catch (e) { /* invalid regex, treat as no filter */ } }

  var df = document.getElementById('date-from').value;
  var dt = document.getElementById('date-to').value;
  var fullDayMatchBox = document.getElementById('full-day-match');
  var showFullMatchingDays = !!(kwRe && fullDayMatchBox && fullDayMatchBox.checked);

  var hidden = new Set();
  document.querySelectorAll('.sender-toggle').forEach(function (cb) {
    if (!cb.checked) { hidden.add(cb.dataset.sender); }
  });

  var messages = Array.prototype.slice.call(document.querySelectorAll('.msg'));
  var matchingDays = new Set();

  // When Show full days with search matches is enabled, first identify every
  // yyyy-MM-dd calendar day that contains at least one keyword match inside the
  // current date range and participant visibility settings. The second pass then
  // shows every message from those matching days, including picture-only MMS
  // messages that have no searchable body text.
  if (showFullMatchingDays) {
    messages.forEach(function (m) {
      var d    = m.dataset.date ? m.dataset.date.slice(0, 10) : '';
      var txt  = m.dataset.text || '';
      var sndr = m.dataset.sender || '';

      var baseOk = (!df || d >= df) && (!dt || d <= dt) && !hidden.has(sndr);

      if (baseOk && kwRe.test(txt)) {
        matchingDays.add(d);
      }
    });
  }

  var vis = 0, tot = 0;

  messages.forEach(function (m) {
    tot++;
    var d        = m.dataset.date ? m.dataset.date.slice(0, 10) : '';
    var txt      = m.dataset.text || '';
    var sndr     = m.dataset.sender || '';
    var selected = m.classList.contains('scrapbook-selected');

    // Date comparison works lexicographically on yyyy-MM-dd strings.
    // Scrapbook Only mode intentionally shows all selected messages, regardless
    // of the current keyword/date/sender filters, so selected messages from
    // earlier searches do not appear to be lost.
    var baseFilterOk = (!df || d >= df) && (!dt || d <= dt) && !hidden.has(sndr);
    var keywordOk = true;

    if (kwRe) {
      keywordOk = showFullMatchingDays ? matchingDays.has(d) : kwRe.test(txt);
    }

    var filterOk = baseFilterOk && keywordOk;
    var ok = scrapbookOnly ? selected : filterOk;

    m.style.display = ok ? '' : 'none';

    // Keyword highlight, only touch msg-body innerHTML when necessary. In full-day
    // mode, messages from the same day that do not contain the keyword remain
    // visible but are not highlighted.
    var bEl = m.querySelector('.msg-body');
    if (bEl) {
      var wasHl = bEl.dataset.hl === '1';
      if (kwRe && ok) {
        bEl.innerHTML    = hlText(txt, kwRe);
        bEl.dataset.hl   = '1';
      } else if (wasHl) {
        // Restore to plain re-escaped text, removing any mark tags.
        bEl.innerHTML  = escHtml(txt);
        bEl.dataset.hl = '0';
      }
    }

    if (ok) { vis++; }
  });

  var selectedCount = updateScrapbookCount();
  var modeLabel = scrapbookOnly ? ' scrapbook messages' : ' messages';

  document.getElementById('msg-count').textContent =
    vis.toLocaleString() + ' of ' + tot.toLocaleString() + modeLabel +
    ' | ' + 'Scrapbook: ' + selectedCount.toLocaleString() + (selectedCount === 1 ? ' message selected' : ' messages selected');
}

// Wrap regex matches in <mark class="kw-hl"> inside safely HTML-escaped text.
function hlText(text, re) {
  // Build a global version of the caller's regex for exec-looping.
  var flags = 'g' + (re.flags.indexOf('i') !== -1 ? 'i' : '');
  var gre = new RegExp(re.source, flags);
  var result = '', last = 0, m;
  while ((m = gre.exec(text)) !== null) {
    result += escHtml(text.slice(last, m.index));
    result += '<mark class="kw-hl">' + escHtml(m[0]) + '</mark>';
    last = gre.lastIndex;
    if (m[0].length === 0) { gre.lastIndex++; } // guard against zero-width matches
  }
  return result + escHtml(text.slice(last));
}

// ---- Utility ----

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function escAttr(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;');
}

function cssEscape(s) {
  if (window.CSS && typeof window.CSS.escape === 'function') {
    return window.CSS.escape(String(s));
  }

  return String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function resetFilters() {
  document.getElementById('kw-input').value  = '';
  document.getElementById('date-from').value = dateMin;
  document.getElementById('date-to').value   = dateMax;
  document.getElementById('full-day-match').checked = true;

  document.querySelectorAll('.sender-toggle').forEach(function (cb) {
    cb.checked = true;
  });

  // This reset button restores filter state and exits Scrapbook Only review mode.
  // It leaves scrapbook selections as-is. Use Uncheck All Scrapbook Messages
  // for that separate action.
  scrapbookOnly = false;
  updateScrapbookOnlyButton();
  applyFilters();
}

function toggleControls() {
  var b = document.getElementById('controls-body');
  var i = document.getElementById('ctrl-chev');
  if (b.style.display === 'none') {
    b.style.display = '';
    i.innerHTML = '&#9650; collapse';
  } else {
    b.style.display = 'none';
    i.innerHTML = '&#9660; expand';
  }
}
'@)
        $Writer.WriteLine("</script>")
    }

    hidden [void] WriteFooter([System.IO.StreamWriter]$Writer) {
        $Writer.WriteLine("<div class='text-center text-muted mt-5 pt-4 border-top' style='clear:both;'>")
        $Writer.WriteLine("<p class='mb-0'>End of Conversation Archive</p>")
        $Writer.WriteLine("<p class='small'>Total Recovered: $($this.MessageList.Count) items</p>")
        $Writer.WriteLine("</div></div></body></html>")
    }
}

function Invoke-SmsArchiveExport {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({ Test-Path $_ })]
        [string]$Path,

        [Parameter(Mandatory = $false, Position = 1)]
        [object[]]$PhoneNumber,

        [Parameter(Mandatory = $false)]
        [string]$OwnerName = "",

        [Parameter(Mandatory = $false)]
        [ValidateSet("All", "Named", "Unknown")]
        [string]$ContactFilter = "All",

        [Parameter(Mandatory = $false)]
        [string]$Keyword,

        [Parameter(Mandatory = $false)]
        [datetime]$StartDate = [datetime]::MinValue,

        [Parameter(Mandatory = $false)]
        [datetime]$EndDate = [datetime]::MaxValue,

        [Parameter(Mandatory = $false)]
        [string]$OutPath
    )

    process {
        try {
            $TargetOut = if ([string]::IsNullOrEmpty($OutPath)) {
                Join-Path ([System.IO.Path]::GetDirectoryName($Path)) "SMS_Export_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
            } else {
                $OutPath
            }

            Write-Verbose "Initializing SMS Processor for: $Path"
            $Processor = [SmsArchiveProcessor]::new($Path, $PhoneNumber)

            $Processor.ContactFilter = $ContactFilter
            $Processor.Keyword       = $Keyword
            $Processor.OwnerName     = $OwnerName
            $Processor.StartDate     = $StartDate
            $Processor.EndDate       = $EndDate

            $ModeDescription = if ($Processor.GroupMode) {
                "Group mode — ALL and ONLY: $($Processor.TargetPhones -join ', ')"
            } else {
                "1:1 mode — $($Processor.TargetPhones[0])"
            }
            Write-Host "Starting Export to: $TargetOut [$ModeDescription]" -ForegroundColor Cyan

            $Result = $Processor.ExportHtml($TargetOut)

            if ($Result.Success) {
                Write-Host "Success! Found $($Result.Matched) messages." -ForegroundColor Green
                return $Result
            }
        } catch {
            Write-Error "Export failed: $($_.Exception.Message)"
        }
    }
}

<#
# -----------------------------------------------------------------------
# 1:1 thread — number only, no friendly name
# -----------------------------------------------------------------------
$OneOnOneParams = @{
    Path        = "C:\Users\Ryan\Downloads\sms-20260428150329.xml"
    PhoneNumber = @("7705961997")
    OutPath     = "C:\temp\SMS_Export_1on1_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    Verbose     = $true
}

# -----------------------------------------------------------------------
# 1:1 thread — with friendly name
# -----------------------------------------------------------------------
$OneOnOneNamedParams = @{
    Path        = "C:\Users\Ryan\Downloads\sms-20260428150329.xml"
    PhoneNumber = @(
        @{ Number = "7705961997"; Name = "Ryan" }
    )
    OutPath     = "C:\temp\SMS_Export_1on1_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    Verbose     = $true
}
#>
# -----------------------------------------------------------------------
# Group chat — ALL and ONLY these two numbers plus the backup phone owner.
# Threads with any different or additional participants are excluded.
# -----------------------------------------------------------------------
$GroupParams = @{
    Path        = "C:\Users\Ryan\Downloads\sms-20260428150329.xml"
    OwnerName   = "Mom"
    PhoneNumber = @(
        @{ Number = "7705961997"; Name = "Ryan" }
    )
    OutPath     = "C:\temp\SMS_Export_Ryan_$(Get-Date -Format 'yyyyMMdd_HHmm').html"
    Verbose     = $true
}
#
#Invoke-SmsArchiveExport @OneOnOneParams
#Invoke-SmsArchiveExport @OneOnOneNamedParams
Invoke-SmsArchiveExport @GroupParams
