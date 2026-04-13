#requires -Version 5.1
using namespace System.DirectoryServices.ActiveDirectory

<#
.SYNOPSIS
    Generates a Windows Update compliance report for all domain controllers.

.DESCRIPTION
    Collects domain controller inventory and update posture, evaluates:
    - absolute update recency
    - same-OS peer build drift

    Optionally gathers lightweight diagnostics for flagged systems and can send an HTML report by email.

.NOTES
    Designed for Windows PowerShell 5.1.
    Uses native .NET DirectoryServices APIs for DC discovery.
    Uses the Windows Update Agent (WUA) COM API for reliable CU detection on Server 2016+.
    System.Web is loaded on demand inside ConvertTo-DCUpdateHtmlReport via Add-Type.
#>

#region Configuration

$script:DCUpdateReportConfig = @{
    ReportTitle              = 'Domain Controller Update Compliance Report'
    UpdateAgeWarningDays     = 45
    UpdateAgeCriticalDays    = 90
    DefaultSmtpPort          = 25
    SuppressHealthyEmail     = $true
    PeerBuildWarningBuckets  = 2
    PeerBuildCriticalBuckets = 4
}

#endregion

#region Helper Functions

function Write-Section {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    Write-Host ''
    Write-Host ('=' * 80) -ForegroundColor DarkCyan
    Write-Host $Message -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor DarkCyan
}

function ConvertTo-BuildValue {
    [CmdletBinding()]
    [OutputType([long])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$VersionString
    )

    $Trimmed = $VersionString.Trim()

    if ($Trimmed -match '^(?:\d+\.\d+\.)?(\d+)(?:\.(\d+))?$') {
        [long]$Build    = [long]$Matches[1]
        [long]$Revision = if ($Matches[2]) { [long]$Matches[2] } else { 0 }
        return ($Build * 100000) + $Revision
    }

    throw "Unsupported build format '$VersionString'."
}

function Get-NormalizedOSKey {
    <#
    .SYNOPSIS
        Strips edition and variant suffixes from an OS string for peer-group normalization.

    .DESCRIPTION
        Collapses "Windows Server 2019 Standard", "Windows Server 2019 Datacenter",
        and "Windows Server 2019 Datacenter: Azure Edition" into a single
        "Windows Server 2019" key so that all DCs on the same OS version are
        baselined together regardless of SKU.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$OperatingSystem
    )

    ($OperatingSystem -replace '\s+(Standard|Datacenter|Enterprise|Essentials|Foundation)\b.*$', '').Trim()
}

function New-DCUpdateStatusObject {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ComputerName,

        [Parameter()]
        [string]$Domain,

        [Parameter()]
        [string]$Site,

        [Parameter()]
        [string]$IPv4Address,

        [Parameter()]
        [string]$OperatingSystem,

        [Parameter()]
        [bool]$IsGlobalCatalog = $false
    )

    [pscustomobject]@{
        ComputerName         = $ComputerName
        Domain               = $Domain
        Site                 = $Site
        IPv4Address          = $IPv4Address
        OperatingSystem      = $OperatingSystem
        IsGlobalCatalog      = $IsGlobalCatalog

        IsReachable          = $false
        QuerySucceeded       = $false
        QueryError           = $null

        LastBootTime         = $null
        LatestUpdateTitle    = $null
        LatestUpdateDate     = $null
        DaysSinceLastUpdate  = $null

        CurrentBuild         = $null
        CurrentUBR           = $null
        CurrentBuildLabel    = $null
        CurrentBuildValue    = $null

        BaselineBuildLabel   = $null
        BaselineBuildValue   = $null
        BuildDelta           = $null

        UpdateRecencyStatus  = 'Unknown'

        PeerBuildBucketDelta = $null
        PeerBuildStatus      = 'Unknown'

        RebootPending        = $false
        ServicingRiskFlag    = $false
        ServicingRiskReason  = $null
        RecentWUFailureCount = $null
        RecentWUFailureIds   = $null

        DiagnosticsError     = $null

        OverallStatus        = 'Unknown'
        NeedsAttention       = $false
        Notes                = $null
        Timestamp            = Get-Date
    }
}

#endregion

#region Inventory

function Get-DCInventory {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetDomain = [Domain]::GetCurrentDomain().Name
    )

    process {
        try {
            $Context           = New-Object DirectoryContext([DirectoryContextType]::Domain, $TargetDomain)
            $DomainObject      = [Domain]::GetDomain($Context)
            $DomainControllers = $DomainObject.DomainControllers
        }
        catch {
            Write-Error "Failed to enumerate domain controllers for '$TargetDomain'. $_"
            return
        }

        foreach ($CurrentDC in $DomainControllers) {
            [pscustomobject]@{
                ComputerName    = $CurrentDC.Name
                Domain          = $TargetDomain
                Site            = $CurrentDC.SiteName
                IPv4Address     = $CurrentDC.IPAddress
                OperatingSystem = $CurrentDC.OSVersion
                IsGlobalCatalog = [bool]$CurrentDC.IsGlobalCatalog
            }
        }
    }
}

#endregion

#region Status Collection

function Get-DCUpdateStatus {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject
    )

    begin {
        $Inventory = New-Object System.Collections.Generic.List[object]
        $Index     = 0
    }

    process {
        [void]$Inventory.Add($InputObject)
    }

    end {
        $Total = $Inventory.Count

        foreach ($CurrentItem in $Inventory) {
            $Index++
            $ComputerName = $CurrentItem.ComputerName

            $ProgressParams = @{
                Activity        = 'Collecting Domain Controller Update Status'
                Status          = "Querying $ComputerName ($Index of $Total)"
                PercentComplete = (($Index / $Total) * 100)
            }
            Write-Progress @ProgressParams

            $StatusObjectParams = @{
                ComputerName    = $CurrentItem.ComputerName
                Domain          = $CurrentItem.Domain
                Site            = $CurrentItem.Site
                IPv4Address     = $CurrentItem.IPv4Address
                OperatingSystem = $CurrentItem.OperatingSystem
                IsGlobalCatalog = $CurrentItem.IsGlobalCatalog
            }
            $Result = New-DCUpdateStatusObject @StatusObjectParams

            try {
                $PingParams = @{
                    ComputerName = $ComputerName
                    Count        = 1
                    Quiet        = $true
                    ErrorAction  = 'Stop'
                }

                if (-not (Test-Connection @PingParams)) {
                    $Result.QueryError     = 'ICMP ping failed.'
                    $Result.Notes          = 'Host did not respond to ping.'
                    $Result.OverallStatus  = 'Unknown'
                    $Result.NeedsAttention = $true
                    $Result
                    continue
                }

                $Result.IsReachable = $true

                # Build/UBR and latest update collected in a single remote round-trip.
                #
                # Get-ComputerInfo is intentionally avoided — it collects the entire system
                # inventory just to retrieve OsBuildNumber, adding several seconds per DC.
                # The registry key already holds both CurrentBuildNumber and UBR.
                #
                # Get-HotFix (Win32_QuickFixEngineering) is intentionally avoided — it does
                # not track cumulative updates on Server 2016+ which are serviced through
                # the component store. The WUA COM API sees the full update history.
                $RemoteScriptBlock = {
                    # Latest successful Windows quality update via WUA COM API
                    $LatestUpdateTitle = $null
                    $LatestUpdateDate = $null

                    try {
                        $WuaSession = New-Object -ComObject Microsoft.Update.Session
                        $WuaSearcher = $WuaSession.CreateUpdateSearcher()
                        $HistoryCount = $WuaSearcher.GetTotalHistoryCount()

                        if ($HistoryCount -gt 0) {
                            $QueryCount = [Math]::Min($HistoryCount, 100)

                            $History = @(
                                $WuaSearcher.QueryHistory(0, $QueryCount) |
                                    Where-Object { $_.ResultCode -in @(2, 3) }
                            )

                            $PreferredUpdate = $History |
                                Where-Object {
                                    $_.Title -match 'KB\d+' -and (
                                        $_.Title -match 'Cumulative Update' -or
                                        $_.Title -match 'Security Monthly Quality Rollup' -or
                                        $_.Title -match 'Monthly Rollup' -or
                                        $_.Title -match 'Quality Update'
                                    )
                                } |
                                Select-Object -First 1

                            if (-not $PreferredUpdate) {
                                $PreferredUpdate = $History |
                                    Where-Object { $_.Title -match 'KB\d+' } |
                                    Select-Object -First 1
                            }

                            if ($PreferredUpdate) {
                                $KbMatch = [regex]::Match($PreferredUpdate.Title, 'KB\d+')
                                $LatestUpdateTitle = if ($KbMatch.Success) {
                                    $KbMatch.Value
                                }
                                else {
                                    $PreferredUpdate.Title
                                }

                                $LatestUpdateDate = $PreferredUpdate.Date
                            }
                        }
                    }
                    catch {
                        # WUA unavailable; fields remain null and DaysSinceLastUpdate will surface as Unknown
                    }

                    # Build number and UBR from registry
                    $CurrentBuild = $null
                    $Ubr          = $null
                    try {
                        $CurrentVersion = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
                        $CurrentBuild   = [string]$CurrentVersion.CurrentBuildNumber
                        $Ubr            = $CurrentVersion.UBR
                    }
                    catch {
                    }

                    $OS = Get-CimInstance -ClassName Win32_OperatingSystem

                    [pscustomobject]@{
                        LastBootTime      = $OS.LastBootUpTime
                        LatestUpdateTitle = $LatestUpdateTitle
                        LatestUpdateDate  = $LatestUpdateDate
                        CurrentBuild      = $CurrentBuild
                        CurrentUBR        = $Ubr
                    }
                }

                $RemoteData = Invoke-Command -ComputerName $ComputerName -ScriptBlock $RemoteScriptBlock -ErrorAction Stop

                $Result.QuerySucceeded    = $true
                $Result.LastBootTime      = $RemoteData.LastBootTime
                $Result.LatestUpdateTitle = $RemoteData.LatestUpdateTitle
                $Result.LatestUpdateDate  = $RemoteData.LatestUpdateDate
                $Result.CurrentBuild      = $RemoteData.CurrentBuild
                $Result.CurrentUBR        = $RemoteData.CurrentUBR

                if ($Result.CurrentBuild -and $null -ne $Result.CurrentUBR) {
                    $Result.CurrentBuildLabel = '{0}.{1}' -f $Result.CurrentBuild, $Result.CurrentUBR
                }
                elseif ($Result.CurrentBuild) {
                    $Result.CurrentBuildLabel = [string]$Result.CurrentBuild
                }

                if ($Result.CurrentBuildLabel) {
                    $Result.CurrentBuildValue = ConvertTo-BuildValue -VersionString $Result.CurrentBuildLabel
                }

                if ($Result.LatestUpdateDate) {
                    $Result.DaysSinceLastUpdate = [int]((Get-Date) - $Result.LatestUpdateDate).TotalDays
                }

                try {
                    $RebootScriptBlock = {
                        $RebootPending = $false

                        $Paths = @(
                            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
                            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
                        )

                        foreach ($CurrentPath in $Paths) {
                            if (Test-Path -Path $CurrentPath) {
                                $RebootPending = $true
                                break
                            }
                        }

                        if (-not $RebootPending) {
                            try {
                                $SessionManager = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -ErrorAction Stop
                                if ($SessionManager.PendingFileRenameOperations) {
                                    $RebootPending = $true
                                }
                            }
                            catch {
                            }
                        }

                        $RebootPending
                    }

                    $Result.RebootPending = [bool](Invoke-Command -ComputerName $ComputerName -ScriptBlock $RebootScriptBlock -ErrorAction Stop)
                }
                catch {
                    if ([string]::IsNullOrWhiteSpace($Result.Notes)) {
                        $Result.Notes = 'Unable to determine reboot pending state.'
                    }
                }
            }
            catch {
                $Result.QueryError     = $_.Exception.Message
                $Result.OverallStatus  = 'Unknown'
                $Result.NeedsAttention = $true
                $Result.Notes          = 'Failed to collect update posture.'
            }

            $Result
        }

        Write-Progress -Activity 'Collecting Domain Controller Update Status' -Completed
    }
}

#endregion

#region Baseline and Assessment

function Get-DCUpdateBaseline {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject
    )

    begin {
        $CollectedObjects = New-Object System.Collections.Generic.List[object]
    }

    process {
        [void]$CollectedObjects.Add($InputObject)
    }

    end {
        $BaselineMap = @{}

        # Group by normalized OS key so Standard/Datacenter/etc. variants on the same
        # OS version share a single peer group and baseline.
        $GroupedObjects = $CollectedObjects | Group-Object -Property {
            Get-NormalizedOSKey -OperatingSystem $_.OperatingSystem
        }

        foreach ($CurrentGroup in $GroupedObjects) {
            $NormalizedOS = [string]$CurrentGroup.Name

            $Candidates = @(
                $CurrentGroup.Group |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_.CurrentBuildLabel) -and $null -ne $_.CurrentBuildValue } |
                    Sort-Object CurrentBuildValue -Descending
            )

            # Track DCs excluded from baseline computation (offline or no build data).
            # A high ExcludedDCCount means the baseline may be understated — the true
            # newest build in the environment might belong to an unreachable DC.
            $ExcludedDCCount = $CurrentGroup.Group.Count - $Candidates.Count

            if ($Candidates.Count -eq 0) {
                $BaselineMap[$NormalizedOS] = [pscustomobject]@{
                    BaselineKey        = $NormalizedOS
                    BaselineBuildLabel = $null
                    BaselineBuildValue = $null
                    BaselineSourceDC   = $null
                    UniqueBuildLabels  = @()
                    BuildBucketMap     = @{}
                    ExcludedDCCount    = $ExcludedDCCount
                }
                continue
            }

            $Newest            = $Candidates[0]
            $UniqueBuildLabels = @($Candidates | Select-Object -ExpandProperty CurrentBuildLabel -Unique)

            $BuildBucketMap = @{}
            for ($Index = 0; $Index -lt $UniqueBuildLabels.Count; $Index++) {
                $BuildBucketMap[$UniqueBuildLabels[$Index]] = $Index
            }

            $BaselineMap[$NormalizedOS] = [pscustomobject]@{
                BaselineKey        = $NormalizedOS
                BaselineBuildLabel = $Newest.CurrentBuildLabel
                BaselineBuildValue = $Newest.CurrentBuildValue
                BaselineSourceDC   = $Newest.ComputerName
                UniqueBuildLabels  = $UniqueBuildLabels
                BuildBucketMap     = $BuildBucketMap
                ExcludedDCCount    = $ExcludedDCCount
            }
        }

        return $BaselineMap
    }
}

function Get-DCUpdateAssessment {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$BaselineMap,

        [Parameter()]
        [ValidateNotNull()]
        [int]$UpdateAgeWarningDays = $script:DCUpdateReportConfig.UpdateAgeWarningDays,

        [Parameter()]
        [ValidateNotNull()]
        [int]$UpdateAgeCriticalDays = $script:DCUpdateReportConfig.UpdateAgeCriticalDays,

        [Parameter()]
        [ValidateNotNull()]
        [int]$PeerBuildWarningBuckets = $script:DCUpdateReportConfig.PeerBuildWarningBuckets,

        [Parameter()]
        [ValidateNotNull()]
        [int]$PeerBuildCriticalBuckets = $script:DCUpdateReportConfig.PeerBuildCriticalBuckets
    )

    process {
        $AssessmentObject = $InputObject.PSObject.Copy()

        # Normalize at lookup time so the key matches what Get-DCUpdateBaseline stored
        $OperatingSystemKey = Get-NormalizedOSKey -OperatingSystem ([string]$AssessmentObject.OperatingSystem)
        $CurrentBaseline    = $null

        $AssessmentObject.BaselineBuildLabel   = $null
        $AssessmentObject.BaselineBuildValue   = $null
        $AssessmentObject.BuildDelta           = $null
        $AssessmentObject.UpdateRecencyStatus  = 'Unknown'
        $AssessmentObject.PeerBuildBucketDelta = $null
        $AssessmentObject.PeerBuildStatus      = 'Unknown'

        if ($BaselineMap.ContainsKey($OperatingSystemKey)) {
            $CurrentBaseline = $BaselineMap[$OperatingSystemKey]
            $AssessmentObject.BaselineBuildLabel = $CurrentBaseline.BaselineBuildLabel
            $AssessmentObject.BaselineBuildValue = $CurrentBaseline.BaselineBuildValue
        }

        if (-not $AssessmentObject.QuerySucceeded) {
            $AssessmentObject.OverallStatus    = 'Unknown'
            $AssessmentObject.NeedsAttention   = $true

            # Build Notes preserving any existing content (e.g. from the collection catch block)
            # and appending a diagnostics error if one was set by a prior diagnostics pass.
            $EarlyNoteParts = New-Object System.Collections.Generic.List[string]
            $ExistingNote   = [string]$AssessmentObject.Notes
            if (-not [string]::IsNullOrWhiteSpace($ExistingNote)) {
                [void]$EarlyNoteParts.Add($ExistingNote)
            }
            else {
                [void]$EarlyNoteParts.Add('Unable to collect update status.')
            }
            if (-not [string]::IsNullOrWhiteSpace($AssessmentObject.DiagnosticsError)) {
                [void]$EarlyNoteParts.Add($AssessmentObject.DiagnosticsError)
            }
            $AssessmentObject.Notes = $EarlyNoteParts -join '; '

            return $AssessmentObject
        }

        if ($null -eq $AssessmentObject.DaysSinceLastUpdate) {
            $AssessmentObject.UpdateRecencyStatus = 'Unknown'
        }
        elseif ($AssessmentObject.DaysSinceLastUpdate -gt $UpdateAgeCriticalDays) {
            $AssessmentObject.UpdateRecencyStatus = 'Critical'
        }
        elseif ($AssessmentObject.DaysSinceLastUpdate -gt $UpdateAgeWarningDays) {
            $AssessmentObject.UpdateRecencyStatus = 'Warning'
        }
        else {
            $AssessmentObject.UpdateRecencyStatus = 'Healthy'
        }

        if ($null -eq $CurrentBaseline -or [string]::IsNullOrWhiteSpace($AssessmentObject.CurrentBuildLabel)) {
            $AssessmentObject.PeerBuildStatus = 'Unknown'
        }
        elseif (-not $CurrentBaseline.BuildBucketMap.ContainsKey($AssessmentObject.CurrentBuildLabel)) {
            $AssessmentObject.PeerBuildStatus = 'Unknown'
        }
        else {
            $AssessmentObject.PeerBuildBucketDelta = [int]$CurrentBaseline.BuildBucketMap[$AssessmentObject.CurrentBuildLabel]
            $AssessmentObject.BuildDelta           = $AssessmentObject.PeerBuildBucketDelta

            if ($AssessmentObject.PeerBuildBucketDelta -lt $PeerBuildWarningBuckets) {
                $AssessmentObject.PeerBuildStatus = 'Healthy'
            }
            elseif ($AssessmentObject.PeerBuildBucketDelta -lt $PeerBuildCriticalBuckets) {
                $AssessmentObject.PeerBuildStatus = 'Warning'
            }
            else {
                $AssessmentObject.PeerBuildStatus = 'Critical'
            }
        }

        if ($AssessmentObject.ServicingRiskFlag) {
            $AssessmentObject.OverallStatus = 'Critical'
        }
        elseif ($AssessmentObject.UpdateRecencyStatus -eq 'Critical' -or $AssessmentObject.PeerBuildStatus -eq 'Critical') {
            $AssessmentObject.OverallStatus = 'Critical'
        }
        elseif ($AssessmentObject.UpdateRecencyStatus -eq 'Warning' -or $AssessmentObject.PeerBuildStatus -eq 'Warning') {
            $AssessmentObject.OverallStatus = 'Warning'
        }
        elseif ($AssessmentObject.UpdateRecencyStatus -eq 'Unknown' -or $AssessmentObject.PeerBuildStatus -eq 'Unknown') {
            $AssessmentObject.OverallStatus = 'Unknown'
        }
        else {
            $AssessmentObject.OverallStatus = 'Healthy'
        }

        $AssessmentObject.NeedsAttention = $AssessmentObject.OverallStatus -ne 'Healthy'

        $NoteParts = New-Object System.Collections.Generic.List[string]

        if ($AssessmentObject.DaysSinceLastUpdate -gt $UpdateAgeWarningDays) {
            [void]$NoteParts.Add("Last update is $($AssessmentObject.DaysSinceLastUpdate) days old")
        }

        if ($AssessmentObject.PeerBuildStatus -in @('Warning', 'Critical')) {
            [void]$NoteParts.Add("Peer build lag is $($AssessmentObject.PeerBuildBucketDelta) bucket(s) behind same-OS baseline $($AssessmentObject.BaselineBuildLabel)")
        }

        if ($AssessmentObject.RebootPending -and $AssessmentObject.NeedsAttention) {
            [void]$NoteParts.Add('Reboot pending')
        }

        if ($AssessmentObject.ServicingRiskFlag -and -not [string]::IsNullOrWhiteSpace($AssessmentObject.ServicingRiskReason)) {
            [void]$NoteParts.Add($AssessmentObject.ServicingRiskReason)
        }

        if (-not [string]::IsNullOrWhiteSpace($AssessmentObject.DiagnosticsError)) {
            [void]$NoteParts.Add($AssessmentObject.DiagnosticsError)
        }

        if (-not [string]::IsNullOrWhiteSpace($AssessmentObject.QueryError)) {
            [void]$NoteParts.Add("Query error: $($AssessmentObject.QueryError)")
        }

        if ($NoteParts.Count -gt 0) {
            $AssessmentObject.Notes = $NoteParts -join '; '
        }
        else {
            $AssessmentObject.Notes = $null
        }

        return $AssessmentObject
    }
}

#endregion

#region Diagnostics

function Get-DCUpdateDiagnostics {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject,

        [Parameter()]
        [int]$LookbackDays = 30
    )

    process {
        $Item = $InputObject.PSObject.Copy()

        if (-not $Item.NeedsAttention -or -not $Item.IsReachable) {
            return $Item
        }

        try {
            $StartTime = (Get-Date).AddDays(-$LookbackDays)

            $ScriptBlock = {
                param($InnerStartTime)

                $Events = Get-WinEvent -FilterHashtable @{
                    LogName   = 'System'
                    StartTime = $InnerStartTime
                } -ErrorAction Stop |
                    Where-Object {
                        $_.ProviderName -eq 'Microsoft-Windows-WindowsUpdateClient' -and $_.LevelDisplayName -eq 'Error'
                    } |
                    Select-Object -First 10 TimeCreated, Id, ProviderName, Message

                [pscustomobject]@{
                    FailureCount = @($Events).Count
                    FailureIds   = if ($Events) { ($Events | Select-Object -ExpandProperty Id | Sort-Object -Unique) -join ',' } else { $null }
                }
            }

            $Diag = Invoke-Command -ComputerName $Item.ComputerName -ScriptBlock $ScriptBlock -ArgumentList $StartTime -ErrorAction Stop

            $Item.RecentWUFailureCount = $Diag.FailureCount
            $Item.RecentWUFailureIds   = $Diag.FailureIds

            if ($Diag.FailureCount -gt 3) {
                $Item.ServicingRiskFlag   = $true
                $Item.ServicingRiskReason = "Multiple Windows Update errors in last $LookbackDays days"
            }
        }
        catch {
            # Store the failure in a dedicated field so the re-assessment pass can
            # incorporate it into Notes without overwriting any prior assessment content.
            $Item.DiagnosticsError = 'Diagnostics query failed.'
        }

        $Item
    }
}

#endregion

#region HTML and Email

function ConvertTo-DCUpdateHtmlReport {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$InputObject,

        [Parameter(Mandatory = $true)]
        [hashtable]$BaselineMap
    )

    begin {
        Add-Type -AssemblyName System.Web
        $CollectedRows = @()
    }

    process {
        $CollectedRows += $InputObject
    }

    end {
        try {
            $AllRows     = @($CollectedRows)
            $FlaggedRows = @($AllRows | Where-Object { $_.NeedsAttention })

            $HealthyCount  = @($AllRows | Where-Object { $_.OverallStatus -eq 'Healthy' }).Count
            $WarningCount  = @($AllRows | Where-Object { $_.OverallStatus -eq 'Warning' }).Count
            $CriticalCount = @($AllRows | Where-Object { $_.OverallStatus -eq 'Critical' }).Count
            $UnknownCount  = @($AllRows | Where-Object { $_.OverallStatus -eq 'Unknown' }).Count

            $BaselineLines = foreach ($CurrentKey in ($BaselineMap.Keys | Sort-Object)) {
                $CurrentBaseline = $BaselineMap[$CurrentKey]
                $EncodedKey      = [System.Web.HttpUtility]::HtmlEncode([string]$CurrentKey)

                if ($null -eq $CurrentBaseline.BaselineBuildLabel) {
                    $ExcludedNote = if ($CurrentBaseline.ExcludedDCCount -gt 0) {
                        " ($($CurrentBaseline.ExcludedDCCount) DC(s) unreachable)"
                    }
                    else { '' }
                    '<strong>{0}</strong>: Unable to determine baseline{1}' -f $EncodedKey, $ExcludedNote
                }
                else {
                    $EncodedBuild  = [System.Web.HttpUtility]::HtmlEncode([string]$CurrentBaseline.BaselineBuildLabel)
                    $EncodedSource = [System.Web.HttpUtility]::HtmlEncode([string]$CurrentBaseline.BaselineSourceDC)
                    # Flag when unreachable DCs may be suppressing the true highest build
                    $ExcludedNote  = if ($CurrentBaseline.ExcludedDCCount -gt 0) {
                        '; <em style="color:#c0712a">warning: {0} DC(s) were unreachable and excluded &mdash; baseline may be understated</em>' -f $CurrentBaseline.ExcludedDCCount
                    }
                    else { '' }
                    '<strong>{0}</strong>: {1} (source: {2}){3}' -f $EncodedKey, $EncodedBuild, $EncodedSource, $ExcludedNote
                }
            }

            $BaselineHtml = if ($BaselineLines) { $BaselineLines -join '<br>' } else { 'No baseline data available.' }

            $Css = @"
<style>
    body { font-family: 'Segoe UI', Tahoma, Arial, sans-serif; color: #333333; margin: 18px; }
    h2 { color: #0044cc; border-bottom: 2px solid #cccccc; padding-bottom: 8px; margin-bottom: 18px; }
    h3 { color: #0044cc; margin-top: 26px; margin-bottom: 10px; }
    p { margin: 8px 0; }
    table { border-collapse: collapse; width: 100%; margin-top: 12px; box-shadow: 0 0 15px rgba(0,0,0,0.12); }
    th { background-color: #009879; color: #ffffff; text-align: left; padding: 10px 12px; font-size: 0.95em; }
    td { padding: 10px 12px; border-bottom: 1px solid #dddddd; vertical-align: top; font-size: 0.93em; }
    tr:nth-of-type(even) { background-color: #f3f3f3; }
    .healthy-text { color: #2e7d32; font-weight: bold; }
    .warning-text { color: #f0ad4e; font-weight: bold; }
    .critical-text { color: #d9534f; font-weight: bold; }
    .unknown-text { color: #6c757d; font-weight: bold; }
    .summary-box { margin: 10px 0 18px 0; padding: 12px; background-color: #f8f9fa; border-left: 4px solid #009879; }
    .footer { margin-top: 24px; font-size: 0.85em; color: #777777; }
    .muted { color: #666666; }
</style>
"@

            $SummaryHtml = @"
<div class='summary-box'>
    <strong>Total DCs:</strong> $($AllRows.Count)<br>
    <strong>Healthy:</strong> $HealthyCount<br>
    <strong>Warning:</strong> $WarningCount<br>
    <strong>Critical:</strong> $CriticalCount<br>
    <strong>Unknown:</strong> $UnknownCount
</div>

<div class='summary-box'>
    <strong>Per-OS Baselines</strong><br>
    $BaselineHtml
</div>
"@

            if ($FlaggedRows.Count -gt 0) {
                $ActionRequiredTable = $FlaggedRows |
                    Sort-Object OverallStatus, OperatingSystem, DaysSinceLastUpdate -Descending |
                    Select-Object ComputerName, Domain, Site, OperatingSystem, LatestUpdateTitle, LatestUpdateDate, DaysSinceLastUpdate, CurrentBuildLabel, BaselineBuildLabel, PeerBuildBucketDelta, UpdateRecencyStatus, PeerBuildStatus, OverallStatus, Notes |
                    ConvertTo-Html -Fragment
            }
            else {
                $ActionRequiredTable = '<p>All domain controllers are currently within defined thresholds.</p>'
            }

            $FullInventoryTable = $AllRows |
                Sort-Object OverallStatus, OperatingSystem, ComputerName |
                Select-Object ComputerName, Domain, Site, OperatingSystem, IsGlobalCatalog, LatestUpdateTitle, LatestUpdateDate, DaysSinceLastUpdate, CurrentBuildLabel, BaselineBuildLabel, PeerBuildBucketDelta, UpdateRecencyStatus, PeerBuildStatus, RebootPending, OverallStatus, Notes |
                ConvertTo-Html -Fragment

            foreach ($StatusValue in @('Healthy', 'Warning', 'Critical', 'Unknown')) {
                $CssClass = switch ($StatusValue) {
                    'Healthy'  { 'healthy-text' }
                    'Warning'  { 'warning-text' }
                    'Critical' { 'critical-text' }
                    'Unknown'  { 'unknown-text' }
                }

                $FindText    = '<td>{0}</td>' -f $StatusValue
                $ReplaceText = '<td class="{0}">{1}</td>' -f $CssClass, $StatusValue
                $ActionRequiredTable = $ActionRequiredTable.Replace($FindText, $ReplaceText)
                $FullInventoryTable  = $FullInventoryTable.Replace($FindText, $ReplaceText)
            }

            $EncodedTitle  = [System.Web.HttpUtility]::HtmlEncode([string]$script:DCUpdateReportConfig.ReportTitle)
            $GeneratedTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

            @"
<html>
<head>
$Css
</head>
<body>
    <h2>$EncodedTitle</h2>
    <p>This report highlights domain controllers with stale update posture, same-OS peer drift, or unknown compliance state.</p>
    $SummaryHtml
    <h3>Action Required</h3>
    $ActionRequiredTable
    <h3>Full Inventory</h3>
    $FullInventoryTable
    <div class='footer'>
        Generated on $GeneratedTime<br>
        <span class='muted'>Overall status is based on both absolute update recency and same-OS peer drift.</span>
    </div>
</body>
</html>
"@
        }
        catch {
            throw "Failed to build DC update HTML report. $($_.Exception.Message)"
        }
    }
}

function Send-DCUpdateEmail {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$HtmlBody,

        [Parameter(Mandatory = $true)]
        [string]$Subject,

        [Parameter(Mandatory = $true)]
        [string[]]$To,

        [Parameter(Mandatory = $true)]
        [string]$From,

        [Parameter(Mandatory = $true)]
        [string]$SmtpServer,

        [Parameter()]
        [int]$SmtpPort = $script:DCUpdateReportConfig.DefaultSmtpPort,

        [Parameter()]
        [switch]$UseSsl,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential
    )

    $MailMessage            = New-Object System.Net.Mail.MailMessage
    $MailMessage.From       = $From
    $MailMessage.Subject    = $Subject
    $MailMessage.Body       = $HtmlBody
    $MailMessage.IsBodyHtml = $true

    foreach ($CurrentRecipient in $To) {
        [void]$MailMessage.To.Add($CurrentRecipient)
    }

    $SmtpClient           = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
    $SmtpClient.EnableSsl = [bool]$UseSsl

    if ($Credential) {
        $SmtpClient.Credentials = $Credential.GetNetworkCredential()
    }
    else {
        $SmtpClient.UseDefaultCredentials = $true
    }

    try {
        Write-Verbose "Sending email via $SmtpServer on port $SmtpPort"
        $SmtpClient.Send($MailMessage)
        Write-Host "✓ Email sent successfully to $($To -join ', ')" -ForegroundColor Green
    }
    catch {
        $ErrorMessage = 'Failed to send SMTP message via {0}:{1}. {2}' -f $SmtpServer, $SmtpPort, $_.Exception.Message
        throw $ErrorMessage
    }
    finally {
        $MailMessage.Dispose()
        $SmtpClient.Dispose()
    }
}

#endregion

#region Main Orchestration

function Invoke-DCUpdateComplianceReport {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$TargetDomain = [Domain]::GetCurrentDomain().Name,

        [Parameter()]
        [switch]$IncludeDiagnostics,

        [Parameter()]
        [switch]$SendEmail,

        # By default, email is suppressed when no DCs need attention (controlled by
        # $script:DCUpdateReportConfig.SuppressHealthyEmail). Pass -SendAlways to
        # deliver the report unconditionally regardless of that setting.
        [Parameter()]
        [switch]$SendAlways,

        [Parameter()]
        [string[]]$To,

        [Parameter()]
        [string]$From,

        [Parameter()]
        [string]$SmtpServer,

        [Parameter()]
        [int]$SmtpPort = $script:DCUpdateReportConfig.DefaultSmtpPort,

        [Parameter()]
        [switch]$UseSsl,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [string]$ExportCsvPath
    )

    Write-Section -Message "Starting DC update compliance report for $TargetDomain"

    Write-Verbose 'Collecting domain controller inventory'
    $Inventory = @(Get-DCInventory -TargetDomain $TargetDomain)

    if ($Inventory.Count -eq 0) {
        throw "No domain controllers were found for '$TargetDomain'."
    }

    Write-Verbose 'Collecting update status'
    $Status = @($Inventory | Get-DCUpdateStatus)

    Write-Verbose 'Determining per-OS baseline map'
    $BaselineMap = $Status | Get-DCUpdateBaseline

    Write-Verbose 'Assessing compliance'
    $AssessmentParams = @{
        BaselineMap = $BaselineMap
    }
    $Assessment = @($Status | Get-DCUpdateAssessment @AssessmentParams)

    if ($IncludeDiagnostics) {
        Write-Verbose 'Collecting diagnostics for flagged systems'
        $Assessment = @($Assessment | Get-DCUpdateDiagnostics)

        Write-Verbose 'Reassessing compliance after diagnostics'
        $Assessment = @($Assessment | Get-DCUpdateAssessment @AssessmentParams)
    }

    if ($ExportCsvPath) {
        Write-Verbose "Exporting CSV to $ExportCsvPath"
        $Assessment | Export-Csv -Path $ExportCsvPath -NoTypeInformation -Encoding UTF8 -Force
    }

    if ($SendEmail) {
        if ([string]::IsNullOrWhiteSpace($SmtpServer)) {
            throw 'SendEmail was specified, but SmtpServer was not provided.'
        }

        if (-not $To -or $To.Count -eq 0) {
            throw 'SendEmail was specified, but no recipient was provided in To.'
        }

        if ([string]::IsNullOrWhiteSpace($From)) {
            throw 'SendEmail was specified, but From was not provided.'
        }

        $IssueCount    = @($Assessment | Where-Object { $_.NeedsAttention }).Count
        $SuppressEmail = -not $SendAlways -and $script:DCUpdateReportConfig.SuppressHealthyEmail -and ($IssueCount -eq 0)

        if ($SuppressEmail) {
            Write-Verbose 'No issues found and SuppressHealthyEmail is enabled. Pass -SendAlways to deliver regardless.'
        }
        else {
            Write-Verbose 'Building HTML report body'
            $HtmlBody = $Assessment | ConvertTo-DCUpdateHtmlReport -BaselineMap $BaselineMap

            if ([string]::IsNullOrWhiteSpace($HtmlBody)) {
                throw 'HTML report body was empty. Email send aborted.'
            }

            $BaselineSummary = @(
                foreach ($CurrentKey in ($BaselineMap.Keys | Sort-Object)) {
                    $CurrentBaseline = $BaselineMap[$CurrentKey]
                    if ($null -eq $CurrentBaseline.BaselineBuildLabel) {
                        '{0}: Unknown' -f $CurrentKey
                    }
                    else {
                        '{0}: {1}' -f $CurrentKey, $CurrentBaseline.BaselineBuildLabel
                    }
                }
            ) -join ' | '

            $SubjectPrefix = if ($IssueCount -gt 0) { 'DC Update Alert' } else { 'DC Update Report' }
            $Subject       = '{0} - {1} - {2}' -f $SubjectPrefix, (Get-Date -Format 'yyyy-MM-dd HH:mm'), $BaselineSummary

            $MailParams = @{
                HtmlBody   = $HtmlBody
                Subject    = $Subject
                To         = $To
                From       = $From
                SmtpServer = $SmtpServer
                SmtpPort   = $SmtpPort
                UseSsl     = $UseSsl
            }

            if ($Credential) {
                $MailParams.Credential = $Credential
            }

            if ($PSBoundParameters.ContainsKey('Verbose')) {
                $MailParams.Verbose = $PSBoundParameters.Verbose
            }

            Send-DCUpdateEmail @MailParams
        }
    }

    Write-Section -Message 'Execution Summary'
    $Assessment |
        Sort-Object OverallStatus, OperatingSystem, DaysSinceLastUpdate -Descending |
        Select-Object ComputerName, Domain, Site, OperatingSystem, LatestUpdateTitle, LatestUpdateDate, DaysSinceLastUpdate, CurrentBuildLabel, BaselineBuildLabel, PeerBuildBucketDelta, UpdateRecencyStatus, PeerBuildStatus, OverallStatus, Notes |
        Format-Table -AutoSize

    return $Assessment
}

#endregion

$Params = @{
    SendEmail         = $true
    SmtpServer        = 
    To                = 
    From              = 
    Verbose           = $true
}

Invoke-DCUpdateComplianceReport @Params
