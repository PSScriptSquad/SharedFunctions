#Requires -Version 5.1

<#
.SYNOPSIS
    High-performance Windows Event Log querying at scale with server-side filtering.

.DESCRIPTION
    Get-Events provides a self-contained, portable solution for querying Windows Event Logs
    locally and remotely. It uses XPath 1.0 for 100% server-side filtering and streams results
    via EventLogReader to minimize memory usage. Supports NTDS message template resolution,
    flexible identity filtering, and named EventData field filtering.

.PARAMETER LogName
    The name of the event log to query (e.g., 'Security', 'System', 'Application', 'Directory Service').

.PARAMETER ComputerName
    Target computer(s). Defaults to local machine. Accepts pipeline input.

.PARAMETER ID
    Event ID(s) to filter.

.PARAMETER Identity
    User identities to filter (SAM account name, UPN, or SID). Automatically routes to appropriate fields.
    Searches: SubjectUserName, TargetUserName, AccountName, User, SubjectUserSid, TargetUserSid.

.PARAMETER NamedDataFilter
    Hashtable for filtering on specific EventData fields by name.
    Example: @{ 'LogonType' = @('2','10'); 'IpAddress' = '192.168.1.1' }

.PARAMETER StartTime
    Include events on or after this time (converted to UTC for filtering).

.PARAMETER EndTime
    Include events on or before this time (converted to UTC for filtering).

.PARAMETER MaxEventsPerComputer
    Maximum number of events to retrieve per target computer. Default is unlimited (-1).

.PARAMETER Credential
    Credentials for remote connections.

.PARAMETER ThrottleLimit
    Maximum concurrent remote operations. Default is 10.

.PARAMETER SkipXmlParsing
    Return minimal fields without XML parsing for maximum throughput.

.PARAMETER IncludeXml
    Include raw event XML in output (only when XML parsing is enabled).

.PARAMETER IncludeRenderedDescription
    Include rendered message description (slower, only when XML parsing is enabled).

.EXAMPLE
    Get-Events -LogName Security -ID 4624 -Identity 'Test' -StartTime (Get-Date).AddHours(-2)
    
    Retrieves logon events for user Test from the past 2 hours.

.EXAMPLE
    Get-Events -LogName Security -ID 4625 -NamedDataFilter @{ 'LogonType' = @('2','10') } -MaxEventsPerComputer 100
    
    Gets failed logon events with interactive or RDP logon types, maximum 100 per computer.

.EXAMPLE
    'DC01','DC02' | Get-Events -LogName 'Directory Service' -ID 1644 -MaxEventsPerComputer 10
    
    Retrieves the 10 newest LDAP query events from each domain controller with NTDS message templates.

.EXAMPLE
    Get-Events -LogName System -ID 1,6,13 -SkipXmlParsing
    
    Ultra-fast query returning only basic fields without XML parsing overhead.

.NOTES
    Author: Ryan Whitlock
    Version: 4.1.0
    Requires: PowerShell 5.1+
    No external module dependencies
#>

#region Component A: Native Type Definition and Load

$script:NativeTypeDefinition = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class NtdsMessageNative
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr LoadLibraryEx(string lpFileName, IntPtr hFile, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool FreeLibrary(IntPtr hModule);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int FormatMessageW(
        uint dwFlags,
        IntPtr lpSource,
        uint dwMessageId,
        uint dwLanguageId,
        StringBuilder lpBuffer,
        int nSize,
        IntPtr Arguments);

    public const uint LOAD_LIBRARY_AS_DATAFILE = 0x00000002;
    public const uint FORMAT_MESSAGE_FROM_HMODULE = 0x00000800;
    public const uint FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
}
'@

# Load native type FIRST - must happen before classes are defined
if (-not ([System.Management.Automation.PSTypeName]'NtdsMessageNative').Type) {
    try {
        Add-Type -TypeDefinition $script:NativeTypeDefinition -ErrorAction Stop
        Write-Verbose "Loaded NtdsMessageNative type successfully"
    } catch {
        throw "CRITICAL: Failed to load NtdsMessageNative type required for class definitions: $_"
    }
}

#endregion

#region Component B: PowerShell Class Definitions

# Classes no longer reference [NtdsMessageNative] directly at parse-time
# They use reflection to access it at run-time, avoiding parse-time errors

class EventQueryFilter {
        [int[]]$EventIDs
        [Nullable[datetime]]$StartTime
        [Nullable[datetime]]$EndTime
        [hashtable]$NamedDataFilter
        [string[]]$IdentityFilter
        [string[]]$IdentityFields = @('SubjectUserName','TargetUserName','AccountName','User','SubjectUserSid','TargetUserSid')

        EventQueryFilter() {
            $this.NamedDataFilter = @{}
        }

        hidden [string] EscapeForXPath([string]$value) {
            return $value -replace "'", "&apos;"
        }

        hidden [string] BuildIdentityPredicate() {
            if (-not $this.IdentityFilter -or $this.IdentityFilter.Count -eq 0) { return $null }

            $tests = [System.Collections.Generic.List[string]]::new()

            foreach ($raw in $this.IdentityFilter) {
                if (-not $raw) { continue }
                $val = [string]$raw
                $esc = $this.EscapeForXPath($val)

                # 1) SID
                if ($val -match '^S-1-\d+(-\d+)+$') {
                    foreach ($f in @('SubjectUserSid','TargetUserSid','MemberSid')) {
                        $tests.Add("(Data[@Name='$f']='$esc')")
                    }
                    continue
                }

                # 2) DOMAIN\User
                if ($val -match '^([^\\]+)\\([^\\]+)$') {
                    $domain = $this.EscapeForXPath($Matches[1])
                    $user   = $this.EscapeForXPath($Matches[2])

                    $tests.Add("((Data[@Name='TargetUserName']='$user') and (Data[@Name='TargetDomainName']='$domain'))")
                    $tests.Add("((Data[@Name='SubjectUserName']='$user') and (Data[@Name='SubjectDomainName']='$domain'))")
                    $tests.Add("(Data[@Name='MemberName']='$domain\\$user')")
                    # Some events use AccountName/AccountDomain
                    $tests.Add("((Data[@Name='AccountName']='$user') and (Data[@Name='AccountDomain']='$domain'))")
                    continue
                }

                # 3) UPN
                if ($val -match '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                    $userPart = $this.EscapeForXPath(($val -split '@',2)[0])
                    foreach ($f in @('TargetUserName','SubjectUserName','AccountName','User')) {
                        $tests.Add("(Data[@Name='$f']='$esc')")
                        $tests.Add("(Data[@Name='$f']='$userPart')")
                    }
                    continue
                }

                # 4) Plain username
                foreach ($f in @('TargetUserName','SubjectUserName','AccountName','User')) {
                    $tests.Add("(Data[@Name='$f']='$esc')")
                    # simple case variants since translate() is not available
                    $lo = $this.EscapeForXPath($val.ToLower())
                    $up = $this.EscapeForXPath($val.ToUpper())
                    if ($lo -ne $esc) { $tests.Add("(Data[@Name='$f']='$lo')") }
                    if ($up -ne $esc) { $tests.Add("(Data[@Name='$f']='$up')") }
                }
            }

            if ($tests.Count -eq 0) { return $null }
            return 'EventData[' + ($tests -join ' or ') + ']'
        }

        [string] BuildXPathQuery() {
            $systemParts = [System.Collections.Generic.List[string]]::new()
        
            if ($this.EventIDs -and $this.EventIDs.Count -gt 0) {
                if ($this.EventIDs.Count -eq 1) {
                    $systemParts.Add("EventID=$($this.EventIDs[0])")
                } else {
                    $systemParts.Add('(' + (($this.EventIDs | ForEach-Object { "EventID=$_"} ) -join ' or ') + ')')
                }
            }
        
            if ($this.StartTime) {
                $timestampUtc = $this.StartTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                $systemParts.Add("TimeCreated[@SystemTime>='$timestampUtc']")
            }
        
            if ($this.EndTime) {
                $timestampUtc = $this.EndTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
                $systemParts.Add("TimeCreated[@SystemTime<='$timestampUtc']")
            }

            $parts = [System.Collections.Generic.List[string]]::new()
        
            if ($systemParts.Count -gt 0) {
                $parts.Add('System[' + ($systemParts -join ' and ') + ']')
            }

            if ($this.NamedDataFilter -and $this.NamedDataFilter.Count -gt 0) {
                foreach ($key in $this.NamedDataFilter.Keys) {
                    $value = $this.NamedDataFilter[$key]
                    if ($value -is [array]) {
                        $orGroup = '(' + (($value | ForEach-Object {
                            $escapedValue = $this.EscapeForXPath([string]$_)
                            "Data[@Name='$key']='$escapedValue'"
                        }) -join ' or ') + ')'
                        $parts.Add("EventData[$orGroup]")
                    } else {
                        $escapedValue = $this.EscapeForXPath([string]$value)
                        $parts.Add("EventData[Data[@Name='$key']='$escapedValue']")
                    }
                }
            }

            $identityPredicate = $this.BuildIdentityPredicate()
            if ($identityPredicate) {
                $parts.Add($identityPredicate)
            }

            if ($parts.Count -gt 0) {
                return '*[' + ($parts -join ' and ') + ']'
            }
        
            Write-Verbose "No filter criteria provided. Using safe default: all events."
            return '*'
        }
    }

class NtdsMessageResolver {
        static hidden [hashtable]$_messageCache = @{}
        static hidden [IntPtr]$_moduleHandle = [IntPtr]::Zero
        static hidden [bool]$_loadAttempted = $false

        static hidden [void] LoadMessageLibrary() {
            if ([NtdsMessageResolver]::_loadAttempted) {
                return
            }
            
            [NtdsMessageResolver]::_loadAttempted = $true
            
            $dllPath = Join-Path -Path $env:SystemRoot -ChildPath 'System32\ntdsmsg.dll'
            if (-not (Test-Path -Path $dllPath)) {
                Write-Verbose "NtdsMessageResolver: ntdsmsg.dll not found at $dllPath"
                return
            }
            
            try {
                # Get the type dynamically to avoid parse-time reference
                $ntdsType = [System.Type]::GetType('NtdsMessageNative')
                if (-not $ntdsType) {
                    Write-Verbose "NtdsMessageNative type not loaded"
                    return
                }
                
                $loadLibraryMethod = $ntdsType.GetMethod('LoadLibraryEx')
                $loadAsDatafile = $ntdsType.GetField('LOAD_LIBRARY_AS_DATAFILE').GetValue($null)
                
                [NtdsMessageResolver]::_moduleHandle = $loadLibraryMethod.Invoke($null, @($dllPath, [IntPtr]::Zero, $loadAsDatafile))
                
                if ([NtdsMessageResolver]::_moduleHandle -eq [IntPtr]::Zero) {
                    Write-Verbose "Failed to load ntdsmsg.dll"
                } else {
                    Write-Verbose "Successfully loaded ntdsmsg.dll"
                }
            } catch {
                Write-Verbose "Exception loading ntdsmsg.dll: $_"
            }
        }

        static [void] Unload() {
            if ([NtdsMessageResolver]::_moduleHandle -ne [IntPtr]::Zero) {
                $ntdsType = [System.Type]::GetType('NtdsMessageNative')
                if ($ntdsType) {
                    $freeLibraryMethod = $ntdsType.GetMethod('FreeLibrary')
                    [void]$freeLibraryMethod.Invoke($null, @([NtdsMessageResolver]::_moduleHandle))
                }
                [NtdsMessageResolver]::_moduleHandle = [IntPtr]::Zero
                Write-Verbose "Unloaded ntdsmsg.dll"
            }
        }

        static [string] GetMessageTemplate([uint32]$eventId) {
            if ([NtdsMessageResolver]::_messageCache.ContainsKey($eventId)) {
                return [NtdsMessageResolver]::_messageCache[$eventId]
            }
            
            [NtdsMessageResolver]::LoadMessageLibrary()
            
            if ([NtdsMessageResolver]::_moduleHandle -eq [IntPtr]::Zero) {
                return $null
            }

            $template = [NtdsMessageResolver]::RetrieveMessage($eventId)
            [NtdsMessageResolver]::_messageCache[$eventId] = $template
            return $template
        }

        static hidden [string] RetrieveMessage([uint32]$eventId) {
            # Get type dynamically to avoid parse-time reference
            $ntdsType = [System.Type]::GetType('NtdsMessageNative')
            if (-not $ntdsType) {
                return $null
            }
            
            $formatMessageMethod = $ntdsType.GetMethod('FormatMessageW')
            $formatFromHModule = $ntdsType.GetField('FORMAT_MESSAGE_FROM_HMODULE').GetValue($null)
            $formatIgnoreInserts = $ntdsType.GetField('FORMAT_MESSAGE_IGNORE_INSERTS').GetValue($null)
            $flags = $formatFromHModule -bor $formatIgnoreInserts
            
            $buffer = [System.Text.StringBuilder]::new(4096)
            $severityMasks = @(0x00000000, 0x40000000, 0x80000000, 0xC0000000)
            $facilityMasks = @(0x00000000, 0x00080000, 0x00030000, 0x000A0000)

            foreach ($facility in $facilityMasks) {
                foreach ($severity in $severityMasks) {
                    $messageId = $severity -bor $facility -bor $eventId
                    $charCount = $formatMessageMethod.Invoke($null, @(
                        $flags, 
                        [NtdsMessageResolver]::_moduleHandle, 
                        $messageId, 
                        0, 
                        $buffer, 
                        $buffer.Capacity, 
                        [IntPtr]::Zero
                    ))
                    if ($charCount -gt 0) {
                        return $buffer.ToString().Trim()
                    }
                }
            }
            return $null
        }
    }

class EventDataParser {
        [int[]]$AllowedEventIds
        [bool]$IncludeXml
        [bool]$IncludeRenderedDescription

        [PSCustomObject] ParseEvent([System.Diagnostics.Eventing.Reader.EventRecord]$event) {
            Write-Verbose "    Parsing event ID $($event.Id) RecordId $($event.RecordId)"
            
            $properties = @{
                Id               = $event.Id
                RecordId         = $event.RecordId
                TimeCreated      = $event.TimeCreated
                LevelDisplayName = $event.LevelDisplayName
                LogName          = $event.LogName
                ProviderName     = $event.ProviderName
                MachineName      = $event.MachineName
                UserId           = $event.UserId
                EventData        = [ordered]@{}
                System           = [ordered]@{}
            }

            try {
                $eventAsXml = [xml]$event.ToXml()
                Write-Verbose "      Raw XML length: $($event.ToXml().Length) characters"
                
                $xmlNamespaceManager = [System.Xml.XmlNamespaceManager]::new($eventAsXml.NameTable)
                $xmlNamespaceManager.AddNamespace("evt", $eventAsXml.DocumentElement.NamespaceURI)
                Write-Verbose "      Namespace: $($eventAsXml.DocumentElement.NamespaceURI)"

                $systemNode = $eventAsXml.SelectSingleNode("//evt:System", $xmlNamespaceManager)
                if ($systemNode) {
                    Write-Verbose "      System node found with $($systemNode.ChildNodes.Count) child nodes"
                    Write-Verbose "      System hashtable before parsing: Count = $($properties.System.Count)"
                    $this.AddXmlNodeProperties($systemNode, $properties.System)
                    Write-Verbose "      System hashtable after parsing: Count = $($properties.System.Count)"
                    Write-Verbose "      System keys: $($properties.System.Keys -join ', ')"
                } else {
                    Write-Verbose "      System node NOT found"
                }

                $eventDataNode = $eventAsXml.SelectSingleNode("//evt:EventData", $xmlNamespaceManager)
                if ($eventDataNode) {
                    Write-Verbose "      EventData node found with $($eventDataNode.ChildNodes.Count) child nodes"
                    $this.ParseEventDataNode($eventDataNode, $properties.EventData, $xmlNamespaceManager)
                    Write-Verbose "      Parsed EventData node with $($properties.EventData.Count) fields"
                } else {
                    Write-Verbose "      EventData node NOT found"
                }

                $isNtdsEvent = $this.AllowedEventIds -contains $event.Id -and (
                    $event.LogName -eq 'Directory Service' -or $event.ProviderName -like '*NTDS*'
                )

                if ($isNtdsEvent) {
                    Write-Verbose "      Attempting NTDS template resolution for Event ID $($event.Id)"
                    $ntdsTemplate = [NtdsMessageResolver]::GetMessageTemplate([uint32]$event.Id)
                    if ($ntdsTemplate) {
                        $properties.Add('NtdsMessageTemplate', $ntdsTemplate)
                        Write-Verbose "      NTDS template resolved"
                    }
                }
                
                if ($this.IncludeXml) {
                    $properties.Add('Xml', $event.ToXml())
                }

                if ($this.IncludeRenderedDescription) {
                    try {
                        $properties.Add('Description', $event.FormatDescription())
                    } catch {
                        $properties.Add('Description', "Failed to render: $_")
                    }
                }
            }
            catch {
                Write-Warning "Failed to parse XML for event $($event.RecordId): $($_.Exception.Message)"
            }
            
            return [PSCustomObject]$properties
        }

        hidden [void] ParseEventDataNode([System.Xml.XmlNode]$node, [System.Collections.Specialized.OrderedDictionary]$target, [System.Xml.XmlNamespaceManager]$ns) {
            $dataNodes = $node.SelectNodes("evt:Data", $ns)
            foreach ($dataNode in $dataNodes) {
                if ($dataNode.HasAttribute("Name")) {
                    $name = $dataNode.GetAttribute("Name")
                    try {
                        $target.Add($name, $dataNode.InnerText)
                        Write-Verbose "        Added EventData field: $name"
                    } catch {
                        Write-Verbose "        Failed to add EventData field $($name): $_"
                    }
                } else {
                    $index = $target.Count
                    try {
                        $target.Add("Data$index", $dataNode.InnerText)
                    } catch {
                        Write-Verbose "        Failed to add EventData field Data $($index): $_"
                    }
                }
            }
        }

        hidden [void] AddXmlNodeProperties([System.Xml.XmlNode]$node, [System.Collections.Specialized.OrderedDictionary]$target) {
            foreach ($childNode in $node.ChildNodes) {
                if ($childNode.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }

                # Always use a stable element name for keys
                $nodeName = if ($childNode.LocalName) { $childNode.LocalName } else { $childNode.Name }

                # Derive a useful value
                $value = $childNode.InnerText
                if ([string]::IsNullOrWhiteSpace($value) -and $childNode.Attributes.Count -gt 0) {
                    switch ($nodeName) {
                        'Provider' {
                            $nameAttr = $childNode.Attributes['Name']
                            if ($nameAttr -and -not [string]::IsNullOrWhiteSpace($nameAttr.Value)) {
                                $value = $nameAttr.Value
                            }
                        }
                        'TimeCreated' {
                            $sysAttr = $childNode.Attributes['SystemTime']
                            if ($sysAttr -and -not [string]::IsNullOrWhiteSpace($sysAttr.Value)) {
                                $value = $sysAttr.Value
                            }
                        }
                        default {
                            if ($childNode.Attributes.Count -eq 1) {
                                $value = $childNode.Attributes[0].Value
                            }
                        }
                    }
                }

                # Base key (e.g., 'Provider', 'TimeCreated', etc.)
                try {
                    if ($target.Contains($nodeName)) { $target[$nodeName] = $value }
                    else { $target.Add($nodeName, $value) }
                } catch { }

                # Attribute keys (e.g., 'Provider_Name', 'TimeCreated_SystemTime', etc.)
                if ($childNode.Attributes.Count -gt 0) {
                    foreach ($attr in $childNode.Attributes) {
                        $attrName = "{0}_{1}" -f $nodeName, $attr.Name
                        try {
                            if ($target.Contains($attrName)) { $target[$attrName] = $attr.Value }
                            else { $target.Add($attrName, $attr.Value) }
                        } catch { }
                    }
                }
            }
        }
    }

class EventLogQuery {
        [string]$LogName
        [string]$ComputerName
        [EventQueryFilter]$Filter
        [int]$MaxEvents = -1
        [bool]$ParseXml = $true

        hidden [EventDataParser]$_parser

        EventLogQuery([string]$logName, [string]$computerName) {
            $this.LogName = $logName
            $this.ComputerName = $computerName
            $this.Filter = [EventQueryFilter]::new()
            $this._parser = [EventDataParser]::new()
        }

        [System.Collections.ArrayList] Execute() {
            $this._parser.AllowedEventIds = $this.Filter.EventIDs
            $xpath = $this.Filter.BuildXPathQuery()
            Write-Verbose "  Computer: $($this.ComputerName)"
            Write-Verbose "  LogName: $($this.LogName)"
            Write-Verbose "  XPath: $xpath"
            Write-Verbose "  MaxEvents: $($this.MaxEvents)"
            Write-Verbose "  ParseXml: $($this.ParseXml)"

            $eventLogQuery = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
                $this.LogName, [System.Diagnostics.Eventing.Reader.PathType]::LogName, $xpath
            )
            $eventLogQuery.ReverseDirection = $true
            $eventLogQuery.TolerateQueryErrors = $true

            $session = $null
            $reader = $null
            $results = [System.Collections.ArrayList]::new()

            try {
                if ($this.ComputerName -ne $env:COMPUTERNAME -and $this.ComputerName -ne 'localhost') {
                    Write-Verbose "  Creating remote session to $($this.ComputerName)"
                    $session = [System.Diagnostics.Eventing.Reader.EventLogSession]::new($this.ComputerName)
                    $eventLogQuery.Session = $session
                } else {
                    Write-Verbose "  Using local event log session"
                }

                Write-Verbose "  Creating EventLogReader..."
                $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($eventLogQuery)
                $matchedCount = 0

                Write-Verbose "  Starting event enumeration..."
                while ($true) {
                    $eventRecord = $reader.ReadEvent()
                    if (-not $eventRecord) {
                        Write-Verbose "  No more events to read"
                        break
                    }

                    try {
                        Write-Verbose "    Read event ID $($eventRecord.Id) RecordId $($eventRecord.RecordId)"
                        
                        $outputObject = if ($this.ParseXml) {
                            $this._parser.ParseEvent($eventRecord)
                        } else {
                            [PSCustomObject]@{
                                Id               = $eventRecord.Id
                                RecordId         = $eventRecord.RecordId
                                TimeCreated      = $eventRecord.TimeCreated
                                LogName          = $eventRecord.LogName
                                ProviderName     = $eventRecord.ProviderName
                                MachineName      = $eventRecord.MachineName
                                UserId           = $eventRecord.UserId
                            }
                        }
                        
                        $outputObject | Add-Member -NotePropertyName 'ComputerName' -NotePropertyValue $this.ComputerName -Force
                        
                        Write-Verbose "    Adding event object to results collection"
                        [void]$results.Add($outputObject)
                        
                        $matchedCount++
                        
                        if ($this.MaxEvents -gt 0 -and $matchedCount -ge $this.MaxEvents) {
                            Write-Verbose "  Reached MaxEvents limit: $($this.MaxEvents)"
                            break
                        }
                    } finally {
                        $eventRecord.Dispose()
                    }
                }

                Write-Verbose "  Query complete. Processed $matchedCount events from $($this.ComputerName)"
                return $results

            } catch {
                Write-Warning "Event log query failed for computer '$($this.ComputerName)' on log '$($this.LogName)': $_"
                Write-Verbose "  Exception details: $($_.Exception.Message)"
                Write-Verbose "  Stack trace: $($_.ScriptStackTrace)"
                return [System.Collections.ArrayList]::new()
            } finally {
                if ($reader) {
                    $reader.Dispose()
                    Write-Verbose "  Disposed EventLogReader"
                }
                if ($session) {
                    $session.Dispose()
                    Write-Verbose "  Disposed EventLogSession"
                }
            }
        }
    }

#endregion

#region Component C: Pre-parse Class Definitions for Remoting

<#
.SYNOPSIS
    Reliably extracts the text of the script's class definitions for remote execution.

.DESCRIPTION
    This block is necessary to overcome a fundamental challenge with PowerShell remoting and self-contained scripts.
    For Invoke-Command to use custom classes, the raw text of those class definitions must be passed into the
    remote ScriptBlock. This requires the script to reliably find its own source file.

    Standard variables like `$MyInvocation.MyCommand.Path` are unreliable as they can point to the wrong file
    (or be null) when the script is dot-sourced, especially by testing frameworks like Pester. This leads to
    remoting failures.

    The solution is to parse the script file ONCE when it is first loaded using the Abstract Syntax Tree (AST).
    This logic uses a fallback chain to find the script's path in various environments:
    1. `$PSCommandPath`             - For standard execution (F5 / direct run).
    2. `$global:psEditor`           - For VS Code "Run Selection" (F8).
    3. `$psISE`                     - For PowerShell ISE "Run Selection" (F8).

    By pre-parsing and storing the class text in `$script:GetEvents_ClassDefinitions`, we ensure the Get-Events
    function is both portable (no external module dependencies) and adheres to the DRY principle (avoids
    duplicating class code inside the remote scriptblock).
#>

# Find the path to *this* script file, supporting F5, F8 in VS Code, and F8 in ISE
$thisScriptPath = $null

if ($PSCommandPath) {
    $thisScriptPath = $PSCommandPath
} elseif ($global:psEditor) {
    $thisScriptPath = $global:psEditor.GetEditorContext().CurrentFile.Path
} elseif ($psISE) {
    $thisScriptPath = $psISE.CurrentFile.FullPath
}

# Parse this script file ONCE upon loading to reliably get class definitions
if (-not [string]::IsNullOrWhiteSpace($thisScriptPath)) {
    try {
        $scriptAst = [System.Management.Automation.Language.Parser]::ParseFile(
            $thisScriptPath,
            [ref]$null,
            [ref]$null
        )

        $classAsts = $scriptAst.FindAll({
            $args[0] -is [System.Management.Automation.Language.TypeDefinitionAst]
        }, $true)
        
        $script:GetEvents_ClassDefinitions = ($classAsts | ForEach-Object { $_.Extent.Text }) -join "`r`n`r`n"

        if ([string]::IsNullOrWhiteSpace($script:GetEvents_ClassDefinitions)) {
            throw "Failed to extract any class definitions from $thisScriptPath."
        }
    } catch {
        Write-Warning "CRITICAL: Failed to pre-parse class definitions from '$thisScriptPath' for remoting. Remote execution will fail. Error: $_"
    }
} else {
    Write-Warning "CRITICAL: Could not determine the script path. Remote execution will fail."
}

#endregion

#region Component D: Public Function Get-Events

function Get-Events {
    [CmdletBinding(PositionalBinding=$false)]
    [OutputType([PSCustomObject])]
    param(
        [Parameter(Mandatory=$true)]
        [string]$LogName,

        [Parameter(ValueFromPipeline=$true)]
        [string[]]$ComputerName = @($env:COMPUTERNAME),

        [Parameter()]
        [int[]]$ID,

        [Parameter()]
        [ValidateScript({
            foreach ($user in ($_ | Where-Object { $_ })) {
                if ($user -notmatch '^[A-Za-z0-9_.-]+(\\[A-Za-z0-9_.-]+)?$' -and
                    $user -notmatch '^S-1-\d+(-\d+)+$' -and
                    $user -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') {
                    throw "Identity '$user' must be SAM (user or DOMAIN\user), UPN, or SID."
                }
            }
            return $true
        })]
        [string[]]$Identity,

        [Parameter()]
        [hashtable]$NamedDataFilter,

        [Parameter()]
        [datetime]$StartTime,

        [Parameter()]
        [datetime]$EndTime,

        [Parameter()]
        [int]$MaxEventsPerComputer = -1,

        [Parameter()]
        [PSCredential]$Credential,

        [Parameter()]
        [int]$ThrottleLimit = 10,

        [Parameter()]
        [switch]$SkipXmlParsing,

        [Parameter()]
        [switch]$IncludeXml,

        [Parameter()]
        [switch]$IncludeRenderedDescription
    )

    begin {
        Write-Verbose "=== Get-Events BEGIN ==="
        
        # Verify native type is loaded
        if (-not ([System.Management.Automation.PSTypeName]'NtdsMessageNative').Type) {
            Write-Warning "NtdsMessageNative type not loaded. NTDS template resolution will not work."
        } else {
            Write-Verbose "NtdsMessageNative type verified"
        }

        # Verify classes are loaded
        try {
            $null = [EventLogQuery]
            Write-Verbose "Classes verified loaded"
        } catch {
            throw "Classes not loaded properly: $_"
        }

        # Accumulator for pipeline input
        $allComputerNames = [System.Collections.Generic.List[string]]::new()
        
        Write-Verbose "Parameters:"
        Write-Verbose "  LogName: $LogName"
        Write-Verbose "  ID: $($ID -join ',')"
        Write-Verbose "  Identity: $($Identity -join ',')"
        Write-Verbose "  StartTime: $StartTime"
        Write-Verbose "  EndTime: $EndTime"
        Write-Verbose "  MaxEventsPerComputer: $MaxEventsPerComputer"
        Write-Verbose "  SkipXmlParsing: $($SkipXmlParsing.IsPresent)"
    }

    process {
        Write-Verbose "=== Get-Events PROCESS ==="
        # Collect all computer names from pipeline
        foreach ($computer in $ComputerName) {
            $allComputerNames.Add($computer)
            Write-Verbose "Added computer to queue: $computer"
        }
    }

    end {
        Write-Verbose "=== Get-Events END ==="
        Write-Verbose "Total computers queued: $($allComputerNames.Count)"
        
        # Deduplicate and categorize computers
        $localComputerNameSet = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::InvariantCultureIgnoreCase
        )
        $localComputerNameSet.Add($env:COMPUTERNAME) | Out-Null
        $localComputerNameSet.Add('localhost') | Out-Null
        $localComputerNameSet.Add('.') | Out-Null

        $uniqueComputers = $allComputerNames | Select-Object -Unique
        $localComputers = [System.Collections.Generic.List[string]]::new()
        $remoteComputers = [System.Collections.Generic.List[string]]::new()

        foreach ($computer in $uniqueComputers) {
            if ($localComputerNameSet.Contains($computer)) {
                $localComputers.Add($env:COMPUTERNAME)
                Write-Verbose "Categorized as LOCAL: $computer"
            } else {
                $remoteComputers.Add($computer)
                Write-Verbose "Categorized as REMOTE: $computer"
            }
        }

        # --- Local Execution ---
        if ($localComputers.Count -gt 0) {
            Write-Verbose "--- Starting LOCAL execution ---"
            Write-Verbose "Executing local query on $($localComputers[0])"
            
            try {
                $localQuery = [EventLogQuery]::new($LogName, $env:COMPUTERNAME)
                $localQuery.MaxEvents = $MaxEventsPerComputer
                $localQuery.ParseXml = -not $SkipXmlParsing.IsPresent
                $localQuery.Filter.EventIDs = $ID
                $localQuery.Filter.StartTime = $StartTime
                $localQuery.Filter.EndTime = $EndTime
                $localQuery.Filter.IdentityFilter = $Identity
                
                if ($PSBoundParameters.ContainsKey('NamedDataFilter')) {
                    $localQuery.Filter.NamedDataFilter = $NamedDataFilter
                    Write-Verbose "Applied NamedDataFilter with $($NamedDataFilter.Keys.Count) keys"
                }
                
                $localQuery._parser.IncludeXml = $IncludeXml.IsPresent
                $localQuery._parser.IncludeRenderedDescription = $IncludeRenderedDescription.IsPresent
                
                Write-Verbose "Executing local query..."
                # Capture output from Execute() and write to pipeline
                $localResults = $localQuery.Execute()
                Write-Verbose "Local query returned $(@($localResults).Count) results"
                
                # Output to pipeline
                $localResults | Write-Output
                Write-Verbose "Local query completed"
                
            } catch {
                Write-Error "Local query failed: $_"
                Write-Verbose "Exception: $($_.Exception.Message)"
            }
        }

        # --- Remote Execution ---
        if ($remoteComputers.Count -gt 0) {
            Write-Verbose "--- Starting REMOTE execution ---"
            Write-Verbose "Executing remote queries on $($remoteComputers.Count) computer(s)"
            
        # Check if the class definitions were loaded successfully earlier
        if (-not $script:GetEvents_ClassDefinitions) {
            Write-Error "Cannot perform remote execution because class definitions were not loaded."
            return
        }
        Write-Verbose "Using pre-parsed class definitions for remoting."
            
            # Build the remote scriptblock using the stored class definitions
            $remoteScriptBlock = [scriptblock]::Create(@"
param(
    `$LogName, `$FilterData, `$MaxEvents, `$ParseXml, `$IncludeXml, `$IncludeRenderedDescription
)

# 1. Load P/Invoke definitions
`$nativeTypeDefinition = @'
$($script:NativeTypeDefinition)
'@

if (-not ([System.Management.Automation.PSTypeName]'NtdsMessageNative').Type) {
    try { 
        Add-Type -TypeDefinition `$nativeTypeDefinition -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load native type on remote: `$_"
    }
}

# 2. Load Class definitions
$($script:GetEvents_ClassDefinitions)

# 3. Execute Query
try {
    `$remoteQuery = [EventLogQuery]::new(`$LogName, `$env:COMPUTERNAME)
    `$remoteQuery.MaxEvents = `$MaxEvents
    `$remoteQuery.ParseXml = `$ParseXml
    `$remoteQuery.Filter.EventIDs = `$FilterData.EventIDs
    `$remoteQuery.Filter.StartTime = `$FilterData.StartTime
    `$remoteQuery.Filter.EndTime = `$FilterData.EndTime
    `$remoteQuery.Filter.IdentityFilter = `$FilterData.IdentityFilter
    `$remoteQuery.Filter.NamedDataFilter = `$FilterData.NamedDataFilter
    `$remoteQuery._parser.IncludeXml = `$IncludeXml
    `$remoteQuery._parser.IncludeRenderedDescription = `$IncludeRenderedDescription
    `$remoteQuery.Execute()
} catch {
    Write-Error "Remote query execution failed: `$_"
}
"@)

            # Prepare filter data for serialization
            $filterData = @{
                EventIDs        = $ID
                StartTime       = $StartTime
                EndTime         = $EndTime
                IdentityFilter  = $Identity
                NamedDataFilter = if ($PSBoundParameters.ContainsKey('NamedDataFilter')) { $NamedDataFilter } else { @{} }
            }

            # Build Invoke-Command parameters
            $invokeParams = @{
                ComputerName = $remoteComputers
                ScriptBlock  = $remoteScriptBlock
                ArgumentList = @(
                    $LogName, 
                    $filterData, 
                    $MaxEventsPerComputer,
                    (-not $SkipXmlParsing.IsPresent),
                    $IncludeXml.IsPresent,
                    $IncludeRenderedDescription.IsPresent
                )
                ErrorAction  = 'Continue'
            }
            
            if ($PSBoundParameters.ContainsKey('Credential')) {
                $invokeParams.Credential = $Credential
            }
            
            if ($ThrottleLimit -gt 0) {
                $invokeParams.ThrottleLimit = $ThrottleLimit
            }

            try {
                Write-Verbose "Invoking remote command..."
                $remoteResults = Invoke-Command @invokeParams
                Write-Verbose "Remote command returned $($remoteResults.Count) results"
                
                $remoteResults | 
                    Select-Object -Property * -ExcludeProperty PSComputerName, RunspaceId, PSShowComputerName |
                    Write-Output
                    
            } catch {
                Write-Error "Remote execution failed: $_"
                Write-Verbose "Exception: $($_.Exception.Message)"
            }
        }

        # Cleanup
        Write-Verbose "Cleaning up..."
        [NtdsMessageResolver]::Unload()
        Write-Verbose "=== Get-Events COMPLETE ==="
    }
}
#endregion
