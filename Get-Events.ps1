function Get-Events {
    <#
        .SYNOPSIS
            Retrieves Windows event log entries based on provided filters.

        .DESCRIPTION
            This function retrieves Windows event log entries filtered by log name, event IDs, user identity, start time, and end time.
            The retrieved events are converted to a custom object with nested properties reflecting the original XML structure of the event.

        .PARAMETER LogName
            The name of the event log (e.g., 'Security').

        .PARAMETER ID
            An array of event IDs to filter by.

        .PARAMETER Identity
            The user identity (SAM account name) to filter events for.

        .PARAMETER StartTime
            The start time for the events to retrieve.

        .PARAMETER EndTime
            The end time for the events to retrieve.

        .EXAMPLE
            Get-Events -LogName "Security" -ID 4624, 4625

        .EXAMPLE
            Get-Events -LogName "Security" -Identity "jdoe"

        .EXAMPLE
            Get-Events -LogName "Application" -StartTime (Get-Date).AddDays(-1)

        .NOTES
            Name: Get-Events
            Author: Ryan Whitlock
            Date: 07.10.2024
            Version: 1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Application', 'Security', 'System', 'Setup', 'ForwardedEvents')]
        [string]$LogName,

        [Parameter()]
        [int[]]$ID,

        [Parameter()]
        [ValidateScript({
            try {
                $null = Get-ADUser -Identity $_ -ErrorAction Stop
                $true
            } catch {
                throw "User '$($_)' not found."
            }
        })]
        [string]$Identity,

        [Parameter()]
        [datetime]$StartTime,

        [Parameter()]
        [datetime]$EndTime
    )

    begin {
        # Initialize filter hashtable
        $FilterHt = @{LogName = $LogName}

        # Process parameters using switch statement
        switch ($PSBoundParameters.Keys) {
            'ID' {
                $FilterHt['ID'] = $ID
            }
            'StartTime' {
                $FilterHt['StartTime'] = $StartTime
            }
            'EndTime' {
                $FilterHt['EndTime'] = $EndTime
            }
            'Identity' {
                $User = Get-ADUser -Identity $Identity
                $FilterHt['Data'] = $User.SamAccountName
            }
        }
    }

    process {
        try {
            $Events = Get-WinEvent -FilterHashtable $FilterHt | ForEach-Object {
                $EventXml = [xml]$_.ToXml()

                # Handle XML namespaces
                $NS = New-Object System.Xml.XmlNamespaceManager($EventXml.NameTable)
                $NS.AddNamespace("default", $EventXml.DocumentElement.NamespaceURI)

                $properties = @{
                    EventID           = $_.Id
                    Message           = $_.Message
                    TimeCreated       = $_.TimeCreated
                    ContainerLog      = $_.ContainerLog
                    LevelDisplayName  = $_.LevelDisplayName
                    OpcodeDisplayName = $_.OpcodeDisplayName
                }

                function Add-XmlNodeProperties {
                    param (
                        [System.Xml.XmlNode]$node,
                        [hashtable]$props,
                        [string]$parentPath = ""
                    )

                    foreach ($child in $node.ChildNodes) {
                        $nodeName = $child.Name
                        $nodePath = if ($parentPath) { "$parentPath.$nodeName" } else { $nodeName }

                        if ($child.HasChildNodes -and $child.ChildNodes.Count -gt 1) {
                            if (-not $props.ContainsKey($nodeName)) {
                                $props[$nodeName] = @{}
                            }
                            Add-XmlNodeProperties -node $child -props $props[$nodeName] -parentPath $nodePath
                        } else {
                            $props[$nodeName] = $child.InnerText
                        }
                    }
                }

                Add-XmlNodeProperties -node $EventXml.DocumentElement -props $properties

                [PSCustomObject]$properties
            }
            
            Write-Output $Events
        } catch {
            Write-Error "Failed to retrieve events: $_"
        }
    }

    end {}
}
