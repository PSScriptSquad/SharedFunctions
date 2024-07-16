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
            Version: 2.3
    #>
    [CmdletBinding()]
    [OutputType([PSCustomObject[]])]
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
        # Function to recursively add XML nodes to the hashtable
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
                    # Check if the node is Binary and decode it
                    if ($nodeName -match 'BinaryEventData|Binary|EventPayload' ) {
                        $props[$nodeName] = ConvertFrom-HexString -InputObject $child.InnerText
                    } else {
                        $props[$nodeName] = $child.InnerText
                    }
                }
            }
        }

        function ConvertFrom-HexString {
            <#
                .SYNOPSIS
                    Converts a hex string to a byte array or a decoded text string.

                .DESCRIPTION
                    The ConvertFrom-HexString function takes a string of hexadecimal values and converts it into either a raw byte array or a text string based on the provided encoding.
                    This can be useful for interpreting hex dumps or any encoded data that needs to be converted to a readable format.

                .PARAMETER InputObject
                    The hex string(s) to convert. This parameter is mandatory and can accept multiple strings from the pipeline.

                .PARAMETER Delimiter
                    Specifies the delimiter used to separate hex pairs in the input string. The default is a space (" ").

                .PARAMETER RawBytes
                    Switch to output raw byte arrays instead of a decoded text string. When this switch is used, the output will be a byte array.

                .PARAMETER Encoding
                    Specifies the encoding to use when converting the byte array to a text string. Valid values are Ascii, UTF32, UTF7, UTF8, BigEndianUnicode, and Unicode.
                    The default is UTF8.

                .EXAMPLE
                    PS C:\> "48656c6c6f20576f726c64" | ConvertFrom-HexString
                    Hello World

                    PS C:\> "48 65 6c 6c 6f 20 57 6f 72 6c 64" | ConvertFrom-HexString -Delimiter " "
                    Hello World

                    PS C:\> "48656c6c6f20576f726c64" | ConvertFrom-HexString -RawBytes
                    72 101 108 108 111 32 87 111 114 108 100
            #>
            [CmdletBinding()]
            param (
                # Value to convert
                [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
                [string[]] $InputObject,
        
                # Delimiter between Hex pairs
                [Parameter(Mandatory=$false)]
                [string] $Delimiter = " ",
        
                # Output raw byte array
                [Parameter(Mandatory=$false)]
                [switch] $RawBytes,
        
                # Encoding to use for text strings
                [Parameter(Mandatory=$false)]
                [ValidateSet("Ascii", "UTF32", "UTF7", "UTF8", "BigEndianUnicode", "Unicode")]
                [string] $Encoding = "UTF8"
            )

            process {
                foreach ($strHex in $InputObject) {
                    if ($strHex.Contains($Delimiter)) {
                        $listHex = $strHex -split $Delimiter
                    } else {
                        $listHex = @()
                        for ($i = 0; $i -lt $strHex.Length; $i += 2) {
                            $listHex += $strHex.Substring($i, 2)
                        }
                    }

                    [byte[]] $outBytes = [byte[]]::new($listHex.Count)
                    for ($i = 0; $i -lt $listHex.Count; $i++) {
                        $outBytes[$i] = [byte]::Parse($listHex[$i], [System.Globalization.NumberStyles]::HexNumber)
                    }

                    if ($RawBytes) {
                        Write-Output $outBytes
                    } else {
                        $outString = [Text.Encoding]::$Encoding.GetString($outBytes)
                        Write-Output $outString
                    }
                }
            }
        }

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
                $properties = @{}

                # Dynamically add properties from the event object
                $_.PSObject.Properties | ForEach-Object {
                    $properties[$_.Name] = $_.Value
                }

                # Convert the event to XML
                $EventXml = [xml]$_.ToXml()

                # Handle XML namespaces
                $NS = New-Object System.Xml.XmlNamespaceManager($EventXml.NameTable)
                $NS.AddNamespace("default", $EventXml.DocumentElement.NamespaceURI)

                # Add XML nodes to the hashtable
                Add-XmlNodeProperties -node $EventXml.DocumentElement -props $properties

                # Sort properties alphabetically
                $sortedProperties = [ordered]@{}
                foreach ($key in ($properties.Keys | Sort-Object)) {
                    $sortedProperties[$key] = $properties[$key]
                }

                [PSCustomObject]$sortedProperties
            }
            
            Write-Output $Events
        } catch {
            Write-Error "Failed to retrieve events: $_"
        }
    }

    end {}
}
