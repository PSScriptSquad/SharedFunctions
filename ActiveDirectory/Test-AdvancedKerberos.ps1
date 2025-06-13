# =======================================================================
# Kerberos Diagnostic Module
#
# This script contains a suite of functions for diagnosing and testing
# Kerberos authentication from a client's perspective.
#
# To execute, run:
# Test-AdvancedKerberos -DomainController "your-dc.your-domain.com"
# =======================================================================

#-----------------------------------------------------------------------
# SECTION 1: Private Helper Functions
# Private Helper Functions for ASN.1 and Kerberos Packet Handling
#-----------------------------------------------------------------------
function New-Asn1Length {
	param([int]$Length)
	if ($Length -lt 128) {
		return @([byte]$Length)
	}
	else {
		$bytes = @()
		$temp = $Length
		while ($temp -gt 0) {
			$bytes = ,([byte]($temp -band 0xFF)) + $bytes
			$temp = $temp -shr 8
		}
		$prefixByte = [byte](0x80 + $bytes.Length)
		return ,$prefixByte + $bytes
	}
}

function New-Asn1Integer {
	param([int]$Value)
	if ($Value -eq 0) {
		$intBytes = @([byte]0)
	}
	else {
		$absVal = [Math]::Abs($Value)
		$bytes = @()
		while ($absVal -gt 0) {
			$bytes = ,([byte]($absVal -band 0xFF)) + $bytes
			$absVal = $absVal -shr 8
		}
		if ($Value -ge 0 -and ($bytes[0] -band 0x80)) {
			$bytes = ,([byte]0) + $bytes
		}
		$intBytes = $bytes
	}
	$lenBytes = New-Asn1Length $intBytes.Length
	return ,([byte]0x02) + $lenBytes + $intBytes
}

function New-Asn1BitString {
	param([byte[]]$Bits)
	if (-not $Bits -or $Bits.Length -le 0) {
		throw "BitString data cannot be null or empty"
	}
	$unusedBits = 0
	$content = ,([byte]$unusedBits) + $Bits
	$lenBytes = New-Asn1Length $content.Length
	return ,([byte]0x03) + $lenBytes + $content
}

function New-Asn1KerberosTime {
	param([DateTime]$Time)
	$timeStr = $Time.ToUniversalTime().ToString("yyyyMMddHHmmssZ")
	$bytes = [Text.Encoding]::ASCII.GetBytes($timeStr)
	$lenBytes = New-Asn1Length $bytes.Length
	return ,([byte]0x18) + $lenBytes + $bytes
}

function New-Asn1KerberosString {
	param([string]$Str)
	if ([string]::IsNullOrEmpty($Str)) {
		throw "Kerberos string cannot be null or empty"
	}
	$bytes = [Text.Encoding]::ASCII.GetBytes($Str)
	$lenBytes = New-Asn1Length $bytes.Length
	return ,([byte]0x1B) + $lenBytes + $bytes
}

function New-Asn1Sequence {
	param(
		[Parameter(Mandatory)]
		[byte[]]$ContentBytes
	)
	$lenBytes = New-Asn1Length $ContentBytes.Length
	return ,([byte]0x30) + $lenBytes + $ContentBytes
}

function New-Asn1SequenceOf {
	[CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[][]]$Elements
    )

    $contentBytes = foreach ($el in $Elements) { $el }
    return New-Asn1Sequence -ContentBytes $contentBytes
}

function New-KerberosPrincipalArray {
	param([string]$PrincipalName)
	$parts = $PrincipalName.Split('/')
	if ($parts.Count -eq 0) {
		throw "PrincipalName cannot be empty"
	}
	$out = @()
	foreach ($component in $parts) {
		if (-not [string]::IsNullOrEmpty($component)) {
			$out += New-Asn1KerberosString $component
		}
		else {
			throw "Empty component in principal: '$PrincipalName'"
		}
	}
	return $out
}

function New-KerberosPrincipalName {
	param(
		[Parameter(Mandatory)]
		[string]$Name,
		[int]$NameType = 1
	)
	$ntBytes = New-Asn1Integer $NameType
	$ntSection = ,([byte]0xA0) + (New-Asn1Length $ntBytes.Length) + $ntBytes

	$stringElems = New-KerberosPrincipalArray -PrincipalName $Name
	$stringSeq = New-Asn1SequenceOf $stringElems
	$nsSection = ,([byte]0xA1) + (New-Asn1Length $stringSeq.Length) + $stringSeq

	$combined = $ntSection + $nsSection
	return New-Asn1Sequence -ContentBytes $combined
}

function New-KerberosAsReqPacket {
	[CmdletBinding()]
	param(
		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[string]$ClientName,

		[Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
		[string]$Realm,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [int]$Nonce,

		[string]$ServerName = $null,

		[DateTime]$TillTime,

		[int[]]$EncryptionTypes = @(18, 17, 23)
	)
	if ([string]::IsNullOrWhiteSpace($ServerName)) {
		$ServerName = "krbtgt/$Realm"
	}

	$zeroBytes = [byte[]](0, 0, 0, 0)
	$kdcOptionsBytes = New-Asn1BitString -Bits $zeroBytes
	$kdcOptionsSec = ,([byte]0xA0) + (New-Asn1Length $kdcOptionsBytes.Length) + $kdcOptionsBytes

	$cnameBytes = New-KerberosPrincipalName -Name $ClientName -NameType 1
	$cnameSection = ,([byte]0xA1) + (New-Asn1Length $cnameBytes.Length) + $cnameBytes

	$realmBytes = New-Asn1KerberosString -Str $Realm
	$realmSection = ,([byte]0xA2) + (New-Asn1Length $realmBytes.Length) + $realmBytes

	$snameBytes = New-KerberosPrincipalName -Name $ServerName -NameType 2
	$snameSection = ,([byte]0xA3) + (New-Asn1Length $snameBytes.Length) + $snameBytes

	$tillBytes = New-Asn1KerberosTime -Time $TillTime
	$tillSection = ,([byte]0xA5) + (New-Asn1Length $tillBytes.Length) + $tillBytes

	$nonceBytes = New-Asn1Integer -Value $nonce
	$nonceSection = ,([byte]0xA7) + (New-Asn1Length $nonceBytes.Length) + $nonceBytes

	$etypeInts = foreach ($e in $EncryptionTypes) { New-Asn1Integer -Value $e }
	$etypeSeq = New-Asn1SequenceOf -Elements $etypeInts
	$etypeSection = ,([byte]0xA8) + (New-Asn1Length $etypeSeq.Length) + $etypeSeq

	$reqBodyContent = $kdcOptionsSec + $cnameSection + $realmSection + $snameSection + $tillSection + $nonceSection + $etypeSection
	$reqBodySeq = New-Asn1Sequence -ContentBytes $reqBodyContent
	$reqBodySection = ,([byte]0xA4) + (New-Asn1Length $reqBodySeq.Length) + $reqBodySeq

	$pvnoBytes = New-Asn1Integer -Value 5
	$pvnoSection = ,([byte]0xA1) + (New-Asn1Length $pvnoBytes.Length) + $pvnoBytes

	$msgTypeBytes = New-Asn1Integer -Value 10 # AS-REQ
	$msgTypeSection = ,([byte]0xA2) + (New-Asn1Length $msgTypeBytes.Length) + $msgTypeBytes

	$kdcReqContent = $pvnoSection + $msgTypeSection + $reqBodySection
	$kdcReqSeq = New-Asn1Sequence -ContentBytes $kdcReqContent

	$lengthBytes = New-Asn1Length $kdcReqSeq.Length
	return ,([byte]0x6A) + $lengthBytes + $kdcReqSeq
}

function ConvertFrom-Asn1 {
	param([byte[]]$Data)

	function Parse-Node {
		param(
			[byte[]]$Bytes,
			[int]$Offset
		)
		$originalOffset = $Offset
		$node = [PSCustomObject]@{
			Tag = $null; TagName = 'UNKNOWN'; Length = 0; Value = $null
			RawValueBytes = $null; Offset = $originalOffset; TotalBytes = 0
		}

		# 1. Parse Tag
		$tagByte = $Bytes[$Offset++]
		$node.Tag = $tagByte
		$isConstructed = ($tagByte -band 0x20) -ne 0
		$tagClass = $tagByte -shr 6
		$tagNumber = $tagByte -band 0x1F
		$node.TagName = switch ($tagClass) {
			0 { # Universal
				switch ($tagNumber) {
					2 { 'INTEGER' }
					3 { 'BIT STRING' }
					4 { 'OCTET STRING' }
					5 { 'NULL' }
					16 { 'SEQUENCE' }
					17 { 'SET' }
					18 { 'GeneralString' }
					24 { 'GeneralizedTime' }
					27 { 'GeneralString' }  # Added for KerberosString
					default { "Universal[$tagNumber]" }
				}
			}
			2 { "ContextSpecific[$tagNumber]" }
			1 { "Application[$tagNumber]" }
			3 { "Private[$tagNumber]" }
		}
		if ($isConstructed) {
			$node.TagName += " (Constructed)"
		}

		# 2. Parse Length
		$lenByte = $Bytes[$Offset++]
		if ($lenByte -band 0x80) { # Long form
			$numLenBytes = $lenByte -band 0x7F
			if (($Offset + $numLenBytes) -gt $Bytes.Length) { throw "ASN.1 parse error: Invalid length field." }
			for ($i = 0; $i -lt $numLenBytes; $i++) {
				$node.Length = ($node.Length -shl 8) + $Bytes[$Offset++]
			}
		}
		else { # Short form
			$node.Length = $lenByte
		}

		# 3. Parse Value
		$valueOffset = $Offset
		if (($valueOffset + $node.Length) -gt $Bytes.Length) { throw "ASN.1 parse error: Length exceeds data boundary." }
		$node.RawValueBytes = $Bytes[$valueOffset..($valueOffset + $node.Length - 1)]
		$Offset += $node.Length

		if ($isConstructed) {
			$node.Value = [System.Collections.ArrayList]@()
			$childOffset = 0
			while ($childOffset -lt $node.Length) {
				$childNode, $childBytesConsumed = Parse-Node -Bytes $node.RawValueBytes -Offset $childOffset
				[void]$node.Value.Add($childNode)
				$childOffset += $childBytesConsumed
			}
		}
		else {
			switch ($node.TagName) {
				'INTEGER' {
					$reversed = [byte[]]($node.RawValueBytes); [System.Array]::Reverse($reversed)
					if (($node.RawValueBytes[0] -band 0x80) -ne 0 -and $node.RawValueBytes.Length -gt 0) {
						$newBytes = [byte[]]::new($reversed.Length + 1); [System.Array]::Copy($reversed, 0, $newBytes, 0, $reversed.Length); $reversed = $newBytes
					}
					$node.Value = [System.Numerics.BigInteger]::new($reversed)
				}
				{ ($_ -eq 'GeneralString') -or ($_ -eq 'GeneralizedTime') } {
					$node.Value = [System.Text.Encoding]::ASCII.GetString($node.RawValueBytes)
				}
				default {
					$node.Value = ($node.RawValueBytes | ForEach-Object { $_.ToString('X2') }) -join ''
				}
			}
		}
		$node.TotalBytes = $Offset - $originalOffset
		return $node, $node.TotalBytes
	}
	$parsed, $bytesConsumed = Parse-Node -Bytes $Data -Offset 0
	return $parsed
}

function Find-Asn1NodeByTagPath {
	param($Node, [int[]]$TagPath)
	$currentNode = $Node
	foreach ($tagNumber in $TagPath) {
		if (-not $currentNode -or -not $currentNode.Value -is [System.Collections.ArrayList]) {
			return $null
		}
		$foundChild = $currentNode.Value | Where-Object { ($_.Tag -band 0x1F) -eq ($tagNumber -band 0x1F) } | Select-Object -First 1
		if (-not $foundChild) {
			return $null
		}
		$currentNode = $foundChild
	}
	return $currentNode
}

function Find-PaDataByType {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Node,
        [Parameter(Mandatory)]
        [int]$PaType
    )

    Write-Verbose "Looking for PA-DATA type $PaType in node: $($Node.TagName)"
    
    # Check if Node has Value property and it's iterable
    if (-not $Node.Value -or -not ($Node.Value -is [System.Collections.ArrayList])) {
        Write-Verbose "Node.Value is not a valid collection"
        return $null
    }

    Write-Verbose "Node has $($Node.Value.Count) children"
    
    foreach ($i in 0..($Node.Value.Count - 1)) {
        $child = $Node.Value[$i]
        Write-Verbose "Checking child $i`: $($child.TagName) (0x$($child.Tag.ToString('X2')))"
        
        # Each child should be a PA-DATA SEQUENCE
        if (-not $child.Value -or -not ($child.Value -is [System.Collections.ArrayList])) {
            Write-Verbose "  Child $i has no valid children"
            continue
        }

        Write-Verbose "  Child $i has $($child.Value.Count) grandchildren"
        
        # Look for padata-type [1] INTEGER
        foreach ($j in 0..($child.Value.Count - 1)) {
            $grandchild = $child.Value[$j]
            Write-Verbose "    Grandchild $j`: $($grandchild.TagName) (0x$($grandchild.Tag.ToString('X2')))"
            
            if ($grandchild.Tag -eq 0xA1) { # [1] padata-type
                # Look for INTEGER inside the context tag
                if ($grandchild.Value -and ($grandchild.Value -is [System.Collections.ArrayList])) {
                    $intNode = $grandchild.Value | Where-Object { $_.Tag -eq 0x02 }
                    if ($intNode) {
                        $foundType = [int]$intNode.Value
                        Write-Verbose "      Found padata-type: $foundType"
                        
                        if ($foundType -eq $PaType) {
                            Write-Verbose "Found PA-DATA with type $PaType"
                            return $child
                        }
                    }
                }
            }
        }
    }
    
    Write-Verbose "PA-DATA with type $PaType not found"
    return $null
}

function Get-EtypeInfo2FromError {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [byte[]]$EDataBytes
    )

    try {
        Write-Verbose "Parsing e-data ($($EDataBytes.Length) bytes) to unwrap the OCTET STRING..."
        $eDataWrapperNode = ConvertFrom-Asn1 -Data $EDataBytes

        if ($eDataWrapperNode.Tag -ne 0x04) {
            Write-Warning "Expected e-data to be an OCTET STRING, but found $($eDataWrapperNode.TagName). Attempting to parse directly."
            $parsedEData = $eDataWrapperNode
        } else {
            Write-Verbose "Successfully unwrapped OCTET STRING. Now parsing the inner PA-DATA sequence..."
            $parsedEData = ConvertFrom-Asn1 -Data $eDataWrapperNode.RawValueBytes
        }
        
        Write-Verbose "=== Inner E-DATA (PA-DATA Sequence) STRUCTURE ==="
        Debug-Asn1Structure -Node $parsedEData -MaxDepth 5
        Write-Verbose "==============================================="
        
        $etypeInfoNode = Find-PaDataByType -Node $parsedEData -PaType 19
        if (-not $etypeInfoNode) {
            Write-Verbose "Did not find PA-DATA type 19 (ETYPE-INFO2), looking for type 11 (ETYPE-INFO)..."
            $etypeInfoNode = Find-PaDataByType -Node $parsedEData -PaType 11
        }

        if (-not $etypeInfoNode) {
            Write-Verbose "No ETYPE-INFO or ETYPE-INFO2 found in e-data."
            return @()
        }

        # The PA-DATA structure has two children: padata-type [1] and padata-value [2].
        # We need the padata-value [2] node.
        $paDataValueNode = $etypeInfoNode.Value | Where-Object { $_.Tag -eq 0xA2 } | Select-Object -First 1
        
        if (-not $paDataValueNode -or -not ($paDataValueNode.Value -is [System.Collections.ArrayList]) -or $paDataValueNode.Value.Count -eq 0) {
            Write-Verbose "Found ETYPE-INFO node but it contains no padata-value."
            return @()
        }
        
        # *** START: The new critical fix ***
        # The padata-value [2] contains an OCTET STRING. We must unwrap it.
        $innerOctetStringNode = $paDataValueNode.Value[0]
        if ($innerOctetStringNode.Tag -ne 0x04) {
            Write-Warning "Expected inner value of PA-DATA to be an OCTET STRING, but it was not."
            return @()
        }

        Write-Verbose "Unwrapping final OCTET STRING to get the ETYPE-INFO2 sequence."
        # Parse the bytes *inside* the final OCTET STRING to get the list of encryption types.
        $etypeInfoSequence = ConvertFrom-Asn1 -Data $innerOctetStringNode.RawValueBytes
        # *** END: The new critical fix ***
        
        $etypeIds = @()
        if ($etypeInfoSequence.Value -is [System.Collections.ArrayList]) {
            # Iterate over each ETYPE-INFO2-ENTRY in the sequence
            foreach ($entry in $etypeInfoSequence.Value) {
                if ($entry.Value -is [System.Collections.ArrayList]) {
                    # Find the etype [0] INTEGER
                    $etypeTagNode = $entry.Value | Where-Object { $_.Tag -eq 0xA0 } | Select-Object -First 1
                    if ($etypeTagNode -and $etypeTagNode.Value -is [System.Collections.ArrayList]) {
                        $intNode = $etypeTagNode.Value | Where-Object { $_.Tag -eq 0x02 } | Select-Object -First 1
                        if ($intNode) {
                            $etypeId = [int]$intNode.Value
                            $etypeIds += $etypeId
                            Write-Verbose "Found supported encryption type ID: $etypeId"
                        }
                    }
                }
            }
        }
        
        Write-Verbose "Extracted $($etypeIds.Count) encryption types: $($etypeIds -join ', ')"
        return $etypeIds
    }
    catch {
        Write-Verbose "Error parsing ETYPE-INFO: $($_.Exception.Message) at $($_.ScriptStackTrace)"
        return @()
    }
} 

function Get-EncryptionTypeMap {
    return @{
        1  = 'DES-CBC-CRC'
        3  = 'DES-CBC-MD5'
        17 = 'AES128-CTS-HMAC-SHA1-96'
        18 = 'AES256-CTS-HMAC-SHA1-96'
        19 = 'AES128-CTS-HMAC-SHA256-128'
        20 = 'AES256-CTS-HMAC-SHA384-192'
        23 = 'RC4-HMAC'
        24 = 'RC4-HMAC-EXP'
    }
}

function Convert-EncryptionType {
    [CmdletBinding(DefaultParameterSetName = 'IdToName')]
    param(
        # ---------- ID ➔ Name ----------
        [Parameter(Mandatory,
                   ParameterSetName = 'IdToName',
                   Position = 0)]
        [ValidateScript({
            if (-not (Get-EncryptionTypeMap).ContainsKey($_)) {
                throw "Unsupported encryption-type ID: $_"
            }
            $true
        })]
        [int]$EtypeId,

        # ---------- Name ➔ ID ----------
        [Parameter(Mandatory,
                   ParameterSetName = 'NameToId',
                   Position = 0)]
        [ValidateScript({
            if (-not ((Get-EncryptionTypeMap).Values -contains $_)) {
                throw "Unsupported encryption-type name: '$_'"
            }
            $true
        })]
        [string]$EtypeName
    )

    $map = Get-EncryptionTypeMap

    switch ($PSCmdlet.ParameterSetName) {
        'IdToName' { return $map[$EtypeId] }

        'NameToId' {
            return ($map.GetEnumerator() |
                    Where-Object { $_.Value -ieq $EtypeName } |
                    Select-Object -First 1 -ExpandProperty Key)
        }
    }
}

function Get-KerberosErrorDescription {
	param([int]$ErrorCode)
	$map = @{
		1 = "KDC_ERR_NAME_EXP - Client expired"
		2 = "KDC_ERR_SERVICE_EXP - Server expired"
		3 = "KDC_ERR_BAD_PVNO - Bad protocol version"
		6 = "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found"
		7 = "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found"
		8 = "KDC_ERR_PRINCIPAL_NOT_UNIQUE - Multiple entries"
		12 = "KDC_ERR_NEVER_VALID - Ticket not yet valid"
		14 = "KDC_ERR_ETYPE_NOSUPP - Encryption type not supported"
		18 = "KDC_ERR_CLIENT_REVOKED"
		23 = "KDC_ERR_KEY_EXPIRED"
		24 = "KDC_ERR_PREAUTH_FAILED"
		25 = "KDC_ERR_PREAUTH_REQUIRED"
		32 = "KDC_ERR_SKEW - Clock skew too great"
		68 = "KDC_ERR_WRONG_REALM"
	}

	if ($map.ContainsKey($ErrorCode)) {
		return $map[$ErrorCode]
	}
	else {
		return "Unknown error code: $ErrorCode"
	}
}

function Get-KerberosResponseAnalysis {
    param([byte[]]$ResponseBytes)

    $analysis = [pscustomobject]@{
        Type                       = 'UNKNOWN'
        IsSuccess                  = $false
        ErrorCode                  = $null
        ErrorDescription           = 'Response was not a valid AS-REP or KRB-ERROR.'
        SupportedEncryptionIds     = @()
        SupportedEncryptionNames   = @()
    }

    if (-not $ResponseBytes -or $ResponseBytes.Length -lt 2) {
        $analysis.Type             = 'EMPTY_RESPONSE'
        $analysis.ErrorDescription = 'No response data received from KDC.'
        return $analysis
    }

    try {
        $parsedResponse = ConvertFrom-Asn1 -Data $ResponseBytes

        switch ($parsedResponse.Tag) {
            0x6B {   # AS-REP
                $analysis.Type        = 'AS-REP'
                $analysis.IsSuccess   = $true
                $analysis.ErrorDescription = 'Authentication successful (AS-REP received).'
            }

            0x7E {   # KRB-ERROR
                $analysis.Type = 'KRB-ERROR'

                # Find error-code: KRB-ERROR SEQUENCE -> [6] error-code INTEGER
                $errNode = Find-Asn1NodeByTagPath -Node $parsedResponse -TagPath @(0x30, 0xA6, 0x02)
                $errCode = if ($errNode) { [int]$errNode.Value } else { $null }

                $analysis.ErrorCode        = $errCode
                $analysis.ErrorDescription = Get-KerberosErrorDescription $errCode

                # Look for e-data field [12] which contains PA-DATA
                if ($errCode -eq 25) {  # KDC_ERR_PREAUTH_REQUIRED
                    $eDataNode = Find-Asn1NodeByTagPath -Node $parsedResponse -TagPath @(0x30, 0xAC)
                    
                    if ($eDataNode) {
                        Write-Verbose "Found e-data field, extracting encryption types..."
                        $etypeIds = Get-EtypeInfo2FromError -EDataBytes $eDataNode.RawValueBytes
                        $analysis.SupportedEncryptionIds = $etypeIds
                        $analysis.SupportedEncryptionNames = $etypeIds | ForEach-Object { 
                            try { Convert-EncryptionType -EtypeId $_ } 
                            catch { "Unknown($_ )" }
                        }
                    }
                }
                elseif ($errCode -eq 0) {
                    $analysis.IsSuccess = $true
                }
            }
        }
    }
    catch {
        $analysis.ErrorDescription = "Failed to parse KDC response: $($_.Exception.Message)"
        Write-Verbose "Response parsing error: $($_.Exception.Message)"
    }

    return $analysis
}

function Debug-Asn1Structure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        $Node,
        [int]$Depth = 0,
        [int]$MaxDepth = 10
    )
    
    if ($Depth -gt $MaxDepth) {
        Write-Verbose ("  " * $Depth) + "... (max depth reached)"
        return
    }
    
    $indent = "  " * $Depth
    $tagHex = "0x{0:X2}" -f $Node.Tag
    
    Write-Verbose "$indent$($Node.TagName) ($tagHex) - Length: $($Node.Length)"
    
    if ($Node.Value -is [System.Collections.ArrayList]) {
        Write-Verbose "$indent  Children: $($Node.Value.Count)"
        foreach ($child in $Node.Value) {
            Debug-Asn1Structure -Node $child -Depth ($Depth + 1) -MaxDepth $MaxDepth
        }
    } else {
        $valueStr = if ($Node.Value -is [string]) { 
            $Node.Value 
        } elseif ($Node.Value -is [System.Numerics.BigInteger]) { 
            $Node.Value.ToString() 
        } else { 
            $Node.Value.ToString() 
        }
        Write-Verbose "$indent  Value: $valueStr"
    }
}

#-----------------------------------------------------------------------
# Helper Functions for Test-TgtRequest
#-----------------------------------------------------------------------
function Test-KerberosSpn {
    <#
    .SYNOPSIS
        Checks for the registration of a Service Principal Name (SPN) in Active Directory.
    .PARAMETER Spn
        The Service Principal Name to check. Example: "HTTP/web.contoso.com".
    .EXAMPLE
        Test-KerberosSpn -Spn "HOST/dc01.contoso.com"
    .OUTPUTS
        System.String
        A status string: "SKIPPED", "MISSING", "DUPLICATE", "OK", or "CHECK_FAILED".
    .NOTES
        Requires the Microsoft Active Directory module. This is intended as an internal
        helper function for other Kerberos tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Spn
    )

    # Check if the AD module is available before trying to use its cmdlets.
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        return "SKIPPED (ActiveDirectory module not available)"
    }

    try {
        # Search for any account (user or computer) with the specified SPN.
        $adObjects = Get-ADObject -Filter "ServicePrincipalName -eq '$Spn'" -ErrorAction Stop
        
        if ($null -eq $adObjects) {
            return "MISSING - The SPN '$Spn' is not registered on any account."
        }
        
        if (($adObjects | Measure-Object).Count -gt 1) {
            $accounts = ($adObjects.DistinguishedName) -join ', '
            return "DUPLICATE - The SPN '$Spn' is registered on multiple accounts: $accounts"
        }

        return "OK - Registered to '$($adObjects.DistinguishedName)'"
    }
    catch {
        return "CHECK_FAILED - An error occurred while querying Active Directory: $($_.Exception.Message)"
    }
}

#-----------------------------------------------------------------------
# Helper Functions for Test-TgsAndSpnValidation
#-----------------------------------------------------------------------
function Get-TicketFlags {
    param([int]$Flags)

    $flagNames = @()
    if ($flags -band 0x40000000) { $flagNames += "forwardable" }
    if ($flags -band 0x20000000) { $flagNames += "forwarded" }
    if ($flags -band 0x10000000) { $flagNames += "proxiable" }
    if ($flags -band 0x08000000) { $flagNames += "proxy" }
    if ($flags -band 0x04000000) { $flagNames += "allow_postdate" }
    if ($flags -band 0x02000000) { $flagNames += "postdated" }
    if ($flags -band 0x01000000) { $flagNames += "invalid" }
    if ($flags -band 0x00800000) { $flagNames += "renewable" }
    if ($flags -band 0x00400000) { $flagNames += "initial" }
    if ($flags -band 0x00200000) { $flagNames += "pre_authent" }
    if ($flags -band 0x00100000) { $flagNames += "hw_authent" }
    if ($flags -band 0x00080000) { $flagNames += "ok_as_delegate" }
    if ($flags -band 0x00040000) { $flagNames += "anonymous" }
    if ($flags -band 0x00020000) { $flagNames += "enc_pa_rep" }
    if ($flags -band 0x00010000) { $flagNames += "name_canonicalize" }
    return $flagNames -join " "
}

function Get-CacheFlags {
    param([int]$Flags)
    $flagNames = @()
    if ($flags -band 0x1) { $flagNames += "PRIMARY" }
    if ($flags -band 0x2) { $flagNames += "DELEGATION" }
    if ($flags -band 0x4) { $flagNames += "S4U" }
    if ($flags -band 0x8) { $flagNames += "ASC_GSS_CONTEXT" }
    return $flagNames -join " "
}

function Parse-KerbExternalName {
    param(
        [IntPtr]$nameStructPtr
    )

    if ($nameStructPtr -eq [IntPtr]::Zero) { return "" }

    try {
        # Read the first two fields of KERB_EXTERNAL_NAME
        $nameType = [System.Runtime.InteropServices.Marshal]::ReadInt16($nameStructPtr)
        $nameCount = [System.Runtime.InteropServices.Marshal]::ReadInt16($nameStructPtr, 2)
        
        if ($nameCount -eq 0) { return "" }

        $names = @()
        # Start reading UNICODE_STRING array immediately after the header (4 bytes)
        $usArrayPtr = [IntPtr]($nameStructPtr.ToInt64() + 4)
        $sizeOfUnicodeString = 8  # UNICODE_STRING is 8 bytes (Length:2, MaxLength:2, Buffer:4/8)
        
        # Determine if we're on 64-bit (Buffer pointer is 8 bytes) or 32-bit (4 bytes)
        $is64Bit = [IntPtr]::Size -eq 8
        if ($is64Bit) {
            $sizeOfUnicodeString = 16  # Length:2, MaxLength:2, Padding:4, Buffer:8
        }

        for ($j = 0; $j -lt $nameCount; $j++) {
            $currentUsPtr = [IntPtr]($usArrayPtr.ToInt64() + ($j * $sizeOfUnicodeString))
            
            # Read UNICODE_STRING fields manually
            $length = [System.Runtime.InteropServices.Marshal]::ReadInt16($currentUsPtr)
            $maxLength = [System.Runtime.InteropServices.Marshal]::ReadInt16($currentUsPtr, 2)
            
            # Buffer pointer location depends on architecture
            $bufferPtr = if ($is64Bit) {
                [System.Runtime.InteropServices.Marshal]::ReadIntPtr($currentUsPtr, 8)
            } else {
                [System.Runtime.InteropServices.Marshal]::ReadIntPtr($currentUsPtr, 4)
            }

            if ($bufferPtr -ne [IntPtr]::Zero -and $length -gt 0) {
                $nameString = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($bufferPtr, $length / 2)
                if ($nameString) {
                    $names += $nameString
                }
            }
        }
        return $names -join "/"
    }
    catch {
        Write-Verbose "Could not parse KERB_EXTERNAL_NAME at address $($nameStructPtr): $_"
        return ""
    }
}

function Get-KerberosTicket {
    <#
    .SYNOPSIS
        Retrieves Kerberos tickets from the current user's ticket cache via the native LSA API.
    .DESCRIPTION
        Calls into Secur32.dll and Advapi32.dll with P/Invoke (via Add-Type) to query the
        Kerberos authentication package for cached tickets. Returns structured objects
        rather than parsing klist.exe output. Enhanced to include Session Key Type and
        additional ticket details like Client Name and Service Name.
    .OUTPUTS
        System.Management.Automation.PSCustomObject
    .NOTES
        - Does not require SeTcbPrivilege by using LsaConnectUntrusted and LogonId=0.
        - Tested on PowerShell 5.1 / Windows 10+.
        - Retrieving full ticket details may impact performance for many tickets.
    #>
    [CmdletBinding()]
    param()

    $TokenQuery = 0x0008
    $signature = @"
    using System;
    using System.Runtime.InteropServices;

    public class Secur32 {
        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaConnectUntrusted(out IntPtr LsaHandle);
        
        [DllImport("Secur32.dll", SetLastError = false)]
        public static extern uint LsaLookupAuthenticationPackage(
            IntPtr LsaHandle, 
            ref LSA_STRING PackageName, 
            out uint AuthenticationPackage
        );
        
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaCallAuthenticationPackage(
            IntPtr LsaHandle, 
            uint AuthenticationPackage, 
            IntPtr ProtocolSubmitBuffer, 
            uint SubmitBufferLength, 
            out IntPtr ProtocolReturnBuffer, 
            out uint ReturnBufferLength, 
            out uint ProtocolStatus
        );
        
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaDeregisterLogonProcess(IntPtr LsaHandle);
        
        [DllImport("secur32.dll", SetLastError = false)]
        public static extern uint LsaFreeReturnBuffer(IntPtr buffer);
        
        [DllImport("advapi32.dll", SetLastError = false)]
        public static extern bool GetTokenInformation(
            IntPtr TokenHandle, 
            TOKEN_INFORMATION_CLASS TokenInformationClass, 
            IntPtr TokenInformation, 
            uint TokenInformationLength, 
            out uint ReturnLength
        );
        
        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern IntPtr GetCurrentProcess();
        
        [DllImport("advapi32.dll", SetLastError = false)]
        public static extern bool OpenProcessToken(
            IntPtr ProcessHandle, 
            uint DesiredAccess, 
            out IntPtr TokenHandle
        );
        
        [DllImport("kernel32.dll", SetLastError = false)]
        public static extern bool CloseHandle(IntPtr handle);
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_STRING { 
        public ushort Length; 
        public ushort MaximumLength; 
        public IntPtr Buffer; 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING { 
        public ushort Length; 
        public ushort MaximumLength; 
        public IntPtr Buffer; 
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KERB_QUERY_TKT_CACHE_REQUEST { 
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType; 
        public LUID LogonId; 
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct KERB_QUERY_TKT_CACHE_RESPONSE { 
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType; 
        public uint CountOfTickets; 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LUID { 
        public uint LowPart; 
        public int HighPart; 
    }

    public enum KERB_PROTOCOL_MESSAGE_TYPE : uint {
        KerbQueryTicketCacheMessage = 1,
        KerbRetrieveEncodedTicketMessage = 8
    }

    [StructLayout(LayoutKind.Sequential, Pack = 8)]
    public struct KERB_TICKET_CACHE_INFO {
        public UNICODE_STRING ServerName; 
        public UNICODE_STRING RealmName;
        public long StartTime; 
        public long EndTime; 
        public long RenewTime;
        public int EncryptionType; 
        public uint TicketFlags;
    }

    public enum TOKEN_INFORMATION_CLASS { 
        TokenStatistics = 10 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_STATISTICS {
        public LUID TokenId; 
        public LUID AuthenticationId; 
        public long ExpirationTime;
        public uint TokenType; 
        public uint ImpersonationLevel; 
        public uint DynamicCharged;
        public uint DynamicAvailable; 
        public uint GroupCount; 
        public uint PrivilegeCount;
        public LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SecHandle { 
        public IntPtr dwLower; 
        public IntPtr dwUpper; 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_REQUEST {
        public KERB_PROTOCOL_MESSAGE_TYPE MessageType; 
        public LUID LogonId;
        public UNICODE_STRING TargetName; 
        public uint TicketFlags; 
        public uint CacheOptions;
        public int EncryptionType; 
        public SecHandle CredentialsHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_RETRIEVE_TKT_RESPONSE { 
        public KERB_EXTERNAL_TICKET Ticket; 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_CRYPTO_KEY { 
        public int KeyType; 
        public uint Length; 
        public IntPtr Value; 
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct KERB_EXTERNAL_TICKET {
        public IntPtr ServiceName; 
        public IntPtr TargetName; 
        public IntPtr ClientName;
        public UNICODE_STRING DomainName; 
        public UNICODE_STRING TargetDomainName; 
        public UNICODE_STRING AltTargetDomainName;
        public KERB_CRYPTO_KEY SessionKey; 
        public uint TicketFlags; 
        public uint Flags;
        public long KeyExpirationTime; 
        public long StartTime; 
        public long EndTime; 
        public long RenewUntil;
        public long TimeSkew; 
        public uint EncodedTicketSize; 
        public IntPtr EncodedTicket;
    }
"@
    Add-Type -TypeDefinition $signature -Language CSharp -ErrorAction Stop

    $encryptionMap = @{
        1  = "DES-CBC-CRC"
        3  = "DES-CBC-MD5"
        17 = "AES-128-CTS-HMAC-SHA1-96"
        18 = "AES-256-CTS-HMAC-SHA1-96"
        23 = "RC4-HMAC"
        24 = "RC4-HMAC-EXP"
    }

    $lsaHandle = [IntPtr]::Zero
    $pReq = [IntPtr]::Zero
    $returnBuffer = [IntPtr]::Zero
    $kerbNameBuf = [IntPtr]::Zero
    $tokenHandle = [IntPtr]::Zero

    try {
        $status = [Secur32]::LsaConnectUntrusted([ref]$lsaHandle)
        if ($status -ne 0) { 
            throw "LsaConnectUntrusted failed: 0x$($status.ToString('X8'))" 
        }

        $kerbName = "kerberos"
        $kerbPkg = New-Object LSA_STRING
        $kerbNameBuf = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($kerbName)
        $kerbPkg.Buffer = $kerbNameBuf
        $kerbPkg.Length = [System.Text.Encoding]::ASCII.GetByteCount($kerbName)
        $kerbPkg.MaximumLength = $kerbPkg.Length + 1
        
        $authPkg = 0
        $status = [Secur32]::LsaLookupAuthenticationPackage($lsaHandle, [ref]$kerbPkg, [ref]$authPkg)
        if ($status -ne 0) { 
            throw "LsaLookupAuthenticationPackage failed: 0x$($status.ToString('X8'))" 
        }

        $req = New-Object KERB_QUERY_TKT_CACHE_REQUEST
        $req.MessageType = [KERB_PROTOCOL_MESSAGE_TYPE]::KerbQueryTicketCacheMessage
        $req.LogonId = New-Object LUID
        
        $reqSize = [System.Runtime.InteropServices.Marshal]::SizeOf($req)
        $pReq = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($reqSize)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($req, $pReq, $false)

        $protStatus = 0
        $returnedLen = 0
        $status = [Secur32]::LsaCallAuthenticationPackage(
            $lsaHandle, 
            $authPkg, 
            $pReq, 
            [uint32]$reqSize, 
            [ref]$returnBuffer, 
            [ref]$returnedLen, 
            [ref]$protStatus
        )
        if ($status -ne 0) { 
            throw "LsaCallAuthenticationPackage failed: 0x$($status.ToString('X8'))" 
        }

        if ($returnBuffer -eq [IntPtr]::Zero -or $returnedLen -eq 0) { 
            Write-Verbose "No tickets returned"
            return @() 
        }

        $hdr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($returnBuffer, [System.Type][KERB_QUERY_TKT_CACHE_RESPONSE])
        if ($hdr.CountOfTickets -eq 0) { 
            return @() 
        }

        $tickets = for ($i = 0; $i -lt $hdr.CountOfTickets; $i++) {
            $thisPtr = [IntPtr](
                $returnBuffer.ToInt64() + 
                [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][KERB_QUERY_TKT_CACHE_RESPONSE]) + 
                ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([System.Type][KERB_TICKET_CACHE_INFO]))
            )
            $info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($thisPtr, [System.Type][KERB_TICKET_CACHE_INFO])

            $ticketReqPtr = [IntPtr]::Zero
            $ticketReturnBuffer = [IntPtr]::Zero
            $ticketTargetNameBuf = [IntPtr]::Zero
            
            try {
                $ticketReq = New-Object KERB_RETRIEVE_TKT_REQUEST
                $ticketReq.MessageType = [KERB_PROTOCOL_MESSAGE_TYPE]::KerbRetrieveEncodedTicketMessage
                $ticketReq.LogonId = New-Object LUID
                $ticketReq.CacheOptions = 0x00000002 # KERB_RETRIEVE_TICKET_USE_CACHE_ONLY

                $serverName = if ($info.ServerName.Buffer -ne [IntPtr]::Zero -and $info.ServerName.Length) { 
                    [System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.ServerName.Buffer, $info.ServerName.Length/2) 
                } else { 
                    "" 
                }
                
                if ($serverName) {
                    $ticketTargetNameBuf = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($serverName)
                    $ticketReq.TargetName = New-Object UNICODE_STRING
                    $ticketReq.TargetName.Length = $serverName.Length * 2
                    $ticketReq.TargetName.MaximumLength = $ticketReq.TargetName.Length + 2
                    $ticketReq.TargetName.Buffer = $ticketTargetNameBuf
                }

                $ticketReqSize = [System.Runtime.InteropServices.Marshal]::SizeOf($ticketReq)
                $ticketReqPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ticketReqSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($ticketReq, $ticketReqPtr, $false)

                $ticketProtStatus = 0 
                $ticketReturnedLen = 0
                $status = [Secur32]::LsaCallAuthenticationPackage(
                    $lsaHandle, 
                    $authPkg, 
                    $ticketReqPtr, 
                    [uint32]$ticketReqSize, 
                    [ref]$ticketReturnBuffer, 
                    [ref]$ticketReturnedLen, 
                    [ref]$ticketProtStatus
                )

                Write-Verbose "Ticket retrieval for $serverName - Status: 0x$($status.ToString('X8')), ProtStatus: 0x$($ticketProtStatus.ToString('X8')), BufferLen: $ticketReturnedLen"
                
                if ($status -eq 0 -and $ticketProtStatus -eq 0 -and $ticketReturnBuffer -ne [IntPtr]::Zero) {
                    $response = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ticketReturnBuffer, [System.Type][KERB_RETRIEVE_TKT_RESPONSE])
                    $ticketExt = $response.Ticket

                    # Get session key type
                    $sessionKeyType = if ($encryptionMap[$ticketExt.SessionKey.KeyType]) { 
                        $encryptionMap[$ticketExt.SessionKey.KeyType] 
                    } else { 
                        "Unknown ($($ticketExt.SessionKey.KeyType))" 
                    }
                    
                    # Parse the external names using the fixed helper function
                    $clientName = Parse-KerbExternalName -nameStructPtr $ticketExt.ClientName
                    $serviceName = Parse-KerbExternalName -nameStructPtr $ticketExt.ServiceName

                    # Parse domain names from UNICODE_STRING structures
                    $domainName = if ($ticketExt.DomainName.Buffer -ne [IntPtr]::Zero -and $ticketExt.DomainName.Length) {
                        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketExt.DomainName.Buffer, $ticketExt.DomainName.Length/2)
                    } else { 
                        "" 
                    }

                    $targetDomainName = if ($ticketExt.TargetDomainName.Buffer -ne [IntPtr]::Zero -and $ticketExt.TargetDomainName.Length) {
                        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketExt.TargetDomainName.Buffer, $ticketExt.TargetDomainName.Length/2)
                    } else { 
                        "" 
                    }

                    $altTargetDomainName = if ($ticketExt.AltTargetDomainName.Buffer -ne [IntPtr]::Zero -and $ticketExt.AltTargetDomainName.Length) {
                        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ticketExt.AltTargetDomainName.Buffer, $ticketExt.AltTargetDomainName.Length/2)
                    } else { 
                        "" 
                    }

                    # Get realm name from basic cache info if detailed domains are empty
                    $realmName = if ($info.RealmName.Buffer -ne [IntPtr]::Zero -and $info.RealmName.Length) { 
                        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.RealmName.Buffer, $info.RealmName.Length/2) 
                    } else { 
                        "" 
                    }

                    # Enhanced KDC Called logic - try multiple sources
                    $kdcCalled = ""
                    if ($altTargetDomainName) {
                        $kdcCalled = $altTargetDomainName
                    } elseif ($targetDomainName) {
                        $kdcCalled = $targetDomainName
                    } elseif ($realmName) {
                        $kdcCalled = $realmName
                    }
                    
                    # If still empty, try to extract from server name
                    if (!$kdcCalled -and $serverName) {
                        $serverParts = $serverName.Split('/')
                        if ($serverParts.Length -gt 1) {
                            $hostPart = $serverParts[1]
                            $domainPart = $hostPart.Split('.', 2)
                            if ($domainPart.Length -gt 1) {
                                $kdcCalled = $domainPart[1].ToUpper()
                            }
                        }
                    }

                    $startTime = if ($ticketExt.StartTime) { 
                        [DateTime]::FromFileTime($ticketExt.StartTime).ToLocalTime() 
                    } else { 
                        $null 
                    }
                    
                    $endTime = if ($ticketExt.EndTime) { 
                        [DateTime]::FromFileTime($ticketExt.EndTime).ToLocalTime() 
                    } else { 
                        $null 
                    }
                    
                    $renewTime = if ($ticketExt.RenewUntil) { 
                        [DateTime]::FromFileTime($ticketExt.RenewUntil).ToLocalTime() 
                    } else { 
                        $null 
                    }
                    
                    $keyExpTime = if ($ticketExt.KeyExpirationTime) { 
                        [DateTime]::FromFileTime($ticketExt.KeyExpirationTime).ToLocalTime() 
                    } else { 
                        $null 
                    }

                    $ticketFlags = "0x{0:X8} -> {1}" -f $ticketExt.TicketFlags, (Get-TicketFlags $ticketExt.TicketFlags)
                    $cacheFlags = "{0} -> {1}" -f $ticketExt.Flags, (Get-CacheFlags $ticketExt.Flags)

                    # Create the object with properties in klist-like order for default display
                    $ticketObj = [PSCustomObject]@{
                        PSTypeName = 'KerberosTicket'
                        Client = if ($clientName -and $domainName) { 
                            "$clientName @ $domainName" 
                        } else { 
                            $clientName 
                        }
                        Server = if ($serviceName -and $domainName) { 
                            "$serviceName @ $domainName" 
                        } else { 
                            $serviceName 
                        }
                        KerbTicket_Encryption_Type = if ($encryptionMap[$info.EncryptionType]) { 
                            $encryptionMap[$info.EncryptionType] 
                        } else { 
                            "Unknown ($($info.EncryptionType))" 
                        }
                        Ticket_Flags = $ticketFlags
                        Start_Time = if ($startTime) { 
                            $startTime.ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        End_Time = if ($endTime) { 
                            $endTime.ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        Renew_Time = if ($renewTime) { 
                            $renewTime.ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        Session_Key_Type = $sessionKeyType
                        Cache_Flags = $cacheFlags
                        Kdc_Called = $kdcCalled
                        # Additional properties available with Select-Object *
                        TimeSkew = $ticketExt.TimeSkew
                        EncodedTicketSize = $ticketExt.EncodedTicketSize
                        KeyExpirationTime = if ($keyExpTime) { 
                            $keyExpTime.ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        DomainName = $domainName
                        TargetDomainName = $targetDomainName
                        AltTargetDomainName = $altTargetDomainName
                        RealmName = $realmName
                        RawTicketFlags = $ticketExt.TicketFlags
                        RawCacheFlags = $ticketExt.Flags
                    }
                    
                    # Add default display properties
                    $ticketObj.PSObject.TypeNames.Insert(0, 'KerberosTicket')
                    $ticketObj
                } else {
                    Write-Verbose "Failed to retrieve detailed ticket for $serverName - Status: 0x$($status.ToString('X8')), ProtStatus: 0x$($ticketProtStatus.ToString('X8'))"
                    
                    # Enhanced fallback - try to get realm info from the basic cache info
                    $realmName = if ($info.RealmName.Buffer -ne [IntPtr]::Zero -and $info.RealmName.Length) { 
                        [System.Runtime.InteropServices.Marshal]::PtrToStringUni($info.RealmName.Buffer, $info.RealmName.Length/2) 
                    } else { 
                        "" 
                    }
                    
                    # Try to parse client from current user context if available
                    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
                    $clientDisplay = if ($currentUser -and $realmName) {
                        $username = $currentUser.Split('\')[-1]  # Get username part
                        "$username @ $realmName"
                    } else { 
                        "" 
                    }
                    
                    # Try to extract KDC from server name for fallback
                    $kdcFallback = ""
                    if ($serverName) {
                        $serverParts = $serverName.Split('/')
                        if ($serverParts.Length -gt 1) {
                            $hostPart = $serverParts[1]
                            $domainPart = $hostPart.Split('.', 2)
                            if ($domainPart.Length -gt 1) {
                                $kdcFallback = $domainPart[1].ToUpper()
                            }
                        }
                    }
                    if (!$kdcFallback -and $realmName) {
                        $kdcFallback = $realmName
                    }
                    
                    $fallbackObj = [PSCustomObject]@{
                        PSTypeName = 'KerberosTicket'
                        Client = $clientDisplay
                        Server = if ($serverName -and $realmName) { 
                            "$serverName @ $realmName" 
                        } else { 
                            $serverName 
                        }
                        KerbTicket_Encryption_Type = if ($encryptionMap[$info.EncryptionType]) { 
                            $encryptionMap[$info.EncryptionType] 
                        } else { 
                            "Unknown ($($info.EncryptionType))" 
                        }
                        Ticket_Flags = "0x{0:X8} -> {1}" -f $info.TicketFlags, (Get-TicketFlags $info.TicketFlags)
                        Start_Time = if ($info.StartTime) { 
                            [DateTime]::FromFileTime($info.StartTime).ToLocalTime().ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        End_Time = if ($info.EndTime) { 
                            [DateTime]::FromFileTime($info.EndTime).ToLocalTime().ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        Renew_Time = if ($info.RenewTime) { 
                            [DateTime]::FromFileTime($info.RenewTime).ToLocalTime().ToString("M/d/yyyy H:mm:ss") + " (local)" 
                        } else { 
                            "" 
                        }
                        Session_Key_Type = if ($encryptionMap[$info.EncryptionType]) { 
                            $encryptionMap[$info.EncryptionType] 
                        } else { 
                            "Unknown ($($info.EncryptionType))" 
                        }
                        Cache_Flags = "0"
                        Kdc_Called = $kdcFallback
                        # Limited additional properties for fallback
                        TimeSkew = 0
                        EncodedTicketSize = 0
                        KeyExpirationTime = ""
                        DomainName = ""
                        TargetDomainName = ""
                        AltTargetDomainName = ""
                        RealmName = $realmName
                        RawTicketFlags = $info.TicketFlags
                        RawCacheFlags = 0
                    }
                    
                    $fallbackObj.PSObject.TypeNames.Insert(0, 'KerberosTicket')
                    $fallbackObj
                }
            }
            catch {
                Write-Warning "Error retrieving full ticket for $($serverName): $_"
            }
            finally {
                if ($ticketReqPtr -ne [IntPtr]::Zero) { 
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ticketReqPtr) 
                }
                if ($ticketReturnBuffer -ne [IntPtr]::Zero) { 
                    [Secur32]::LsaFreeReturnBuffer($ticketReturnBuffer) | Out-Null 
                }
                if ($ticketTargetNameBuf -ne [IntPtr]::Zero) { 
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ticketTargetNameBuf) 
                }
            }
        }
        
        return $tickets
    }
    catch { 
        Write-Error "Get-KerberosTicket failed: $_"
        return @() 
    }
    finally {
        if ($tokenHandle) { 
            [Secur32]::CloseHandle($tokenHandle) | Out-Null 
        }
        if ($pReq) { 
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($pReq) 
        }
        if ($returnBuffer) { 
            [Secur32]::LsaFreeReturnBuffer($returnBuffer) | Out-Null 
        }
        if ($kerbNameBuf) { 
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($kerbNameBuf) 
        }
        if ($lsaHandle) { 
            [Secur32]::LsaDeregisterLogonProcess($lsaHandle) | Out-Null 
        }
    }
}

#-----------------------------------------------------------------------
# Helper Functions for Test-TgsAndSpnValidation
#-----------------------------------------------------------------------
function Get-KerberosErrorAnalysis {
    <#
    .SYNOPSIS
        Provides detailed analysis of Win32 error codes in the context of Kerberos PAC validation.
    #>
    param(
        [int]$ErrorCode,
        [string]$TestPath
    )

    $analysis = @{
        Category = 'Unknown'
        Diagnostics = ''
    }

    switch ($ErrorCode) {
        # Access Denied - Strong PAC validation failure indicator
        5 {
            $analysis.Category = 'PAC_Validation_Likely'
            $analysis.Diagnostics = @"
STRONG INDICATOR: This is likely a PAC validation failure. The authentication succeeded (server recognized the user), but authorization failed.

Possible causes:
• PAC validation failed due to trust relationship issues
• User's group memberships in the PAC don't match what the server expects
• Time synchronization issues affecting PAC validation
• Corrupted or tampered PAC data
• Cross-domain trust configuration problems

Recommended actions:
• Check domain trust relationships
• Verify time synchronization between client, DC, and target server
• Review security event logs on the target server (Events 4625, 4768, 4769)
• Test with a different user account
• Check if the issue persists after 'klist purge' and re-authentication
"@
        }
        
        # Network path not found
        53 {
            $analysis.Category = 'Network_Connectivity'
            $analysis.Diagnostics = @"
NETWORK ISSUE: The network path cannot be found. This is typically not a PAC validation issue.

Possible causes:
• Target server is unreachable (network/firewall)
• Server service not running on target
• DNS resolution failure
• NetBIOS name resolution issues

This error occurs before Kerberos authentication, so PAC validation is not being tested.
"@
        }
        
        # The network name cannot be found
        67 {
            $analysis.Category = 'Name_Resolution'
            $analysis.Diagnostics = @"
NAME RESOLUTION: Cannot resolve the network name. This prevents Kerberos authentication from occurring.

Possible causes:
• DNS resolution failure for the target server
• NetBIOS name resolution issues
• Incorrect server name in the path

This error occurs before Kerberos authentication, so PAC validation cannot be tested.
"@
        }
        
        # Multiple connections with different credentials
        1219 {
            $analysis.Category = 'Credential_Conflict'
            $analysis.Diagnostics = @"
CREDENTIAL CONFLICT: Multiple connections to the same server with different credentials.

This is not a PAC validation issue. Disconnect existing connections:
• net use /delete \\servername
• net use * /delete (to clear all)

Then retry the test.
"@
        }
        
        # No logon servers available
        1311 {
            $analysis.Category = 'Domain_Controller_Unavailable'
            $analysis.Diagnostics = @"
DC UNAVAILABLE: No domain controllers are available to process the authentication request.

This prevents Kerberos authentication from occurring, so PAC validation cannot be tested.

Possible causes:
• All domain controllers are down or unreachable
• Network connectivity issues to domain controllers
• DNS issues preventing DC location
"@
        }
        
        # Logon failure: target account name incorrect (SPN issues)
        1396 {
            $analysis.Category = 'SPN_Issue'
            $analysis.Diagnostics = @"
SPN ISSUE: The target account name is incorrect. This is typically a Service Principal Name (SPN) problem.

This prevents proper Kerberos authentication, so PAC validation cannot be tested.

Common causes:
• Missing or incorrect SPN registration for the service
• Duplicate SPNs registered to multiple accounts
• SPN format issues

Check SPNs with: setspn -L [target-server-name]
"@
        }
        
        # Logon failure
        1326 {
            $analysis.Category = 'Authentication_Failure'
            $analysis.Diagnostics = @"
AUTHENTICATION FAILURE: Logon failure occurred during Kerberos authentication.

This could be related to PAC validation, but could also be other authentication issues.

Possible causes:
• User account locked, disabled, or expired
• Password expired or incorrect
• Authentication policy restrictions
• PAC validation failure
• Trust relationship issues

Check security event logs for more specific error details.
"@
        }
        
        default {
            $analysis.Category = 'Other'
            $analysis.Diagnostics = @"
An error occurred that is not commonly associated with PAC validation issues.

For comprehensive troubleshooting:
• Check the target server's event logs
• Review Kerberos-specific events (4768, 4769, 4771)
• Verify network connectivity and name resolution
• Ensure the Server service is running on the target

Error code $ErrorCode may require additional research for specific diagnosis.
"@
        }
    }

    return $analysis
}
#endregion Private Helpers


#-----------------------------------------------------------------------
# SECTION 2: Public Functions
# These are the functions intended for the end-user to call.
#-----------------------------------------------------------------------
function Test-DnsResolution {
    <#
    .SYNOPSIS
        Resolves DNS for a domain controller and returns IPv4 addresses.
    .DESCRIPTION
        Performs a DNS lookup on the specified domain controller using System.Net.Dns.
    .PARAMETER DomainController
        The FQDN or hostname of the domain controller to resolve.
    .INPUTS
        System.String. You can pipe a domain controller FQDN to this function.
    .OUTPUTS
        System.Collections.Hashtable
    .EXAMPLE
        Test-DnsResolution -DomainController "dc01.contoso.com"
    .LINK
        https://docs.microsoft.com/en-us/dotnet/api/system.net.dns
    .NOTES
        Only returns IPv4 addresses.
    #>
	param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )

    Write-Verbose "Resolving DNS for $DomainController"

	$result = @{
		success = $false
		resolvedIPs = @()
		errorMessage = $null
	}

	try {
		$ipv4Addresses = [System.Net.Dns]::GetHostAddresses($DomainController) |
            Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
            ForEach-Object { $_.IPAddressToString }

		if ($ipv4Addresses.Count -eq 0) {
			$result.ErrorMessage = "No IPv4 addresses found for $DomainController"
		} else {
			$result.Success = $true
			$result.ResolvedIPs = $ipv4Addresses
		}
	} catch [System.Net.Sockets.SocketException] {
        $result.ErrorMessage = "DNS resolution failed: $($_.Exception.Message)"
    } catch {
		$result.ErrorMessage = "An unexpected error occurred during DNS resolution: $($_.Exception.Message)"
	}

	return $result
}

function Test-TcpConnectivity {
    <#
    .SYNOPSIS
        Tests TCP connectivity to specific ports on a domain controller with a configurable timeout.
    .DESCRIPTION
        Attempts to open a TCP connection to specified ports using the .NET TcpClient class.
        This allows for a precise connection timeout and includes retry logic.
    .PARAMETER DomainController
        The FQDN or hostname of the domain controller to test.
    .PARAMETER TimeoutSeconds
        The maximum number of seconds to wait for a single TCP connection attempt to succeed.
    .PARAMETER RetryDelaySeconds
        The number of seconds to wait between retry attempts.
    .PARAMETER RetryCount
        The number of retry attempts for each port.
    .PARAMETER Ports
        An array of port numbers to test.
    .INPUTS
        System.String
    .OUTPUTS
        System.Collections.Hashtable
    .EXAMPLE
        Test-TcpConnectivity -DomainController "dc01.contoso.com" -TimeoutSeconds 3 -RetryCount 2
    .LINK
        System.Net.Sockets.TcpClient
    .NOTES
        This function uses the .NET TcpClient for precise timeout control and does not
        depend on Test-NetConnection or ICMP (ping).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 5,

        [Parameter()]
        [ValidateRange(0, 30)]
        [int]$RetryDelaySeconds = 3,

        [Parameter()]
        [ValidateRange(1, 5)]
        [int]$RetryCount = 3,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [int[]]$Ports = @(88, 389, 636)
    )

    Write-Verbose "Testing TCP connectivity to $DomainController on ports: $($Ports -join ', ')"

    $result = @{}
    foreach ($port in $Ports) {
        $label = "TcpPort$port"
        $success = $false
        $message = ""
        $connectionTimeMs = $null
        $remoteAddress = $null

        for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
            Write-Verbose "Attempt $attempt of $RetryCount for port $port"
            $tcpClient = $null
            $stopwatch = [System.Diagnostics.Stopwatch]::new()
            
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $stopwatch.Start()

                # Start the asynchronous connection attempt
                $connectTask = $tcpClient.ConnectAsync($DomainController, $port)

                # Wait for the task to complete, with our specified timeout
                $isCompletedInTime = $connectTask.Wait($TimeoutSeconds * 1000)

                $stopwatch.Stop()
                
                if ($isCompletedInTime -and $tcpClient.Connected) {
                    $success = $true
                    $message = "Open (TCP connection successful on attempt $attempt)"
                    $connectionTimeMs = $stopwatch.ElapsedMilliseconds
                    # Get the IP we actually connected to from the endpoint
                    $remoteAddress = ($tcpClient.Client.RemoteEndPoint).Address.ToString()
                    break # Exit the retry loop on success
                } else {
                    # This case handles the timeout
                    $tcpClient.Close() # Close the client on timeout to clean up the socket
                    $message = "Attempt $attempt failed: Connection to port $port timed out after $TimeoutSeconds seconds."
                }
            } catch {
                $stopwatch.Stop()
                $message = "Attempt $attempt failed with an exception: $($_.Exception.Message)"
            } finally {
                # Ensure the client is always disposed of properly
                if ($null -ne $tcpClient) {
                    $tcpClient.Dispose()
                }
            }
            
            if ($attempt -lt $RetryCount) {
                Start-Sleep -Seconds $RetryDelaySeconds
            }
        }

        $result[$label] = @{
            Success          = $success
            Message          = $message
            ConnectionTimeMs = $connectionTimeMs
            RemoteAddress    = $remoteAddress
        }
    }

    return $result
}

function Invoke-KerberosAsRequest {
	<#
	.SYNOPSIS
		Invokes a Kerberos AS-REQ to test KDC reachability and discover supported encryption types.

	.DESCRIPTION
        Builds a minimal ASN.1-encoded KERBEROS_AS_REQ packet and sends it over UDP to the specified KDC.
        The function analyzes the KDC response to determine:
        1. Basic connectivity and KDC health
        2. Supported encryption types (extracted from ETYPE-INFO2 in error responses)
        
        When the KDC returns KDC_ERR_PREAUTH_REQUIRED, it includes ETYPE-INFO2 data that lists
        all encryption types the KDC supports for the realm. This allows discovery of supported
        encryption algorithms without requiring credentials.

	.PARAMETER Server
		FQDN or hostname of the target KDC.

	.PARAMETER Port
		UDP port for Kerberos (default 88).

	.PARAMETER Realm
		Kerberos realm (e.g., CONTOSO.COM). If omitted, derived from the Server name.

	.PARAMETER ClientName
		Client principal name to use in the request. Defaults to current user.

	.PARAMETER TimeoutMs
		Maximum milliseconds to wait for UDP response (default 5000).

	.PARAMETER TillTime
		Ticket lifetime end time (defaults to 8 hours from now).

	.PARAMETER Nonce
		Request nonce (defaults to random value).

	.PARAMETER RequestedEncryptionTypes
		Array of encryption type IDs to request. Defaults to common types.

	.NOTES
        The function does not require credentials - it uses the KDC's preauth-required response
        to discover supported encryption types. This is more reliable than attempting actual
        authentication and works even with non-existent user accounts.

	.EXAMPLE
		Invoke-KerberosAsRequest -Server dc01.contoso.com -Verbose
		
		Tests KDC connectivity and discovers all supported encryption types.

	.EXAMPLE
		Invoke-KerberosAsRequest -Server dc01.contoso.com -ClientName testuser
		
		Tests with a specific client name (useful for testing with known accounts).

    .INPUTS
        System.String
    .OUTPUTS
        PSCustomObject with KDC test results and supported encryption types
	#>
	[CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Server,

        [Parameter()]
        [ValidateRange(1, 65535)]
        [int]$Port = 88,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]$Realm = $null,

        [Parameter()]
        [string]$ClientName = $null,

        [Parameter()]
        [ValidateRange(100, 60000)]
        [int]$TimeoutMs = 5000,

        [Parameter()]
        [DateTime]$TillTime = [DateTime]::Now.AddHours(8),

        [Parameter()]
        [int]$Nonce = (Get-Random -Minimum 1 -Maximum ([int]::MaxValue)),

        [Parameter()]
        [ValidateSet('DES-CBC-CRC', 'DES-CBC-MD5', 'AES128-CTS-HMAC-SHA1-96', 'AES256-CTS-HMAC-SHA1-96', 'RC4-HMAC', 'AES128-CTS-HMAC-SHA256-128', 'AES256-CTS-HMAC-SHA384-192')]
        [string[]]$RequestedEncryptionTypes = @('AES256-CTS-HMAC-SHA1-96', 'AES128-CTS-HMAC-SHA1-96', 'RC4-HMAC')
    )

    begin {
        # Set default client name if not provided
        if ([string]::IsNullOrEmpty($ClientName)) {
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            if ($currentUser -match '\\') {
                $ClientName = $currentUser.Split('\')[1]
            }
            else {
                $ClientName = $currentUser
            }
            Write-Verbose "ClientName not specified; using: $ClientName"
        }

        # Convert string encryption types to integers
        $requestedEncryptionTypeInts = foreach ($etypeStr in $RequestedEncryptionTypes) {
            Convert-EncryptionType -EtypeName $etypeStr
        }
    }

    process {
        try {
            # Derive realm from server name if not provided
            if ([string]::IsNullOrWhiteSpace($Realm)) {
                $labels = $Server.Split('.')
                switch ($labels.Count) {
                    { $_ -ge 3 } {
                        $Realm = ($labels[1..($labels.Count - 1)] -join '.').ToUpper()
                        break
                    }
                    2 {
                        $Realm = ($labels -join '.').ToUpper()
                        break
                    }
                    default {
                        throw "Cannot derive realm from server name '$Server'. Please specify the -Realm parameter."
                    }
                }
                Write-Verbose "Derived realm from server name: $Realm"
            }

            Write-Verbose "Testing Kerberos KDC: $Server`:$Port (Realm: $Realm)"
            Write-Verbose "Client: $ClientName, Nonce: $Nonce, TillTime: $($TillTime.ToString('yyyy-MM-dd HH:mm:ss'))"
            Write-Verbose "Requested Encryption Types: $($RequestedEncryptionTypes -join ', ')"
            
            Write-Verbose "[1/5] Building AS-REQ packet..."
            $asReqPacket = New-KerberosAsReqPacket -ClientName $ClientName -Realm $Realm -TillTime $TillTime -EncryptionTypes $requestedEncryptionTypeInts -Nonce $Nonce
            Write-Verbose "  AS-REQ packet size: $($asReqPacket.Length) bytes"

            Write-Verbose "[2/5] Resolving hostname..."
            $ServerIP = $null
            try {
                $dnsRecords = [System.Net.Dns]::GetHostAddresses($Server)
                $ServerIP = $dnsRecords | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
                if (-not $ServerIP) {
                    throw "No IPv4 address found for '$Server'"
                }
                Write-Verbose "  Resolved to: $($ServerIP.IPAddressToString)"
            }
            catch {
                throw "DNS resolution failed for '$Server': $($_.Exception.Message)"
            }

            Write-Verbose "[3/5] Sending AS-REQ packet..."
            $udpClient = $null
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                $udpClient = New-Object System.Net.Sockets.UdpClient
                $udpClient.Client.ReceiveTimeout = $TimeoutMs
                $udpClient.Client.SendTimeout = $TimeoutMs
                $remoteEP = [System.Net.IPEndPoint]::new($ServerIP, $Port)
                
                $bytesSent = $udpClient.Send($asReqPacket, $asReqPacket.Length, $remoteEP)
                Write-Verbose "  Sent $bytesSent bytes"

                Write-Verbose "[4/5] Waiting for response (timeout: ${TimeoutMs}ms)..."
                $receivedEP = $remoteEP
                $response = $udpClient.Receive([ref]$receivedEP)
                $stopwatch.Stop()
                Write-Verbose "  Received $($response.Length) bytes in $($stopwatch.ElapsedMilliseconds)ms"

                Write-Verbose "[5/5] Analyzing response..."
                $analysis = Get-KerberosResponseAnalysis -ResponseBytes $response
                
                # Determine if KDC is operational
                $isOperational = $analysis.IsSuccess -or 
                                ($analysis.Type -eq 'KRB-ERROR' -and $analysis.ErrorCode -in @(6, 25))
                
                if ($analysis.Type -eq 'KRB-ERROR' -and $analysis.ErrorCode -eq 6) {
                    Write-Verbose "  KDC is operational (client principal unknown - expected)"
                }
                elseif ($analysis.Type -eq 'KRB-ERROR' -and $analysis.ErrorCode -eq 25) {
                    Write-Verbose "  KDC is operational (pre-authentication required - expected)"
                }
                elseif ($analysis.IsSuccess) {
                    Write-Verbose "  KDC response indicates success: $($analysis.ErrorDescription)"
                }
                else {
                    Write-Verbose "  KDC error: $($analysis.ErrorDescription)"
                }

                $result = [PSCustomObject]@{
                    PSTypeName                  = 'KerberosAsRequestResult'
                    Success                     = $isOperational
                    Operational                 = $isOperational
                    Server                      = $Server
                    ServerIP                    = $ServerIP.IPAddressToString
                    Port                        = $Port
                    Realm                       = $Realm
                    ClientName                  = $ClientName
                    RequestedEncryptionTypes    = $RequestedEncryptionTypes
                    RequestedEncryptionTypeIds  = $requestedEncryptionTypeInts
                    SupportedEncryptionIds      = $analysis.SupportedEncryptionIds
                    SupportedEncryptionNames    = $analysis.SupportedEncryptionNames
                    ResponseTime                = $stopwatch.ElapsedMilliseconds
                    ResponseSize                = $response.Length
                    ResponseType                = $analysis.Type
                    ErrorCode                   = $analysis.ErrorCode
                    ErrorDescription            = $analysis.ErrorDescription
                    Timestamp                   = [DateTime]::Now
                }
                
                return $result
            }
            catch [System.Net.Sockets.SocketException] {
                $stopwatch.Stop()
                $errorMsg = switch ($_.Exception.SocketErrorCode) {
                    'TimedOut' { "Connection timed out after ${TimeoutMs}ms - KDC may be unreachable or not responding" }
                    'ConnectionRefused' { "Connection refused - KDC service may not be running on port $Port" }
                    'HostUnreachable' { "Host unreachable - network connectivity issue" }
                    'NetworkUnreachable' { "Network unreachable - routing issue" }
                    default { "Socket error: $($_.Exception.SocketErrorCode) - $($_.Exception.Message)" }
                }
                throw $errorMsg
            }
            finally {
                if ($udpClient) {
                    $udpClient.Close()
                    $udpClient.Dispose()
                }
            }
        }
        catch {
            return [PSCustomObject]@{
                PSTypeName                  = 'KerberosAsRequestResult'
                Success                     = $false
                Operational                 = $false
                Server                      = $Server
                ServerIP                    = if ($ServerIP) { $ServerIP.IPAddressToString } else { $null }
                Port                        = $Port
                Realm                       = $Realm
                ClientName                  = $ClientName
                RequestedEncryptionTypes    = $RequestedEncryptionTypes
                RequestedEncryptionTypeIds  = if ($requestedEncryptionTypeInts) { $requestedEncryptionTypeInts } else { @() }
                SupportedEncryptionIds      = @()
                SupportedEncryptionNames    = @()
                ResponseTime                = if ($stopwatch) { $stopwatch.ElapsedMilliseconds } else { 0 }
                ResponseSize                = 0
                ResponseType                = 'ERROR'
                ErrorCode                   = $null
                ErrorDescription            = $_.Exception.Message
                Timestamp                   = [DateTime]::Now
            }
        }
    }
}

function Test-TimeSynchronization {
    <#
    .SYNOPSIS
        Checks time synchronization against a domain controller using w32tm.exe.
    .DESCRIPTION
        Executes the w32tm.exe utility to determine the time offset between the local machine
        and the specified domain controller. It then evaluates if the skew is within the
        acceptable range for Kerberos authentication (typically 5 minutes).
    .PARAMETER DomainController
        The domain controller to check against.
    .INPUTS
        System.String
    .OUTPUTS
        PSCustomObject
    .EXAMPLE
        Test-TimeSynchronization -DomainController "dc01.contoso.com"
    .LINK
        w32tm
    .NOTES
        This function is a robust wrapper for w32tm.exe. It checks the command's exit code
        and handles parsing errors gracefully. A non-zero time skew is expected in normal
        operation; the key result is whether the skew is within the allowed maximum.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )

    Write-Verbose "Checking time synchronization with $DomainController using w32tm.exe"

    $result = [PSCustomObject]@{
        Success          = $false
        TimeSkewSeconds  = $null
        IsSkewAcceptable = $false
        MaxAllowedSkew   = 300 # 5 minutes is the default maximum for Kerberos
        ErrorMessage     = ''
    }

    try {
        # Execute w32tm, merging the error stream (2) into the success stream (1)
        # so we can capture all output from the command.
        $w32tmOutput = w32tm.exe /stripchart /computer:$DomainController /samples:1 /dataonly 2>&1

        # A non-zero exit code is the most reliable sign of command failure.
        if ($LASTEXITCODE -ne 0) {
            $result.ErrorMessage = "w32tm.exe failed with exit code $LASTEXITCODE. Error: $($w32tmOutput -join ' ')"
            # Exit here; no point in trying to parse the output if the command failed.
            return $result
        }

        # If the command succeeded, now we can safely attempt to parse its output.
        # This regex looks for a line ending with a comma, optional space, and the time offset.
        $offsetLine = $w32tmOutput | Select-String -Pattern ',\s*([+\-][0-9\.]+s)$'

        if ($offsetLine) {
            # The capture group ([1]) contains the offset string like "+0.00123s"
            # We remove the "s" and convert it to a double.
            $timeSkewString = $offsetLine.Matches[0].Groups[1].Value.Replace('s', '')
            $timeSkew = [Math]::Abs([double]$timeSkewString)

            $result.Success = $true
            $result.TimeSkewSeconds = $timeSkew
            $result.IsSkewAcceptable = ($timeSkew -le $result.MaxAllowedSkew)

            if (-not $result.IsSkewAcceptable) {
                $result.ErrorMessage = "Time skew of $timeSkew seconds exceeds the Kerberos maximum of $($result.MaxAllowedSkew) seconds."
            }
        }
        else {
            # The command ran, but the output didn't contain the data we expected.
            $result.ErrorMessage = "Could not parse time offset from w32tm output. Output was: $($w32tmOutput -join ' ')"
        }
    }
    catch {
        $result.ErrorMessage = "An exception occurred while running w32tm.exe: $($_.Exception.Message)"
    }

    return $result
}

function Test-AlternativeAuthentication {
    <#
    .SYNOPSIS
        Tests non-Kerberos authentication methods (NTLM, Basic, Anonymous) against an LDAP server.
    .DESCRIPTION
        Validates non-Kerberos LDAP authentication methods for diagnostic purposes. It reports not only
        on success or failure, but also on the security implications of the configuration.
    .PARAMETER DomainController
        The domain controller to test.
    .PARAMETER Credential
        Optional credentials for testing authenticated methods like NTLM and Basic.
    .PARAMETER TimeoutSeconds
        Timeout for LDAP connection attempts.
    .INPUTS
        System.Management.Automation.PSCredential
    .OUTPUTS
        PSCustomObject
    .EXAMPLE
        Test-AlternativeAuthentication -DomainController "dc01.contoso.com"
    .LINK
        System.DirectoryServices.Protocols.LdapConnection
    .NOTES
        This function is used for diagnostic purposes when Kerberos authentication fails, or to audit
        which legacy authentication protocols are enabled on a domain controller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 60)]
        [int]$TimeoutSeconds = 15
    )

    # This private helper function eliminates repetitive try/catch blocks.
    function Invoke-LdapBind {
        param(
            [Parameter(Mandatory)]
            [System.DirectoryServices.Protocols.LdapConnection]$Connection
        )
        $bindResult = @{ Success = $false; ErrorMessage = $null }
        try {
            $Connection.Bind()
            $bindResult.Success = $true
        }
        catch {
            $bindResult.ErrorMessage = $_.Exception.Message
        }
        finally {
            if ($Connection) {
                $Connection.Dispose()
            }
        }
        return $bindResult
    }

    Write-Verbose "Testing alternative authentication methods against $DomainController"

    $result = [PSCustomObject]@{
        DomainController      = $DomainController
        Timestamp             = Get-Date
        AnonymousBindResult   = 'NotTested'
        AnonymousBindError    = ''
        NtlmBindResult        = 'NotTested'
        NtlmBindError         = ''
        BasicBindResult       = 'NotTested'
        BasicBindError        = ''
    }

    # Test Anonymous Authentication
    Write-Verbose "Testing anonymous LDAP bind..."
    $anonymousConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
    $anonymousConn.SessionOptions.ProtocolVersion = 3
    $anonymousConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $anonymousConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
    
    $anonymousResult = Invoke-LdapBind -Connection $anonymousConn
    # A successful anonymous bind is a security risk. A failure is the expected, secure state.
    $result.AnonymousBindResult = if ($anonymousResult.Success) { 'Enabled (Insecure)' } else { 'Disabled (Secure)' }
    $result.AnonymousBindError = $anonymousResult.ErrorMessage


    # Test NTLM Authentication
    Write-Verbose "Testing NTLM authentication..."
    $ntlmConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
    $ntlmConn.SessionOptions.ProtocolVersion = 3
    $ntlmConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
    $ntlmConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Ntlm
    if ($Credential) {
        $ntlmConn.Credential = $Credential.GetNetworkCredential()
    }
    
    $ntlmResult = Invoke-LdapBind -Connection $ntlmConn
    $result.NtlmBindResult = if ($ntlmResult.Success) { 'Success' } else { 'Failure' }
    $result.NtlmBindError = $ntlmResult.ErrorMessage


    # Test Basic Authentication (only if credentials provided)
    if ($Credential) {
        Write-Verbose "Testing Basic authentication..."
        $basicConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
        $basicConn.SessionOptions.ProtocolVersion = 3
        $basicConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
        $basicConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
        $basicConn.Credential = $Credential.GetNetworkCredential()
        
        $basicResult = Invoke-LdapBind -Connection $basicConn
        # A successful Basic bind is a security risk. A failure is the expected, secure state.
        $result.BasicBindResult = if ($basicResult.Success) { 'Enabled (Insecure)' } else { 'Disabled (Secure)' }
        $result.BasicBindError = $basicResult.ErrorMessage
    }
    else {
        $result.BasicBindResult = 'Skipped'
        $result.BasicBindError = 'No credentials provided'
    }

    return $result
}

function Test-KerberosSession {
    <#
    .SYNOPSIS
        Checks the current user's session to verify it was authenticated using a Kerberos-capable provider.
    .DESCRIPTION
        Uses the .NET [System.Security.Principal.WindowsIdentity] class to inspect the
        current PowerShell session's security context. It considers both 'Kerberos' and 'Negotiate'
        as successful authentication types for a domain environment.
    .OUTPUTS
        PSCustomObject with details about the current session's identity.
    .EXAMPLE
        Test-KerberosSession
    .NOTES
        A result of 'Negotiate' indicates the session will attempt to use Kerberos first before
        falling back to NTLM, and is considered a success for this test.
    #>
    [CmdletBinding()]
    param()

    $result = [PSCustomObject]@{
        Success            = $false
        UserName           = 'Unknown'
        AuthenticationType = 'Unknown'
        ImpersonationLevel = 'Unknown'
        Message            = ''
    }

    try {
        $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        
        $result.UserName = $identity.Name
        $result.AuthenticationType = $identity.AuthenticationType
        $result.ImpersonationLevel = $identity.ImpersonationLevel

        if ($result.AuthenticationType -in 'Kerberos', 'Negotiate') {
            $result.Success = $true
            $result.Message = "Session authentication provider is '$($result.AuthenticationType)', which supports Kerberos."
        }
        else {
            $result.Message = "The current session is authenticated via '$($result.AuthenticationType)', which does not use Kerberos. Domain authentication will likely fail or use NTLM."
        }
    }
    catch {
        $result.Message = "An error occurred while getting the current Windows identity: $($_.Exception.Message)"
    }

    return $result
}

function Test-TgtRequest {
    <#
     <#
    .SYNOPSIS
        Provides a detailed diagnostic test of Kerberos LDAP bind configurations.
    .DESCRIPTION
        Performs a comprehensive test of Kerberos authentication by attempting an LDAP bind for each
        possible security configuration. It includes highly specific exception handling and secondary
        diagnostic checks (like for SPNs) to precisely diagnose the root cause of failures.
    .PARAMETER DomainController
        The domain controller to test.
    .PARAMETER Credential
        Optional alternate credentials for testing.
    .PARAMETER TimeoutSeconds
        Timeout for each individual LDAP bind operation.
    .INPUTS
        System.Management.Automation.PSCredential
    .OUTPUTS
        A stream of PSCustomObjects with detailed results for each configuration tested.
    .EXAMPLE
        Test-TgtRequest -DomainController "dc01.contoso.com" | Where-Object { -not $_.Success }
    .NOTES
        This function is designed for high-fidelity root cause analysis.
    #>
    [CmdletBinding(DefaultParameterSetName = 'CurrentUser')]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter(ParameterSetName = 'AlternateCredential', Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [ValidateRange(1, 120)]
        [int]$TimeoutSeconds = 30
    )

    begin {
        try {
            Add-Type -AssemblyName System.DirectoryServices.Protocols -ErrorAction Stop
        }
        catch {
            throw "Failed to load required assembly 'System.DirectoryServices.Protocols'."
        }
    }

    process {
        $authType = if ($PSCmdlet.ParameterSetName -eq 'AlternateCredential') {
            "AlternateCredential ($($Credential.UserName))"
        }
        else {
            "CurrentUser ($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))"
        }
        $timestamp = Get-Date

        $securityConfigurations = @(
            [pscustomobject]@{ Signing = $true; Sealing = $true; Description = "Signing and Sealing" },
            [pscustomobject]@{ Signing = $true; Sealing = $false; Description = "Signing Only" },
            [pscustomobject]@{ Signing = $false; Sealing = $false; Description = "No Signing or Sealing" }
        )

        foreach ($config in $securityConfigurations) {
            $ldapConn = $null
            $isSuccess = $false
            $errorMessage = $null
            $errorCategory = 'None'
            
            Write-Verbose "Attempting Kerberos bind with configuration: $($config.Description)"
            
            try {
                # ... (LDAP connection setup is the same as before)
                $ldapConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
                $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
                $ldapConn.SessionOptions.ProtocolVersion = 3
                $ldapConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)
                $ldapConn.SessionOptions.Signing = $config.Signing
                $ldapConn.SessionOptions.Sealing = $config.Sealing
                if ($PSCmdlet.ParameterSetName -eq 'AlternateCredential') {
                    $ldapConn.Credential = $Credential.GetNetworkCredential()
                }

                $ldapConn.Bind()
                $isSuccess = $true
            }
            catch [System.TimeoutException] {
                $errorCategory = 'Timeout'
                $errorMessage = "Operation timed out after $TimeoutSeconds seconds. This suggests a network or firewall issue is blocking the LDAP response from the server."
            }
            catch [System.DirectoryServices.Protocols.LdapException] {
                $errorCategory = 'LdapError'
                $baseMessage = "LDAP server returned an error: $($_.Exception.Message) (Code: $($_.Exception.ErrorCode))."
                
                # If it's an Invalid Credentials error, it could be an SPN issue. Launch a secondary test.
                if ($_.Exception.ErrorCode -eq 49) {
                    $expectedSpn = "LDAP/$DomainController"
                    Write-Verbose "LDAP error 49 detected. Running correlated SPN check for '$expectedSpn'..."
                    $spnStatus = Test-KerberosSpn -Spn $expectedSpn
                    $baseMessage += " [DIAGNOSIS: This error code often relates to SPN issues. SPN check result: $spnStatus]"
                }
                $errorMessage = $baseMessage
            }
            catch [System.Security.Authentication.AuthenticationException] {
                $errorCategory = 'AuthenticationError'
                $exMessage = $_.Exception.Message
                # Parse the generic authentication exception for common Kerberos-related keywords.
                $diagnosticHint = switch -Regex ($exMessage) {
                    'The target principal name is incorrect' { "This is a classic SPN or DNS alias issue. The name the client is using does not match the Kerberos ticket." }
                    'unsupported etype|encryption type' { "This indicates a cipher suite mismatch. The client or server may have certain encryption types (like RC4) disabled by policy." }
                    default { "This may indicate a client-side Kerberos provider issue, a bad ticket in the local cache, or a problem with the underlying SSPI security context." }
                }
                $errorMessage = "A general authentication failure occurred: `"$exMessage`". [DIAGNOSIS: $diagnosticHint]"
            }
            catch {
                $errorCategory = 'UnexpectedError'
                $errorMessage = "An unexpected exception occurred: $($_.Exception.Message)"
            }
            finally {
                if ($ldapConn) {
                    $ldapConn.Dispose()
                }
            }
            
            [PSCustomObject]@{
                DomainController    = $DomainController
                AuthenticationType  = $authType
                Timestamp           = $timestamp
                Configuration       = $config.Description
                Success             = $isSuccess
                ErrorCategory       = $errorCategory
                ErrorMessage        = $errorMessage
            }
        }
    }
}

function Test-TgsAndSpnValidation {
    <#
    .SYNOPSIS
        Tests TGS request and validates the SPN ticket in the cache using the LSA API.
    .DESCRIPTION
        This function first triggers a service ticket request, then calls the robust Get-KerberosTicket
        function to query the LSA ticket cache directly. It validates the ticket by searching the
        structured results, which is far more reliable than parsing klist.exe output.
    .PARAMETER DomainController
        The domain controller to test against.
    .PARAMETER Credential
        Alternate credentials. If provided, the test is skipped because Get-KerberosTicket can only inspect
        the ticket cache of the current user's logon session.
    .PARAMETER PurgeCache
        If specified, this switch will run 'klist purge' to clear all Kerberos tickets BEFORE
        running the test. Use with caution.
    .INPUTS
        System.Management.Automation.PSCredential
    .OUTPUTS
        PSCustomObject
    .EXAMPLE
        Test-TgsAndSpnValidation -DomainController "dc01.contoso.com"
    .NOTES
        Requires the Microsoft ActiveDirectory PowerShell module to be available for the ticket trigger.
        WARNING: Using the -PurgeCache switch is a destructive action that will affect the current user session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter()]
        [switch]$PurgeCache
    )

    $result = [PSCustomObject]@{
        Success           = $false
        SpnChecked        = "ldap/$DomainController" # Note: LSA returns lower-case SPNs
        TicketRequested   = $false
        TicketFound       = $false
        EncryptionType    = 'Not Found'
        ErrorMessage      = ''
    }

    if ($PSBoundParameters.ContainsKey('Credential')) {
        $result.ErrorMessage = 'Test skipped: This function inspects the current logon session ticket cache only.'
        return $result
    }

    if ($PurgeCache.IsPresent) {
        Write-Verbose "Purging Kerberos ticket cache as requested by -PurgeCache switch."
        try {
            klist.exe purge | Out-Null
        } catch { Write-Warning "An error occurred while trying to purge the ticket cache: $($_.Exception.Message)" }
    }

    # Step 1: Trigger a service ticket request.
    try {
        Write-Verbose "Triggering new service ticket request for $($result.SpnChecked)"
        Get-ADRootDSE -Server $DomainController -ErrorAction Stop | Out-Null
        $result.TicketRequested = $true
    }
    catch {
        $result.ErrorMessage = "Failed to trigger a service ticket request (Get-ADRootDSE). Error: $($_.Exception.Message)"
        return $result
    }

    # Step 2: Query the cache using the robust API wrapper.
    try {
        $cachedTickets = Get-KerberosTicket -ErrorAction Stop

        # All parsing is replaced by this simple, reliable Where-Object clause.
        $theTicket = $cachedTickets | Where-Object { $_.Server -match $result.SpnChecked }
        
        if ($theTicket) {
            $result.Success = $true
            $result.TicketFound = $true
            $result.EncryptionType = $theTicket.KerbTicket_Encryption_Type
            $result.ErrorMessage = "Successfully found service ticket in cache via LSA API."
        }
        else {
            $result.ErrorMessage = "A ticket for '$($result.SpnChecked)' was not found in the cache after a successful request."
        }
    }
    catch {
        $result.ErrorMessage = "An error occurred while querying the LSA ticket cache: $($_.Exception.Message)"
    }

    return $result
}

function Test-KerberosPacValidation {
    <#
    .SYNOPSIS
        Performs a direct, low-level functional test of Kerberos PAC validation by accessing a network share via the Win32 API.
    .DESCRIPTION
        This function tests the usability of the Privilege Attribute Certificate (PAC) by using P/Invoke to call the native
        CreateFileW Windows API. This bypasses higher-level PowerShell providers to get faster and more specific error codes.
        It attempts to open a known directory (like SYSVOL). The function returns detailed diagnostics about the PAC validation.
    .PARAMETER DomainController
        The domain controller to target for the test. The test will attempt to access its SYSVOL share.
    .PARAMETER PurgeCache
        Optional. If specified, runs 'klist purge' before the test to ensure a fresh ticket is requested.
    .PARAMETER TestPath
        Optional. Custom UNC path to test. Defaults to \\DomainController\SYSVOL.
    .PARAMETER IncludeTicketInfo
        Optional. If specified, includes current Kerberos ticket information in the output.
    .OUTPUTS
        PSCustomObject indicating the success or failure of the PAC validation test, including detailed diagnostics.
    .EXAMPLE
        Test-KerberosPacValidation -DomainController "dc01.contoso.com"
    .EXAMPLE
        Test-KerberosPacValidation -DomainController "dc01.contoso.com" -PurgeCache -IncludeTicketInfo
    .EXAMPLE
        Test-KerberosPacValidation -DomainController "dc01.contoso.com" -TestPath "\\dc01.contoso.com\netlogon"
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController,

        [Parameter()]
        [switch]$PurgeCache,

        [Parameter()]
        [string]$TestPath,

        [Parameter()]
        [switch]$IncludeTicketInfo
    )

    # Enhanced C# signatures for Win32 API calls with better error handling
    $signature = @"
    using System;
    using System.Runtime.InteropServices;
    using System.ComponentModel;
    
    public class Kernel32 {
        public const uint GENERIC_READ = 0x80000000;
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr CreateFileW(
            [MarshalAs(UnmanagedType.LPWStr)] string filename,
            uint access,
            uint share,
            IntPtr securityAttributes,
            uint creationDisposition,
            uint flagsAndAttributes,
            IntPtr templateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();
    }

    public class Advapi32 {
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool LogonUser(
            string username,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token
        );
    }
"@

    # Only add the type if it hasn't been added already
    if (-not ([System.Management.Automation.PSTypeName]'Kernel32').Type) {
        Add-Type -TypeDefinition $signature -Language CSharp -ErrorAction Stop
    }

    # Initialize result object with more comprehensive information
    $result = [PSCustomObject]@{
        PSTypeName          = 'Kerberos.PacValidationResult'
        Success             = $false
        Action              = $null
        TestPath            = $null
        SpnRequested        = $null
        Win32ErrorCode      = $null
        ErrorCategory       = $null
        Message             = ''
        DetailedDiagnostics = ''
        TicketInfo          = $null
        Timestamp           = Get-Date
        ComputerName        = $env:COMPUTERNAME
        UserContext         = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    }

    # Set test path - allow override or default to SYSVOL
     $result.TestPath = if ($PSBoundParameters.ContainsKey('TestPath')) { 
        $TestPath 
    } else { 
        "\\$DomainController\SYSVOL" 
    }    

    $result.Action = "Win32 API call to open '$($result.TestPath)'"
    
    # Extract service from path for SPN determination
    $targetServer = ($result.TestPath -replace '^\\\\([^\\]+).*$', '$1')
    $result.SpnRequested = "cifs/$targetServer"

    # Purge cache if requested
    if ($PurgeCache.IsPresent) {
        Write-Verbose "Purging Kerberos ticket cache to force fresh authentication..."
        try { 
            $purgeResult = & klist.exe purge 2>&1
            Write-Verbose "Cache purge result: $purgeResult"
        }
        catch { 
            Write-Warning "Failed to purge ticket cache: $($_.Exception.Message)"
        }
    }

    # Capture pre-test ticket information if requested
    if ($IncludeTicketInfo.IsPresent) {
        try {
            $ticketOutput = Get-KerberosTicket
            $result.TicketInfo = @{
                PreTest = $ticketOutput
                PostTest = $null
            }
        }
        catch {
            Write-Verbose "Could not capture ticket information: $($_.Exception.Message)"
        }
    }

    $handle = [IntPtr]::Zero
    try {
        Write-Verbose "Attempting low-level CreateFileW API call to '$TestPath'..."
        Write-Verbose "This will trigger Kerberos authentication and PAC validation if successful."
        
        # Perform the actual API call
        $handle = [Kernel32]::CreateFileW(
            $result.TestPath,
            [Kernel32]::GENERIC_READ,
            [Kernel32]::FILE_SHARE_READ,
            [IntPtr]::Zero,
            [Kernel32]::OPEN_EXISTING,
            [Kernel32]::FILE_FLAG_BACKUP_SEMANTICS,
            [IntPtr]::Zero
        )
        
        if ($handle -eq [Kernel32]::INVALID_HANDLE_VALUE) {
            # Get the specific error code
            $errorCode = [Kernel32]::GetLastError()
            $result.Win32ErrorCode = $errorCode
            $result.Success = $false
            
            # Get standard error message
            $win32Exception = New-Object System.ComponentModel.Win32Exception($errorCode)
            $baseErrorMessage = $win32Exception.Message

            # Enhanced error categorization and diagnostics
            $errorAnalysis = Get-KerberosErrorAnalysis -ErrorCode $errorCode -TestPath $TestPath
            $result.ErrorCategory = $errorAnalysis.Category
            $result.Message = "$baseErrorMessage (Win32 Error: $errorCode)"
            $result.DetailedDiagnostics = $errorAnalysis.Diagnostics
            
            Write-Verbose "CreateFileW failed with error code: $errorCode"
            Write-Verbose "Error category: $($errorAnalysis.Category)"
        }
        else {
            $result.Success = $true
            $result.ErrorCategory = 'Success'
            $result.Message = "Successfully accessed the share. Kerberos authentication and PAC validation completed successfully."
            $result.DetailedDiagnostics = "The server accepted the Kerberos ticket and validated the PAC without issues. The user has appropriate permissions to access the requested resource."
            
            Write-Verbose "CreateFileW succeeded - PAC validation appears successful"
        }
    }
    catch {
        $result.Success = $false
        $result.ErrorCategory = 'Exception'
        $result.Message = "PowerShell exception during API call: $($_.Exception.Message)"
        $result.DetailedDiagnostics = "An unexpected error occurred during the P/Invoke operation. This may indicate a problem with the API call setup or system state."
        Write-Error "Exception in Test-KerberosPacValidation: $($_.Exception.Message)"
    }
    finally {
        # Always clean up the handle
        if ($handle -ne [IntPtr]::Zero -and $handle -ne [Kernel32]::INVALID_HANDLE_VALUE) {
            $closeResult = [Kernel32]::CloseHandle($handle)
            if (-not $closeResult) {
                Write-Warning "Failed to close file handle properly"
            }
        }
    }

    # Capture post-test ticket information if requested
    if ($IncludeTicketInfo.IsPresent -and $result.TicketInfo) {
        try {
            $postTicketOutput = Get-KerberosTicket
            $result.TicketInfo.PostTest = $postTicketOutput
        }
        catch {
            Write-Verbose "Could not capture post-test ticket information: $($_.Exception.Message)"
        }
    }

    return $result
}

function Test-KerberosCipherSuite {
    <#
    .SYNOPSIS
        Tests which Kerberos encryption ciphers are supported by a Domain Controller and the local client.
    .DESCRIPTION
        This function determines the intersection of supported Kerberos encryption types between the local
        machine (client) and the remote KDC (server). It queries the server by sending an AS-REQ for
        each known cipher and checks the client's configuration in the registry.
    .PARAMETER DomainController
        The FQDN of the Domain Controller (KDC) to test.
    .OUTPUTS
        PSCustomObject with detailed results about client, server, and common supported ciphers.
    .EXAMPLE
        Test-KerberosCipherSuite -DomainController "dc01.contoso.com"
    .NOTES
        This test is crucial for diagnosing "unsupported etype" errors. It depends on the
        Get-EncryptionTypeMap and Invoke-KerberosAsRequest functions.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainController
    )

    # Use the centralized helper function to get the definitive cipher map.
    $cipherMap = Get-EncryptionTypeMap

    # ---- 1. Test Server Supported Ciphers ----
    Write-Verbose "Querying server '$DomainController' for supported ciphers..."
    $serverSupported = [System.Collections.ArrayList]::new()
    
    # Iterate through the string names of the ciphers.
    foreach ($cipherName in $cipherMap.Values) {
        # Skip experimental or deprecated types we don't want to actively test.
        if ($cipherName -like '*-EXP') { continue }

        Write-Verbose "  - Testing for $cipherName..."
        
        # Call Invoke-KerberosAsRequest with the new string-based parameter.
        $result = Invoke-KerberosAsRequest -Server $DomainController -RequestedEncryptionTypes @($cipherName)
        
        # 'Operational' is true if we get PREAUTH_REQUIRED, which means the KDC understood the etype.
        # An explicit 'ETYPE_NOSUPP' error (14) is a definitive failure.
        if ($result.Operational -and $result.ErrorCode -ne 14) {
            [void]$serverSupported.Add($cipherName)
            Write-Verbose "    ...Supported."
        }
        else {
            Write-Verbose "    ...Not supported (Error: $($result.ErrorDescription))."
        }
    }

    # ---- 2. Test Client Supported Ciphers ----
    Write-Verbose "Querying local client for supported ciphers via registry..."
    $clientSupported = [System.Collections.ArrayList]::new()
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
    $regValue = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

    if ($regValue) {
        $supportedBitmap = $regValue.SupportedEncryptionTypes
        # Note: These bit flags correspond to the legacy mechanism for enabling/disabling etypes.
        if (($supportedBitmap -band 0x1) -and $cipherMap.ContainsValue('DES-CBC-CRC')) { [void]$clientSupported.Add('DES-CBC-CRC') }
        if (($supportedBitmap -band 0x2) -and $cipherMap.ContainsValue('DES-CBC-MD5')) { [void]$clientSupported.Add('DES-CBC-MD5') }
        if (($supportedBitmap -band 0x4) -and $cipherMap.ContainsValue('RC4-HMAC')) { [void]$clientSupported.Add('RC4-HMAC') }
        if (($supportedBitmap -band 0x8) -and $cipherMap.ContainsValue('AES128-CTS-HMAC-SHA1-96')) { [void]$clientSupported.Add('AES128-CTS-HMAC-SHA1-96') }
        if (($supportedBitmap -band 0x10) -and $cipherMap.ContainsValue('AES256-CTS-HMAC-SHA1-96')) { [void]$clientSupported.Add('AES256-CTS-HMAC-SHA1-96') }
        # Note: Newer SHA-2 types are generally enabled by default on modern OSes if not explicitly disabled.
        # This check is a simplification for this function.
    }
    else {
        # If the registry value is not set, Windows uses secure defaults.
        Write-Verbose "Registry value 'SupportedEncryptionTypes' not found. Client is using OS defaults."
        [void]$clientSupported.Add('RC4-HMAC')
        [void]$clientSupported.Add('AES128-CTS-HMAC-SHA1-96')
        [void]$clientSupported.Add('AES256-CTS-HMAC-SHA1-96')
        [void]$clientSupported.Add('AES128-CTS-HMAC-SHA256-128')
        [void]$clientSupported.Add('AES256-CTS-HMAC-SHA384-192')
    }

    # ---- 3. Analyze and Return Results ----
    $commonCiphers = $serverSupported | Where-Object { $clientSupported.Contains($_) }
    $isSecureOverlap = $commonCiphers | Where-Object { $_ -like 'AES*' }

    return [PSCustomObject]@{
        PSTypeName              = 'Kerberos.CipherSuiteResult'
        Success                 = [bool]$isSecureOverlap
        Message                 = if ([bool]$isSecureOverlap) { "Success: Client and Server share a secure (AES) cipher." } else { "Failure: No common AES cipher found." }
        ClientSupportedCiphers  = $clientSupported.ToArray() | Sort-Object
        ServerSupportedCiphers  = $serverSupported.ToArray() | Sort-Object
        CommonCiphers           = $commonCiphers | Sort-Object
        RecommendedAction       = if (-not [bool]$isSecureOverlap) { "Ensure both client and server have a common AES cipher suite enabled for Kerberos." } else { "None" }
    }
}


#-----------------------------------------------------------------------
# SECTION 3: Main Orchestrator Function
#-----------------------------------------------------------------------
function Test-AdvancedKerberos {
	<#
	.SYNOPSIS
		Performs a comprehensive, multi-stage Kerberos diagnostic test.
	.DESCRIPTION
		Acts as an orchestrator to run a series of Kerberos-related tests in a logical order.
		It begins with pre-flight checks for prerequisites like DNS, network connectivity, and time sync.
		If pre-flight checks pass, it proceeds to run deep authentication and ticket validation tests.
		It provides a rich, color-coded summary to the console for interactive use, and also returns
		a single, comprehensive object containing all raw test results for programmatic use.
	.PARAMETER DomainController
		The FQDN of the Domain Controller to target for the tests.
	.PARAMETER Credential
		Optional PSCredential for running tests with alternate credentials.
		Note: Some tests like ticket cache validation will be skipped when using alternate credentials.
	.PARAMETER PurgeTicketCache
		Optional switch to run 'klist purge' before TGS/SPN validation tests. Use with caution.
    .NOTES
		Name: Test-AdvancedKerberos
		Author: Ryan Whitlock
		Date: 06.06.2025
		Version: 1.0
	#>

	[CmdletBinding(DefaultParameterSetName = 'CurrentUser')]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$DomainController,

		[Parameter(ParameterSetName = 'AlternateCredential')]
		[System.Management.Automation.PSCredential]$Credential,

		[Parameter()]
		[switch]$PurgeTicketCache
	)

	# This internal helper standardizes the rich console output.
	function Write-TestStepResult {
		param(
			[string]$TestName,
			[PSCustomObject]$ResultObject,
			[string]$SuccessProperty = 'Success',
			[string]$Details,
			[string]$StatusOverride
		)

		$status = 'FAIL'
		$color = 'Red'
		$symbol = '✗'
		$message = $ResultObject.ErrorMessage

		if ($ResultObject.$SuccessProperty) {
			$status = 'PASS'
			$color = 'Green'
			$symbol = '✓'
			$message = $ResultObject.Message
		}

		if ($PSBoundParameters.ContainsKey('StatusOverride')) {
			$status = $StatusOverride
			switch ($status) {
				'WARN' { $color = 'Yellow'; $symbol = '⚠' }
				'INFO' { $color = 'Cyan'; $symbol = 'ℹ' }
			}
		}

		Write-Host (" " * 2) -NoNewline
		Write-Host "[$symbol] " -ForegroundColor $color -NoNewline
		Write-Host $TestName

		$detailsToDisplay = if ($PSBoundParameters.ContainsKey('Details')) { $Details } else { $message }
		if ($detailsToDisplay) {
			Write-Host (" " * 6) -NoNewline
			Write-Host $detailsToDisplay -ForegroundColor Gray
		}
	}

	# ---- MAIN ORCHESTRATOR LOGIC ----
	$AllResults = [ordered]@{
		'TestParameters' = @{
			DomainController = $DomainController
			UsingAlternateCredential = $PSBoundParameters.ContainsKey('Credential')
			TestStartTime = Get-Date
		}
	}
	$criticalError = $false

	Write-Host "`n=== Comprehensive Kerberos Test for '$DomainController' ===" -ForegroundColor Cyan
	Write-Host "`n--- Performing Pre-Flight Checks ---" -ForegroundColor Yellow

	# 1. Session Check
	$sessionResult = Test-KerberosSession
	$AllResults.'KerberosSession' = $sessionResult
	Write-TestStepResult -TestName "Client session supports Kerberos" -ResultObject $sessionResult -Details $sessionResult.Message
	if (-not $sessionResult.Success) { $criticalError = $true }

	# 2. DNS Resolution
	$dnsResult = Test-DnsResolution -DomainController $DomainController
	$AllResults.'DnsResolution' = $dnsResult
	$dnsDetails = if ($dnsResult.Success) { "Resolved IPs: $($dnsResult.ResolvedIPs -join ', ')" } else { $dnsResult.ErrorMessage }
	Write-TestStepResult -TestName "DNS resolution for '$DomainController'" -ResultObject $dnsResult -Details $dnsDetails
	if (-not $dnsResult.Success) { $criticalError = $true }


	# 3. TCP Connectivity
	$tcpResult = $null
	if (-not $criticalError) {
		$tcpResult = Test-TcpConnectivity -DomainController $DomainController -Ports @(88, 389, 636)
		$AllResults.'TcpConnectivity' = $tcpResult
		if (-not $tcpResult.TcpPort88.Success -or -not $tcpResult.TcpPort389.Success) { $criticalError = $true }
		Write-TestStepResult -TestName "TCP Port 88 (Kerberos)" -ResultObject $tcpResult.TcpPort88
		Write-TestStepResult -TestName "TCP Port 389 (LDAP)" -ResultObject $tcpResult.TcpPort389
		$ldapsStatus = if ($tcpResult.TcpPort636.Success) { 'PASS' } else { 'WARN' }
		Write-TestStepResult -TestName "TCP Port 636 (LDAPS)" -ResultObject $tcpResult.TcpPort636 -StatusOverride $ldapsStatus -Details "Note: LDAPS is recommended but not required for Kerberos."
	}
	else { Write-Host "  - Skipping TCP Connectivity tests due to previous critical error." -ForegroundColor DarkGray }

	# 4. Time Synchronization
	$timeResult = $null
	if (-not $criticalError) {
		$timeResult = Test-TimeSynchronization -DomainController $DomainController
		$AllResults.'TimeSynchronization' = $timeResult
		$timeDetails = if ($timeResult.Success) { "Actual skew: $($timeResult.TimeSkewSeconds.ToString('F3')) seconds" } else { $timeResult.ErrorMessage }
		Write-TestStepResult -TestName "Time skew is within 5 minutes" -ResultObject $timeResult -SuccessProperty 'IsSkewAcceptable' -Details $timeDetails
		if (-not $timeResult.IsSkewAcceptable) { $criticalError = $true }
	}
	else { Write-Host "  - Skipping Time Synchronization test due to previous critical error." -ForegroundColor DarkGray }


	if ($criticalError) {
		Write-Error "Cannot proceed with authentication tests. Please resolve critical pre-flight errors."
		$AllResults.OverallStatus = 'FAIL (Pre-Flight)'
		return [PSCustomObject]$AllResults
	}
    
	# 5. Fallback Authentication Audit
	Write-Host "`n--- Performing Fallback Authentication Audit ---" -ForegroundColor Yellow
	$altAuthParams = @{ DomainController = $DomainController }
	if ($PSBoundParameters.ContainsKey('Credential')) { $altAuthParams.Credential = $Credential }
	$altAuthResult = Test-AlternativeAuthentication @altAuthParams
	$AllResults.'AlternativeAuth' = $altAuthResult
	
	# Create temporary result objects to pass to the formatter, determining PASS/WARN status
	$anonResultObj = [pscustomobject]@{ Success = ($altAuthResult.AnonymousBindResult -ne 'Enabled (Insecure)'); ErrorMessage = $altAuthResult.AnonymousBindResult }
	Write-TestStepResult -TestName "Anonymous LDAP bind is disabled" -ResultObject $anonResultObj -StatusOverride $(if ($anonResultObj.Success) {'PASS'} else {'WARN'}) -Details "Details: $($altAuthResult.AnonymousBindResult)"
	
	$ntlmResultObj = [pscustomobject]@{ Success = ($altAuthResult.NtlmBindResult -eq 'Success'); ErrorMessage = $altAuthResult.NtlmBindResult }
	Write-TestStepResult -TestName "NTLM authentication" -ResultObject $ntlmResultObj -StatusOverride $( if ($ntlmResultObj.Success) {'PASS'} else {'WARN'}) -Details "Details: $($altAuthResult.NtlmBindResult) (Note: NTLM working is a good fallback, but Kerberos is preferred)"
	
	$basicResultObj = [pscustomobject]@{ Success = ($altAuthResult.BasicBindResult -ne 'Enabled (Insecure)'); ErrorMessage = $altAuthResult.BasicBindResult }
	Write-TestStepResult -TestName "Basic LDAP bind is disabled/skipped" -ResultObject $basicResultObj -StatusOverride $(if ($basicResultObj.Success) {'PASS'} else {'WARN'}) -Details "Details: $($altAuthResult.BasicBindResult)"

	Write-Host "`n--- Performing Deep Authentication Tests ---" -ForegroundColor Yellow

	# 6. Low-Level KDC Check
	$asReqResult = Invoke-KerberosAsRequest -Server $DomainController
	$AllResults.'RawAsRequest' = $asReqResult
	$asReqDetails = $asReqResult.ErrorDescription
	if ($asReqResult.ErrorCode -eq 25) {
		$asReqDetails += " - Note: This is an expected and healthy response for this test."
	}
	Write-TestStepResult -TestName "Low-level KDC check (UDP 88)" -ResultObject $asReqResult -SuccessProperty 'Operational' -Details $asReqDetails

	# 7. High-Level Kerberos Bind (TGT/TGS)
	$tgtResults = Test-TgtRequest @altAuthParams
	$AllResults.'KerberosLdapBind' = $tgtResults
	Write-Host "  • Kerberos LDAP bind security configurations:"
	foreach ($res in $tgtResults) {
		Write-TestStepResult -TestName "    - $($res.Configuration)" -ResultObject $res -Details $res.ErrorMessage
	}

	# 8. SPN Ticket Validation in Cache
	$tgsParams = @{ DomainController = $DomainController }
	if ($PurgeTicketCache) { $tgsParams.PurgeCache = $true }
	$tgsResult = Test-TgsAndSpnValidation @tgsParams
	$AllResults.'SpnTicketValidation' = $tgsResult
	$tgsDetails = "Ticket Found: $($tgsResult.TicketFound), Encryption: $($tgsResult.EncryptionType)"
	Write-TestStepResult -TestName "SPN ticket validation in cache" -ResultObject $tgsResult -Details $tgsDetails

    # 9. Cipher Suite Compatibility
	$cipherResult = Test-KerberosCipherSuite -DomainController $DomainController; $AllResults.'CipherSuite' = $cipherResult
	$cipherDetails = "Common Ciphers: $($cipherResult.CommonCiphers -join ', ')"
	Write-TestStepResult -TestName "Client and KDC share a secure cipher" -ResultObject $cipherResult -Details $cipherDetails
    
    # 10. PAC Validation
	$pacParams = @{ DomainController = $DomainController; IncludeTicketInfo = $true}
	if ($PurgeTicketCache) { $pacParams.PurgeCache = $true }
	$pacResult = Test-KerberosPacValidation @pacParams 
	$AllResults.'PacValidation' = $pacResult
	Write-TestStepResult -TestName "PAC validation via file share access" -ResultObject $pacResult -Details $pacResult.Message

	# --- NEW: Final Summary Section ---
	Write-Host "`n`n=== TEST SUMMARY ===" -ForegroundColor Cyan
	
	# Aggregate results for summary counts
	$summaryCounters = @{ Pass = 0; Fail = 0; Warn = 0 }
	$failedTestDetails = [System.Collections.ArrayList]::new()

	if ($sessionResult.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("Kerberos Session Support") }
	if ($dnsResult.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("DNS Resolution") }
	if ($tcpResult.TcpPort88.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("TCP Port 88") }
	if ($tcpResult.TcpPort389.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("TCP Port 389") }
	if ($tcpResult.TcpPort636.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Warn++ }
	if ($timeResult.IsSkewAcceptable) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("Time Synchronization") }
	if ($asReqResult.Operational) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("Low-level KDC Check") }
	if ($altAuthResult.AnonymousBindResult -ne 'Enabled (Insecure)') { $summaryCounters.Pass++ } else { $summaryCounters.Warn++ }
	if ($altAuthResult.BasicBindResult -ne 'Enabled (Insecure)') { $summaryCounters.Pass++ } else { $summaryCounters.Warn++ }
	if ($altAuthResult.NtlmBindResult -eq 'Success') { $summaryCounters.Pass++ } else { $summaryCounters.Warn++ }
	foreach ($res in $tgtResults) { if ($res.Success) { $summaryCounters.Pass++ } else { $summaryCounters.Fail++; [void]$failedTestDetails.Add("Kerberos LDAP Bind: $($res.Configuration)") } }
	if ($tgsResult.Success) { $summaryCounters.Pass++ } else { if($tgsResult.ErrorMessage -notmatch 'skipped'){ $summaryCounters.Fail++; [void]$failedTestDetails.Add("SPN Ticket Validation") } }
    if ($pacResult.Success) { $summaryCounters.Pass++ } else { if($pacResult.Message -notmatch 'skipped'){ $summaryCounters.Fail++; [void]$failedTestDetails.Add("PAC Validation") } }

	# Display counts
	Write-Host (" " * 2 + "Tests Passed:   " + $summaryCounters.Pass) -ForegroundColor Green
	Write-Host (" " * 2 + "Tests w/Warning:" + $summaryCounters.Warn) -ForegroundColor Yellow
	Write-Host (" " * 2 + "Tests Failed:   " + $summaryCounters.Fail) -ForegroundColor Red
	
	# Determine and display overall status
	$overallStatus = 'SUCCESS'
	$overallColor = 'Green'
	if ($summaryCounters.Fail -gt 0) {
		$overallStatus = 'FAILURE'
		$overallColor = 'Red'
	}
	elseif ($summaryCounters.Warn -gt 0) {
		$overallStatus = 'SUCCESS WITH WARNINGS'
		$overallColor = 'Yellow'
	}
	Write-Host "`nOverall Status: " -NoNewline
	Write-Host $overallStatus -ForegroundColor $overallColor

	# List critical issues and recommendations
	if ($failedTestDetails.Count -gt 0) {
		Write-Host "`nCRITICAL ISSUES:" -ForegroundColor Red
		$failedTestDetails | ForEach-Object { Write-Host ("  - $_") }
	}

	$recommendations = [System.Collections.ArrayList]::new()
	if ($altAuthResult.AnonymousBindResult -match 'Enabled') { [void]$recommendations.Add("Anonymous LDAP binding is enabled. For better security, this should be disabled on domain controllers.") }
	if ($altAuthResult.BasicBindResult -match 'Enabled') { [void]$recommendations.Add("Basic LDAP authentication is enabled. This sends credentials in a weakly protected format and should be disabled.") }
	if ($summaryCounters.Warn -gt 0) { [void]$recommendations.Add("Review items with a [WARN] status for potential security or configuration improvements.") }
	if ($recommendations.Count -gt 0) {
		Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Yellow
		$recommendations | ForEach-Object { Write-Host ("  - $_") }
	}

	$AllResults.Summary = @{
		OverallStatus = $overallStatus
		PassedCount = $summaryCounters.Pass
		WarningCount = $summaryCounters.Warn
		FailedCount = $summaryCounters.Fail
		FailedTests = $failedTestDetails
		Recommendations = $recommendations
	}
	
	return [PSCustomObject]$AllResults
}
