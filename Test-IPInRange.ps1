function Test-IPInRange {
    <#
        .SYNOPSIS
            Checks if an IP address falls within a specified range in CIDR notation or subnet mask.
        .DESCRIPTION
            This function determines if a given IP address is within a specified range represented in CIDR (Classless Inter-Domain Routing) notation or subnet mask.
            It takes an IP address and a range (in CIDR notation or subnet mask) as input parameters and returns $true if the IP address is within the range, otherwise $false.
        .PARAMETER IPAddress
            IP Address to be checked.
        .PARAMETER CIDR
            Range in which to search using CIDR notation (e.g., 192.168.1.0/24).
        .PARAMETER SubnetAddress
            The base address of the subnet (e.g., 192.168.1.0).
        .PARAMETER SubnetMask
            Subnet mask for the range (e.g., 255.255.255.0).
        .EXAMPLE
            Test-IPInRange -IPAddress '192.168.1.5' -CIDR '192.168.1.0/24'
            This command checks if the IP address 192.168.1.5 is within the range 192.168.1.0/24.
        .EXAMPLE
            Test-IPInRange -IPAddress '192.168.1.5' -SubnetAddress '192.168.1.0' -SubnetMask '255.255.255.0'
            This command checks if the IP address 192.168.1.5 is within the range 192.168.1.0 with subnet mask 255.255.255.0.
        .NOTES
            Name: Test-IPInRange 
            Author: Ryan Whitlock
            Date: 07.22.2021
            Version: 1.2
            Changes: Added support for subnet mask notation with parameter sets.
    #>
    [cmdletbinding(DefaultParameterSetName='CIDR')]
    [outputtype([System.Boolean])]
    param(
        # IP Address to find.
        [parameter(Mandatory, ValueFromPipeline, Position=0)]
        [validatescript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [string]
        $IPAddress,

        # CIDR range parameter set.
        [parameter(Mandatory, Position=1, ParameterSetName='CIDR')]
        [ValidateScript( {
            if (-not ([System.Net.IPAddress]::TryParse($_, [ref]$null) -and 
                      [System.Net.IPAddress]$_ -is [System.Net.IPAddress] -and 
                      ([System.Net.IPAddress]$_).AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork)) {
                Throw "$($_) does not appear to be a valid IPv4 address"
            }
            $true
        })]
        [string]
        $CIDR,

        # Subnet address parameter set.
        [parameter(Mandatory, Position=1, ParameterSetName='Subnet')]
        [validatescript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [string]
        $SubnetAddress,

        # Subnet mask parameter set.
        [parameter(Mandatory, Position=2, ParameterSetName='Subnet')]
        [validatescript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [string]
        $SubnetMask
    )

    function Convert-SubnetMaskToCIDR {
        param (
            [string]$SubnetMask
        )
        $binaryOctets = ([System.Net.IPAddress]::Parse($SubnetMask)).GetAddressBytes() | 
                      ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }
                                            
        return ($binaryOctets  -join "").TrimEnd("0").Length
    }

    switch ($PSCmdlet.ParameterSetName) {
        'CIDR' {
            # Split range into the address and the CIDR notation
            [String]$CIDRAddress, [int]$CIDRBits = $CIDR -split '/'
        }
        'Subnet' {
            [String]$CIDRAddress = $SubnetAddress
            [int]$CIDRBits       = Convert-SubnetMaskToCIDR -SubnetMask $SubnetMask
        }
    }

    # Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation.
    [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0)
    [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()), 0)
    [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits))

    # Determine whether the address is in the range.
    return (($BaseAddress -band $Mask) -eq ($Address -band $Mask))
}
