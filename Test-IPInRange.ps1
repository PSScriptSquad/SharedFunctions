function Test-IPInRange {
    <#
    .SYNOPSIS
        Checks if an IP address falls within a specified range in CIDR notation.
    .DESCRIPTION
        This function determines if a given IP address is within a specified range represented in CIDR (Classless Inter-Domain Routing) notation.
        It takes an IP address and a range (in CIDR notation) as input parameters and returns $true if the IP address is within the range, otherwise $false.
    .PARAMETER IPAddress
        IP Address to be checked.
    .PARAMETER Range
        Range in which to search using CIDR notation (e.g., 192.168.1.0/24).
    .EXAMPLE
        IPInRange -IPAddress '192.168.1.5' -Range '192.168.1.0/24'
        This command checks if the IP address 192.168.1.5 is within the range 192.168.1.0/24.
    .NOTES
        Name: Test-IPInRange 
        Author: Ryan Whitlock
        Date: 07.22.2021
        Version: 1.0
        Changes: Added comments, improved clarity and readability.
    #>
    [cmdletbinding()]
    [outputtype([System.Boolean])]
    param(
        # IP Address to find.
        [parameter(Mandatory,ValueFromPipeline,
                   Position=0)]
        [validatescript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [string]
        $IPAddress,
        # Range in which to search using CIDR notation. (ippaddr/bits)
        [parameter(Mandatory,
                   Position=1)]
        [validatescript({
            $IP   = ($_ -split '/')[0]
            $Bits = ($_ -split '/')[1]
            (([System.Net.IPAddress]($IP)).AddressFamily -eq 'InterNetwork')
            if (-not($Bits)) {
                throw 'Missing CIDR notiation.'
            } elseif (-not(0..32 -contains [int]$Bits)) {
                throw 'Invalid CIDR notation. The valid bit range is 0 to 32.'
            }
        })]
        [alias('CIDR')]
        [string]
        $Range
    )

    # Split range into the address and the CIDR notation
    [String]$CIDRAddress = $Range.Split('/')[0]
    [int]$CIDRBits       = $Range.Split('/')[1]

    # Address from range and the search address are converted to Int32 and the full mask is calculated from the CIDR notation.
    [int]$BaseAddress    = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($CIDRAddress)).GetAddressBytes()), 0)
    [int]$Address        = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()), 0)
    [int]$Mask           = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl ( 32 - $CIDRBits))

    # Determine whether the address is in the range.
    if (($BaseAddress -band $Mask) -eq ($Address -band $Mask)) {
        $true
    } else {
        $false
    }
}
