function Get-IPCalc {
    <#
    .SYNOPSIS
        Calculates network information based on a given CIDR notation or IP address and subnet mask.

    .DESCRIPTION
        The Get-IPCalc function allows you to calculate network details like the network address, broadcast address, 
        usable hosts, and subnet mask based on either a CIDR notation or an IP address and subnet mask combination.

        The function returns a custom object with all the relevant network information, such as:
            - IP address
            - Network length (CIDR bits)
            - Subnet mask
            - Network address
            - First usable host address
            - Last usable host address
            - Broadcast address
            - Number of usable hosts
            - Total number of hosts

        This function supports both IPv4 CIDR notation (e.g., '192.168.1.0/24') and a combination of IP address and subnet mask.

    .PARAMETER CIDR
        A string representing an IPv4 address with CIDR notation (e.g., '192.168.1.0/24').
        This parameter is used to calculate the network information based on the provided CIDR.

    .PARAMETER IPAddress
        A string representing an IPv4 address (e.g., '192.168.1.0'). 
        This parameter is used along with the SubnetMask parameter to calculate network information.

    .PARAMETER SubnetMask
        A string representing the subnet mask (e.g., '255.255.255.0') that corresponds to the IPAddress.
        This parameter is used along with the IPAddress parameter to calculate network information.

    .EXAMPLE
        Get-IPCalc -CIDR '192.168.1.0/24'

        This command calculates and returns network information for the IP address 192.168.1.0 with a /24 prefix length.

    .EXAMPLE
        Get-IPCalc -IPAddress '192.168.1.0' -SubnetMask '255.255.255.0'

        This command calculates and returns network information for the IP address 192.168.1.0 with the subnet mask 255.255.255.0.

    .NOTES  
        Name: Get-IPCalc
        Author: Ryan Whitlock
        Date: 07.10.2020
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding(DefaultParameterSetName='CIDR')]
    [OutputType([PSCustomObject])]
    param (
        # CIDR range parameter set.
        [Parameter(Mandatory, Position=1, ParameterSetName='CIDR')]
        [ValidateScript({
            # Split the input into IP address and prefix length
            if ($_ -match '^(\d{1,3}(\.\d{1,3}){3})/(\d{1,2})$') {
                $IPAddress = $matches[1]
                $CIDRBits = [int]$matches[3]

                # Validate that the IP address is a valid IPv4 address
                if (-not [System.Net.IPAddress]::TryParse($IPAddress, [ref]$null)) {
                    Throw "$IPAddress does not appear to be a valid IPv4 address"
                }

                # Validate that the prefix length is between 0 and 32
                if ($CIDRBits -lt 0 -or $CIDRBits -gt 32) {
                    Throw "$CIDRBits is not a valid CIDR prefix length. It should be between 0 and 32."
                }

                $true
            }
            else {
                Throw "$($_) does not appear to be in valid CIDR notation (e.g., 192.168.1.0/24)"
            }
        })]
        [ValidateNotNullOrEmpty()]
        [string]$CIDR,

        # Subnet address parameter set.
        [Parameter(Mandatory, Position=1, ParameterSetName='Subnet')]
        [ValidateScript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [ValidateNotNullOrEmpty()]
        [string]$IPAddress,

        # Subnet mask parameter set.
        [Parameter(Mandatory, Position=2, ParameterSetName='Subnet')]
        [ValidateScript({
            ([System.Net.IPAddress]$_).AddressFamily -eq 'InterNetwork'
        })]
        [ValidateNotNullOrEmpty()]
        [string]$SubnetMask
    )

    begin {
        function Convert-SubnetMaskToCIDR {
            param (
                [string]$SubnetMask
            )
            $binaryOctets = ([System.Net.IPAddress]::Parse($SubnetMask)).GetAddressBytes() | 
                            ForEach-Object { [Convert]::ToString($_, 2).PadLeft(8, '0') }
            return ($binaryOctets -join "").TrimEnd("0").Length
        }

        function Convert-CIDRToSubnetMask {
            param (
                [int]$CIDRBits
            )
            $mask = [math]::pow(2, 32) - [math]::pow(2, 32 - $CIDRBits)
            return [System.Net.IPAddress]::new($mask).ToString()
        }

        function Get-NetworkAddress {
            param (
                [string]$IPAddress,
                [string]$SubnetMask
            )
            $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $maskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes()

            $networkBytes = for ($i = 0; $i -lt $ipBytes.Length; $i++) {
                $ipBytes[$i] -band $maskBytes[$i]
            }
            return [System.Net.IPAddress]::new($networkBytes)
        }

        function Get-BroadcastAddress {
            param (
                [string]$IPAddress,
                [string]$SubnetMask
            )
            $ipBytes = [System.Net.IPAddress]::Parse($IPAddress).GetAddressBytes()
            $maskBytes = [System.Net.IPAddress]::Parse($SubnetMask).GetAddressBytes()

            $broadcastBytes = for ($i = 0; $i -lt $ipBytes.Length; $i++) {
                $ipBytes[$i] -bor ($maskBytes[$i] -bxor 255)
            }
            return [System.Net.IPAddress]::new($broadcastBytes)
        }

        function Get-TotalHosts {
            param (
                [int]$CIDRBits
            )
            return [math]::pow(2, (32 - $CIDRBits))
        }

        switch ($PSCmdlet.ParameterSetName) {
            'CIDR' {
                # Split range into the address and the CIDR notation
                [string]$CIDRAddress, [int]$CIDRBits = $CIDR -split '/'
                $SubnetMask = Convert-CIDRToSubnetMask -CIDRBits $CIDRBits
            }
            'Subnet' {
                [string]$CIDRAddress = $IPAddress
                [int]$CIDRBits       = Convert-SubnetMaskToCIDR -SubnetMask $SubnetMask
            }
        }

        $NetworkAddress = Get-NetworkAddress -IPAddress $CIDRAddress -SubnetMask $SubnetMask
        $BroadcastAddress = Get-BroadcastAddress -IPAddress $CIDRAddress -SubnetMask $SubnetMask
        $TotalHosts = Get-TotalHosts -CIDRBits $CIDRBits
        $UsableHosts = $TotalHosts - 2

        # Calculate HostMin and HostMax
        $hostMinBytes = $NetworkAddress.GetAddressBytes()
        $hostMinBytes[3] = $hostMinBytes[3] + 1
        $HostMin = [System.Net.IPAddress]::new($hostMinBytes)

        $hostMaxBytes = $BroadcastAddress.GetAddressBytes()
        $hostMaxBytes[3] = $hostMaxBytes[3] - 1
        $HostMax = [System.Net.IPAddress]::new($hostMaxBytes)
    }

    process {
        $Object = [pscustomobject][ordered]@{
            PSTypeName      = 'Network.IPCalcResult'
            IP              = $CIDRAddress
            NetworkLength   = $CIDRBits
            SubnetMask      = $SubnetMask
            NetworkAddress  = $NetworkAddress.ToString()
            HostMin         = $HostMin.ToString()
            HostMax         = $HostMax.ToString()
            Broadcast       = $BroadcastAddress.ToString()
            UsableHosts     = $UsableHosts
            TotalHosts      = $TotalHosts
        }

        Write-Output $Object
    }
}
