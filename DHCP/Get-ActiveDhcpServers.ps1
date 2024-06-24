function Get-ActiveDhcpServers {
    <#
    .SYNOPSIS
        Retrieves active DHCP servers from the domain.
    .DESCRIPTION
        This function queries all DHCP servers in the domain and checks their status.
        It returns a list of DHCP servers that are responding.
    .EXAMPLE
        PS C:\> Get-ActiveDhcpServers
        This example retrieves and lists all active DHCP servers in the "example.com" domain.
    .NOTES
        Author: Ryan Whitlock
        Date: 2024-06-05
        Version: 1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$DomainName
    )

    # Ensure the DhcpServer module is imported
    Import-Module DhcpServer -ErrorAction Stop

    # Retrieve DHCP servers from the specified domain or default domain
    $DhcpServers = if ($DomainName) {
        Get-DhcpServerInDC -DomainName $DomainName
    } else {
        Get-DhcpServerInDC
    }

    if (!$DhcpServers) {
        Write-Host "[*] Error - No DHCP servers found in the domain $DomainName"
        throw "No DHCP servers found"
    }
 
    # Filter out active DHCP servers
    $activeServers = foreach ($server in $DhcpServers) { 
        try {
            Get-DhcpServerSetting -ComputerName $server.DnsName -ErrorAction SilentlyContinue | Out-Null
            $server
        }
        catch {
            Write-Host "[*] DHCP server $($server.DnsName.ToUpper()) is not responding!"
        }
    }
    # Return the list of active servers
    return $activeServers
}
