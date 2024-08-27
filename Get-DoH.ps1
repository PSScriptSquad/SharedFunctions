function Get-DoH {
    <#
    .SYNOPSIS
        Retrieves DNS over HTTPS (DoH) records for a specified domain.

    .DESCRIPTION
        The Get-DOH function sends a DNS over HTTPS (DoH) request to Google's DNS service and retrieves the DNS records for the specified domain and record type.

    .PARAMETER Domain
        Specifies the domain name for which to retrieve the DNS record. The domain name is validated to ensure it is properly formatted.

    .PARAMETER Type
        Specifies the DNS record type to retrieve (e.g., A, AAAA, CNAME, MX, etc.). Only specific DNS record types are allowed. Default is 'A'.

    .EXAMPLE
        Get-DOH -Domain 'google.com' -Type 'A'

        Retrieves the 'A' DNS records for the domain 'google.com'.

    .EXAMPLE
        Get-DOH -Domain 'example.com' -Type 'MX'

        Retrieves the 'MX' DNS records for the domain 'example.com'.

    .NOTES
        Name: Get-DOH
        Author: Ryan Whitlock
        Date: 08.27.2024
        Version: 1.0
        Changes: Initial release 
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Specify the domain name to query.")]
        [ValidatePattern('^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.?)+(?:[a-zA-Z]{2,})$')]
        [string]$Domain,

        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Specify the DNS record type to query (e.g., A, AAAA, CNAME, MX). Default is 'A'.")]
        [ValidateSet('A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT', 'PTR', 'SRV')]
        [string]$Type = 'A'
    )

    $Url = "https://dns.google.com/resolve?name=$Domain&type=$Type"
    $Response = (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content | ConvertFrom-Json

    Write-Output $Response.Answer
}
