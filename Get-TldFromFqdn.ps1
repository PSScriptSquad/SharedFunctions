function Get-TldFromFqdn {
    <#
        .SYNOPSIS
            Validates and extracts top-level domain (TLD) from a fully qualified domain name (FQDN).
        .DESCRIPTION
            This function validates whether the provided FQDN contains a valid top-level domain (TLD) and returns it.
            It retrieves a list of TLDs from the publicsuffix.org website and checks if the provided FQDN ends with any of these TLDs.
            If a valid TLD is found, it extracts and returns the TLD along with its immediate parent domain.
            This function requires an active internet connection to retrieve the list of TLDs from publicsuffix.org.
        .EXAMPLE
            Get-TldFromFqdn -Fqdn "subdomain.example.com"
            Returns: "example.com"

            Get-TldFromFqdn -Fqdn "example.co.uk"
            Returns: "co.uk"
        .NOTES
            Name: Get-TldFromFqdn
            Author: Ryan Whitlock
            Date: 06.01.2023
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [String]
        $Fqdn
    )
    
    # Retrieve TLD list if not already loaded
    if (-not $script:TldsList) {
        $TldsListRow = Invoke-RestMethod -Uri https://publicsuffix.org/list/public_suffix_list.dat
        $script:TldsList = ($TldsListRow -split "`n" | Where-Object {$_ -notlike '//*' -and $_})
        [array]::Reverse($script:TldsList)
    }

    $isValidTld = $false
    foreach ($Tld in $script:TldsList){
        if ($Fqdn -like "*.$Tld"){
            $isValidTld = $true
            break
        }
    }

    if ($isValidTld){
        # Extract TLD and immediate parent domain
        ($Fqdn -replace "\.$Tld" -split '\.')[-1] + ".$Tld"
    } else {
        throw 'Not a valid TLD'
    }
}
