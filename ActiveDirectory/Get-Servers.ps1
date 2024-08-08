function Get-Servers {
    <#
    .SYNOPSIS
        Retrieves servers via LDAP within specified organizational units (OUs).

    .DESCRIPTION
        This function queries Active Directory to find servers within the specified OUs. 
        It constructs an LDAP filter based on the provided OUs and searches for servers matching the criteria. 
        If no OUs are specified, it searches across the entire directory. 
        This function does not require the Remote Server Administration Tools (RSAT) and is optimized for fast execution.

    .PARAMETER defaultNamingContext
        The default naming context for the LDAP query. If not provided, it defaults to the
        naming context of the RootDSE.

    .PARAMETER OU
        An array of organizational units to search for servers. This parameter is optional
        and only accepts alphabetic characters and spaces.

    .EXAMPLE
        Get-Servers -OU "Sales", "Marketing"
        Get-Servers

    .NOTES
        Name: Get-Servers
        Author: Ryan Whitlock
        Date: 06.01.2021
        Version: 2.0
        Changes: Added comments, improved clarity and readability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false, Position=0)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if ($_ -match '^LDAP://[^/]+$') {
                $true
            } else {
                throw "defaultNamingContext should be a valid LDAP path."
            }
        })]
        [string]$defaultNamingContext = ([ADSI]"LDAP://RootDSE").defaultNamingContext,

        [Parameter(Mandatory=$false, Position=1)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            foreach ($item in $_) {
               # Validate each OU to contain only alphabetic characters and spaces
                if ($item -match '^[a-zA-Z ]+$') {
                    try {
                        # Check if the OU exists in Active Directory
                        $searcher = [ADSISearcher]"(&(objectCategory=organizationalUnit)(ou=$item))"
                        $searcher.SearchRoot = [ADSI]"LDAP://$defaultNamingContext"
                        if ($null -ne $searcher.FindOne()) {
                            continue
                        } else {
                            throw "OU '$item' does not exist in Active Directory."
                        }
                    } catch {
                        throw "Failed to search for OU '$item'. Error: $_"
                    }
                } else {
                    throw "OU should only contain alphabetic characters and spaces."
                }
            }
            $true
        })]
        [string[]]$OU
    )

    begin {
        # Construct the LDAP filter based on provided OUs or default filter
        $LDAPFilter = [System.Text.StringBuilder]::New()
        if ($PSBoundParameters.ContainsKey('OU')) {
            # Create an LDAP filter for the specified OUs
            $OULdapString = ($OU | ForEach-Object { "(OU=$_)" }) -join ''
            [void]$LDAPFilter.Append("(|$OULdapString)")
        } else {
            # Default LDAP filter to find servers across the entire directory
            [void]$LDAPFilter.Append("(&(objectClass=Computer)(operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2))")
        }

        # Initialize DirectorySearcher with the default naming context
        $DirSearcher = New-Object DirectoryServices.DirectorySearcher($defaultNamingContext)
        $DirSearcher.Filter = $LDAPFilter.ToString()
        $DirSearcher.SearchScope = [System.DirectoryServices.SearchScope]::Subtree
    }

    process {
        if ($PSBoundParameters.ContainsKey('OU')) {
            # Load the "ou" property if OUs are specified
            $DirSearcher.PropertiesToLoad.Add("ou") | Out-Null

            # Find all entries matching the OU filter and retrieve their distinguished names
            $DirSearcher.FindAll() | ForEach-Object {
                $entry = $_.GetDirectoryEntry()
                $distinguishedName = $entry.distinguishedName

                # Initialize DirectorySearcher for each distinguished name found
                $ObjectSearcher = New-Object DirectoryServices.DirectorySearcher
                $ObjectSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$distinguishedName")
                $ObjectSearcher.Filter = '(&(objectClass=Computer)(operatingSystem=*server*)(!userAccountControl:1.2.840.113556.1.4.803:=2))'

                # Return DNS hostnames of found LDAP servers
                $ObjectSearcher.FindAll() | ForEach-Object {
                    $_.Properties["dnshostname"] | ForEach-Object { $_ }
                } | Where-Object { $_ -ne $null }
            }
        } else {
            # Load the "dnshostname" property if no OUs are specified
            $DirSearcher.PropertiesToLoad.Add("dnshostname") | Out-Null

            # Find all entries and return DNS hostnames of found LDAP servers
            $DirSearcher.FindAll() | ForEach-Object {
                $_.Properties["dnshostname"] | ForEach-Object { $_ }
            } | Where-Object { $_ -ne $null }
        }
    }
}
