function Get-GroupMembershipRecursive {
    <#
    .SYNOPSIS
        Retrieves all Active Directory group memberships for a specified user or computer, including nested group memberships.

    .DESCRIPTION
        The Get-GroupMembershipRecursive function accepts a user or computer name and retrieves all the Active Directory group memberships for that object. 
        It performs a recursive search to include all nested groups in the output.

        This function requires the Active Directory module to be installed and configured on the system.
        The function makes use of caching to improve performance by avoiding redundant AD lookups for already processed groups.

    .PARAMETER Identity
        Specifies the name(s) of the user or computer whose group memberships should be retrieved.
        This parameter is mandatory and accepts one or more names as a string array.

    .PARAMETER Type
        Specifies the type of the object, either "User" or "Computer".
        This parameter is mandatory and limits the input to the values "User" or "Computer" to prevent invalid input.

    .EXAMPLE
        # Retrieve recursive group memberships for a specific user
        Get-GroupMembershipRecursive -Identity "jdoe" -Type "User"

        # Retrieve recursive group memberships for multiple computers
        Get-GroupMembershipRecursive -Identity "comp01", "comp02" -Type "Computer"

    .NOTES
        Name: Get-GroupMembershipRecursive
        Author: Ryan Whitlock
        Date: 10.23.2024
        Version: 1.0
        Changes: Initial release 
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String[]]$Identity,  # Can be user or computer name

        [Parameter(Mandatory = $true)]
        [ValidateSet("User", "Computer")]
        [String]$Type  # Specify whether the input is a User or Computer
    )
    begin {
        # Initialize a hashtable to cache AD groups for faster lookup, avoiding redundant AD queries.
        # Format: Key = group distinguished name, Value = ADGroup object
        $ADGroupCache = @{}
        
        # Hashtable to temporarily store the groups for the current object being processed.
        $ObjectGroups = @{}

        # Define a recursive helper function to process each group.
        function __findPath ([string]$currentGroup) {
            Write-Verbose "Processing group: $currentGroup"

            # Only process if the group has not already been added to avoid infinite loops
            if (!$ObjectGroups.ContainsKey($currentGroup)) {
                # Check cache first to avoid redundant AD lookups
                $groupObject = if ($ADGroupCache.ContainsKey($currentGroup)) {
                    Write-Verbose "Found group in cache: $currentGroup"
                    $ADGroupCache[$currentGroup]
                } else {
                    # Retrieve group from AD and add it to the cache
                    Write-Verbose "Group: $currentGroup is not present in cache. Retrieving and caching."
                    $g = Get-ADGroup -Identity $currentGroup -Property "MemberOf"
                    # Immediately add group to local cache:
                    $ADGroupCache.Add($g.DistinguishedName, $g)
                    $g
                }

                # Add the current group to the list for the current object
                $ObjectGroups.Add($currentGroup, $groupObject)
                Write-Verbose "Member of: $currentGroup"

                # Recursively process each parent group
                foreach ($p in $groupObject.MemberOf) {
                    __findPath $p
                }
            } else {
                Write-Verbose "Closed walk or duplicate on '$currentGroup'. Skipping."
            }
        }
    }
    process {
        foreach ($name in $Identity) {
            Write-Verbose "========== $name ($Type) =========="

            # Clear group membership for each new object to avoid data carry-over
            $ObjectGroups.Clear()

            # Retrieve the object based on the specified type (User or Computer)
            if ($Type -eq "User") {
                $Object = Get-ADUser -Identity $name -Property "MemberOf"
            } elseif ($Type -eq "Computer") {
                $Object = Get-ADComputer -Identity $name -Property "MemberOf"
            }

            # Process each group that the object is a member of
            if ($Object -and $Object.MemberOf) {
                $Object.MemberOf | ForEach-Object { __findPath $_ }
            } else {
                Write-Warning "$name does not have any group memberships."
            }

            # Output a custom object with the results for the current AD object
            [PSCustomObject]@{
                Name     = $Object.Name
                Type     = $Type
                MemberOf = $ObjectGroups.Values
            }
        }
    }
}
