function Get-GroupMembersRecursive {
    <#
    .SYNOPSIS
        Retrieves members of Active Directory groups recursively, including nested group memberships.

    .DESCRIPTION
        The Get-GroupMembersRecursive function retrieves all members of one or more specified Active Directory groups.
        It recursively processes nested groups, ensuring that all user objects within the specified groups and any 
        sub-groups are included in the output. The function caches groups to avoid redundant calls to Active Directory,
        improving performance for large or deeply nested group structures.

        This function requires the Active Directory module. Ensure the module is imported and that you have 
        appropriate permissions to query group and user objects in Active Directory.

    .PARAMETER GroupName
        Specifies the name(s) of the Active Directory group(s) to retrieve members from.
        This parameter is mandatory and accepts one or more group names as a string array.

    .EXAMPLE
        Get-GroupMembersRecursive -GroupName "Domain Admins"

        Retrieves all members of the "Domain Admins" group, including members of any nested groups.

    .EXAMPLE
        "Group1", "Group2" | Get-GroupMembersRecursive

        Pipes multiple group names to the function, returning all users in each group and any nested groups.

    .NOTES
        Name: Get-GroupMembersRecursive
        Author: Ryan Whitlock
        Date: 10.23.2024
        Version: 1.0
        Changes: Initial release 

    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [String[]]$GroupName
    )
    begin {
        # Initialize hashtables to store cached groups and group members.
        $ADGroupCache = @{}
        $GroupMembers = @{}

        # Define a recursive helper function to find group members.
        function __findGroupMembers ([string]$currentGroup) {
            Write-Verbose "Processing group: $currentGroup"

            # Skip processing if the group has already been processed.
            if (!$GroupMembers.ContainsKey($currentGroup)) {
                # Attempt to retrieve the group from cache. If not cached, fetch from AD.
                $groupObject = if ($ADGroupCache.ContainsKey($currentGroup)) {
                    Write-Verbose "Found group in cache: $currentGroup"
                    $ADGroupCache[$currentGroup]
                } else {
                    Write-Verbose "Group: $currentGroup is not in cache. Retrieving and caching."
                    $g = Get-ADGroup -Identity $currentGroup -Property "Members"
                    # Cache the group by its DistinguishedName to avoid re-fetching it.
                    $ADGroupCache.Add($g.DistinguishedName, $g)
                    $g
                }

                # Add current group to processed groups
                $GroupMembers[$currentGroup] = @()

                # Loop through each member of the current group.
                foreach ($member in $groupObject.Members) {
                    # Retrieve member object from AD (user or group).
                    $memberObject = Get-ADObject -Identity $member
                    if ($memberObject.objectClass -eq 'group') {
                        # If member is a group, call this function recursively.
                        Write-Verbose "$member is a group. Recursing into it."
                        __findGroupMembers $memberObject.DistinguishedName
                    } else {
                        # If member is a user, add to the current group's members.
                        Write-Verbose "$member is a user. Adding to the group members list."
                        $GroupMembers[$currentGroup] += $memberObject
                    }
                }
            } else {
                # Skip groups that are already processed.
                Write-Verbose "Group '$currentGroup' already processed. Skipping."
            }
        }
    }
    process {
        # Process each group provided in the GroupName parameter.
        foreach ($group in $GroupName) {
            Write-Verbose "========== $group =========="
            # Invoke the recursive function to retrieve members for each group.
            __findGroupMembers $group
        }

        # Output the collected group members as a flat list.
        return $GroupMembers.GetEnumerator() | ForEach-Object {$_.Value}        
    }
}
