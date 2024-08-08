function Add-GroupMember {
    <#
    .SYNOPSIS
        Adds a computer to multiple Active Directory groups.

    .DESCRIPTION
        This function accepts a computer name and a comma-separated list of groups,
        splits the list on commas, and loops through each group to add the computer 
        to the group using the Add-ADGroupMember cmdlet. The function validates the 
        parameters to ensure they are not null or empty and that the groups exist.

    .PARAMETER ComputerName
        The name of the computer to be added to the groups.

    .PARAMETER GroupList
        A comma-separated list of Active Directory groups.

    .EXAMPLE
        Add-Group -ComputerName "MyComputer" -GroupList "Group1,Group2,Group3"    
        This will add the computer "MyComputer" to the groups "Group1", "Group2", and "Group3".

    .NOTES
        Name: Add-GroupMember
        Author: Ryan Whitlock
        Date: 08.07.2024
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]        
        [ValidateScript({
            # Split the comma-separated list into an array and check if each group exists
            $Groups = $_ -split ','
            foreach ($Group in $Groups) {
                if (-not (Get-ADGroup -Filter { Name -eq $Group.Trim() } -ErrorAction SilentlyContinue)) {
                    throw "Group '$group' does not exist."
                }
            }
            $true
        })]
        [ValidateNotNullOrEmpty()]
        [string]$GroupList
    )

    begin {
        # Split the comma-separated list into an array
        $Groups = $GroupList -split ','
    }

    process {
        foreach ($Group in $Groups) {
            # Trim any leading/trailing whitespace from the group name
            $GroupName = $group.Trim()

            # Use the ShouldProcess method to check for WhatIf/Confirm
            if ($PSCmdlet.ShouldProcess("$GroupName", "Add $ComputerName to group")) {
                try {
                    # Add the computer to the group
                    Add-ADGroupMember -Identity $GroupName -Members $ComputerName

                    Write-Host "Successfully added $ComputerName to $groupName"
                } catch {
                    Write-Host "Failed to add $ComputerName to $GroupName. Error: $_"
                }
            }
        }
    }
}
