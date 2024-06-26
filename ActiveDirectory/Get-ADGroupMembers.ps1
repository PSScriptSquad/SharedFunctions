function Get-ADGroupMembers {
    <#
    .SYNOPSIS
        Return all group members for specified groups.

    .FUNCTIONALITY
        Active Directory

    .DESCRIPTION
        Return all group members for specified groups. Requires .NET 3.5, does not require RSAT.
    
    .PARAMETER Group
        One or more Security Groups to enumerate.

    .PARAMETER Recurse
        Whether to recurse groups. Note that subgroups are NOT returned if this is true, only user accounts.
        Default value is $True.

    .EXAMPLE
        # Get all group members in Domain Admins or nested subgroups, only include samaccountname property.
        Get-ADGroupMembers "Domain Admins" | Select-Object -ExpandProperty samaccountname

    .EXAMPLE
        # Get members for objects returned by Get-ADGroupMembers.
        Get-ADGroupMembers -Group "Domain Admins" | Get-Member

    .NOTES
        Name: Get-ADGroupMembers
        Author: Ryan Whitlock
        Date: 6.25.2024
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [ValidateScript({
            # Add the .NET type
            $NetType = 'System.DirectoryServices.AccountManagement'
            try {
                Add-Type -AssemblyName $NetType -ErrorAction Stop
            }
            catch {
                throw "Could not load $($NetType): Confirm .NET 3.5 or later is installed"
            }
            
            # Set up context type
            $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            
            # Validate group existence
            $GroupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ContextType, $_)
            if (!$GroupPrincipal) {
                throw "Group '$_' does not exist."
            }
            $true
        })]
        [string[]]$Group,
        
        [bool]$Recurse = $true
    )

    begin {
        # Add the .NET type (only if it's not already added)
        if (-not [System.Management.Automation.PSTypeName]'System.DirectoryServices.AccountManagement.GroupPrincipal') {
            $NetType = 'System.DirectoryServices.AccountManagement'
            try {
                Add-Type -AssemblyName $NetType -ErrorAction Stop
            }
            catch {
                throw "Could not load $($NetType): Confirm .NET 3.5 or later is installed"
            }
        }

        function Get-NestedGroups {
            param (
                [System.DirectoryServices.AccountManagement.Principal]$Principal
            )

            $nestedGroups = @()
        
            if ($Recurse -and $Principal -is [System.DirectoryServices.AccountManagement.GroupPrincipal]) {
                foreach ($member in $Principal.Members) {
                    # Recursively collect nested groups
                    $nestedGroups += Get-NestedGroups -Principal $member
                }
            }
            
            # Only add the principal if it's a GroupPrincipal
            if ($Principal -is [System.DirectoryServices.AccountManagement.GroupPrincipal]) {
                $nestedGroups += $Principal
            }
        
            return $nestedGroups
        }

        # Set up context type
        $ContextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain
    }

    process {
        foreach ($GroupName in $Group) {
           try {
                # Find group
                $GroupPrincipal = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($ContextType, $GroupName)
                
                if ($GroupPrincipal) {
                    $members = $GroupPrincipal.GetMembers($Recurse) | ForEach-Object {
                        # Get nested groups for each member
                        $nestedGroups = Get-NestedGroups -Principal $GroupPrincipal
                        
                        # Construct GroupPath
                        $groupPath = if ($nestedGroups.Count -gt 1) {
                            $nestedGroups[-1..0].Name -join ' -> '
                        } else {
                            $GroupName
                        }
                        
                        [PSCustomObject]@{
                            GroupPath = $groupPath
                            Member = $_
                        }                        
                    }

                    $members
                }
                else {
                    Write-Warning "Could not find group '$GroupName'"
                }
            }
            catch {
                Write-Error "Could not obtain members for $($GroupName): $_"
            }
        }
    }

    end {
        # Clean up
        $ContextType = $null
    }
}
