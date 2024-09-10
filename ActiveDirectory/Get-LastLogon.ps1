function Get-LastLogon {
    <#
    .SYNOPSIS
        Retrieves the last logon time for one or more users across all domain controllers.

    .DESCRIPTION
        The Get-LastLogon function queries all domain controllers in the current Active Directory domain 
        to retrieve the last logon time for one or more users. It uses parallel processing (runspaces) to 
        speed up the queries by running them concurrently across multiple domain controllers. The function 
        returns the most recent logon time across all domain controllers.

        This function retrieves both the LastLogon and LastLogonTimestamp attributes from Active Directory. 
        LastLogon is the most accurate but only updated on the domain controller where the user last logged in. 
        LastLogonTimestamp is replicated across all domain controllers but can be delayed by up to 14 days. 

    .PARAMETER Identity
        Specifies one or more user identities to query. 
        This can be a user's SamAccountName, DistinguishedName, UserPrincipalName, or Name. 
        Accepts an array of strings, and the user(s) will be queried on all domain controllers.

    .EXAMPLE
        Get-LastLogon -Identity "jsmith"
    
        Retrieves the last logon time for the user "jsmith" by querying all domain controllers in the current domain.

    .EXAMPLE
        Get-LastLogon -Identity "jsmith","mjones"

        Retrieves the last logon time for both "jsmith" and "mjones" by querying all domain controllers in the current domain.

    .EXAMPLE
        "jsmith" | Get-LastLogon

        Passes "jsmith" from the pipeline to the function, retrieving their last logon time from all domain controllers.

    .NOTES
        Name: Get-LastLogon
        Author: Ryan Whitlock
        Inspired by: krzydoug - https://www.reddit.com/r/PowerShell/comments/mfvgwn/getlastlogon_get_accurate_last_logon_time_for_user/
        Date: 09.10.2024
        Version: 1.0
        Changes: Initial release    
    #>
    [CmdletBinding()]
    Param(
        [Alias("UserName", "User", "SamAccountName", "Name", "DistinguishedName", "UserPrincipalName", "DN", "UPN")]
        [Parameter(ValueFromPipeline, Position = 0, Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Identity
    )

    begin {
        try {
            $DCList = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.Name
        } catch {
            Write-Error "Failed to retrieve domain controllers. Please ensure you have permissions and network connectivity."
            return
        }

        # Create a runspace pool to control the degree of parallelism (using available CPU cores)
        $RunspacePool = [runspacefactory]::CreateRunspacePool(1, [Environment]::ProcessorCount)
        $RunspacePool.Open()

        # Collection to track the runspaces
        $Runspaces = @()
    }

    process {
        foreach ($CurrentUser in $Identity) {
            $Filter = switch -Regex ($CurrentUser) {
                '=' { 'DistinguishedName';break }
                '@' { 'UserPrincipalName';break }
                ' ' { 'Name';break }
                default { 'SamAccountName' }
            }

            Write-Verbose "Checking last logon for user: $CurrentUser"

            # Start a runspace for each domain controller query
            $Runspaces = foreach ($DC in $DCList) {
                $Runspace = [Powershell]::Create().AddScript({
                    param ($DC, $filter, $currentUser)
                    
                    try {
                        $AD = [ADSI]"LDAP://$DC"
                        $Searcher = [DirectoryServices.DirectorySearcher]::new($AD, "($Filter=$CurrentUser)")
                        $Account = $Searcher.FindOne()

                        if ($Account) {
                            $Logon = $($Account.Properties.lastlogon)
                            $LogonTimestamp = $($Account.Properties.lastlogontimestamp)

                            return @{
                                DC                 = $DC
                                LastLogon          = $Logon
                                LastLogonTimestamp = $LogonTimestamp
                            }
                        } else {
                            return @{ DC = $DC; Error = "User not found on DC" }
                        }
                    } catch {
                        return @{ DC = $DC; Error = $_.Exception.Message }
                    }
                }).AddArgument($DC).AddArgument($Filter).AddArgument($CurrentUser)

                # Assign runspace to the runspace pool
                $Runspace.RunspacePool = $RunspacePool

                # Store the runspace in the collection
                [PSCustomObject]@{
                    Pipe      = $Runspace
                    Status    = $Runspace.BeginInvoke()
                    DC        = $DC
                }
            }

            # Wait for all runspaces to finish and collect the results
            $Results = foreach ($RunspaceData in $Runspaces) {
                $Runspace = $RunspaceData.Pipe
                $Status = $RunspaceData.Status
                $Runspace.EndInvoke($Status)   
                $Runspace.Dispose()
            }

            # Process the logon times from all domain controllers
            $LogonTimes = $Results | Where-Object { $_.LastLogon -ne $null } | ForEach-Object {
                [datetime]::FromFileTime($_.LastLogon)
            }
            $LogonTimestamps = $Results | Where-Object { $_.LastLogonTimestamp -ne $null } | ForEach-Object {
                [datetime]::FromFileTime($_.LastLogonTimestamp)
            }

            # Combine logon times and timestamps, sort them, and find the most recent one
            $AllLogonTimes = $LogonTimes + $LogonTimestamps | Sort-Object -Descending | Select-Object -First 1

            if ($AllLogonTimes) {
                if ($allLogonTimes.Year -eq 1601) {
                    [PSCustomObject]@{
                        User      = $CurrentUser
                        LastLogon = "Never logged on"
                    }
                } else {
                    [PSCustomObject]@{
                        User      = $CurrentUser
                        LastLogon = $AllLogonTimes
                    }
                }
            } else {
                Write-Warning "No logon information found for user $currentUser."
            }
        }
    }

    end {
        # Close the runspace pool after all tasks are done
        $RunspacePool.Close()
        $RunspacePool.Dispose()

        Write-Verbose "Finished processing logon information."
    }
}
