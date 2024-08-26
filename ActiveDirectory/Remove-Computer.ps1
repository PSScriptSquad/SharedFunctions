function Remove-Computer {
    <#
    .SYNOPSIS
        Removes a computer from Active Directory.

    .DESCRIPTION
        This function removes a specified computer from Active Directory. It validates the existence of the computer,
        and verifies domain connectivity before attempting to remove the computer.
        After removal, it verifies that the computer has been successfully removed.

    .PARAMETER ComputerName
        The name of the computer to be removed from Active Directory.

    .EXAMPLE
        Remove-Computer -ComputerName "Computer123"
        This example removes the computer named "Computer123" from Active Directory.

    .NOTES
        Name: Remove-Computer
        Author: Ryan Whitlock
        Date: 08.05.2024
        Version: 1.0
        Changes: Initial release 

    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateScript({
            try {
                Test-ADComputerExistence -ComputerName $_ 
            } catch {
                throw $_  
            }           
        })]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName
    )
    
    process {
        # Check if ShouldProcess is allowed (used for WhatIf and Confirm)
        if ($PSCmdlet.ShouldProcess($ComputerName, "Remove computer from Active Directory")) {
            try {
                # Remove the computer from Active Directory
                Remove-ADComputer -Identity $ComputerName -Confirm:$false -ErrorAction Stop
                Write-Host "Computer $ComputerName has been successfully removed from Active Directory." -ForegroundColor Green
            }
            catch {
                throw "Failed to remove computer '$ComputerName' from Active Directory."
            }

            # Verify that the computer has been removed
            try {
                $computer = Get-ADComputer -Filter { Name -eq $ComputerName } -ErrorAction SilentlyContinue
                if ($null -ne $computer) {
                    throw "Computer '$ComputerName' still exists in Active Directory. Removal might have failed."
                } else {
                    Write-Host "Verified that computer '$ComputerName' has been removed from Active Directory." -ForegroundColor Green
                }
            }
            catch {
                throw "Error occurred while verifying the removal of computer '$ComputerName'."
            }
        } else {
            Write-Host "Operation for removing computer '$ComputerName' was skipped due to WhatIf or Confirm preference." -ForegroundColor Yellow
        }
    }
}
