function New-Computer {
    <#
    .SYNOPSIS
        Creates a new Active Directory computer object.

    .DESCRIPTION
        The New-Computer function creates a new computer object in Active Directory with the specified name and 
        Organizational Unit (OU). It validates the computer name to ensure it adheres to Microsoft's naming standards 
        and length requirements. The function also checks if the specified OU exists, verifies connectivity to the 
        domain, and ensures that a computer with the same name does not already exist.

    .PARAMETER ComputerName
        The name of the computer to be created. Must be 1 to 15 characters long and can only contain letters, numbers, and hyphens.

    .PARAMETER OU
        The distinguished name of the Organizational Unit (OU) where the computer object will be created. The OU must 
        exist in Active Directory.

    .EXAMPLE
        New-Computer -ComputerName "CompName123" -OU "OU=Computers,DC=example,DC=com"
        Creates a new computer object named 'CompName123' in the specified Organizational Unit (OU).

    .EXAMPLE
        New-Computer -ComputerName "Server01" -OU "OU=Servers,DC=example,DC=com"
        Creates a new computer object named 'Server01' in the specified Organizational Unit (OU).

    .NOTES
        Name: New-Computer
        Author: Ryan Whitlock
        Date: 08.05.2024
        Version: 1.0
        Changes: Initial release 
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateLength(1, 15)]
        [ValidatePattern("^[a-zA-Z0-9\-]+$")]  
        [ValidateScript({
            try {
                $Identity = Get-ADComputer -Identity $_ -ErrorAction Stop
                if ($Identity) {
                    throw "A computer with the name '$_' already exists in Active Directory."
                } else {
                    $true
                }
            } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                throw "No domain connectivity. Please check your network and domain settings."
            } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
                $true # Computer does not exist, proceed
            } catch {
                throw "An unexpected error occurred while checking for existing computer: $_"
            }              
        })]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            try {
                Get-ADOrganizationalUnit -Identity $_ -ErrorAction Stop
                $true
            } catch {
                throw "The specified Organizational Unit '$_' does not exist or cannot be accessed."
            }
        })]
        [ValidateNotNullOrEmpty()]
        [string]$OU
    )

    process {
        # Create the computer object
        if ($PSCmdlet.ShouldProcess("Creating computer '$ComputerName' in OU '$OU'")) {
            try {
                New-ADComputer -Name $ComputerName -SamAccountName $ComputerName -Path $OU -Enabled $true
                Write-Host "Computer '$ComputerName' has been successfully created in the domain." -ForegroundColor Green
            } catch {
                throw "Failed to create the computer object. Error: $_"
            }
        } else {
            Write-Host "Operation was canceled by the user or due to WhatIf parameter." -ForegroundColor Yellow
        }
    }
}
