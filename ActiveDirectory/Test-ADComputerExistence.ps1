function Test-ADComputerExistence {
    <#
    .SYNOPSIS
        Checks if a specified computer exists in Active Directory and optionally throws an error if the computer should not exist.

    .DESCRIPTION
        The Test-ADComputerExistence function verifies the existence of a computer in Active Directory.
        By default, the function expects the computer to exist and throws an error if it does not.
        If the `-ShouldNotExist` switch is used, the function throws an error if the computer exists.
        Additional catches handle specific exceptions that might occur during the check.

    .PARAMETER ComputerName
        The name of the computer to check in Active Directory.
        This parameter is mandatory and accepts input from the pipeline.

    .PARAMETER ShouldNotExist
        A switch parameter that controls the function's behavior:
        - If specified, the function expects the computer to NOT exist in AD. It will throw an error if the computer exists.
        - If not specified, the function expects the computer to exist in AD. It will throw an error if the computer does not exist.

    .EXAMPLE
        Test-ADComputerExistence -ComputerName "Computer1"
    
        This command checks if the computer named "Computer1" exists in Active Directory. If it does not exist,
        the function throws an error.

    .EXAMPLE
        Test-ADComputerExistence -ComputerName "Computer1" -ShouldNotExist
    
        This command checks if the computer named "Computer1" does not exist in Active Directory. If it exists,
        the function throws an error.

    .NOTES
        Name: Test-ADComputerExistence
        Author: Ryan Whitlock
        Date: 08.23.2024
        Version: 1.0
        Changes: Initial release 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $false)]
        [switch]$ShouldNotExist
    )

    process {
        try {
            Get-ADComputer -Identity $ComputerName -ErrorAction Stop | Out-Null
            
            if ($ShouldNotExist) {
                # Computer exists but should not exist
                throw [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] "A computer with the name '$ComputerName' already exists in Active Directory."
            } else {
                # Computer exists and should exist
                return $true
            }

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            if ($ShouldNotExist) {
                # Computer does not exist and should not exist
                return $true
            } else {
                # Computer does not exist but should exist
                throw "A computer with the name '$ComputerName' does not exist in Active Directory, but it should."
            }
        } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            throw "No domain connectivity. Please check your network and domain settings."
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityAlreadyExistsException] {
            throw "A computer with the name '$ComputerName' already exists in Active Directory."
        } catch {
            throw "An unexpected error occurred while checking for the computer '$ComputerName': $_"
        }
    }
}
