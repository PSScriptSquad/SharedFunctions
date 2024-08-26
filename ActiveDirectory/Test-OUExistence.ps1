function Test-OUExistence {
    <#
    .SYNOPSIS
        Verifies the existence of an Active Directory Organizational Unit (OU) by its Distinguished Name.

    .DESCRIPTION
        This function checks whether a specified Organizational Unit (OU) exists in Active Directory.
        It takes the Distinguished Name (DN) of the OU as input. If the OU does not exist or there is an issue accessing it,
        the function will throw an appropriate error.

    .PARAMETER OUDistinguishedName
        The Distinguished Name (DN) of the Organizational Unit (OU) that you want to verify.

    .EXAMPLE
        Test-OUExistence -OUDistinguishedName "OU=Computers,DC=example,DC=com"

        This command checks if the OU "OU=Computers,DC=example,DC=com" exists in Active Directory.
        If it does not exist, an error will be thrown.

    .NOTES
        Name: Test-OUExistence
        Author: Ryan Whitlock
        Date: 08.23.2024
        Version: 1.0
        Changes: Initial release 
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$OUDistinguishedName
    )

    try {
        # Attempt to get the Organizational Unit
        Get-ADOrganizationalUnit -Identity $OUDistinguishedName -ErrorAction Stop | Out-Null
        Write-Verbose "The Organizational Unit '$OUDistinguishedName' exists."
        return $true
    }
    catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Handle the case where the OU is not found
        throw "Error: The Organizational Unit with Distinguished Name '$OUDistinguishedName' does not exist."
    }
    catch [System.UnauthorizedAccessException] {
        # Handle insufficient permissions
        throw "Error: Access denied while attempting to access the Organizational Unit with Distinguished Name '$OUDistinguishedName'. Please check your permissions."
    }
    catch {
        # Handle any other types of exceptions
        throw "An unexpected error occurred while accessing the Organizational Unit '$OUDistinguishedName': $_"
    }
}
