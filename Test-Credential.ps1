Function Test-Credential {
    <#
        .SYNOPSIS
            Validates provided credentials against Active Directory.

        .DESCRIPTION
            This function validates the provided credentials against Active Directory by creating a PrincipalContext 
            for authentication and then checking the credentials. If valid, it returns the PSCredential object; 
            otherwise, it displays an error message.

        .PARAMETER Credentials
            A PSCredential object that contains the username and password to be validated.

        .PARAMETER Server
            (Optional) Specifies the domain controller to use for authentication. If provided, this value is used 
            as the "name" argument in the PrincipalContext constructor.

        .PARAMETER Domain
            (Optional) Specifies the domain name. Defaults to the current user's domain (from $env:USERDOMAIN). 
            If the PSCredential contains a non-empty domain, that value will override this parameter.

        .EXAMPLE
            Test-Credential -Credentials $cred -Server "ADServer" -Domain "example.com"
            This example validates the provided credentials against the domain controller "ADServer" and the domain "example.com".

        .NOTES
            Name: Test-Credential
            Author: Ryan Whitlock
            Date: 06.05.2023
            Version: 1.6
            Changes: Fixed parameter handling, argument ordering, and the error message function.
    #>
    [CmdletBinding()]
    param( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credentials,
        
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN
    )
    begin {
        # Load the required .NET assembly.
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement 

        # Extract username, password, and domain from the credential.
        $netCred = $Credentials.GetNetworkCredential()
        $UserName = $netCred.UserName
        $Password = $netCred.Password
        
        # If the credential contains a domain, use it.
        if (-not [string]::IsNullOrEmpty($netCred.Domain)) {
            $Domain = $netCred.Domain
        }
        
        # Build the constructor arguments for PrincipalContext.
        if ($Server) {
            $principalContextArgs = @(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                $Server, 
                $Domain
            )
        }
        else {
            $principalContextArgs = @(
                [System.DirectoryServices.AccountManagement.ContextType]::Domain, 
                $Domain
            )
        }
        
        # Helper function for retrieving a more detailed error message
        function Get-UserValidationErrorMessage {
            param (
                [Parameter(Mandatory=$true)]
                [System.DirectoryServices.AccountManagement.PrincipalContext]$PrincipalContext,
                [Parameter(Mandatory=$true)]
                [string]$UserName
            )
            try {
                # Pass the PrincipalContext instance directly.
                $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($PrincipalContext, $UserName)
                if ($null -eq $userPrincipal) {
                    return "User does not exist."
                }
                elseif ($userPrincipal.IsAccountLockedOut()) {
                    return "Account is locked out."
                }
                elseif ($userPrincipal.Enabled -eq $false) {
                    return "Account is disabled."
                }
                else {
                    return "Invalid username: $UserName or password."
                }
            }
            catch {
                return "Invalid username or password."
            }
        }
    }

    process {
        try {
            # Create the PrincipalContext using the prepared arguments.
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $principalContextArgs -ErrorAction Stop

            # Validate the credentials.
            if ($principalContext.ValidateCredentials($UserName, $Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)) {
                return $Credentials
            }
            else {
                $errorMessage = Get-UserValidationErrorMessage -PrincipalContext $principalContext -UserName $UserName
                throw $errorMessage
            }
        }
        catch [System.DirectoryServices.AccountManagement.PrincipalServerDownException] {
            $errorMessage = "The server could not be contacted for domain '$Domain'."
        }
        catch {
            $errorMessage = "Error in domain '$Domain': $($_.Exception.Message)"
        }

        # Display the error using a Windows Forms message box.
        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}
