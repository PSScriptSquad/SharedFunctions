Function Test-Credential {
    <#
        .SYNOPSIS
            Validates provided credentials against Active Directory.
    
        .DESCRIPTION
            This function validates the provided credentials by creating a PrincipalContext 
            and verifying that the credentials are correct. If validation fails, it attempts 
            to provide a more specific error by checking if the user exists, or if the account 
            is locked or disabled.
    
        .PARAMETER Credentials
            A PSCredential object that contains the username and password to be validated.
    
        .PARAMETER Server
            (Optional) Specifies the domain controller to use for authentication.
    
        .PARAMETER Domain
            (Optional) Specifies the domain name. Defaults to the current user's domain 
            (from $env:USERDOMAIN). If the PSCredential contains a non-empty domain, that 
            value will override this parameter.
    
        .EXAMPLE
            Test-Credential -Credentials $cred -Server "ADServer" -Domain "example.com"
            This example validates the provided credentials against the domain controller 
            "ADServer" and the domain "example.com".

        .NOTES
            Name: Test-Credential
            Author: Ryan Whitlock
            Date: 06.05.2023
            Version: 1.7
            Changes: Threw specific exceptions based on the condition of the user account.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSCredential])]
    param( 
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]$Credentials,
        
        [Parameter(Mandatory = $false)]
        [string]$Server,
        
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN
    )
    
    begin {
        # Load required assemblies.
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        
        # Extract username, password, and (if provided) domain from the credential.
        $netCred = $Credentials.GetNetworkCredential()
        $UserName = $netCred.UserName
        $Password = $netCred.Password
        
        if (-not [string]::IsNullOrEmpty($netCred.Domain)) {
            $Domain = $netCred.Domain
        }
        
        # Prepare the PrincipalContext constructor arguments.
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
    }
    
    process {
        try {
            # Create the PrincipalContext.
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $principalContextArgs -ErrorAction Stop

            # Validate the credentials.
            if ($principalContext.ValidateCredentials($UserName, $Password, [System.DirectoryServices.AccountManagement.ContextOptions]::Negotiate)) {
                return $Credentials
            }
            else {
                # If validation fails, try to determine why.
                $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity($principalContext, $UserName)
                
                if ($null -eq $userPrincipal) {
                    throw [System.Security.Authentication.InvalidCredentialException] "User '$UserName' does not exist in domain '$Domain'."
                }
                elseif ($userPrincipal.IsAccountLockedOut()) {
                    throw [System.Security.Authentication.InvalidCredentialException] "Account '$UserName' is locked out in domain '$Domain'."
                }
                elseif (-not $userPrincipal.Enabled) {
                    throw [System.Security.Authentication.InvalidCredentialException] "Account '$UserName' is disabled in domain '$Domain'."
                }
                else {
                    throw [System.Security.Authentication.InvalidCredentialException] "Invalid credentials for user '$UserName' in domain '$Domain'."
                }
            }
        }
        catch [System.DirectoryServices.AccountManagement.PrincipalServerDownException] {
            $errorMessage = "The server could not be contacted for domain '$Domain'."
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.MessageBox]::Show($errorMessage, "Error!",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $null
        }
        catch [System.Security.Authentication.InvalidCredentialException] {
            $errorMessage = $_.Exception.Message
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.MessageBox]::Show($errorMessage, "Error!",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $null
        }
        catch {
            $errorMessage = "Error in domain '$Domain': $($_.Exception.Message)"
            Add-Type -AssemblyName System.Windows.Forms
            [void][System.Windows.Forms.MessageBox]::Show($errorMessage, "Error!",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Warning)
            return $null
        }
    }
}
