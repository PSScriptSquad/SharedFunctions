Function Test-Credential {
    <#
        .SYNOPSIS
            Validates provided credentials against Active Directory.

        .DESCRIPTION
            This function validates the provided credentials against Active Directory. It creates a PrincipalContext object
            for Active Directory authentication and then validates the credentials. If the validation is successful,
            it returns the credentials; otherwise, it displays a warning.

        .PARAMETER Credentials
            Specifies the credentials to be validated.

        .PARAMETER Server
            Specifies the server to use for authentication. This parameter is optional.

        .PARAMETER Domain
            Specifies the domain to use for authentication. This parameter is optional and defaults to the current user's domain.

        .EXAMPLE
            Test-Credential -Credentials $cred -Server "ADServer" -Domain "example.com"
            This example validates the provided credentials against the Active Directory server "ADServer" with the domain "example.com".

        .NOTES
            Name: Test-Credential
            Author: Ryan Whitlock
            Date: 06.05.2023
            Version: 1.5
            Changes: Threw specific exceptions based on the condition of the user account.
    #>
    param( 
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credentials,
        
        [Parameter(Mandatory = $false)]
        $Server,
        
        [Parameter(Mandatory = $false)]
        [string]$Domain = $env:USERDOMAIN
    )
    begin {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement 

        $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain 
        $Domain = $Credentials.GetNetworkCredential().Domain
        $UserName = $Credentials.GetNetworkCredential().UserName
        $Password = $Credentials.GetNetworkCredential().Password

        $argumentList = New-Object -TypeName "System.Collections.ArrayList"
        [void]$argumentList.Add($contextType)
        [void]$argumentList.Add($Domain)
    
        if ($null -ne $Server) {
            [void]$argumentList.Add($Server)
        }

        Function Get-UserValidationErrorMessage {
            param (
                [Parameter(Mandatory=$true)]
                [System.DirectoryServices.AccountManagement.PrincipalContext]$PrincipalContext,

                [Parameter(Mandatory=$true)]
                [string]$UserName
            )

            try {
                $userPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::FindByIdentity(
                    [System.DirectoryServices.AccountManagement.ContextType]::($principalContext.ContextType), 
                    $UserName
                )
                if ($null -eq $userPrincipal) {
                    return "User does not exist."
                } elseif ($userPrincipal.IsAccountLockedOut()) {
                    return "Account is locked out."
                } elseif ($userPrincipal.Enabled -eq $false) {
                    return "Account is disabled."
                } else {
                    return "Invalid username or password."
                }
            } catch {
                return "Invalid username or password."
            }
        }
    }

    process {
        try {
            $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $argumentList -ErrorAction Stop

            if ($principalContext.ValidateCredentials($UserName, $Password)) {
                return $Credentials
            } else {
                $errorMessage = Get-UserValidationErrorMessage -PrincipalContext $principalContext -UserName $UserName
                throw $errorMessage
            }
        } catch [System.DirectoryServices.AccountManagement.PrincipalServerDownException] {
            $errorMessage = "The server could not be contacted."
        } catch {
            $errorMessage = "Error: $_"
        }

        Add-Type -AssemblyName System.Windows.Forms
        [System.Windows.Forms.MessageBox]::Show($errorMessage, "Error!", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
    }
}
