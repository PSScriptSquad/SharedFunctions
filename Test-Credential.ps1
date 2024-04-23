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
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    param( 
        [Parameter(Mandatory=$true)] # Specifies that the parameter is mandatory
        [ValidateNotNull()] # Validates that the parameter is not null
        [System.Management.Automation.PSCredential] # Specifies the data type for the parameter as PSCredential
        [System.Management.Automation.Credential()]  # Specifies that the parameter accepts credential objects
        $Credentials, # Parameter for the credentials
        
        [Parameter(Mandatory = $false)] # Specifies that the parameter is optional
        $Server, # Parameter for the server
        
        [Parameter(Mandatory = $false)] # Specifies that the parameter is optional
        [string]$Domain = $env:USERDOMAIN # Parameter for the domain with a default value of the current user's domain
    )

    # Adds the System.DirectoryServices.AccountManagement assembly
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement 

    # Specifies the context type as Domain
    $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain 
    
    # Extracts domain and username from the credentials if specified in the format "Domain\Username"
    $Domain = $Credentials.GetNetworkCredential().Domain
    $UserName = $Credentials.GetNetworkCredential().UserName

    # Creates an ArrayList to store arguments for creating PrincipalContext
    $argumentList = New-Object -TypeName "System.Collections.ArrayList"
    $null = $argumentList.Add($contextType)
    $null = $argumentList.Add($Domain)
    
    # Adds server to the argument list if provided
    if($null -ne $Server){
        $argumentList.Add($Server)
    }
    
    try {
        # Creates a PrincipalContext object for Active Directory authentication
        $principalContext = New-Object System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $argumentList -ErrorAction Stop
        
        # Validates credentials against Active Directory
        if ($principalContext.ValidateCredentials($UserName, $Credentials.GetNetworkCredential().Password)) {
            Return $Credentials # Returns credentials if validation is successful
        } else {
            $errorMessage = "$Domain\$UserName - AD Authentication failed"
            Write-Warning $errorMessage # Displays a warning if authentication failed
        }
    } catch {
        $errorMessage = "$Domain\$UserName - Error creating PrincipalContext: $_"
        Write-Warning $errorMessage # Displays a warning if an error occurs while creating PrincipalContext
    }
}
