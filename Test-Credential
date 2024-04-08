Function Test-Credential {
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
    
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement # Adds the System.DirectoryServices.AccountManagement assembly
    
    $contextType = [System.DirectoryServices.AccountManagement.ContextType]::Domain # Specifies the context type as Domain
    
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
