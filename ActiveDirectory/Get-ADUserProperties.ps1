function Get-ADUserProperties {
    <#
        .SYNOPSIS
            Retrieves properties of an Active Directory user, handling invalid properties and specific exceptions.

        .DESCRIPTION
            This function attempts to retrieve the specified properties of an Active Directory user. If an invalid property is specified,
            it removes the invalid property and tries again. It also handles specific Active Directory exceptions like user not found and server down.

        .PARAMETER Identity
            The identity of the Active Directory user (e.g., username, distinguished name, etc.).

        .PARAMETER Properties
            An array of properties to retrieve for the specified user.

        .EXAMPLE
            PS C:\> Get-ADUserProperties -Identity "jdoe" -Properties @("extensionAttribute1", "displayName", "mail")
            Retrieves the specified properties for the user with identity 'jdoe'.

        .NOTES
            Name: Get-ADUserProperties
            Author: Ryan Whitlock
            Date: 06.20.2024
            Version: 1.0
            Changes: Initial release
    #>
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identity,

        [Parameter(Mandatory = $true)]
        [string[]]$Properties
    )

    # Function to remove the invalid property and try again
    function Retry-GetADUser {
        param (
            [string]$Id,
            [string[]]$Props
        )

        try {
            # Attempt to retrieve user information
            $UserInfo = Get-ADUser -Identity $Id -Properties $Props
            return $UserInfo
        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            # Handle user not found exception
            Write-Error "Retry: User not found with identity: $Id."
        } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
            # Handle AD server down exception
            Write-Error "Retry: Unable to connect to the Active Directory server."
        } catch [System.ArgumentException] {
            # Handle the specific invalid property exception
            if ($_.Exception.Message -match "One or more properties are invalid" -and $_.Exception.InnerException -is [System.ServiceModel.FaultException] -and $_.Exception.InnerException.Message -match "Sorting or Selection Property is invalid") {
                $InvalidPropertyName = $_.Exception.ParamName
                if ($InvalidPropertyName) {
                    Write-Warning "Retry: Removing invalid property: $InvalidPropertyName"
                    
                    # Remove the invalid property from the list
                    $NewProps = $Props -ne $InvalidPropertyName

                    # Retry with the new list of properties
                    return Retry-GetADUser -Id $Id -Props $NewProps
                } else {
                    Write-Error "Retry: Invalid property not identified."
                }
            } else {
                Write-Error "Retry: Argument exception encountered: $_"
            }
        } catch {
            Write-Error "Retry: Unknown error: $($_.Exception.Message)"
        }
    }

    try {
        $UserInfo = Get-ADUser -Identity $Identity -Properties $Properties
        return $UserInfo
    } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
        # Handle user not found exception
        Write-Error "User not found with identity: $Identity."
    } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        # Handle AD server down exception
        Write-Error "Unable to connect to the Active Directory server."
    } catch [System.ArgumentException] {
        # Handle the specific invalid property exception
        if ($_.Exception.Message -match "One or more properties are invalid" -and $_.Exception.InnerException -is [System.ServiceModel.FaultException] -and $_.Exception.InnerException.Message -match "Sorting or Selection Property is invalid") {
            $InvalidPropertyName = $_.Exception.ParamName
            if ($InvalidPropertyName) {
                Write-Warning "Removing invalid property: $InvalidPropertyName"
                
                # Remove the invalid property from the list
                $NewProperties = $Properties -ne $InvalidPropertyName

                # Retry with the new list of properties
                return Retry-GetADUser -Id $Identity -Props $NewProperties
            } else {
                Write-Error "Invalid property not identified."
                throw $_
            }
        } else {
            Write-Error "Argument exception encountered: $_"
            throw $_
        }
    } catch {
        Write-Error "Unknown error: $($_.Exception.Message)"
        throw $_
    }
}
