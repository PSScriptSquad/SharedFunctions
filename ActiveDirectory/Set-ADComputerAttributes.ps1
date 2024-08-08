function Set-ADComputerAttributes {
    <#
    .SYNOPSIS
        Sets specified Active Directory computer attributes.

    .DESCRIPTION
        This function takes a computer name and a hashtable of Active Directory attributes, and sets the specified attributes on the computer object in Active Directory. It validates that the computer exists in AD and provides feedback on each attribute set operation.

    .PARAMETER ComputerName
        The name of the computer object in Active Directory.

    .PARAMETER ADAttributes
        A hashtable containing the Active Directory attributes and their values to be set on the computer object.

    .EXAMPLE
        $ADAttributes = [PSCustomObject]@{
            useraccountcontro    : 4096
            businesscategory     : Accounting
            division             : Southeast
            info                 : 
            machinerole          : 
            extensionAttribute1  : 127
            roomnumber           : 01.8.106.000
            serialnumber         : MJ079N5L
            destinationindicator : 
            comment              : 
            managedby            : CN=185 TSTs,OU=Users,OU=Groups,DC=example,DC=com
            description          : 
        }
    
        Set-ADComputerAttributes -ComputerName "PC001" -ADAttributes $ADAttributes

    .NOTE
        Name: Set-ADComputerAttributes
        Author: Ryan Whitlock
        Date: 08.07.2024
        Version: 1.0
        Changes: Initial release 
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            try {
                $Identity = Get-ADComputer -Identity $_ -ErrorAction Stop
                if ($Identity) {
                    $true
                } else {
                    throw "A computer with the name '$_' does not exist in Active Directory."
                }
            } catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
                throw "No domain connectivity. Please check your network and domain settings."
            } catch {
                throw "A computer with the name '$_' does not exist in Active Directory."
            }              
        })]
        [ValidateNotNullOrEmpty()]
        [string]$ComputerName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSCustomObject]$ADAttributes
    )

    Process {      
        foreach ($ADAttribute in $ADAttributes.PSObject.Properties) {
            if ($null -ne $ADAttribute.Value -and $ADAttribute.Value -ne '') {
                try {
                    if ($PSCmdlet.ShouldProcess("Computer: $ComputerName", "Set attribute $($ADAttribute.Name) to $($ADAttribute.Value)")) {
                        # Set the attribute on the computer object
                        Set-ADComputer -Identity $ComputerName -Replace @{$ADAttribute.Name = $ADAttribute.Value} -ErrorAction Stop

                        # Validate the attribute was set
                        $updatedComputer = Get-ADComputer -Identity $ComputerName -Properties $ADAttribute.Name -ErrorAction Stop
                        if ($updatedComputer.$($ADAttribute.Name) -eq $ADAttribute.Value) {
                            Write-Output "Successfully set '$($ADAttribute.Name)' to '$($ADAttribute.Value)' on '$ComputerName'." -ForegroundColor Green
                        } else {
                            Write-Error "Failed to set '$($ADAttribute.Name)' to '$($ADAttribute.Value)' on '$ComputerName'."
                        }
                    }
                } catch {
                    Write-Error "Error setting attribute '$($ADAttribute.Name)' on '$ComputerName': $_"
                }
            }
        }            
    }
}
