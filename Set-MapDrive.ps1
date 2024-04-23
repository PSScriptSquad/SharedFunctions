Function Set-MapDrive {
    <#
        .SYNOPSIS
            Maps a network drive to a specified server using specified credentials.
        .DESCRIPTION
            This function maps a network drive to a specified server using specified credentials.
            It checks for any existing mapped drives, removes any problematic ones, and then maps the new drive.
            It can optionally specify a child path for the mapped drive.
        .PARAMETER Server
            Specifies the server to map the drive to.
        .PARAMETER Creds
            Specifies the credentials to use for mapping the drive.
        .PARAMETER ChildPath
            Specifies an optional child path for the mapped drive.
        .EXAMPLE
            Set-MapDrive -Server "ServerName" -Creds $creds
            Maps a drive to \\ServerName using the provided credentials.
        .EXAMPLE
            Set-MapDrive -Server "ServerName" -Creds $creds -ChildPath "Folder"
            Maps a drive to \\ServerName\Folder using the provided credentials.
        .NOTES
            Name: Set-MapDrive
            Author: Ryan Whitlock
            Date: 12.03.2023
            Version: 1.0
            Changes: Added comments
    #>
    param(
        [Parameter(Mandatory=$true,
            ValueFromPipeline=$true,
            Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Server,
        [Parameter(Mandatory=$true,Position = 1)]
        [ValidateNotNull()]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Creds,
        [Parameter(Mandatory=$false,Position = 2)]
        [ValidateNotNullOrEmpty()]
        [string]$ChildPath
    )

    begin {
        # Generate a list of available drive letters from D to Z
        $DriveLetters = [char[]]([int][char]'D'..[int][char]'Z') | ForEach-Object {"$($_):"}
        
        # Get currently mapped drives
        $CurrentDrives = Get-SmbMapping
        
        # Find and remove problematic drives
        $BustedDrives = $CurrentDrives | Where-Object {$_.Status -ne "OK"}
        If ($BustedDrives) {
            Remove-SmbMapping $BustedDrives.LocalPath -UpdateProfile -Force
        }
    }

    process {
        # Check if a drive is already mapped to the specified server
        $FilteredCurrentDrive = $CurrentDrives | Where-Object {$_.RemotePath -match $Server}
        If ($FilteredCurrentDrive) {
            return
        }             
        
        Try {
            # Map the network drive
            (New-Object -ComObject WScript.Network).MapNetworkDrive(
                # Choose an available drive letter
                ($DriveLetters | Where-Object {(Get-SmbMapping).LocalPath -notcontains $_} | Select-Object -Last 1), 
                # Construct the UNC path
                $(Join-Path "\\$($server)" "$($ChildPath)"), 
                $false, 
                # Provide credentials
                $($Creds.UserName), 
                $($Creds.GetNetworkCredential().Password)
            )
        } catch {
            # If mapping fails, catch the exception
            $_.Exception
        }
    }

    end {
        # Return the updated list of mapped drives
        return Get-SmbMapping
    }
}
