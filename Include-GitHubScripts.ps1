function Include-GitHubScripts {
    <#
        .SYNOPSIS
            Imports PowerShell scripts from a specified GitHub repository.

        .DESCRIPTION
            The Include-GitHubScripts function downloads and sources PowerShell scripts from a specified GitHub repository.
            Optionally, it supports authentication using a GitHub username and token for private repositories.

        .PARAMETER Owner
            The owner of the GitHub repository. Defaults to 'PSScriptSquad'.

        .PARAMETER Repository
            The name of the GitHub repository. Defaults to 'SharedFunctions'.

        .PARAMETER Path
            The path within the repository. Defaults to the root directory.

        .PARAMETER ScriptFileNames
            The names of the script files to be imported. This parameter is mandatory.

        .PARAMETER User
            (Optional) The GitHub username for authentication.

        .PARAMETER Token
            (Optional) The GitHub token for authentication.

        .EXAMPLE
            . Include-GitHubScripts -ScriptFileNames @("Test-IPInRange.ps1") -Verbose

        .EXAMPLE
            . Include-GitHubScripts -Owner "MyUser" -Repository "MyRepo" -Path "Scripts" -ScriptFileNames @("Script1.ps1", "Script2.ps1") -User "MyUser" -Token "MyToken" -Verbose
        
        .NOTES
            Name: Include-GitHubScripts
            Author: Ryan Whitlock
            Date: 07.12.2024
            Version: 1.0
            Changes: Initial release
    #>
    [CmdletBinding()]
    Param(
        [string]$Owner = 'PSScriptSquad',
        [string]$Repository = 'SharedFunctions',
        [string]$Path = '',
        [Parameter(Mandatory = $true)]
        [string[]]$ScriptFileNames,
        [string]$User,
        [string]$Token
    )

    Begin {
        function Validate-Uri {
            param (
                [string]$Uri
            )
            try {
                [void][System.Uri]::IsWellFormedUriString($Uri, [System.UriKind]::Absolute)
                return $true
            } catch {
                return $false
            }
        }

        function Download-And-Source-Script {
            param (
                [string]$DownloadUrl,
                [hashtable]$Headers = $null
            )
            try {
                $DownloadedContent = Invoke-WebRequest -Uri $DownloadUrl -Headers $Headers -ErrorAction Stop
                . ([ScriptBlock]::Create($DownloadedContent.Content))
                Write-Verbose "Successfully imported script from $DownloadUrl"
            } catch {
                Write-Error "Unable to download or source script from '$DownloadUrl'. Error: $_"
            }
        }

        $BaseUri = "https://api.github.com/repos/$Owner/$Repository/contents/$Path"
        if (-not (Validate-Uri -Uri $BaseUri)) {
            Write-Error "The URI '$BaseUri' is not valid."
            return
        }

        $Headers = @{}
        if ($PSBoundParameters.ContainsKey('User') -and $PSBoundParameters.ContainsKey('Token')) {
            $AuthPair = "$($User):$($Token)"
            $EncAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($AuthPair))
            $Headers.Authorization = "Basic $EncAuth"
        }

        try {
            $WebResponse = Invoke-WebRequest -Uri $BaseUri -Headers $Headers -ErrorAction Stop
            $ContentObjects = $WebResponse.Content | ConvertFrom-Json
        } catch {
            Write-Error "Failed to retrieve content from GitHub repository. Error: $_"
            return
        }
    }

    Process {
        $Files = ($ContentObjects | Where-Object { $_.type -eq "file" }).download_url
        $Directories = $ContentObjects | Where-Object { $_.type -eq "dir" }

        foreach ($Directory in $Directories) {
            . Include-GitHubScripts -Owner $Owner -Repository $Repository -Path $Directory.path -ScriptFileNames $ScriptFileNames -User $User -Token $Token
        }

        foreach ($File in $Files) {
            $FileName = [System.IO.Path]::GetFileName($File)
            if ($ScriptFileNames -contains $FileName) {
                . Download-And-Source-Script -DownloadUrl $File -Headers $Headers
            }
        }
    }

    End {
        Write-Verbose "Completed importing scripts from GitHub."
    }
}
