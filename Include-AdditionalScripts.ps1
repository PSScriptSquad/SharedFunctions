function Include-AdditionalScripts {
    <#
        .SYNOPSIS
            Function to include additional PowerShell script files based on the environment.
        .DESCRIPTION
            The Include-AdditionalScripts function includes specified PowerShell script files
            based on the environment in which the script is running (PowerShell ISE, VS Code,
            or other environments). It recursively searches for script files in the specified
            Functions directory and executes them.
        .EXAMPLE
            Include-AdditionalScripts -ScriptFileNames @("Get-ADUserProperties.ps1")
            Includes the script file 'Get-ADUserProperties.ps1' in the current PowerShell environment.
        .NOTES
            Author: Ryan Whitlock
            Date: 06.20.2024
            Version: 1.1
            Changes: Cleaned up code and added comments.
    #>
     param (
        [string[]]$ScriptFileNames
    )

    # Determine the base path for the Functions directory
    $basePath = if ($psISE) {
        Split-Path $psISE.CurrentFile.FullPath
    } elseif ($env:TERM_PROGRAM -eq 'vscode') {
        $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\')
    } else {
        $PSScriptRoot
    }

    # Join the base path with the Functions directory
    $functionsPath = Join-Path -Path $basePath -ChildPath 'Functions'

    # Get the script files and include them
    Get-ChildItem -Path $functionsPath -Recurse -Include $ScriptFileNames | ForEach-Object {
        . $_.FullName
    }
}
