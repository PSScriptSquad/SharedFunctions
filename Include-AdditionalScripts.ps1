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
            Version: 1.0
            Changes: Initial release
    #>
     param (
        [string[]]$ScriptFileNames
    )

    # Check the current environment and include script files accordingly
    if ($psISE){
        (Get-ChildItem (Join-Path (Split-Path $psISE.CurrentFile.FullPath) Functions) -Recurse -Include $ScriptFileNames) | ForEach-Object {. $_.FullName}
    }elseif($env:TERM_PROGRAM -eq 'vscode'){
        (Get-ChildItem (Join-Path $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath('.\') Functions) -Recurse -Include $ScriptFileNames) | ForEach-Object {. $_.FullName}
    }else{
        (Get-ChildItem (Join-Path $PSScriptRoot Functions) -Recurse -Include $ScriptFileNames) | ForEach-Object {. $_.FullName}
    }
}
