function Execute-Command {
    <#
        .SYNOPSIS
            Execute a command with given parameters and return the result.
        .DESCRIPTION
            This function executes a command with optional arguments, verb, and timeout. It returns an object containing details about the execution, including exit code, standard output, and standard error.        
        .PARAMETER commandPath
            Specifies the path of the command to execute.
        .PARAMETER Arguments
            Specifies an array of arguments to pass to the command.
        .PARAMETER sVerb
            Specifies the verb to use when starting the process.
        .PARAMETER TimeoutMilliseconds
            Specifies the timeout period for the command execution in milliseconds. Default is 300000 milliseconds (5 minutes).        
        .EXAMPLE
            Execute-Command -commandPath "C:\Program Files\MyApp\myapp.exe" -Arguments @("-arg1", "-arg2") -sVerb "runas" -TimeoutMilliseconds 60000
            Executes myapp.exe with arguments -arg1 and -arg2, using the "runas" verb, and a timeout of 60 seconds.        
        .NOTES
            Name: Execute-Command 
            Author: Ryan Whitlock
            Date: 02.01.2024
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$commandPath,

        [Parameter(Mandatory=$false)]
        [String[]]$Arguments,

        [Parameter(Mandatory=$false)]
        [String]$sVerb,

        [Parameter(Mandatory=$false)]
        [Int]$TimeoutMilliseconds = 300000 # 5 minutes
    )

    # Setting process invocation parameters.
    $startInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $startInfo.CreateNoWindow = $true
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.FileName = $commandPath

    # Add arguments if provided
    if (! [String]::IsNullOrEmpty($Arguments)){
        $startInfo.Arguments = $Arguments
    }

    # Add verb if provided
    if (![String]::IsNullOrEmpty($sVerb)) {
        $startInfo.Verb = $sVerb
    }

    # Creating process object.
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo = $startInfo

    # Starting process.
    [Void]$Process.Start()

    # Read standard output and standard error asynchronously
    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()

    # Wait for process to exit
    $bRet = $Process.WaitForExit($TimeoutMilliseconds)

    # If process hasn't exited within timeout, kill it
    if (-Not $bRet) {
        $Process.Kill()
    }

    # Get output and error text
    $outText = $outTask.Result
    $errText = $errTask.Result

    # If process was killed due to timeout, append a message to error text
    if (-Not $bRet) {
        $errText = $errText + ($commandPath + " was killed due to timeout after " + ($TimeoutMilliseconds/1000) + " sec ")
    }

    # Create result object
    $Result = New-Object -TypeName PSObject -Property ([Ordered]@{
        "ExeFile"  = $commandPath
        "Args"     = $Arguments -join " "
        "ExitCode" = $Process.ExitCode
        "StdOut"   = $outText
        "StdErr"   = $errText
    })

    # Return the result object
    return $Result
}
