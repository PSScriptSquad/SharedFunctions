function Execute-Command {
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
    $pinfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $pinfo.RedirectStandardOutput = $true
    $pinfo.RedirectStandardError = $true
    $pinfo.FileName = $commandPath

    # Setting arguments if provided.
    if ($Arguments) {
        $pinfo.Arguments = $Arguments -join " "
    }

    # Setting the verb if provided.
    if ($sVerb) {
        $pinfo.Verb = $sVerb
    }

    # Creating process object.
    $Process = New-Object -TypeName System.Diagnostics.Process
    $Process.StartInfo = $pinfo

    # Starting the process.
    [Void]$Process.Start()

    # Asynchronously reading standard output and error.
    $outTask = $Process.StandardOutput.ReadToEndAsync()
    $errTask = $Process.StandardError.ReadToEndAsync()

    # Waiting for the process to exit or timeout.
    $bRet = $Process.WaitForExit($TimeoutMilliseconds)

    # If the process did not exit within the timeout, kill it.
    if (-Not $bRet) {
        $Process.Kill()
    }

    # Retrieving the output and error text.
    $outText = $outTask.Result
    $errText = $errTask.Result

    # If the process was killed due to timeout, append an appropriate message to error text.
    if (-Not $bRet) {
        $errText = $errText + ($commandPath + " was killed due to timeout after " + ($TimeoutMilliseconds / 1000) + " seconds")
    }

    # Creating a PSObject to store the result.
    $Result = New-Object -TypeName PSObject -Property ([Ordered] @{
        "ExeFile"  = $commandPath
        "Args"     = $Arguments -join " "
        "ExitCode" = $Process.ExitCode
        "StdOut"   = $outText
        "StdErr"   = $errText
    })

    return $Result
}
