function Invoke-ExternalCommand {
    <#
        .SYNOPSIS
            Executes an external command and captures its output.

        .DESCRIPTION
            This function executes an external command with optional arguments, a verb, and a timeout.
            It returns a PSObject containing details about the execution: the executable file,
            arguments, exit code, standard output, and standard error. If the process exceeds the 
            specified timeout, it is terminated.

        .PARAMETER CommandPath
            Specifies the full path to the executable command to run. The file must exist.

        .PARAMETER Arguments
            Specifies an array of command-line arguments to pass to the executable.

        .PARAMETER Verb
            Specifies the verb to use when starting the process (e.g. "runas" for elevation).

        .PARAMETER TimeoutMilliseconds
            Specifies the maximum time, in milliseconds, to wait for the command to complete.
            The default is 300000 (5 minutes).

        .INPUTS
            System.String. The CommandPath must be a valid string path to an executable file.

        .OUTPUTS
            PSObject. An object with the following properties:
                ExeFile  - The path to the executable.
                Args     - The command-line arguments as a single string.
                ExitCode - The exit code of the process.
                StdOut   - The standard output from the process.
                StdErr   - The standard error from the process.

        .EXAMPLE
            Invoke-ExternalCommand -CommandPath "C:\Program Files\MyApp\myapp.exe" |
                -Arguments @("-arg1", "-arg2") -Verb "runas" -TimeoutMilliseconds 60000

            This example runs myapp.exe with arguments -arg1 and -arg2 using the "runas" verb,
            with a timeout of 60 seconds.

        .NOTES
            Author: Ryan Whitlock
            Date: 02.01.2024
            Version: 1.3
            Changes: The output object is now written from the process block only.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({ Test-Path $_ -PathType Leaf })]
        [string]$CommandPath,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Arguments,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]$Verb,

        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 2147483647)]
        [int]$TimeoutMilliseconds = 300000
    )

    begin {
        # Configure the ProcessStartInfo.
        $startInfo = New-Object -TypeName System.Diagnostics.ProcessStartInfo
        $startInfo.CreateNoWindow          = $true
        $startInfo.UseShellExecute         = $false
        $startInfo.RedirectStandardOutput  = $true
        $startInfo.RedirectStandardError   = $true
        $startInfo.FileName                = $CommandPath

        if ($Arguments -and $Arguments.Count -gt 0) {
            # Combine arguments into a single command-line string.
            $startInfo.Arguments = $Arguments -join " "
        }

        if (![string]::IsNullOrEmpty($Verb)) {
            $startInfo.Verb = $Verb
        }

        # Create the process object.
        $processObject = New-Object -TypeName System.Diagnostics.Process
        $processObject.StartInfo = $startInfo
    }

    process {
        try {
            if (-not $processObject.Start()) {
                Write-Error "Failed to start process: $CommandPath"
                return  # Flow-control exit from process block.
            }

            # Read standard output and error asynchronously.
            $stdOutTask = $processObject.StandardOutput.ReadToEndAsync()
            $stdErrTask = $processObject.StandardError.ReadToEndAsync()

            # Wait for the process to exit within the specified timeout.
            $exited = $processObject.WaitForExit($TimeoutMilliseconds)

            if (-not $exited) {
                $processObject.Kill()
            }

            # Retrieve outputs.
            $stdOutText = $stdOutTask.Result
            $stdErrText = $stdErrTask.Result

            if (-not $exited) {
                $stdErrText += " Process was terminated due to timeout after $($TimeoutMilliseconds/1000) seconds."
            }

            # Construct the result object.
            $commandResult = [PSCustomObject]@{
                ExeFile  = $CommandPath
                Args     = if ($Arguments) { $Arguments -join " " } else { "" }
                ExitCode = $processObject.ExitCode
                StdOut   = $stdOutText
                StdErr   = $stdErrText
            }

            # Write the result from the process block.
            Write-Output $commandResult
        }
        catch {
            Write-Error "An error occurred while executing the command: $_"
        }
    }

    end {
        # Dispose of the process object.
        if ($processObject) {
            $processObject.Dispose()
        }
    }
}
