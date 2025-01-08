function Invoke-JobHandler {
    <#
    .SYNOPSIS
        Waits for PowerShell jobs to reach a terminating state, while tracking progress.

    .DESCRIPTION
        The Invoke-JobHandler cmdlet waits for a job to be in a terminating state before continuing execution. The terminating states are:
        Completed, Failed, Stopped, Suspended, and Disconnected. 

        You can wait until a specified job, or all jobs, are in a terminating state. You can also set a maximum wait time for the job using 
        the Timeout parameter, or use the Force parameter to wait for a job in the Suspended or Disconnected states.

        This cmdlet supports local jobs started using Start-Job, and remote jobs created using Invoke-Command with the -AsJob parameter. 
        Custom job types, such as workflow jobs or scheduled jobs, are also supported if the module defining them is imported into the session.

    .PARAMETER Job
        Specifies the jobs for which this cmdlet waits. Enter a variable that contains the job objects or a command 
        that gets the job objects. You can also use a pipeline operator to send job objects to the Invoke-JobHandler cmdlet. 
        By default, Invoke-JobHandler waits for all jobs created in the current session.

    .PARAMETER Id
        Specifies an array of IDs of jobs for which this cmdlet waits.

        The ID is an integer that uniquely identifies the job in the current session. It is easier to remember and type than the instance ID, 
        but it is unique only in the current session. You can type one or more IDs, separated by commas. To find the ID of a job, type Get-Job.

    .PARAMETER Name
        Specifies friendly names of jobs for which this cmdlet waits.

    .PARAMETER InstanceId
        Specifies an array of instance IDs of jobs for which this cmdlet waits. The default is all jobs.

        An instance ID is a GUID that uniquely identifies the job on the computer. To find the instance ID of a job, use Get-Job.

    .PARAMETER State
        Specifies a job state. This cmdlet waits only for jobs in the specified state (e.g., Completed, Running, Failed).

    .PARAMETER Filter
        Specifies a hash table of conditions. This cmdlet waits for jobs that satisfy all of the conditions in the hash table. 
        Enter a hash table where the keys are job properties and the values are job property values.

        This parameter works only on custom job types, such as workflow jobs and scheduled jobs. It does not work on standard jobs, 
        such as those created by using the Start-Job cmdlet. For information about support for this parameter, see the help topic for the job type.

    .PARAMETER Any
        Indicates that this cmdlet returns the job object and continues execution when any job finishes. By default, 
        Invoke-JobHandler waits until all of the specified jobs are complete before it displays the prompt.

    .PARAMETER Timeout
        Specifies the maximum wait time for each job, in seconds. The default value, -1, indicates that the cmdlet waits 
        until the job finishes. The timing starts when the job starts.

        If this time is exceeded, the wait ends and execution continues, even if the job is still running. The command does 
        not display any error message.

    .PARAMETER Force
        Indicates that this cmdlet continues to wait for jobs in the Suspended or Disconnected state. By default, Invoke-JobHandler returns, 
        or ends the wait, when jobs are in one of the following states:
            Completed
            Failed
            Stopped
            Suspended
            Disconnected
        
    .PARAMETER ShowProgress
        Indicates that this cmdlet should show progress of the Job(s) it is waiting for. 

    .EXAMPLE
        Get-Job | Invoke-JobHandler

        This command waits for all of the jobs running in the current session to finish.

    .EXAMPLE
        Invoke-JobHandler -Id 5 -Force

        Waits for the job with ID 5 to complete, waiting even if it is in a Suspended or Disconnected state.
    #>

    [CmdletBinding(DefaultParameterSetName = 'IdParameterSet')]
    [OutputType([PSCustomObject])]
    param (
        [Parameter(Mandatory = $true, 
            Position = 0, 
            ValueFromPipeline = $true, 
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName = 'JobParameterSet')]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.Job[]]$Job,

        [Parameter(Mandatory = $true, 
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName = 'IdParameterSet')]
        [ValidateNotNullOrEmpty()]
        [Int32[]]$Id,

        [Parameter(Mandatory = $true, 
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName = 'NameParameterSet')]
        [ValidateNotNullOrEmpty()]
        [String[]]$Name,

        [Parameter(Mandatory = $true, 
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName = 'InstanceIdParameterSet')]
        [ValidateNotNullOrEmpty()]
        [Guid[]]$InstanceId,

        [Parameter(Mandatory = $true, 
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ParameterSetName = 'StateParameterSet')]
        [ValidateSet('NotStarted', 'Running', 'Completed', 'Failed', 'Stopped', 'Blocked', 'Suspended', 'Disconnected', 'Suspending', 'Stopping', 'AtBreakpoint')]
        [String]$State,

        [Parameter(Mandatory = $true, 
            Position = 0,
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true,
            ParameterSetName = 'FilterParameterSet')]
        [ValidateNotNullOrEmpty()]
        [Hashtable]$Filter,

        [Parameter()]
        [switch]$Any,

        [Parameter()]
        [Alias('TimeoutSec')]
        [ValidateRange(-1, [Int32]::MaxValue)]
        [int]$Timeout = -1,

        [Parameter()]
        [switch]$Force,

        [Parameter()]
        [switch]$ShowProgress
    )

    begin {
        # Helper functions and scriptblocks
        function Write-ProgressHelper {
            [CmdletBinding()]
            param(
                [int]$i,
                [int]$TotalCount,
                [string]$Activity,
                [string]$CurrentOperation = ""
            )

            # Check if the window width has changed
            $WindowWidthChanged = $WindowWidth -ne $Host.UI.RawUI.WindowSize.Width

            # Update the window width if changed
            if ($WindowWidthChanged) { 
                $WindowWidth = $Host.UI.RawUI.WindowSize.Width 
            }

            # Calculate the progress completed based on the current position
            $ProgressCompleted = [math]::floor($i * $WindowWidth / $TotalCount)

            # Update progress only if the window width has changed or progress has been updated
            if ($WindowWidthChanged -or $ProgressCompleted -ne $LastProgressCompleted) {
               Write-Progress -activity $Activity -status "Processed: $i of $($TotalCount)" -percentComplete (($i / $TotalCount) * 100) -CurrentOperation $CurrentOperation
            }

            # Store last progress completed for comparison
            $LastProgressCompleted = $ProgressCompleted 
        }

        # function to handle job timeouts
        function Invoke-JobTimeoutHandler {
            param (
                [System.Management.Automation.Job]$Job,
                [int]$Timeout
            )

            # If the job hasn't started yet or is in a non-running state, return
            if ($null -eq $Job.PSBeginTime) {
                Write-Verbose "Job $($Job.Id) has not started yet."
                return
            }

            # No need to timeout jobs that are already completed or not in a running state
            if ($Job.State -in 'Completed', 'Failed', 'Stopped') {
                Write-Verbose "Job $($Job.Id) is already in a final state: $($Job.State)."
                return
            }

            # Convert the timeout to a timespan for easy comparison
            $TimeoutDuration = [TimeSpan]::FromMinutes($Timeout)

            # Calculate elapsed time
            $ElapsedTime = $(Get-Date) - $Job.PSBeginTime

            # Check if the elapsed time has exceeded the timeout
            if ($ElapsedTime -ge $TimeoutDuration) {
                $ElapsedSeconds = [math]::Round($ElapsedTime.TotalSeconds, 2)
                Write-Warning "Job $($Job.Id) has exceeded the timeout of $($TimeoutDuration.TotalSeconds) seconds. Elapsed time: $ElapsedSeconds seconds."

                # Try to stop the job safely
                try {
                    Stop-Job -Job $Job -Force
                    Write-Verbose "Job $($Job.Id) has been stopped."
                }
                catch {
                    Write-Error "Failed to stop job $($Job.Id). Error: $_"
                }
            }
            else {
                Write-Verbose "Job $($Job.Id) is still within the timeout period."
            }
        }
        
        function Get-JobResults {
            param (
                [System.Management.Automation.Job[]]$AllJobs               
            )
            # Collect results and errors
            $Results = foreach ($Job in $AllJobs) {
                if ($Job.State -eq 'Failed') {
                    [PSCustomObject]@{
                        'ComputerName' = $Job.Location
                        'Error'        = $Job.JobStateInfo.Reason.Message
                    }
                } else {
                    try {
                        $Output = Receive-Job -Job $Job -ErrorAction Stop
                        [PSCustomObject]@{
                            'ComputerName' = $Job.Location
                            'Output'       = $Output
                        }
                    } catch {
                        [PSCustomObject]@{
                            'ComputerName' = $Job.Location
                            'Error'        = $_.Exception.Message
                        }
                    }
                }
            }

            # Remove all parent jobs (removing parent jobs also removes child jobs)
            $ParentJobs = Get-Job | Where-Object { $_.ChildJobs.Count -eq 0 }
            $ParentJobs | ForEach-Object { Remove-Job -Job $_ }

            # Return responding and non-responding systems
            return [PSCustomObject]@{
                RespondingSystems    = $Results | Where-Object { -not $_.Error }
                NotRespondingSystems = $Results | Where-Object { $_.Error }
            }
        }   
      

        # End helper functions
        
        switch ($PSCmdlet.ParameterSetName) {
            'JobParameterSet' {
                $jobsToWaitFor = $Job
            }
            'IdParameterSet' {
                $jobsToWaitFor = Get-Job -Id $Id
            }
            'NameParameterSet' {
                $jobsToWaitFor = Get-Job -Name $Name
            }
            'InstanceIdParameterSet' {
                $jobsToWaitFor = Get-Job -InstanceId $InstanceId
            }
            'StateParameterSet' {
                $jobsToWaitFor = Get-Job | Where-Object { $_.State -eq $State }
            }
            'FilterParameterSet' {
                $jobsToWaitFor = Get-Job | Where-Object {
                    $Match = $true
                    foreach ($Key in $Filter.Keys) {
                        if ($_.PSObject.Properties[$Key] -ne $Filter[$Key]) {
                            $Match = $false
                            break
                        }
                    }
                    $Match                    
                }
            }
            default {
                $jobsToWaitFor = Get-Job
            }
        }

        # Check if there are any jobs to handle
        if ($null -eq $jobsToWaitFor -or $jobsToWaitFor.Count -eq 0) {
            throw "There are no jobs to wait for!"
        }

        # Handle remote jobs and ensure that child jobs are included for tracking
        $AllJobs = foreach ($Job in $jobsToWaitFor) {
            if ($Job.PSJobTypeName -eq "RemoteJob"){
                $Job.ChildJobs
            } else {
                $Job
            }
        }

        $TotalJobsCount = $AllJobs.Count
        $CompletedJobsCount = 0
    }

    process {        
        while ($true){
            # Refresh job states by getting updated job objects (so we reflect their latest states)
            $AllJobs = $AllJobs | ForEach-Object { Get-Job -Id $_.Id }

            # Count jobs that have reached a "final" state (Completed, Failed, Stopped) or are in states we care about
            $CompletedJobsCount = ($AllJobs | Where-Object { $_.State -in 'Completed', 'Failed', 'Stopped' }).Count

            # If Force is NOT used, include Suspended and Disconnected as "completed" states
            if (-not $Force) {
                $CompletedJobsCount += ($AllJobs | Where-Object { $_.State -in 'Suspended', 'Disconnected' }).Count
            }

            # If all jobs are completed (depending on the Force parameter), break the loop
            if ($CompletedJobsCount -eq $TotalJobsCount) {
                break
            }
            
            if ($ShowProgress) {
                foreach ($AllJob in $AllJobs) {
                    $ProgressHelperArg = @{
                        Activity         = "Waiting for jobs to complete"
                        i                = $CompletedJobsCount
                        TotalCount       = $TotalJobsCount
                        CurrentOperation = $AllJob.Location
                    }
                    Write-ProgressHelper @ProgressHelperArg                    
                
                    Start-Sleep -Seconds 1
                }        
            } else {
                Start-Sleep -Seconds 1
            }

            # Invoke timeout handling if applicable
            if ($Timeout -ne -1) {
                foreach ($Job in $AllJobs) {
                    Invoke-JobTimeoutHandler -Job $Job -Timeout $Timeout
                }
            }

            # If Any is specified, break out if any job completes
            if ($Any -and ($AllJobs.State -contains "Completed")) {
                break
            }
        }

        if ($ShowProgress) {
            Write-Progress -Activity "Waiting for jobs to complete" -Status "Completed." -Completed
        }

        return Get-JobResults -AllJobs $AllJobs
    }

    end {

    }
}
