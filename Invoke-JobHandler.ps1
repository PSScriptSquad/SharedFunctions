function Invoke-JobHandler {
    <#
    .SYNOPSIS
        Waits for PowerShell jobs to reach a terminating state, while tracking progress, with optional handling of Suspended and Disconnected states.

    .DESCRIPTION
        The Invoke-JobHandler cmdlet waits for one or more PowerShell jobs to reach a terminating state before continuing execution. 
        The cmdlet provides the ability to track job progress and handle custom timeout conditions. It also supports waiting for specific jobs
        by ID, Name, or InstanceId, and can filter jobs by their state or other properties using a filter hashtable.

        By default, the cmdlet will stop waiting when all specified jobs are in one of the following terminating states:
        Completed, Failed, Stopped, Suspended, or Disconnected.

        If the -Force parameter is used, the cmdlet will continue waiting for jobs that are in Suspended or Disconnected states 
        until they move to a final state such as Completed, Failed, or Stopped.

        The cmdlet supports both local jobs started using Start-Job and remote jobs created using Invoke-Command with the -AsJob parameter. 
        Custom job types, such as workflow jobs or scheduled jobs, are also supported if the appropriate module defining them is imported 
        into the session.

    .PARAMETER Job
        Specifies the job objects to wait for. This can be provided as a variable that contains job objects or via pipeline input. 
        You can also retrieve job objects by using Get-Job and passing them to Invoke-JobHandler.

    .PARAMETER Id
        Specifies the IDs of jobs to wait for. You can provide one or more job IDs as an array. To get the job IDs, use Get-Job.

    .PARAMETER Name
        Specifies the friendly names of jobs to wait for. You can provide one or more job names. To get the names, use Get-Job.

    .PARAMETER InstanceId
        Specifies the instance IDs (GUIDs) of jobs to wait for. Each instance ID uniquely identifies a job. 
        To get the instance ID of a job, use Get-Job.

    .PARAMETER State
        Specifies a job state to wait for. The cmdlet will wait only for jobs in the specified state (e.g., Running, Completed, Failed, Stopped).

    .PARAMETER Filter
        Specifies a hash table to filter jobs based on their properties. The key is the property name, and the value is the property value. 
        Only jobs that match all conditions in the hash table will be waited for. This parameter is useful for filtering custom job types.

    .PARAMETER Any
        Returns and continues execution as soon as any of the specified jobs reach a terminating state, instead of waiting for all jobs to complete.

    .PARAMETER Timeout
        Specifies the maximum wait time for each job, in seconds. By default, there is no timeout (-1). If a job exceeds the specified timeout, 
        it will be stopped, and execution will continue.

    .PARAMETER Force
        Continues waiting for jobs in the Suspended or Disconnected states. Without the -Force parameter, the cmdlet considers 
        these states as terminating, and the wait ends. With -Force, the cmdlet will continue waiting until the jobs move to a final state 
        (Completed, Failed, or Stopped).

    .PARAMETER ShowProgress
        Displays the progress of the jobs being tracked. The progress bar updates as jobs complete.

    .EXAMPLE
        # Example 1: Wait for all jobs to complete
        Get-Job | Invoke-JobHandler

        This example waits for all jobs running in the current session to complete. It uses pipeline input from Get-Job.

    .EXAMPLE
        # Example 2: Wait for a specific job by ID with a timeout
        Invoke-JobHandler -Id 5 -Timeout 60

        Waits for the job with ID 5 to complete, with a maximum wait time of 60 seconds. If the job is still running after 60 seconds, 
        it will be stopped.

    .EXAMPLE
        # Example 3: Continue waiting even if the job is Suspended or Disconnected
        Invoke-JobHandler -Id 10 -Force

        Waits for the job with ID 10 to complete, even if it enters a Suspended or Disconnected state. Without the -Force parameter, 
        the cmdlet would stop waiting when the job enters either of those states.

    .EXAMPLE
        # Example 4: Wait for jobs in a specific state (e.g., only jobs that are currently running)
        Invoke-JobHandler -State Running

        This waits for all jobs that are currently running in the session. The cmdlet will exit once all running jobs are in a terminating state.

    .EXAMPLE
        # Example 5: Use a filter to wait for jobs with specific properties
        $filter = @{
            Name = "BackupJob"
            State = "Running"
        }
        Invoke-JobHandler -Filter $filter

        This example waits for jobs that have the name "BackupJob" and are currently in the "Running" state. Only jobs that meet both 
        criteria will be waited for.

    .EXAMPLE
        # Example 6: Show progress while waiting for jobs
        Invoke-JobHandler -Name "MyJob" -ShowProgress

        This waits for the job named "MyJob" to complete and shows a progress bar that updates as the job runs.

    .EXAMPLE
        # Example 7: Return as soon as any job completes
        $jobs = Get-Job -Name "Job1", "Job2", "Job3"
        Invoke-JobHandler -Job $jobs -Any

        This example waits for the first job (Job1, Job2, or Job3) to complete and returns immediately, without waiting for all jobs to finish.

    .EXAMPLE
        # Example 8: Wait for remote jobs and handle child jobs
        $remoteJob = Invoke-Command -ComputerName "Server01" -ScriptBlock { Start-Sleep 10 } -AsJob
        Invoke-JobHandler -Job $remoteJob

        This waits for the remote job on Server01 to complete. If the remote job has child jobs, they will be handled and waited for as well.

    .NOTES
        Author: Ryan Whitlock
        Date: 09.16.2024
        Version: 1.0
        Changes: Initial release
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
                [System.Management.Automation.Job[]]$Job,
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
            $TimeoutDuration = [TimeSpan]::FromSeconds($Timeout)

            # Calculate elapsed time
            $ElapsedTime = $(Get-Date) - $Job.PSBeginTime

            # Check if the elapsed time has exceeded the timeout
            if ($ElapsedTime -ge $TimeoutDuration) {
                $ElapsedSeconds = [math]::Round($ElapsedTime.TotalSeconds, 2)
                Write-Warning "Job $($Job.Id) has exceeded the timeout of $($TimeoutDuration.TotalSeconds) seconds. Elapsed time: $ElapsedSeconds seconds."

                # Try to stop the job safely
                try {
                    Stop-Job -Job $Job
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
                    # Job failed before execution, likely connection or setup failure
                    [PSCustomObject]@{
                        'ComputerName' = $Job.Location
                        'Output'       = $null  # No output since the job failed
                        'Error'        = $Job.JobStateInfo.Reason.Message
                        'ErrorType'    = 'JobFailed'
                    }
                } else {
                    try {
                        $Output = Receive-Job -Job $Job -ErrorAction Stop
                        # Return the result without duplicating ComputerName if it's in the output
                        [PSCustomObject]@{
                            'ComputerName' = $Job.Location
                            'Output'       = $Output
                            'Error'        = $null  # No error if execution succeeded
                            'ErrorType'    = $null  # No error type if execution succeeded
                        }
                    } catch {
                        # Execution error on the remote system
                        [PSCustomObject]@{
                            'ComputerName' = $Job.Location
                            'Output'       = $null  # No valid output due to execution failure
                            'Error'        = 'ExecutionError: ' + $_.Exception.Message
                            'ErrorType'    = 'ExecutionError'
                        }
                    }
                }
            }

            # Remove all parent jobs (removing parent jobs also removes child jobs)           
            Get-Job | Where { ($_.Id -in $AllJobs.ParentJobId) -or ($AllJobs.ParentJobId -eq $null) } | Remove-Job
                        
            # Return all results
            return $Results
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
                foreach ($ChildJob in $Job.ChildJobs) {
                    # Add the parent job reference to the child job
                    $ChildJob | Add-Member -MemberType NoteProperty -Name ParentJobId -Value $Job.Id -Force
                    $ChildJob | Add-Member -MemberType NoteProperty -Name ParentJobName -Value $Job.Name -Force
                    $ChildJob
                }
            } else {
                $Job
            }
        }

        $TotalJobsCount = $AllJobs.Count
        $CompletedJobsCount = 0
    }

    process {
        $GetJobFrequency = 5  # Time in seconds to refresh job states with Get-Job
        $ElapsedTimeSinceGetJob = 0  # Track time since last Get-Job
        $JobStateCache = $AllJobs.Clone()  # Clone to maintain current state without frequent Get-Job
           
        while ($true){            
            if ($ElapsedTimeSinceGetJob -ge $GetJobFrequency) {
                # Refresh job states by getting updated job objects (so we reflect their latest states)
                $JobStateCache = $AllJobs | ForEach-Object {
                    if (Get-Job -Id $_.Id -ErrorAction SilentlyContinue) {
                        Get-Job -Id $_.Id
                    } else {
                        Write-Warning "Job with ID $_.Id does not exist."
                    }
                }
                $ElapsedTimeSinceGetJob = 0  # Reset the timer
            }

            # Count jobs that have reached a "final" state (Completed, Failed, Stopped)
            $CompletedJobsCount = ($JobStateCache | Where-Object { $_.State -in 'Completed', 'Failed', 'Stopped' }).Count

            # If Force is NOT used, include Suspended and Disconnected as "completed" states
            if (-not $Force) {
                $CompletedJobsCount += ($JobStateCache | Where-Object { $_.State -in 'Suspended', 'Disconnected' }).Count
            }

            if ($CompletedJobsCount -eq $TotalJobsCount) {
                break
            }
            
            if ($ShowProgress) {
                foreach ($AllJob in $JobStateCache) {
                    $ProgressHelperArg = @{
                        Activity         = "Waiting for jobs to complete"
                        i                = $CompletedJobsCount
                        TotalCount       = $TotalJobsCount
                        CurrentOperation = $AllJob.Location
                    }
                    Write-ProgressHelper @ProgressHelperArg                    
                
                    Start-Sleep -Seconds 1
                    $ElapsedTimeSinceGetJob++
                }        
            } else {
                Start-Sleep -Seconds 1
                $ElapsedTimeSinceGetJob++
            }

            # Invoke timeout handling if applicable
            if ($Timeout -ne -1) {
                foreach ($Job in $JobStateCache) {
                    Invoke-JobTimeoutHandler -Job $Job -Timeout $Timeout
                }
            }

            # If Any is specified, break out if any job completes
            if ($Any -and ($JobStateCache.State -contains "Completed")) {
                break
            }
        }

        if ($ShowProgress) {
            Write-Progress -Activity "Waiting for jobs to complete" -Status "Completed." -Completed
        }
        
        # Stop and remove any orphaned jobs if -Any is used
        if ($Any) {
            # Stop any jobs that are still running to prevent them from being orphaned
            $RunningJobs = $JobStateCache | Where-Object { $_.State -eq 'Running' }
            if ($RunningJobs.Count -gt 0) {
                Write-Verbose "Stopping any remaining running jobs since -Any was used."
                $RunningJobs | ForEach-Object { Stop-Job -Job $_ | Remove-Job -Force}
            }
        }        

        return Get-JobResults -AllJobs $JobStateCache
    }

    end {

    }
}

