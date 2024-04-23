Function Start-AsJobHandler {
    <#
      .SYNOPSIS
          Start-AsJobHandler asynchronously receives jobs from Invoke-Command.
      .DESCRIPTION
          Start-AsJobHandler asynchronously receives jobs from Invoke-Command. It provides progress indication and collects results from the jobs. If any job fails, it gathers error information. 
          After completion, it returns responding and non-responding systems along with their output or error messages.
      .PARAMETER ProgressBarMsg
          Specifies the message to display in the progress bar. Default is "Collecting Data...".
      .EXAMPLE
          Start-AsJobHandler -ProgressBarMsg "Processing..."
          This command starts the job handler with a custom progress bar message "Processing..."
      .NOTES
          Name: Start-AsJobHandler 
          Author: Ryan Whitlock
          Date: 06.06.2023
          Version: 1.0
          Changes: Added comments, improved clarity and readability.
  #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$ProgressBarMessage = "Collecting Data..."
    )

    # Check if there are any jobs to handle
    if($null -eq $(Get-Job)){
        throw "There are no jobs"
    }

    # Handle the jobs and provide progress indication
    while((Get-Job).HasMoreData -and (Get-Job).State -eq "Running"){
        foreach ($job in (Get-Job).ChildJobs){
            $ProgressHelperArg = @{
                Activity = $ProgressBarMessage
                i = ((Get-Job).ChildJobs | Where-Object {($_.State -eq "Completed") -or ($_.State -eq "Failed")}).Count
                TotalCount = ((Get-Job).ChildJobs).Count
                CurrentOperation = $job.location
            }

            Write-ProgressHelper @ProgressHelperArg
            Start-Sleep -Seconds 1 
        }   
    }
    Write-Progress -Activity $ProgressBarMsg -Status "Completed." -Completed

    # Collect job data and handle errors
    $notRespondingSystems = @()
    $RespondingSystems = foreach ($job in (Get-Job).ChildJobs){
        If ($Job.JobStateInfo.State -eq 'Failed'){
            $notRespondingSystems += [PSCustomObject]@{
                'Computer Name' = $Job.Location
                'Error' = $Job.JobStateInfo.Reason.Message
            }
        }else{
             $Job.Output
        }
    }

    # Clean up Jobs    
    Get-Job | Stop-Job 
    Get-Job | Remove-Job

    # Return responding and non-responding systems
    return [PSCustomObject]@{
        RespondingSystems = $RespondingSystems
        notRespondingSystems = $notRespondingSystems
    }
}
