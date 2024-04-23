function Write-ProgressHelper {
      <#
        .SYNOPSIS
            Write-ProgressHelper writes progress status to the console.
        .DESCRIPTION
            Write-ProgressHelper function helps in displaying progress status in the console window. 
            It calculates and updates the progress bar based on the current position (i), total count, and window size.
            It updates the progress bar only if the window width has changed or if the progress is updated.
        .PARAMETER i
            The current position in the progress.
        .PARAMETER TotalCount
            The total count of items.
        .PARAMETER Activity
            The activity description to display in the progress bar.
        .PARAMETER CurrentOperation
            The description of the current operation to display in the progress bar.
        .EXAMPLE
            Write-ProgressHelper -i 10 -TotalCount 100 -Activity "Processing Files" -CurrentOperation "Copying File1"
            This command displays progress for processing files where 10 files are processed out of 100, with the current operation "Copying File1".
        .NOTES
            Name: Write-ProgressHelper
            Author: Ryan Whitlock
            Date: 06.29.2023
            Version: 1.1
            Changes: Added Parameter for CurrentOperation
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [int]$i,
        [Parameter(Mandatory=$true)]
        [int]$TotalCount,
        [Parameter(Mandatory=$true)]
        [string]$Activity,
        [Parameter(Mandatory=$false)]
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
       Write-Progress -activity $Activity -status "Grouped: $i of $($TotalCount)" -percentComplete (($i / $TotalCount) * 100) -CurrentOperation $CurrentOperation
    }

    # Store last progress completed for comparison
    $LastProgressCompleted = $ProgressCompleted 
}
