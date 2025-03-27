function Show-MessageBox {
    <#
    .SYNOPSIS
        Displays a Windows Forms message box centered on the active screen, with an optional timeout.

    .DESCRIPTION
        This function creates a message box using System.Windows.Forms and automatically
        positions it in the center of the screen where the user's mouse is currently located.
        It also supports an optional timeout to auto-close the message box.

    .PARAMETER Message
        The message to display in the message box.

    .PARAMETER Title
        The title of the message box window.

    .PARAMETER Buttons
        The type of buttons to display (e.g., OK, OKCancel, YesNo, etc.).
        Default is 'OK'.

    .PARAMETER Icon
        The icon to display in the message box (e.g., Information, Warning, Error, etc.).
        Default is 'Warning'.

    .PARAMETER DefaultButton
        The default button selection (e.g., Button1, Button2, Button3).
        Default is 'Button1'.

    .PARAMETER Timeout
        (Optional) Time in seconds before the message box automatically closes.
        Must be a non-negative integer. If set to 0, the message box will not close automatically.

    .EXAMPLE
        Show-MessageBox "An error occurred." "Error" -Icon Error

    .EXAMPLE
        Show-MessageBox "Do you want to continue?" "Confirm" -Buttons YesNo -Icon Question -DefaultButton Button2

    .EXAMPLE
        Show-MessageBox "Auto-closing in 5 seconds." "Info" -Timeout 5

    .NOTES
        Name: Show-MessageBox
        Author: Ryan Whitlock
        Date: 03.05.2025
        Version: 1.1
        Changes: Added Timeout validation, improved assembly check
    #>

    [CmdletBinding()]
    [OutputType([System.Windows.Forms.DialogResult])]
    param (
        [Parameter(Mandatory, Position=0)]
        [string]$Message,

        [Parameter(Mandatory, Position=1)]
        [string]$Title,

        [Parameter(Position=2)]
        [System.Windows.Forms.MessageBoxButtons]$Buttons = [System.Windows.Forms.MessageBoxButtons]::OK,

        [Parameter(Position=3)]
        [System.Windows.Forms.MessageBoxIcon]$Icon = [System.Windows.Forms.MessageBoxIcon]::Warning,

        [Parameter(Position=4)]
        [System.Windows.Forms.MessageBoxDefaultButton]$DefaultButton = [System.Windows.Forms.MessageBoxDefaultButton]::Button1,

        [Parameter(Position=5)]
        [ValidateRange(0, [int]::MaxValue)]
        [int]$Timeout = 0
    )

    begin {
        # Load Windows Forms only if not already loaded
        if (-not ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq "System.Windows.Forms" })) {
            Add-Type -AssemblyName System.Windows.Forms
        }

        function Get-ActiveScreenCenter {
            # Get the current mouse position
            [System.Drawing.Point]$MousePosition = [System.Windows.Forms.Cursor]::Position  

            # Find the screen where the mouse is located
            $ActiveScreen = [System.Windows.Forms.Screen]::AllScreens | Where-Object {
                $_.Bounds.Contains($MousePosition)
            }

            # Default to primary screen if no active screen is detected
            if (-not $ActiveScreen) {
                $ActiveScreen = [System.Windows.Forms.Screen]::PrimaryScreen
            }

            # Calculate the center of the active screen
            [int]$ScreenCenterX = [Math]::Round($ActiveScreen.Bounds.Left + ($ActiveScreen.Bounds.Width / 2))
            [int]$ScreenCenterY = [Math]::Round($ActiveScreen.Bounds.Top + ($ActiveScreen.Bounds.Height / 2))

            # Return the screen center as a System.Drawing.Point
            return [System.Drawing.Point]::new($ScreenCenterX, $ScreenCenterY)
        }
    }

    process {
        # Get active screen center using helper function
        [System.Drawing.Point]$ScreenCenter = Get-ActiveScreenCenter

        # Create a small invisible form to act as an owner for the MessageBox
        [System.Windows.Forms.Form]$Form = [System.Windows.Forms.Form]::new()
        $Form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
        $Form.TopMost = $true
        $Form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::None
        $Form.Size = [System.Drawing.Size]::new(1,1)  # Prevent Windows repositioning
        $Form.Location = $ScreenCenter

        # Show the form without making it visible
        $Form.Show()
        $Form.Activate()  # Ensure the message box stays on top
        $Form.Hide()

        # Create a cancellation token source for the timeout
        $CancelTokenSource = [System.Threading.CancellationTokenSource]::new()

        # If a timeout is set, create an async task to close the MessageBox
        if ($Timeout -gt 0) {
            [System.Action[System.Threading.Tasks.Task]]$Action = {
                param($t)
                Write-Debug "Closing message box after $Timeout seconds."
                $Form.Close()
            }
            $Task = [System.Threading.Tasks.Task]::Delay(
                [timespan]::FromSeconds($Timeout), $CancelTokenSource.Token
            ).ContinueWith($Action,
                [System.Threading.Tasks.TaskScheduler]::FromCurrentSynchronizationContext()
            )
        }

        # Show the message box
        [System.Windows.Forms.DialogResult]$Result = [System.Windows.Forms.MessageBox]::Show($Form, $Message, $Title, $Buttons, $Icon, $DefaultButton)

        # Dispose of the form after the message box closes
        $Form.Dispose()

        return $Result
    }

    end {
        # Ensure cleanup of the cancellation token and task
        if ($Timeout -gt 0) {
            try {
                if ($Task.Status -ne 'RanToCompletion') {
                    $CancelTokenSource.Cancel()
                    $Task.Wait()
                    $CancelTokenSource.Dispose()
                }
                $Task.Dispose()
            } catch {
                Write-Debug "Cleanup encountered an issue: $_"
            }
        }
    }
}
