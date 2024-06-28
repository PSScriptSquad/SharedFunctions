function Get-XlsxFile {
    <#
        .SYNOPSIS
            Opens a file dialog to browse and select an Excel spreadsheet file (.xlsx).

        .DESCRIPTION
            This function displays an OpenFileDialog to the user, allowing them to browse for and select a spreadsheet file with the .xlsx extension. The initial directory is set to the user's Downloads folder. The function returns the full path of the selected file.

        .PARAMETER None
            This function does not take any parameters.

        .EXAMPLE
            $selectedFile = Get-XlsxFile
            Write-Output "Selected file path: $selectedFile"

        .NOTES
            Author: Ryan Whitlock
            Date: 09.25.2022
            Version: 1.1
    #>
    # Load necessary assembly for Windows Forms
    Add-Type -AssemblyName System.Windows.Forms

    # Get current user's username
    $curuser = [Environment]::UserName

    # Initialize OpenFileDialog with specific properties
    $FileBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
        InitialDirectory = "C:\Users\$curuser\Downloads"
        Filter = 'Spreadsheet Files (*.xlsx)|*.xlsx'
        Title = "Select an Excel File to Process"
    }

    # Show the dialog and capture the result
    $result = $FileBrowser.ShowDialog()

    # Check if the user selected a file
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        # Return the selected file path
        return $FileBrowser.FileName
    } else {
        # Return null if no file was selected
        return $null
    }
}
