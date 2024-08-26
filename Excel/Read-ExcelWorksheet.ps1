function Read-ExcelWorksheet {
    <#
        .SYNOPSIS
            Reads data from a specified worksheet in an Excel file and returns it as an array of PSCustomObjects.

        .DESCRIPTION
            This function opens an Excel spreadsheet, reads data from a named worksheet, and returns the data as an array of 
            PSCustomObjects. Each object represents a row in the worksheet, with properties named according to the column headers.

        .PARAMETER filePath
            The full path to the Excel file.

        .PARAMETER worksheetName
            The name of the worksheet to read data from.

        .EXAMPLE
            $data = Read-ExcelWorksheet -filePath "C:\path\to\your\file.xlsx" -worksheetName "Sheet1"
            $data | ForEach-Object { $_ }
        .NOTES
            Name: Read-ExcelWorksheet
            Author: Ryan Whitlock
            Date: 09.25.2022
            Version: 1.1
            Changes: Fixed empty headers 
    #>
    [CmdletBinding()]
    param (
        # Validate that the file exists
        [ValidateScript({ Test-Path $_ })]
        [System.IO.FileInfo]$FilePath,

        # Name of the worksheet to read from
        [string]$WorksheetName
    )

    # Create Excel COM object
    $Excel = New-Object -ComObject Excel.Application
    $Excel.Visible = $false
    $Excel.DisplayAlerts = $false

    # Open the workbook
    $Workbook = $excel.Workbooks.Open($FilePath)

    try {
        # Get the specified worksheet
        $Worksheet = $Workbook.Sheets.Item($WorksheetName)
        if (-not $worksheet) {
            Write-Error "The worksheet $worksheetName does not exist in the file $filePath."
            return
        }

        # Read data from the worksheet
        $UsedRange = $Worksheet.UsedRange
        $Data = @()

        # Extract header information from the first row
        $Headers = @()
        $LastColumn = $UsedRange.Columns.Count
        for ($col = 1; $col -le $LastColumn; $col++) {
            $HeaderText = $Worksheet.Cells.Item(1, $col).Text.Trim()
            if ($HeaderText -ne "") {
                $Headers += $HeaderText
            } else {
                $LastColumn = $col - 1
                break
            }
        }

        # Iterate over the rows to read the data
        for ($row = 2; $row -le $UsedRange.Rows.Count; $row++) {
            $RowObject = [PSCustomObject]@{}
            $IsRowEmpty = $true

            for ($col = 1; $col -le $LastColumn; $col++) {
                $CellValue = $Worksheet.Cells.Item($row, $col).Text.Trim()
                if ($CellValue -ne "") {
                    $IsRowEmpty = $false
                }
                $RowObject | Add-Member -MemberType NoteProperty -Name $Headers[$col - 1] -Value $CellValue
            }

            # Add non-empty rows to the data array
            if (-not $IsRowEmpty) {
                $Data += $RowObject
            }
        }

        return $Data
    } catch {
        Write-Error "An error occurred: $_"
    } finally {
        # Add a small delay before cleanup to ensure Excel is ready
        Start-Sleep -Seconds 1

        # Clean up
        $RetryCount = 3
        while ($RetryCount -gt 0) {
            try {
                $Workbook.Close($false)
                $Excel.Quit()
                break
            } catch {
                Start-Sleep -Milliseconds 500
                $RetryCount--
                if ($RetryCount -eq 0) {
                    Write-Error "Failed to close Excel properly after multiple attempts: $_"
                }
            }
        }

        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Worksheet) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Workbook) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}
