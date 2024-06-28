function Read-ExcelWorksheet {
    <#
        .SYNOPSIS
            Reads data from a specified worksheet in an Excel file and returns it as an array of PSCustomObjects.

        .DESCRIPTION
            This function opens an Excel spreadsheet, reads data from a named worksheet, and returns the data as an array of PSCustomObjects. 
            Each object represents a row in the worksheet, with properties named according to the column headers.

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
            Version: 1.0
            Changes: Initial release 
    #>
    [CmdletBinding()]
    param (
        # Validate that the file exists
        [ValidateScript({ Test-Path $_ })]
        [string]$filePath,

        # Name of the worksheet to read from
        [string]$worksheetName
    )

    # Create Excel COM object
    $excel = New-Object -ComObject Excel.Application
    $excel.Visible = $false
    $excel.DisplayAlerts = $false

    # Open the workbook
    $workbook = $excel.Workbooks.Open($filePath)

    try {
        # Get the specified worksheet
        $worksheet = $workbook.Sheets.Item($worksheetName)
        if (-not $worksheet) {
            Write-Error "The worksheet $worksheetName does not exist in the file $filePath."
            return
        }

        # Read data from the worksheet
        $usedRange = $worksheet.UsedRange
        $data = @()

        # Extract header information from the first row
        $headers = @()
        for ($col = 1; $col -le $usedRange.Columns.Count; $col++) {
            $headers += $worksheet.Cells.Item(1, $col).Text
        }

        # Iterate over the rows to read the data
        for ($row = 2; $row -le $usedRange.Rows.Count; $row++) {
            $rowObject = [PSCustomObject]@{}
            $isRowEmpty = $true

            for ($col = 1; $col -le $usedRange.Columns.Count; $col++) {
                $cellValue = $worksheet.Cells.Item($row, $col).Text
                if ($cellValue -ne "") {
                    $isRowEmpty = $false
                }
                $rowObject | Add-Member -MemberType NoteProperty -Name $headers[$col - 1] -Value $cellValue
            }

            # Add non-empty rows to the data array
            if (-not $isRowEmpty) {
                $data += $rowObject
            }
        }

        return $data
    } catch {
        Write-Error "An error occurred: $_"
    } finally {
        # Clean up
        $workbook.Close($false)
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($worksheet) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($workbook) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}
