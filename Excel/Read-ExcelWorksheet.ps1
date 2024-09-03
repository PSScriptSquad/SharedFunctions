function Read-ExcelWorksheet {
    <#
        .SYNOPSIS
            Reads data from a specified worksheet in an Excel file and returns it as an array of PSCustomObjects.

        .DESCRIPTION
            This function opens an Excel spreadsheet, reads data from a named worksheet, and returns the data as an array of 
            PSCustomObjects. Each object represents a row in the worksheet, with properties named according to the column headers.

        .PARAMETER FilePath
            The full path to the Excel file.

        .PARAMETER WorksheetName
            The name of the worksheet to read data from.

        .EXAMPLE
            $data = Read-ExcelWorksheet -FilePath "C:\path\to\your\file.xlsx" -WorksheetName "Sheet1"
            $data | ForEach-Object { $_ }
        .NOTES
            Name: Read-ExcelWorksheet
            Author: Ryan Whitlock
            Date: 09.25.2022
            Version: 1.7
            Changes: Added additional validations for worksheet existence, empty worksheet, and cell content length.
    #>
    [CmdletBinding()]
    param (
        # Validate that the file is not null, not empty, exists, is not locked, and has a valid Excel extension
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({
            if (-not (Test-Path $_)) {
                throw "File does not exist: $_"
            }

            # Check if the file is locked by another process
            try {
                $fileStream = [System.IO.File]::Open($_.FullName, 'Open', 'Read', 'Read')
                $fileStream.Close()
            } catch {
                throw "The file '$($_.FullName)' is locked and cannot be accessed."
            }

            $extension = [System.IO.Path]::GetExtension($_)
            if ($extension -notin ".xlsx", ".xlsm", ".xlsb", ".xls") {
                throw "Invalid file extension: $extension. Only .xlsx, .xlsm, .xlsb, and .xls are allowed."
            }
            return $true
        })]
        [System.IO.FileInfo]$FilePath,

        # Name of the worksheet to read from
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$WorksheetName
    )

    begin {
        # Initialize Excel COM object
        $Excel = New-Object -ComObject Excel.Application
        $Excel.Visible = $false
        $Excel.DisplayAlerts = $false
    }

    process {
        # Open the workbook
        $Workbook = $excel.Workbooks.Open($FilePath)

        try {
            # Get the specified worksheet
            $Worksheet = $Workbook.Sheets.Item($WorksheetName)
            if (-not $worksheet) {
                throw "The worksheet '$WorksheetName' does not exist in the file '$FilePath'."
            }

            # Read data from the worksheet
            $UsedRange = $Worksheet.UsedRange

            # Validate that the worksheet is not empty
            if ($UsedRange.Rows.Count -eq 0 -or $UsedRange.Columns.Count -eq 0) {
                throw "The worksheet '$WorksheetName' in the file '$FilePath' is empty."
            }

            # Extract header information from the first row
            $Headers = @()
            $LastColumn = $UsedRange.Columns.Count

            # Check if there are no columns
            if ($LastColumn -lt 1) {
                throw "The worksheet '$WorksheetName' in the file '$FilePath' does not have any columns."
            }

            $HeaderHashSet = [System.Collections.Generic.HashSet[string]]::new()
            $ValidColumns = @()  # Track valid columns with non-empty headers

            for ($col = 1; $col -le $LastColumn; $col++) {
                $HeaderText = $Worksheet.Cells.Item(1, $col).Text.Trim()
                if ($HeaderText -eq "") {
                    # Skip this column if the header is empty
                    continue
                }
                if (-not $HeaderHashSet.Add($HeaderText)) {
                    throw "Duplicate header detected: '$HeaderText'. Headers must be unique."
                }
                $Headers += $HeaderText
                $ValidColumns += $col  # Track the column as valid
            }

            # Iterate over the rows to read the data
            for ($row = 2; $row -le $UsedRange.Rows.Count; $row++) {
                $RowObject = [PSCustomObject]@{}
                $IsRowEmpty = $true

                foreach ($col in $ValidColumns) {
                    $CellValue = $Worksheet.Cells.Item($row, $col).Text.Trim()
                    if ($CellValue.Length -gt 255) {
                        throw "Cell in row $row, column $col exceeds the maximum allowed length of 255 characters."
                    }
                    if ($CellValue -ne "") {
                        $IsRowEmpty = $false
                    }
                    $RowObject | Add-Member -MemberType NoteProperty -Name $Headers[$ValidColumns.IndexOf($col)] -Value $CellValue
                }

                # Output each non-empty row as it's processed
                if (-not $IsRowEmpty) {
                    Write-Output $RowObject
                }
            }

        } catch {
            Write-Error "An error occurred: $_"
        } finally {
            # Clean up workbook COM object
            $Workbook.Close($false)
        }
    }

    end {
        # Ensure cleanup of Excel COM object
        $Excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Worksheet) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Workbook) | Out-Null
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($Excel) | Out-Null
        [System.GC]::Collect()
        [System.GC]::WaitForPendingFinalizers()
    }
}
