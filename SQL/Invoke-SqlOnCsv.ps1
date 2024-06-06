function Invoke-SqlOnCsv {
    <#
        .SYNOPSIS
            Executes an SQL query on a CSV or TSV file and returns the results as a DataTable.
        .DESCRIPTION
            This function uses the Microsoft.Jet.OLEDB.4.0 provider to execute an SQL query on a specified CSV or TSV file.
            It supports specifying whether the CSV/TSV file contains headers and allows for setting the delimiter.
        .PARAMETER CsvFilePath
            The path to the CSV or TSV file on which to execute the SQL query. The file must have a .csv or .tsv extension.
        .PARAMETER SqlQuery
            The SQL query to execute on the CSV or TSV file.
        .PARAMETER Headers
            A switch indicating whether the first row of the CSV or TSV file contains headers.
        .PARAMETER Delimiter
            The delimiter used in the file. Valid options are ',' for comma and 't' for tab.
        .EXAMPLE
            Invoke-SqlOnCsv -CsvFilePath "C:\data\example.csv" -SqlQuery "SELECT * FROM example.csv" -Headers -Delimiter ","
            This example executes the SQL query "SELECT * FROM example.csv" on the specified CSV file with headers and a comma delimiter.
        .NOTES
            Name: Invoke-SqlOnCsv 
            Author: Ryan Whitlock
            Date: 05.05.2024
            Version: 1
            Changes: Initial Version
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [ValidateScript({Test-Path $_ -and $_.Extension -match ".csv|.tsv"})]
        [System.IO.FileInfo]$CsvFilePath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlQuery,

        [Parameter(Mandatory=$false)]
        [switch]$Headers,

        [Parameter(Mandatory=$false)]
        [ValidateSet(",","t")]
        $Delimiter = ","
    )
    begin{
        # The Text OleDB driver is only available in PowerShell x86. Start x86 shell if using x64.
        # This has to be the first check this script performs.
        if ($env:Processor_Architecture -ne "x86")   { 
	        Write-Warning "Switching to x86 shell"
	        &"$env:windir\syswow64\windowspowershell\v1.0\powershell.exe" "$PSCommandPath $args"; return 
        }

        # Initialize a new DataTable object to store query results
        $DataTable = New-Object System.Data.DataTable

        # Setup the data source path by extracting the directory from the file path
        $DataSource = $CsvFilePath.DirectoryName

        try {
            # Initialize the OleDbConnection object
            $Connection = New-Object System.Data.OleDb.OleDbconnection
            # Setup OleDB using Microsoft Text Driver.
            $ConnectionString = "Provider=Microsoft.Jet.OLEDB.4.0;Data Source=$DataSource;Extended Properties='text;HDR=$($Headers.IsPresent);FMT=Delimited($Delimiter)';"
            $Connection.ConnectionString = $ConnectionString

            # Open the connection
            $Connection.Open()

        } catch {
            # Throw an error if connection fails
            Throw "Failed to connect to the CSV file '$CsvFilePath': $($_.Exception.Message)"
        }
    }
    Process{ 
        try {
           # Initialize the OleDbCommand object
           $Command = New-Object System.Data.OleDB.OleDBCommand
           $Command.Connection = $Connection
           $Command.CommandText = $SqlQuery

           # Execute the query and load the results into the DataTable
           $Reader = $Command.ExecuteReader()
           $DataTable.Load($Reader)
        } catch {
            Throw "Failed to execute SQL query: $SqlQuery. Error: $($_.Exception.Message)"
        }
    }
    End{
        try {
            # Close the SQL connection
            $Connection.Close()
            # return the populated DataTable
            return $DataTable
        } catch {
            Throw "Failed to close connection: $($_.Exception.Message)"
        }
    }
}
