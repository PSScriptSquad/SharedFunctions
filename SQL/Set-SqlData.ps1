function Set-SqlData {
  <#
    .SYNOPSIS
        This function bulk inserts data into a SQL Server table.
    .DESCRIPTION
        Set-SqlData takes a PSObject as input and bulk inserts it into a specified SQL Server table. It uses SQL Bulk Copy to efficiently transfer large amounts of data.
    .PARAMETER data
        The data to be inserted into the SQL Server table. This should be a PSObject.
    .PARAMETER server
        The name of the SQL Server instance.
    .PARAMETER database
        The name of the database to insert the data into.
    .PARAMETER table
        The name of the table to insert the data into.
    .PARAMETER batchsize
        The number of rows to be sent in each batch to the SQL Server.
    .EXAMPLE
        $data | Set-SqlData -server "ServerName" -database "DatabaseName" -table "TableName"
        This command inserts data from the $data PSObject into the specified SQL Server table.
    .NOTES
        Name: Set-SqlData
        Author: Ryan Whitlock
        Date: 06.07.2023
        Version: 1.1
        Changes: Added comments, improved clarity and readability.
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory=$true, ValueFromPipeline)]
        [ValidateNotNullOrEmpty()]
        [PSObject]$data,

        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$server,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$database,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [String]$table,

        [parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [int32]$batchsize = 50000
    )

    Begin {
        # Build the SQL bulk copy connection and set the timeout to infinite
        $connectionstring = "Data Source=$server;Integrated Security=true;Initial Catalog=$database;"
        $bulkcopy = New-Object Data.SqlClient.SqlBulkCopy($connectionstring, [System.Data.SqlClient.SqlBulkCopyOptions]::TableLock)
        $bulkcopy.DestinationTableName = $table
        $bulkcopy.BulkCopyTimeout = 0
        $bulkcopy.BatchSize = $batchsize
    }

    Process {
        $datatable = $data | ConvertTo-DataTable

        # Add in all the remaining rows since the last clear
        if ($datatable.Rows.Count -gt 0) {
            $bulkcopy.WriteToServer($datatable)
            $datatable.Clear()
        }
    }

    End {
        $bulkcopy.Close()
        $bulkcopy.Dispose()
        $datatable.Dispose()
    }
}
