function Get-SqlData {
    <#
        .SYNOPSIS
            This function retrieves data from a SQL Server database using the provided SQL query.
        .DESCRIPTION
            The Get-SqlData function establishes a connection to a SQL Server database and executes the provided SQL query. 
            It returns the query results in the form of a DataTable object.
            The function supports both Windows and SQL Server authentication.
            This function is useful for querying data from SQL Server within PowerShell scripts.
        .PARAMETER SQLServer
            Specifies the name or IP address of the SQL Server instance.
        .PARAMETER SQLDBName
            Specifies the name of the SQL database.
        .PARAMETER SqlQuery
            Specifies the SQL query to execute.
        .PARAMETER Credential
            Specifies optional credentials for SQL Server authentication.
        .EXAMPLE
            $result = Get-SqlData -SQLServer "localhost" -SQLDBName "TestDB" -SqlQuery "SELECT * FROM Employees" -Credential (Get-Credential)
            Retrieves all records from the Employees table in the TestDB database located on the local SQL Server instance using provided credentials.
        .NOTES
            Name: Get-SqlData
            Author: Ryan Whitlock
            Date: 11.30.2023
            Version: 1.1
            Changes: Added comments, improved clarity and readability.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SQLServer,                # SQL Server name or IP address
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SQLDBName,                # Database name
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$SqlQuery,                 # SQL query to execute
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Credential()]
        [System.Management.Automation.PSCredential]$Credential  # Optional credential for SQL authentication
    ) 
    begin{
        try {
            # Initialize a new DataTable object to store query results
            $DataTable = New-Object System.Data.DataTable
            
            # Create a connection to the SQL Server instance if one isn't already open
            $SQLConnection = New-Object System.Data.SqlClient.SqlConnection
            $SQLConnection.ConnectionString = "Server = $SQLServer; Database = $SQLDBName;"

            if ($Credential) {
                # If credentials provided, use SQL Server authentication
                $sqlCred = $Credential.GetNetworkCredential()
                $SQLConnection.Credential = $sqlCred
            } else {
                # Use Windows authentication
                $SQLConnection.ConnectionString += "Integrated Security = True;"
            }

            # Open the SQL connection
            $SQLConnection.Open()
        } catch {
            # Throw an error if connection fails
            Throw "Failed to connect to SQL Server '$SQLServer' with database '$SQLDBName': $($_.Exception.Message)"
        }
    }
    Process{ 
        try {
            # Execute the SQL query and store the results in $DataTable
            $Command = New-Object System.Data.SqlClient.SqlCommand
            $Command.Connection = $SQLConnection
            $Command.CommandText = $SqlQuery
            $Reader = $Command.ExecuteReader()
            $DataTable.Load($Reader)
        } catch {
            Throw "Failed to execute SQL query: $SqlQuery. Error: $($_.Exception.Message)"
        }
    }
    End{
        try {
            # Close the SQL connection and return the populated DataTable
            $SQLConnection.Close()
            return $DataTable
        } catch {
            Throw "Failed to close SQL connection: $($_.Exception.Message)"
        }
    }
}
