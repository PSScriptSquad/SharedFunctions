function Get-SqlData {
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
