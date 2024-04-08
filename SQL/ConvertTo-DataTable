function ConvertTo-DataTable {
    <#
    .Synopsis
        Creates a DataTable from an object
    .Description
        Creates a DataTable from an object, containing all properties (except built-in properties from a database)
    .Example
        Get-ChildItem | Select Name, LastWriteTime | ConvertTo-DataTable
    .Link
        Select-DataTable
    .Link
        Import-DataTable
    .Link
        Export-DataTable
    #> 
    [OutputType([Data.DataTable])]
    param(
        # The input objects
        [Parameter(Position=0, Mandatory=$true, ValueFromPipeline = $true)]
        [PSObject[]]
        $InputObject
    ) 
 
    begin { 
        # Initialize a DataTable
        $outputDataTable = New-Object Data.DataTable   
          
        # Store known column names to avoid duplicates
        $knownColumns = @{}
    } 

    process {         
        foreach ($In in $InputObject) { 
            # Create a new row for each object
            $DataRow = $outputDataTable.NewRow()   
            
            # Check if the object is a DataRow
            $isDataRow = $In.PSObject.TypeNames -like "*.DataRow*" -as [bool]

            # Define simple types for easy lookup
            $simpleTypes = @('System.Boolean', 'System.Byte[]', 'System.Byte', 'System.Char', 'System.DateTime', 'System.Decimal', 'System.Double', 'System.Guid', 'System.Int16', 'System.Int32', 'System.Int64', 'System.Single', 'System.UInt16', 'System.UInt32', 'System.UInt64')
            $SimpletypeLookup = @{}
            foreach ($s in $simpleTypes) {
                $SimpletypeLookup[$s] = $s
            }            
            
            foreach ($property in $In.PSObject.Properties) {   
                # Skip internal DataRow properties if applicable
                if ($isDataRow -and 'RowError', 'RowState', 'Table', 'ItemArray', 'HasErrors' -contains $property.Name) {
                    continue     
                }
                
                # Retrieve property name and value
                $propName = $property.Name
                $propValue = $property.Value
                $IsSimpleType = $SimpletypeLookup.ContainsKey($property.TypeNameOfValue)

                # Add new column if not exists
                if (-not $outputDataTable.Columns.Contains($propName)) {   
                    $outputDataTable.Columns.Add((
                        New-Object Data.DataColumn -Property @{
                            ColumnName = $propName
                            DataType = if ($IsSimpleType) {
                                $property.TypeNameOfValue
                            } else {
                                'System.Object'
                            }
                        }
                    ))
                }                   
                
                # Set value for the current property
                $DataRow.Item($propName) = if ($IsSimpleType -and $propValue) {
                    $propValue
                } elseif ($propValue) {
                    [PSObject]$propValue
                } else {
                    [DBNull]::Value
                }
            }   
            
            # Add the row to the DataTable
            $outputDataTable.Rows.Add($DataRow)   
        } 
    }  
      
    end { 
        # Output the DataTable
        ,$outputDataTable
    } 
}
