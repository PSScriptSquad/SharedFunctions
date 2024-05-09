function Get-ProcessorUtilization {
    <#
        .SYNOPSIS
            Retrieves CPU utilization information for each processor core.
        .DESCRIPTION
            This function retrieves CPU utilization information for each processor core and the total CPU utilization.
        .EXAMPLE
            Get-ProcessorUtilization
            Retrieves CPU utilization information for each processor core and the total CPU utilization.
        .NOTES
            Name: Get-ProcessorUtilization
            Author: Ryan Whitlock
            Date: 05.09.2024
            Version: 1.0
            Changes: Initial release
    #>
    [alias("Get-TaskManagerCPU")]

    # Retrieves CPU utilization counter samples
    $counterSamples = Get-Counter '\Processor Information(*)\% Processor Utility' | Select-Object -ExpandProperty CounterSamples
    
    Foreach ($counter in $counterSamples) {
        # Skip if the instance name is '_total' or contains ',_total'
        if ($counter.InstanceName -eq '_total' -or $counter.InstanceName -like '*,_total') {
            continue
        }
        
        # Extracting processor name and core number from InstanceName
        $name = "CPU:$($counter.InstanceName.split(',')[0]) Core:$($counter.InstanceName.split(',')[1])"
        
        [PSCustomObject]@{
            Name = $name
            Value = [math]::Round($counter.CookedValue, 2)
            Unit = 'Percent'
            Mode = 'Absolute'
            Float = 1
        }
    }
    
    # Total CPU utilization
    [PSCustomObject]@{
        Name = 'Total'
        Value = [math]::Round(($counterSamples | Where-Object { $_.InstanceName -eq '_Total' }).CookedValue, 2)
        Unit = 'Percent'
        Mode = 'Absolute'
        Float = 1
    }
}
