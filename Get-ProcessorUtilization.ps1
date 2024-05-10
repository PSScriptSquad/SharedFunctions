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
            Version: 2.0
            Changes: Updated logic and removed PRTG specific properties 
    #>
    [alias("Get-TaskManagerCPU")]

    # Retrieves CPU utilization counter samples with a sample size of 20
    $counterSamples = Get-Counter '\Processor Information(*)\% Processor Utility' -SampleInterval 1 -MaxSamples 20 | 
        Select-Object -ExpandProperty CounterSamples |
        Group-Object -Property InstanceName | ForEach-Object {

            # Calculate average and maximum CPU usage for each core
            $Stats = $_.Group | Measure-Object -Property CookedValue -Average -Maximum

            # Find the latest timestamp
            $Time = $_.Group | Measure-Object -Property Timestamp -Maximum

            # Create a custom object with calculated statistics
            [PSCustomObject]@{
                'EndTime' = $Time.Maximum
                'Name' = $_.Name
                'Average' = [math]::Round(($Stats).Average, 2)
                'Maximum' = [math]::Round(($Stats).Maximum, 2)
            }
        }

    return $counterSamples
}
