function Get-DomainControllerNTPStripchart {
    [CmdletBinding()]
    param (
        [int]$Samples = 3
    )

    # Get the list of all domain controllers
    $DomainControllers = Get-ADDomainController -Filter *

    # Loop through each domain controller
    $results = foreach ($server in $DomainControllers) {
        # Run the NTP stripchart command and capture the output
        $stripchartOutput = w32tm /stripchart /computer:$($server.HostName) /samples:$Samples /dataonly

        # Parse and format the results as a custom object
        foreach ($line in $stripchartOutput) {
            # Extract the domain controller name from the "Tracking" line
            if ($line -match "^Tracking\s+(?<Server>(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.?)+(?:[a-zA-Z]{2,}))") {
                $currentServer = $matches.Server
            }

            # Extract the timestamp and offset from lines like "10:51:55, -00.0127077s"
            elseif ($line -match "^(?<Timestamp>\d{2}:\d{2}:\d{2}),\s+(?<Offset>(-?\d+\.\d+))s") {
                [pscustomobject]@{
                    DomainController = $currentServer
                    Timestamp        = [datetime]::parseexact($matches.Timestamp,'HH:mm:ss',$null)
                    Offset           = [TimeSpan]::FromSeconds($matches.Offset)
                }
            }
        }
    }

    # Output the final collection of custom objects
    return $results
}
