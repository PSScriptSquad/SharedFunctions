# Create containers for each test file with their specific parameters
$containers = @(
    New-PesterContainer -Path "C:\TEMP\Get-Events\Get-Events.Integration.Tests.ps1"  -Data @{
        RemoteTestComputer = "MS01ACDCX03.SB.gcps5.gwin"
        TestLogName = 'Security'
    }   
)

$pesterConfig = [PesterConfiguration]@{
    Run = @{
        Container = $containers
    }
    CodeCoverage = @{
        Enabled = $true
        Path = "C:\TEMP\Get-Events\Get-Events.ps1"
    }
    Output = @{
        Verbosity = 'Detailed'
    }
    TestResult = @{
        Enabled = $true
    }
    Should = @{
        ErrorAction = 'Stop'
    }
}

Invoke-Pester -Configuration $pesterConfig