function Launch-Edge {
    <#
    .SYNOPSIS
        Launches Microsoft Edge with the specified site in guest mode.

    .DESCRIPTION
        This function starts Microsoft Edge with the `--guest` flag and opens the specified site URL.

    .PARAMETER Site
        The URL of the site to open in Microsoft Edge. Must be a valid absolute URL.

    .EXAMPLE
        Launch-Edge -Site "https://www.example.com"

        This command launches Microsoft Edge in guest mode and opens https://www.example.com.

    .NOTES
        Name: Launch-Edge
        Author: Ryan Whitlock
        Date: 12.11.2024
        Version: 1.0
        Changes: Initial release
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if (-not [Uri]::IsWellFormedUriString($_, [UriKind]::Absolute)) {
                throw "The provided site URL is not valid. Please provide a valid URL."
            }
            $true
        })]
        [ValidateNotNullOrEmpty()]
        [string]$Site
    )

    Begin {
        # Validate that Edge is installed
        if (-not (Get-Package -Name "Microsoft Edge")) {
            Throw "Microsoft Edge is not installed or not available in the system PATH."
        }
    }

    Process {
        try {
            # Start Edge with the specified site
            Start-Process msedge  -ArgumentList "--kiosk $Site --edge-kiosk-type=fullscreen --guest"
            Write-Verbose "Launching Edge with site: $Site"
        }
        catch {
            Write-Error "An error occurred while trying to start Edge: $_"
        }
    }
}
