function Get-RDGatewayHealthCheck {
    <#
        .SYNOPSIS
            Performs a health check on a Windows Remote Desktop Gateway server.

        .DESCRIPTION
            This function checks the health status of an RD Gateway server by sending a web request to a specified endpoint.
            The function requires the DNS name of the RD Gateway server, along with credentials to authenticate the request.
            It returns the HTTP status code and description from the server's response.

        .PARAMETER RDGWServerName
            The DNS name of the RD Gateway server.

        .PARAMETER GWAlias
            The alias for the Gateway server used in the HTTP request. This is optional if the server name is used to connect to the RDG.

        .PARAMETER Path
            The path to the RD Gateway server's RPC endpoint. Default is '/rpc/en-us/rpcproxy.dll'.

        .PARAMETER Timeout
            The timeout duration for the web request in milliseconds. Default is 5000 ms.

        .PARAMETER Username
            The username used for authentication.

        .PARAMETER Password
            The password used for authentication.

        .PARAMETER Domain
            The domain for the provided username.

        .EXAMPLE
            Get-RDGatewayHealthCheck -RDGWServerName "rdgateway.example.com" -Username "user" -Password "pass" -Domain "domain"

        .NOTES
            Ensure that the account used has the necessary permissions to access the RD Gateway server.
            F5 equivalent: RPC_IN_DATA /rpc/en-us/rpcproxy.dll HTTP/1.1\r\nHost: RDWGW.sb.gcps5.gwin

            Name: Get-RDGatewayHealthCheck 
            Author: Ryan Whitlock
            Date: 07.24.2024
            Version: 1.0
            Changes: Initial Release
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RDGWServerName,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$GWAlias,

        [Parameter(Mandatory=$false)]
        [ValidateNotNullOrEmpty()]
        [string]$Path = '/rpc/en-us/rpcproxy.dll',

        [Parameter(Mandatory=$false)]
        [ValidateRange(1000, 60000)]  # Ensuring the timeout is between 1 second and 60 seconds
        [int]$Timeout = 5000,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Username,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Password,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Domain
    )

    begin {
        # Construct the URI for the RD Gateway endpoint
        $HttpUriRoot = New-Object System.UriBuilder('https', $RDGWServerName, 443, $Path)
    }

    process {        
        # Create the HTTP request
        [System.Net.HttpWebRequest]$HttpRequest = [Net.HttpWebRequest]::Create($HttpUriRoot.Uri.AbsoluteUri)
        $HttpRequest.Timeout = $Timeout
        $HttpRequest.Method = 'RPC_IN_DATA'
        $HttpRequest.ProtocolVersion = [System.Net.HttpVersion]::Version11
        $HttpRequest.Host = if ($GWAlias) { $GWAlias } else { $RDGWServerName }
        $HttpRequest.Credentials = New-Object System.Net.NetworkCredential($Username, $Password, $Domain)

        try {
            # Get the response from the server
            [System.Net.HttpWebResponse]$HttpResponse = $HttpRequest.GetResponse()

            # Output the status code and description
            Write-Output "Status: $($HttpResponse.StatusCode) - $($HttpResponse.StatusDescription)"
        } 
        catch [System.Net.WebException] {
            # Handle web exceptions, typically HTTP errors
            $errorResponse = $_.Exception.Response
            if ($errorResponse) {
                $statusCode = $errorResponse.StatusCode
                Write-Error "Error: HTTP $statusCode - $($errorResponse.StatusDescription)"
            } else {
                Write-Error "Error: Network-related or instance-specific error occurred: $($_.Exception.Message)"
            }
        } 
        catch {
            # Handle other exceptions
            Write-Error "An unexpected error occurred: $($_.Exception.Message)"
        }
    }

    end {  }
}
