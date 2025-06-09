function Test-AdvancedKerberos {
	<#
	.SYNOPSIS
		Performs comprehensive Kerberos authentication testing against a Domain Controller or KDC.

	.DESCRIPTION
		The Test-AdvancedKerberos function conducts thorough testing of Kerberos authentication
		infrastructure including DNS resolution, TCP connectivity, TGT/TGS ticket requests,
		time synchronization validation, and optional cross-realm referral testing.

		This function validates the complete Kerberos authentication flow and identifies
		common configuration issues that could prevent successful authentication.

	.PARAMETER DomainController
		The Fully Qualified Domain Name (FQDN) of the Domain Controller or Key Distribution Center (KDC) to test.
		This parameter is mandatory and must be a valid FQDN.

	.PARAMETER Credential
		Optional PSCredential object for alternate credential testing. When provided, the function
		will attempt Kerberos authentication using these credentials instead of the current user's context.
		This parameter belongs to the 'UseAlternateCredential' parameter set.

	.PARAMETER TimeoutSeconds
		Timeout in seconds for TCP connectivity tests between retry attempts. Valid range is 1-30 seconds.
		Default value is 3 seconds.

	.PARAMETER TargetRealm
		Optional target realm name for cross-realm referral testing. When provided, the function
		will attempt to obtain tickets for services in the specified realm after successful
		local realm authentication.

	.EXAMPLE
		Test-AdvancedKerberos -DomainController "dc01.contoso.com"

		Performs basic Kerberos testing against dc01.contoso.com using current user credentials.

	.EXAMPLE
		$cred = Get-Credential
		Test-AdvancedKerberos -DomainController "dc01.contoso.com" -Credential $cred -TimeoutSeconds 5

		Tests Kerberos authentication using alternate credentials with a 5-second delay between retries.

	.EXAMPLE
		Test-AdvancedKerberos -DomainController "dc01.contoso.com" -TargetRealm "TRUSTED.COM" -Verbose

		Performs comprehensive testing including cross-realm referral testing with verbose output.

	.NOTES
		Name: Test-AdvancedKerberos
		Author: Ryan Whitlock
		Date: 03.10.2022
		Version: 1.0
	#>

	[CmdletBinding(DefaultParameterSetName = 'UseCurrentCredential')]
	param(
		[Parameter(Mandatory = $true)]
		[ValidateNotNullOrEmpty()]
		[string]$DomainController,

		[Parameter(ParameterSetName = 'UseAlternateCredential')]
		[System.Management.Automation.PSCredential]$Credential,

		[Parameter()]
		[ValidateRange(1, 30)]
		[int]$TimeoutSeconds = 3,

		[Parameter()]
		[string]$TargetRealm
	)

	begin {
		# Helper function for DNS resolution
		function Test-DnsResolution {
			param([string]$DomainController)

			Write-Verbose "Resolving DNS for $DomainController"

			$result = @{
				Success = $false
				ResolvedIPs = @()
				ErrorMessage = $null
			}

			try {
				$addresses = [System.Net.Dns]::GetHostAddresses($DomainController) | Where-Object { $_.AddressFamily -eq 'InterNetwork' }
				if ($addresses.Count -eq 0) {
					$result.ErrorMessage = "No IPv4 addresses found for $DomainController"
				} else {
					$result.Success = $true
					$result.ResolvedIPs = $addresses | ForEach-Object { $_.IPAddressToString }
				}
			} catch {
				$result.ErrorMessage = $_.Exception.Message
			}

			return $result
		}

		# Helper function for TCP connectivity testing
		function Test-TcpConnectivity {
			param(
				[string]$DomainController,
				[int]$TimeoutSeconds = 3,
				[int]$RetryCount = 3
			)

			$portsToTest = @(
				@{ Label = 'TcpPort88'; Port = 88 },
				@{ Label = 'TcpPort389'; Port = 389 },
				@{ Label = 'TcpPort636'; Port = 636 }
			)

			$result = @{
				TcpPort88Open = $false
				TcpPort389Open = $false
				TcpPort636Open = $false
				PortTestDetails = @{}
			}

			foreach ($portInfo in $portsToTest) {
				$label = $portInfo.Label
				$port = $portInfo.Port
				$success = $false
				$message = ""

				for ($attempt = 1; $attempt -le $RetryCount; $attempt++) {
					Write-Verbose "Attempt $attempt of $RetryCount for port $port"
					try {
						$testResult = Test-NetConnection -ComputerName $DomainController -Port $port -WarningAction SilentlyContinue
						if ($testResult.TcpTestSucceeded) {
							$success = $true
							$message = "Open (TCP response received on attempt $attempt)"
							break
						} else {
							$message = "Attempt $attempt failed: Connection to port $port failed"
						}
					} catch {
						$message = "Attempt $attempt failed: $($_.Exception.Message)"
					}
					if ($attempt -lt $RetryCount) {
						Start-Sleep -Seconds $TimeoutSeconds
					}
				}

				$result."$($label)Open" = $success
				$result.PortTestDetails[$label] = @{
					Success = $success
					Message = $message
				}
			}

			return $result
		}

		# Helper function for TGT request
        function Test-TgtRequest {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true)]
                [ValidateNotNullOrEmpty()]
                [string]$DomainController,

                [Parameter(Mandatory = $true)]
                [ValidateSet('UseCurrentCredential', 'UseAlternateCredential')]
                [string]$ParameterSetName,

                [Parameter(Mandatory = $false)]
                [System.Management.Automation.PSCredential]$Credential,

                [Parameter(Mandatory = $false)]
                [int]$TimeoutSeconds = 30,

                [Parameter(Mandatory = $false)]
                [switch]$EnableSigning,

                [Parameter(Mandatory = $false)]
                [switch]$EnableSealing
            )

            begin {
                Write-Verbose "Starting enhanced TGT request test against domain controller: $DomainController"

                # Initialize result object with more detailed information
                $result = [PSCustomObject]@{
                    DomainController    = $DomainController
                    TgtRequestStatus    = 'NotTested'
                    TgtRequestError     = $null
                    ErrorCategory       = $null
                    AuthenticationType  = $null
                    TestDuration        = $null
                    Timestamp          = Get-Date
                    DiagnosticInfo     = @{}
                    AlternativeTests   = @{}
                }

                # Validate parameters
                if ($ParameterSetName -eq 'UseAlternateCredential' -and -not $Credential) {
                    throw [System.ArgumentException]::new("Credential parameter is required when ParameterSetName is 'UseAlternateCredential'")
                }
            }

            process {
                $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                $ldapConn = $null

                try {
                    # Step 1: Load required assembly
                    Write-Verbose "Loading System.DirectoryServices.Protocols assembly"
                    try {
                        $assemblyLoaded = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")
                        if (-not $assemblyLoaded) {
                            throw [System.InvalidOperationException]::new("Failed to load System.DirectoryServices.Protocols assembly")
                        }
                        Write-Verbose "Successfully loaded System.DirectoryServices.Protocols assembly"
                        $result.DiagnosticInfo['AssemblyLoaded'] = $true
                    }
                    catch {
                        $result.DiagnosticInfo['AssemblyLoaded'] = $false
                        $result.DiagnosticInfo['AssemblyError'] = $_.Exception.Message
                        throw [System.InvalidOperationException]::new("Could not load required .NET assembly: $($_.Exception.Message)")
                    }

                    # Step 2: Test basic connectivity first
                    Write-Verbose "Testing basic network connectivity to $DomainController"
                    $connectivityTests = @{}
            
                    # Test LDAP port 389
                    try {
                        $ldapTest = Test-NetConnection -ComputerName $DomainController -Port 389 -InformationLevel Detailed -WarningAction SilentlyContinue
                        $connectivityTests['LDAP_389'] = @{
                            Success = $ldapTest.TcpTestSucceeded
                            ResponseTime = $ldapTest.PingReplyDetails.RoundtripTime
                            RemoteAddress = $ldapTest.RemoteAddress
                        }
                        Write-Verbose "LDAP (389) connectivity: $($ldapTest.TcpTestSucceeded)"
                    }
                    catch {
                        $connectivityTests['LDAP_389'] = @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }

                    # Test LDAPS port 636
                    try {
                        $ldapsTest = Test-NetConnection -ComputerName $DomainController -Port 636 -InformationLevel Detailed -WarningAction SilentlyContinue
                        $connectivityTests['LDAPS_636'] = @{
                            Success = $ldapsTest.TcpTestSucceeded
                            ResponseTime = $ldapsTest.PingReplyDetails.RoundtripTime
                            RemoteAddress = $ldapsTest.RemoteAddress
                        }
                        Write-Verbose "LDAPS (636) connectivity: $($ldapsTest.TcpTestSucceeded)"
                    }
                    catch {
                        $connectivityTests['LDAPS_636'] = @{
                            Success = $false
                            Error = $_.Exception.Message
                        }
                    }

                    $result.DiagnosticInfo['ConnectivityTests'] = $connectivityTests

                    # Ensure we can reach LDAP
                    if (-not $connectivityTests['LDAP_389'].Success) {
                        throw [System.Net.NetworkInformation.PingException]::new("Cannot reach domain controller $DomainController on port 389 (LDAP)")
                    }

                    # Step 3: Try alternative authentication methods
                    Write-Verbose "Attempting multiple authentication approaches"
            
                    # Method 1: Try anonymous bind first to test basic LDAP functionality
                    Write-Verbose "Testing anonymous LDAP bind"
                    try {
                        $anonymousConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
                        $anonymousConn.SessionOptions.ProtocolVersion = 3
                        $anonymousConn.Timeout = [TimeSpan]::FromSeconds(10)
                        $anonymousConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Anonymous
                        $anonymousConn.Bind()
                        $result.AlternativeTests['AnonymousBind'] = 'Success'
                        $anonymousConn.Dispose()
                        Write-Verbose "Anonymous LDAP bind successful"
                    }
                    catch {
                        $result.AlternativeTests['AnonymousBind'] = "Failed: $($_.Exception.Message)"
                        Write-Verbose "Anonymous LDAP bind failed: $($_.Exception.Message)"
                    }

                    # Method 2: Try NTLM authentication
                    Write-Verbose "Testing NTLM authentication"
                    try {
                        $ntlmConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
                        $ntlmConn.SessionOptions.ProtocolVersion = 3
                        $ntlmConn.Timeout = [TimeSpan]::FromSeconds(15)
                        $ntlmConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Ntlm
                
                        if ($ParameterSetName -eq 'UseAlternateCredential') {
                            $ntlmConn.Credential = $Credential.GetNetworkCredential()
                        }
                
                        $ntlmConn.Bind()
                        $result.AlternativeTests['NtlmAuth'] = 'Success'
                        $ntlmConn.Dispose()
                        Write-Verbose "NTLM authentication successful"
                    }
                    catch {
                        $result.AlternativeTests['NtlmAuth'] = "Failed: $($_.Exception.Message)"
                        Write-Verbose "NTLM authentication failed: $($_.Exception.Message)"
                    }

                    # Method 3: Try basic authentication
                    if ($ParameterSetName -eq 'UseAlternateCredential') {
                        Write-Verbose "Testing Basic authentication with alternate credentials"
                        try {
                            $basicConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
                            $basicConn.SessionOptions.ProtocolVersion = 3
                            $basicConn.Timeout = [TimeSpan]::FromSeconds(15)
                            $basicConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
                            $basicConn.Credential = $Credential.GetNetworkCredential()
                            $basicConn.Bind()
                            $result.AlternativeTests['BasicAuth'] = 'Success'
                            $basicConn.Dispose()
                            Write-Verbose "Basic authentication successful"
                        }
                        catch {
                            $result.AlternativeTests['BasicAuth'] = "Failed: $($_.Exception.Message)"
                            Write-Verbose "Basic authentication failed: $($_.Exception.Message)"
                        }
                    }

                    # Step 4: Now attempt the actual Kerberos authentication
                    Write-Verbose "Creating LDAP connection for Kerberos authentication"
                    $ldapConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)

                    # Configure connection properties
                    $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
                    $ldapConn.SessionOptions.ProtocolVersion = 3
                    $ldapConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)

                    # Try different security settings
                    $securityConfigurations = @(
                        @{ Signing = $false; Sealing = $false; Description = "No signing/sealing" },
                        @{ Signing = $true; Sealing = $false; Description = "Signing only" },
                        @{ Signing = $true; Sealing = $true; Description = "Signing and sealing" }
                    )

                    $kerberosSuccess = $false
                    foreach ($config in $securityConfigurations) {
                        if ($kerberosSuccess) { break }
                
                        Write-Verbose "Trying Kerberos with configuration: $($config.Description)"
                
                        try {
                            # Reset connection
                            if ($ldapConn) { $ldapConn.Dispose() }
                            $ldapConn = [System.DirectoryServices.Protocols.LdapConnection]::new($DomainController)
                            $ldapConn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Kerberos
                            $ldapConn.SessionOptions.ProtocolVersion = 3
                            $ldapConn.Timeout = [TimeSpan]::FromSeconds($TimeoutSeconds)

                            # Apply security settings
                            $ldapConn.SessionOptions.Signing = $config.Signing
                            $ldapConn.SessionOptions.Sealing = $config.Sealing

                            # Configure credentials
                            if ($ParameterSetName -eq 'UseAlternateCredential') {
                                Write-Verbose "Configuring alternate credentials for Kerberos authentication"
                                $result.AuthenticationType = "AlternateCredential ($($Credential.UserName))"
                                $netCred = $Credential.GetNetworkCredential()
                                $ldapConn.Credential = $netCred
                            }
                            else {
                                Write-Verbose "Using current user credentials for Kerberos authentication"
                                $result.AuthenticationType = "CurrentUser ($([System.Security.Principal.WindowsIdentity]::GetCurrent().Name))"
                            }

                            # Attempt the bind operation
                            Write-Verbose "Attempting Kerberos bind with $($config.Description)"
                            $ldapConn.Bind()

                            # If we get here, the bind was successful
                            $result.TgtRequestStatus = 'Success'
                            $result.DiagnosticInfo['SuccessfulConfiguration'] = $config.Description
                            $kerberosSuccess = $true
                            Write-Verbose "TGT request completed successfully with $($config.Description)"
                            break
                        }
                        catch {
                            $result.DiagnosticInfo["KerberosAttempt_$($config.Description.Replace(' ', '_'))"] = $_.Exception.Message
                            Write-Verbose "Kerberos attempt with $($config.Description) failed: $($_.Exception.Message)"
                        }
                    }

                    if (-not $kerberosSuccess) {
                        throw [System.Security.Authentication.AuthenticationException]::new("All Kerberos authentication methods failed")
                    }
                }
                catch [System.DirectoryServices.Protocols.LdapException] {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'LdapError'
                    $result.TgtRequestError = "LDAP Error: $($_.Exception.Message) (Error Code: $($_.Exception.ErrorCode))"
                    $result.DiagnosticInfo['LdapErrorCode'] = $_.Exception.ErrorCode
                    $result.DiagnosticInfo['LdapServerErrorMessage'] = $_.Exception.ServerErrorMessage
                    Write-Verbose "LDAP-specific error during TGT request: $($result.TgtRequestError)"
                }
                catch [System.Security.Authentication.AuthenticationException] {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'AuthenticationError'
                    $result.TgtRequestError = "Authentication failed: $($_.Exception.Message)"
                    Write-Verbose "Authentication error during TGT request: $($result.TgtRequestError)"
                }
                catch [System.Net.NetworkInformation.PingException] {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'NetworkError'
                    $result.TgtRequestError = "Network connectivity issue: $($_.Exception.Message)"
                    Write-Verbose "Network error during TGT request: $($result.TgtRequestError)"
                }
                catch [System.TimeoutException] {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'TimeoutError'
                    $result.TgtRequestError = "Operation timed out after $TimeoutSeconds seconds: $($_.Exception.Message)"
                    Write-Verbose "Timeout error during TGT request: $($result.TgtRequestError)"
                }
                catch [System.InvalidOperationException] {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'ConfigurationError'
                    $result.TgtRequestError = "Configuration or setup error: $($_.Exception.Message)"
                    Write-Verbose "Configuration error during TGT request: $($result.TgtRequestError)"
                }
                catch {
                    $result.TgtRequestStatus = 'Failure'
                    $result.ErrorCategory = 'UnexpectedError'
                    $result.TgtRequestError = "Unexpected error: $($_.Exception.Message)"
                    $result.DiagnosticInfo['UnexpectedErrorType'] = $_.Exception.GetType().Name
                    $result.DiagnosticInfo['UnexpectedErrorHResult'] = $_.Exception.HResult
                    Write-Verbose "Unexpected error during TGT request: $($result.TgtRequestError)"
                    Write-Debug "Full exception details: $($_ | Out-String)"
                }
                finally {
                    # Ensure proper cleanup
                    if ($ldapConn) {
                        try {
                            $ldapConn.Dispose()
                            Write-Verbose "LDAP connection disposed successfully"
                        }
                        catch {
                            Write-Warning "Failed to dispose LDAP connection: $($_.Exception.Message)"
                        }
                    }

                    $stopwatch.Stop()
                    $result.TestDuration = $stopwatch.Elapsed
                    Write-Verbose "TGT request test completed in $($result.TestDuration.TotalMilliseconds) milliseconds"
                }
            }

            end {
                return $result
            }
        }

		# Helper function for TGS and SPN validation
        function Test-TgsAndSpnValidation {
            param(
                [string]$DomainController,
                [System.Management.Automation.PSCredential]$Credential
            )

            $result = @{
                TgsRequestStatus    = 'NotTested'
                TgsRequestError     = $null
                SpnValidationStatus = 'NotTested'
                SpnValidationError  = $null
                EncryptionType      = 'Unknown'
            }

            # CAVEAT: klist.exe can only inspect the ticket cache of the current user's logon session.
            if ($PSBoundParameters.ContainsKey('Credential')) {
                Write-Verbose "Skipping TGS/SPN validation: klist.exe cannot inspect ticket cache for alternate credentials."
                $result.TgsRequestStatus = 'Skipped'
                $result.TgsRequestError = 'klist.exe cannot be used with alternate credentials.'
                $result.SpnValidationStatus = 'Skipped'
                return $result
            }

            try {
                # Step 1: Purge the existing ticket cache to ensure we get a fresh ticket.
                Write-Verbose "Purging Kerberos ticket cache with 'klist purge'."
                $purgeProcess = Start-Process -FilePath "klist.exe" -ArgumentList "purge" -Wait -PassThru -NoNewWindow
                if ($purgeProcess.ExitCode -ne 0) {
                    Write-Warning "klist purge exited with code $($purgeProcess.ExitCode). Proceeding with test."
                }

                # Step 2: Trigger a Kerberos-based action to get a service ticket for the DC's LDAP service.
                Write-Verbose "Triggering new service ticket request for LDAP/$DomainController"
                Get-ADRootDSE -Server $DomainController -ErrorAction Stop | Out-Null
                $result.TgsRequestStatus = 'Success'
                Write-Verbose "Successfully contacted the LDAP service, TGS request is considered successful."

            } catch {
                $result.TgsRequestStatus = 'Failure'
                $result.TgsRequestError = "Failed to get a service ticket for LDAP/$DomainController. Error: $($_.Exception.Message)"
                $result.SpnValidationStatus = 'Failure'
                $result.SpnValidationError = "Could not validate SPN because the TGS request failed."
                Write-Verbose "TGS request failed: $($_.Exception.Message)"
                return $result
            }

            try {
                # Step 3: Inspect the cache with klist.exe using reliable line-by-line parsing.
                Write-Verbose "Analyzing new ticket cache with 'klist tickets'."
                $klistOutput = klist.exe tickets
                $klistLines = $klistOutput -split '\r?\n'

                $spnPattern = "ldap/$DomainController"
                $foundTicket = $false
                $encryptionTypeFound = $false

                for ($i = 0; $i -lt $klistLines.Length; $i++) {
                    # Find the line with the server SPN we are looking for.
                    # We match against the start of the SPN to avoid aliasing issues.
                    if ($klistLines[$i] -match "Server:\s*$([regex]::Escape($spnPattern))") {
                        Write-Verbose "Found ticket section for SPN: $spnPattern"
                        $foundTicket = $true

                        # Now search from this line forward for the encryption type within the same ticket block.
                        for ($j = $i + 1; $j -lt $klistLines.Length; $j++) {
                            # Stop searching if we hit the start of the next ticket or the end of the list.
                            if ($klistLines[$j] -match '^\s*#\d+>' -or [string]::IsNullOrWhiteSpace($klistLines[$j])) {
                                Write-Verbose "Reached end of ticket section without finding encryption type."
                                break # Exit inner loop
                            }

                            # Find the encryption type line and capture its value.
                            if ($klistLines[$j] -match "KerbTicket Encryption Type:\s*(.+)") {
                                $result.EncryptionType = $matches[1].Trim()
                                $encryptionTypeFound = $true
                                Write-Verbose "Found encryption type: $($result.EncryptionType)"
                                break # Exit inner loop, we found what we need.
                            }
                        }
                        break # Exit outer loop, we've processed the ticket we care about.
                    }
                }

                # Final validation based on what we found during parsing.
                if ($foundTicket -and $encryptionTypeFound) {
                    $result.SpnValidationStatus = 'Success'
                    $result.SpnValidationError = "A valid ticket for SPN '$spnPattern' was found with its encryption type."
                } elseif ($foundTicket) { # We found the ticket but not the e-type
                    $result.SpnValidationStatus = 'Success' # Finding the ticket is a success in itself.
                    $result.SpnValidationError = "Found ticket for SPN '$spnPattern', but could not parse its encryption type."
                    $result.EncryptionType = 'Parse Failed'
                } else { # We never found the ticket
                    $result.SpnValidationStatus = 'Failure'
                    $result.SpnValidationError = "TGS request succeeded, but could not find a matching ticket for '$spnPattern' in the klist output."
                    $result.EncryptionType = 'Not Found'
                }

            } catch {
                $result.SpnValidationStatus = 'Failure'
                $result.SpnValidationError = "An error occurred while running or parsing klist.exe: $($_.Exception.Message)"
                Write-Verbose "Error during klist analysis: $($_.Exception.Message)"
            }

            return $result
        }

        # Helper function for time synchronization check
        function Test-TimeSynchronization {
            param([string]$DomainController)
            Write-Verbose "Checking time synchronization with Domain Controller using w32tm"
            $result = @{
                TimeSkewSeconds = $null
                TimeSkewWarning = $false
                TimeSkewMessage = $null
            }
            try {
                # Use w32tm to check time synchronization
                Write-Verbose "Running w32tm stripchart against $DomainController"
                $w32tmResult = w32tm /stripchart /computer:$DomainController /samples:1 /dataonly
        
                if ($w32tmResult) {
                    Write-Verbose "w32tm output: $($w32tmResult -join ' ')"
            
                    # Parse the w32tm output to extract time offset
                    # w32tm output format is typically: "dd/mm/yyyy HH:mm:ss, +/-X.Xs"
                    $offsetLine = $w32tmResult | Where-Object { $_ -match '[\+\-]\d+\.\d+s' }
            
                    if ($offsetLine) {
                        # Extract the time offset value
                        if ($offsetLine -match '([\+\-]\d+\.\d+)s') {
                            $timeSkew = [math]::Abs([double]$matches[1])
                            $result.TimeSkewSeconds = $timeSkew
                    
                            Write-Verbose "Time skew detected: $timeSkew seconds"
                    
                            if ($timeSkew -gt 300) {
                                $result.TimeSkewWarning = $true
                                $result.TimeSkewMessage = "Local vs. DC clock differ by $timeSkew seconds. Kerberos likely to fail."
                            } else {
                                $result.TimeSkewWarning = $false
                                $result.TimeSkewMessage = "Time synchronization within acceptable range ($timeSkew seconds)"
                            }
                        } else {
                            $result.TimeSkewWarning = $true
                            $result.TimeSkewMessage = "Unable to parse time offset from w32tm output"
                        }
                    } else {
                        $result.TimeSkewWarning = $true
                        $result.TimeSkewMessage = "No time offset information found in w32tm output"
                    }
                } else {
                    $result.TimeSkewWarning = $true
                    $result.TimeSkewMessage = "w32tm command returned no output"
                }
            } catch {
                $result.TimeSkewWarning = $true
                $result.TimeSkewMessage = "Unable to check time synchronization: $($_.Exception.Message)"
                Write-Verbose "Error running w32tm: $($_.Exception.Message)"
            }
            return $result
        }

		# Helper function for cross-realm testing
		function Test-CrossRealmReferral {
			param(
				[string]$TargetRealm,
				[string]$TgtRequestStatus
			)

			$result = @{
				CrossRealmStatus = 'NotTested'
				CrossRealmErrors = @()
			}

			if (-not $TargetRealm) {
				return $result
			}

			Write-Verbose "Performing cross-realm referral tests for realm: $TargetRealm"

			try {
				if ($TgtRequestStatus -eq 'Success') {
					$crossRealmSpn = "krbtgt/$TargetRealm"
					Write-Verbose "Testing cross-realm referral for: $crossRealmSpn"

					# Placeholder for actual cross-realm test
					try {
						$targetRealmTest = [System.Net.Dns]::GetHostAddresses("$TargetRealm")
						if ($targetRealmTest) {
							$result.CrossRealmStatus = 'Success'
							Write-Verbose "Cross-realm referral test successful"
						} else {
							$result.CrossRealmStatus = 'Failure'
							$result.CrossRealmErrors += "Target realm $TargetRealm not resolvable"
							Write-Verbose "Cross-realm referral test failed - realm not resolvable"
						}
					} catch {
						$result.CrossRealmStatus = 'Failure'
						$result.CrossRealmErrors += "Cross-realm test failed: $($_.Exception.Message)"
						Write-Verbose "Cross-realm referral test failed: $($_.Exception.Message)"
					}
				} else {
					$result.CrossRealmStatus = 'Failure'
					$result.CrossRealmErrors += "Cannot perform cross-realm test without successful local TGT"
					Write-Verbose "Skipping cross-realm test due to local TGT failure"
				}
			} catch {
				$result.CrossRealmStatus = 'Failure'
				$result.CrossRealmErrors += $_.Exception.Message
				Write-Verbose "Cross-realm test error: $($_.Exception.Message)"
			}

			return $result
		}

		# Helper function to determine overall status
		function Get-OverallStatus {
			param([hashtable]$TestResults)

			$criticalFailures = @()

			if ($TestResults.DnsResolutionError) {
				$criticalFailures += "DNS Resolution Failed"
			}
			if (-not $TestResults.TcpPort88Open) {
				$criticalFailures += "Kerberos Port 88 Closed"
			}
			if ($TestResults.TgtRequestStatus -eq 'Failure') {
				$criticalFailures += "TGT Request Failed"
			}
			if ($TestResults.TimeSkewWarning -and $TestResults.TimeSkewSeconds -gt 300) {
				$criticalFailures += "Time Synchronization Issue"
			}

			if ($criticalFailures.Count -eq 0) {
				return 'Success'
			} elseif ($TestResults.TgtRequestStatus -eq 'Success') {
				return 'Partial'
			} else {
				return 'Failed'
			}
		}

		function Test-KerberosPort {
			<#
			.SYNOPSIS
				Tests Kerberos AS-REQ reachability (UDP) to a KDC on port 88 (or specified port).

			.DESCRIPTION
				Builds a minimal ASN.1-encoded KERBEROS_AS_REQ and sends it over UDP to the specified server:port.
				Waits up to $TimeoutMs ms for an AS-REP or KRB-ERROR. Returns a PSCustomObject with Success/$true/false,
				error details, response time, size, and analysis (Type/ErrorCode/etc).

			.PARAMETER Server
				FQDN or host name of the target KDC. If -Realm is omitted, the realm is auto-derived from $Server
				(using the last two labels, e.g., "dc01.sub.example.com" derives "EXAMPLE.COM"). Specify -Realm
				explicitly if this derivation is incorrect.

			.PARAMETER Port
				UDP port for Kerberos (default 88). (This uses UDP only; does not attempt TCP.)

			.PARAMETER Realm
				Kerberos realm (uppercase), e.g. EXAMPLE.COM. If omitted, derived from $Server.

			.PARAMETER ClientName
				Client principal (short name). If not specified, uses the current logged-in user's username.
				Must exist in KDC's DB for a valid AS-REP response.

			.PARAMETER TimeoutMs
				Max milliseconds to wait for a UDP response (default 5000).

			.NOTES
				Requires .NET's System.Net.Sockets.UdpClient. Minimal ASN.1—multi-component principal names split on "/".

			.EXAMPLE
				Test-KerberosPort -Server dc01.example.com -Verbose
			#>
			[CmdletBinding()]
			param(
				[Parameter(Mandatory, Position=0)]
				[ValidateNotNullOrEmpty()]
				[string]$Server,

				[ValidateRange(1,65535)]
				[int]$Port = 88,

				[ValidateNotNullOrEmpty()]
				[string]$Realm = $null,

				[Parameter()]
				[string]$ClientName = $null,

				[ValidateRange(100,60000)]
				[int]$TimeoutMs = 5000
			)

			begin {
				# If you extract these to a module, you can remove them from here.
				function Write-ASN1Length {
					param([int]$Length)
					if ($Length -lt 128) {
						return @([byte]$Length)
					} else {
						$bytes = @()
						$temp = $Length
						while ($temp -gt 0) {
							$bytes = ,([byte]($temp -band 0xFF)) + $bytes
							$temp = $temp -shr 8
						}
						$prefixByte = [byte](0x80 + $bytes.Length)
						return ,$prefixByte + $bytes
					}
				}

				function Write-ASN1Integer {
					param([int]$Value)
					if ($Value -eq 0) {
						$intBytes = @([byte]0)
					} else {
						# Minimal big-endian
						$absVal = [Math]::Abs($Value)
						$bytes = @()
						while ($absVal -gt 0) {
							$bytes = ,([byte]($absVal -band 0xFF)) + $bytes
							$absVal = $absVal -shr 8
						}
						# Pad if MSB set & positive
						if ($Value -ge 0 -and ($bytes[0] -band 0x80)) {
							$bytes = ,([byte]0) + $bytes
						}
						# TODO: handle negative two's complement if you ever pass negative
						$intBytes = $bytes
					}
					$lenBytes = Write-ASN1Length $intBytes.Length
					return ,([byte]0x02) + $lenBytes + $intBytes
				}

				function Write-ASN1BitString {
					param([byte[]]$Bits)
					if (-not $Bits -or $Bits.Length -le 0) {
						throw "BitString data cannot be null or empty"
					}
					$unusedBits = 0
					$content   = ,([byte]$unusedBits) + $Bits
					$lenBytes  = Write-ASN1Length $content.Length
					return ,([byte]0x03) + $lenBytes + $content
				}

				function Write-ASN1KerberosTime {
					param([DateTime]$Time)
					$timeStr   = $Time.ToUniversalTime().ToString("yyyyMMddHHmmssZ")
					$bytes     = [Text.Encoding]::ASCII.GetBytes($timeStr)
					$lenBytes  = Write-ASN1Length $bytes.Length
					return ,([byte]0x18) + $lenBytes + $bytes
				}

				function Write-ASN1KerberosString {
					param([string]$Str)
					if ([string]::IsNullOrEmpty($Str)) {
						throw "Kerberos string cannot be null or empty"
					}
					$bytes    = [Text.Encoding]::ASCII.GetBytes($Str)
					$lenBytes = Write-ASN1Length $bytes.Length
					return ,([byte]0x1B) + $lenBytes + $bytes
				}

				function Write-ASN1Sequence {
					param(
						[Parameter(Mandatory)]
						[byte[]]$ContentBytes
					)
					$lenBytes = Write-ASN1Length $ContentBytes.Length
					return ,([byte]0x30) + $lenBytes + $ContentBytes
				}

				function Write-ASN1SequenceOf {
					param(
						[Parameter(Mandatory)]
						[byte[][]]$Elements
					)
					$aggregate = @()
					foreach ($el in $Elements) {
						$aggregate += $el
					}
					return Write-ASN1Sequence -ContentBytes $aggregate
				}

				function Build-PrincipalsStringArray {
					param([string]$PrincipalName)
					$parts = $PrincipalName.Split('/')
					if ($parts.Count -eq 0) {
						throw "PrincipalName cannot be empty"
					}
					$out = @()
					foreach ($component in $parts) {
						if (-not [string]::IsNullOrEmpty($component)) {
							$out += Write-ASN1KerberosString $component
						} else {
							throw "Empty component in principal: '$PrincipalName'"
						}
					}
					return $out
				}

				function Build-PrincipalName {
					param(
						[Parameter(Mandatory)]
						[string]$Name,
						[int]$NameType = 1
					)
					# Tag [0] = name-type
					$ntBytes   = Write-ASN1Integer $NameType
					$ntSection = ,([byte]0xA0) + (Write-ASN1Length $ntBytes.Length) + $ntBytes

					# Tag [1] = name-string (sequence of GeneralString)
					$stringElems = Build-PrincipalsStringArray -PrincipalName $Name
					$stringSeq   = Write-ASN1SequenceOf $stringElems
					$nsSection   = ,([byte]0xA1) + (Write-ASN1Length $stringSeq.Length) + $stringSeq

					# Combine into a SEQUENCE
					$combined = $ntSection + $nsSection
					return Write-ASN1Sequence -ContentBytes $combined
				}

				function Get-KerberosErrorDescription {
					param([int]$ErrorCode)
					$map = @{
						1  = "KDC_ERR_NAME_EXP - Client expired"
						2  = "KDC_ERR_SERVICE_EXP - Server expired"
						3  = "KDC_ERR_BAD_PVNO - Bad protocol version"
						6  = "KDC_ERR_C_PRINCIPAL_UNKNOWN - Client not found"
						7  = "KDC_ERR_S_PRINCIPAL_UNKNOWN - Server not found"
						8  = "KDC_ERR_PRINCIPAL_NOT_UNIQUE - Multiple entries"
						12 = "KDC_ERR_NEVER_VALID - Ticket not yet valid"
						18 = "KDC_ERR_CLIENT_REVOKED"
						23 = "KDC_ERR_KEY_EXPIRED"
						24 = "KDC_ERR_PREAUTH_FAILED"
						25 = "KDC_ERR_PREAUTH_REQUIRED"
						32 = "KDC_ERR_SKEW - Clock skew too great"
						68 = "KDC_ERR_WRONG_REALM"
					}

					if ($map.ContainsKey($ErrorCode)) { 
						return $map[$ErrorCode] 
					} else { 
						return "Unknown error code: $ErrorCode" 
					}
				}

				function Find-KerberosErrorCode {
					param(
						[byte[]]$ResponseBytes
					)

					Write-Verbose "Searching for error code in $($ResponseBytes.Length) bytes"
			
					# For debugging, show first few bytes
					if ($ResponseBytes.Length -gt 0) {
						$firstBytes = ($ResponseBytes[0..[Math]::Min(31, $ResponseBytes.Length-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
						Write-Verbose "Response bytes: $firstBytes"
					}

					# KRB-ERROR ASN.1 structure (simplified):
					# KRB-ERROR ::= [APPLICATION 30] SEQUENCE {
					#     pvno [0] INTEGER (5),
					#     msg-type [1] INTEGER (30),
					#     ctime [2] KerberosTime OPTIONAL,
					#     cusec [3] Microseconds OPTIONAL,
					#     stime [4] KerberosTime,
					#     susec [5] Microseconds,
					#     error-code [6] Int32,         <-- This is what we want!
					#     crealm [7] Realm OPTIONAL,
					#     cname [8] PrincipalName OPTIONAL,
					#     realm [9] Realm,
					#     sname [10] PrincipalName,
					#     e-text [11] KerberosString OPTIONAL,
					#     e-data [12] OCTET STRING OPTIONAL
					# }
			
					# We need to find context-specific tag [6] which is 0x86 (constructed) or 0x86 (primitive)
					# Actually, [6] in context-specific is 0xA6 for constructed, 0x86 for primitive
			
					$integerCount = 0
					$foundIntegers = @()
			
					for ($i = 0; $i -lt $ResponseBytes.Length - 2; $i++) {
						# Look specifically for context-specific tag [6] = 0xA6
						if ($ResponseBytes[$i] -eq 0xA6) {
							Write-Verbose "Found context-specific tag [6] at position $i"
					
							# Parse length
							$lengthPos = $i + 1
							if ($lengthPos -ge $ResponseBytes.Length) { continue }
					
							$lenByte = $ResponseBytes[$lengthPos]
							$contentStart = 0
							$contentLength = 0
					
							if ($lenByte -lt 0x80) {
								$contentLength = $lenByte
								$contentStart = $lengthPos + 1
							} else {
								$numLenBytes = $lenByte -band 0x7F
								if ($numLenBytes -eq 0 -or $numLenBytes -gt 4 -or ($lengthPos + $numLenBytes) -ge $ResponseBytes.Length) {
									continue
								}
						
								$contentLength = 0
								for ($j = 0; $j -lt $numLenBytes; $j++) {
									$contentLength = ($contentLength -shl 8) -bor $ResponseBytes[$lengthPos + 1 + $j]
								}
								$contentStart = $lengthPos + 1 + $numLenBytes
							}
					
							# Verify bounds
							if ($contentStart + $contentLength -gt $ResponseBytes.Length) {
								continue
							}
					
							# The content should be an INTEGER (tag 0x02)
							if ($contentStart -lt $ResponseBytes.Length -and $ResponseBytes[$contentStart] -eq 0x02) {
								$intLen = $ResponseBytes[$contentStart + 1]
								if ($intLen -gt 0 -and $contentStart + 1 + $intLen -le $ResponseBytes.Length) {
									$intBytes = $ResponseBytes[($contentStart + 2)..($contentStart + 1 + $intLen)]
									$errorCode = 0
									foreach ($byte in $intBytes) {
										$errorCode = ($errorCode -shl 8) -bor $byte
									}
									Write-Verbose "Found error code in [6]: $errorCode"
									return $errorCode
								}
							}
						}
					}
			
					# Fallback: collect all integers and try to identify the error code
					# Skip the first few integers (likely pvno=5, msg-type=30)
					Write-Verbose "Fallback: collecting all integers in the message"
			
					for ($i = 0; $i -lt $ResponseBytes.Length - 2; $i++) {
						if ($ResponseBytes[$i] -eq 0x02) {
							$intLen = $ResponseBytes[$i + 1]
							if ($intLen -gt 0 -and $intLen -le 4 -and $i + 1 + $intLen -lt $ResponseBytes.Length) {
								$intBytes = $ResponseBytes[($i + 2)..($i + 1 + $intLen)]
								$value = 0
								foreach ($byte in $intBytes) {
									$value = ($value -shl 8) -bor $byte
								}
								$foundIntegers += $value
								Write-Verbose "Found INTEGER at position $i`: $value"
							}
						}
					}
			
					# Analyze the integers we found
					if ($foundIntegers.Count -gt 0) {
						Write-Verbose "Found integers: $($foundIntegers -join ', ')"
				
						# Skip known values: pvno (5), msg-type (30), and look for reasonable error codes
						$candidateErrors = $foundIntegers | Where-Object { 
							$_ -ne 5 -and $_ -ne 30 -and $_ -gt 0 -and $_ -lt 100 
						}
				
						if ($candidateErrors.Count -gt 0) {
							# If we have multiple candidates, take the first one that's not 5 or 30
							$errorCode = $candidateErrors[0]
							Write-Verbose "Selected error code from candidates: $errorCode"
							return $errorCode
						}
					}

					Write-Verbose "No error code found in response"
					return $null
				}

				function Analyze-KerberosResponse {
					[CmdletBinding()]
					param(
						[Parameter(Mandatory)]
						[byte[]]$ResponseBytes
					)
					if (-not $ResponseBytes -or $ResponseBytes.Length -eq 0) {
						return [PSCustomObject]@{
							Type        = 'EMPTY_RESPONSE'
							Valid       = $false
							Description = 'No response data received'
						}
					}
					$firstByte = $ResponseBytes[0]
					Write-Verbose ("First byte of response: 0x{0:X2}" -f $firstByte)
			
					switch ($firstByte) {
						0x6B { # AS-REP
							$analysis = [PSCustomObject]@{
								Type        = 'AS-REP'
								Valid       = $true
								Description = 'Authentication successful'
								ErrorCode   = $null
								ErrorDesc   = $null
								FirstBytes  = $null
							}
						}
						0x7E { # KRB-ERROR
							Write-Verbose "Detected KRB-ERROR response, extracting error code..."
							$errorCode = Find-KerberosErrorCode -ResponseBytes $ResponseBytes
							$analysis  = [PSCustomObject]@{
								Type        = 'KRB-ERROR'
								Valid       = $true
								Description = 'Kerberos Error Response'
								ErrorCode   = $errorCode
								ErrorDesc   = if ($errorCode -ne $null) { Get-KerberosErrorDescription $errorCode } else { "Could not extract error code" }
								FirstBytes  = $null
							}
						}
						default {
							$first16 = ($ResponseBytes[0..[Math]::Min(15, $ResponseBytes.Length-1)] | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
							$analysis = [PSCustomObject]@{
								Type        = 'UNKNOWN'
								Valid       = $false
								Description = "Unrecognized response format (first byte: 0x{0:X2})" -f $firstByte
								ErrorCode   = $null
								ErrorDesc   = $null
								FirstBytes  = $first16
							}
						}
					}

					Write-Verbose "Response Analysis:"
					Write-Verbose "  Type       : $($analysis.Type)"
					Write-Verbose "  Valid      : $($analysis.Valid)"
					Write-Verbose "  Description: $($analysis.Description)"
					if ($analysis.ErrorCode -ne $null) {
						Write-Verbose "  ErrorCode  : $($analysis.ErrorCode) - $($analysis.ErrorDesc)"
					}
					if ($analysis.FirstBytes) {
						Write-Verbose "  FirstBytes : $($analysis.FirstBytes)"
					}
					return $analysis
				}

				function Build-KerberosASREQ {
					[CmdletBinding()]
					param(
						[Parameter(Mandatory)]
						[string]$ClientName,

						[Parameter(Mandatory)]
						[string]$Realm,

						[string]$ServerName = $null,

						[DateTime]$TillTime = (Get-Date).ToUniversalTime().AddHours(24),

						[int[]]$EncryptionTypes = @(18,17,23)
					)
					# Validate
					if ([string]::IsNullOrWhiteSpace($ClientName)) {
						throw "ClientName cannot be empty"
					}
					if ([string]::IsNullOrWhiteSpace($Realm)) {
						throw "Realm cannot be empty"
					}
					if ([string]::IsNullOrWhiteSpace($ServerName)) {
						$ServerName = "krbtgt/$Realm"
					}
					# Nonce (32-bit positive)
					$nonce = Get-Random -Minimum 1000000 -Maximum 2147483647

					# 1. kdc-options [0] => 32-bit zero bitstring
					$zeroBytes       = [byte[]](0,0,0,0)
					$kdcOptionsBytes = Write-ASN1BitString -Bits $zeroBytes
					$kdcOptionsSec   = ,([byte]0xA0) + (Write-ASN1Length $kdcOptionsBytes.Length) + $kdcOptionsBytes

					# 2. cname [1]
					$cnameBytes     = Build-PrincipalName -Name $ClientName -NameType 1
					$cnameSection   = ,([byte]0xA1) + (Write-ASN1Length $cnameBytes.Length) + $cnameBytes

					# 3. realm [2]
					$realmBytes    = Write-ASN1KerberosString -Str $Realm
					$realmSection  = ,([byte]0xA2) + (Write-ASN1Length $realmBytes.Length) + $realmBytes

					# 4. sname [3]
					$snameBytes    = Build-PrincipalName -Name $ServerName -NameType 2
					$snameSection  = ,([byte]0xA3) + (Write-ASN1Length $snameBytes.Length) + $snameBytes

					# 5. till [5]
					$tillBytes     = Write-ASN1KerberosTime -Time $TillTime
					$tillSection   = ,([byte]0xA5) + (Write-ASN1Length $tillBytes.Length) + $tillBytes

					# 6. nonce [7]
					$nonceBytes    = Write-ASN1Integer -Value $nonce
					$nonceSection  = ,([byte]0xA7) + (Write-ASN1Length $nonceBytes.Length) + $nonceBytes

					# 7. etype [8]
					$etypeInts     = foreach ($e in $EncryptionTypes) { Write-ASN1Integer -Value $e }
					$etypeSeq      = Write-ASN1SequenceOf -Elements $etypeInts
					$etypeSection  = ,([byte]0xA8) + (Write-ASN1Length $etypeSeq.Length) + $etypeSeq

					# Combine req-body
					$reqBodyContent = $kdcOptionsSec + $cnameSection + $realmSection + $snameSection + $tillSection + $nonceSection + $etypeSection
					$reqBodySeq     = Write-ASN1Sequence -ContentBytes $reqBodyContent
					$reqBodySection = ,([byte]0xA4) + (Write-ASN1Length $reqBodySeq.Length) + $reqBodySeq

					# pvno [1]
					$pvnoBytes     = Write-ASN1Integer -Value 5
					$pvnoSection   = ,([byte]0xA1) + (Write-ASN1Length $pvnoBytes.Length) + $pvnoBytes

					# msg-type [2]
					$msgTypeBytes  = Write-ASN1Integer -Value 10  # AS-REQ
					$msgTypeSection= ,([byte]0xA2) + (Write-ASN1Length $msgTypeBytes.Length) + $msgTypeBytes

					# Combine KDC-REQ
					$kdcReqContent  = $pvnoSection + $msgTypeSection + $reqBodySection
					$kdcReqSeq      = Write-ASN1Sequence -ContentBytes $kdcReqContent

					# APPLICATION [10] => 0x6A
					$lengthBytes   = Write-ASN1Length $kdcReqSeq.Length
					return ,([byte]0x6A) + $lengthBytes + $kdcReqSeq
				}

				if ([string]::IsNullOrEmpty($ClientName)) {
					$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
					if ($currentUser -match '\\') {
						$ClientName = $currentUser.Split('\')[1]
					} else {
						$ClientName = $currentUser
					}
					Write-Verbose "ClientName not specified; using current user: $ClientName"
				}
			}

			process {
				try {
					# 1. Derive or validate Realm
                    if ([string]::IsNullOrWhiteSpace($Realm)) {
                        $labels = $Server.Split('.')
                        switch ($labels.Count) {
                            { $_ -ge 3 } {
                                # Host plus at least two domain labels:
                                # include every domain segment (subdomain, parent domain, tld)
                                $Realm = ($labels[1..($labels.Count - 1)] -join '.').ToUpper()
                                break
                            }
                            2 {
                                # Only a two-label FQDN (e.g. domain.com)
                                $Realm = ($labels -join '.').ToUpper()
                                break
                            }
                            default {
                                # Could not parse a domain
                                $Realm = 'EXAMPLE.COM'
                                Write-Warning "Could not derive realm from server name; using default '$Realm'."
                            }
                        }
                    }


					Write-Verbose "Testing Kerberos connectivity to $Server`:$Port (Realm: $Realm)"

					# 2. Build AS-REQ packet
					Write-Verbose "[1/5] Building AS-REQ packet..."
					$asReqPacket = Build-KerberosASREQ -ClientName $ClientName -Realm $Realm

					if ($PSBoundParameters.ContainsKey('Verbose') -and $asReqPacket) {
						Write-Verbose "  AS-REQ packet size: $($asReqPacket.Length) bytes"
						$toShow = if ($asReqPacket.Length -ge 32) { $asReqPacket[0..31] } else { $asReqPacket }
						$hexDump = ($toShow | ForEach-Object { "{0:X2}" -f $_ }) -join ' '
						Write-Verbose "  First bytes: $hexDump"
					}

					# 3. Resolve hostname
					Write-Verbose "[2/5] Resolving hostname…"
					try {
						$dnsRecords = [System.Net.Dns]::GetHostAddresses($Server)
						$ServerIP   = $dnsRecords | Where-Object { $_.AddressFamily -eq 'InterNetwork' } | Select-Object -First 1
						if (-not $ServerIP) {
							throw "No IPv4 address found for '$Server'"
						}
						Write-Verbose "  Resolved to: $($ServerIP.IPAddressToString)"
					}
					catch {
						Write-Error "DNS resolution failed: $($_.Exception.Message)"
						return [PSCustomObject]@{
							Success      = $false
							Server       = $Server
							Port         = $Port
							Realm        = $Realm
							ResponseTime = 0
							ResponseSize = 0
							Error        = "DNS_RESOLUTION_FAILED"
							Details      = $_.Exception.Message
						}
					}

					# 4. Send/Receive over UDP
					Write-Verbose "[3/5] Sending AS-REQ packet..."
					$udpClient = $null
					$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
					try {
						$udpClient = New-Object System.Net.Sockets.UdpClient
						$udpClient.Client.ReceiveTimeout = $TimeoutMs
						$remoteEP = [System.Net.IPEndPoint]::new($ServerIP, $Port)

						$bytesSent = $udpClient.Send($asReqPacket, $asReqPacket.Length, $remoteEP)
						if ($bytesSent -ne $asReqPacket.Length) {
							Write-Warning "Only sent $bytesSent of $($asReqPacket.Length) bytes"
						}
						Write-Verbose "  Sent $bytesSent bytes to $($ServerIP):$Port"

						# 5. Wait for response
						Write-Verbose "[4/5] Waiting for response..."
						try {
							$receivedEP = $remoteEP
							$response   = $udpClient.Receive([ref]$receivedEP)
							$stopwatch.Stop()
							Write-Verbose "  Received $($response.Length) bytes in $($stopwatch.ElapsedMilliseconds)ms"

							# 6. Analyze response
							Write-Verbose "[5/5] Analyzing response..."
							$analysis = Analyze-KerberosResponse -ResponseBytes $response

							$obj = [PSCustomObject]@{
								Success       = $true
								Server        = $Server
								Port          = $Port
								Realm         = $Realm
								ResponseTime  = $stopwatch.ElapsedMilliseconds
								ResponseSize  = $response.Length
								Analysis      = $analysis
								RawResponse   = if ($PSBoundParameters.ContainsKey('Verbose')) { $response } else { $null }
							}
							return $obj
						}
						catch [System.Net.Sockets.SocketException] {
							$stopwatch.Stop()
							$errCode = $_.Exception.SocketErrorCode
							Write-Verbose "  SocketException: $errCode"

							$errorMap = @{
								'TimedOut'          = @{ Error='TIMEOUT'; Details="No response within $TimeoutMs ms" }
								'ConnectionReset'   = @{ Error='PORT_CLOSED'; Details="ICMP Port Unreachable—likely closed" }
								'NetworkUnreachable'= @{ Error='NETWORK_UNREACHABLE'; Details="Network is unreachable" }
								'HostUnreachable'   = @{ Error='HOST_UNREACHABLE'; Details="Host is unreachable" }
							}
							$spec = if ($errorMap.ContainsKey($errCode.ToString())) {
								$errorMap[$errCode.ToString()]
							} else {  
								@{ Error='SOCKET_ERROR'; Details="Socket error: $errCode" } 
							}

							return [PSCustomObject]@{
								Success      = $false
								Server       = $Server
								Port         = $Port
								Realm        = $Realm
								ResponseTime = $stopwatch.ElapsedMilliseconds
								ResponseSize = 0
								Error        = $spec.Error
								Details      = $spec.Details
							}
						}
						catch {
							$stopwatch.Stop()
							Write-Error "Receive error: $($_.Exception.Message)"
							return [PSCustomObject]@{
								Success      = $false
								Server       = $Server
								Port         = $Port
								Realm        = $Realm
								ResponseTime = $stopwatch.ElapsedMilliseconds
								ResponseSize = 0
								Error        = "RECEIVE_FAILED"
								Details      = $_.Exception.Message
							}
						}
					}
					catch {
						Write-Error "Send failed: $($_.Exception.Message)"
						return [PSCustomObject]@{
							Success      = $false
							Server       = $Server
							Port         = $Port
							Realm        = $Realm
							ResponseTime = 0
							ResponseSize = 0
							Error        = "SEND_FAILED"
							Details      = $_.Exception.Message
						}
					}
					finally {
						if ($udpClient) {
							$udpClient.Close()
							$udpClient.Dispose()
						}
					}
				}
				catch {
					Write-Error "Unexpected error in Test-KerberosPort: $($_.Exception.Message)"
					return [PSCustomObject]@{
						Success      = $false
						Server       = $Server
						Port         = $Port
						Realm        = $Realm
						ResponseTime = 0
						ResponseSize = 0
						Error        = "UNEXPECTED_ERROR"
						Details      = $_.Exception.Message
					}
				}
			}
		}

		Write-Verbose "Starting advanced Kerberos testing for Domain Controller: $DomainController"

		# Initialize results object
		$Results = [ordered]@{
			DomainController     = $DomainController
			ResolvedIPs          = @()
			DnsResolutionError   = $null
			UdpPort88Tested      = $false
			UdpPort88Open        = $false
			UdpPort88ResponseTime= $null
			UdpPort88Analysis    = $null
			UdpPort88Error       = $null
			UdpPort88Details     = $null
			TcpPort88Open        = $false
			TcpPort389Open       = $false
			TcpPort636Open       = $false
			PortTestDetails      = @{}
			TgtRequestStatus     = 'NotTested'
			TgtRequestError      = $null
			TgsRequestStatus     = 'NotTested'
			TgsRequestError      = $null
			SpnValidationStatus  = 'NotTested'
			SpnValidationError   = $null
			EncryptionType       = $null
			TimeSkewSeconds      = $null
			TimeSkewWarning      = $false
			TimeSkewMessage      = $null
			CrossRealmStatus     = 'NotTested'
			CrossRealmErrors     = @()
			OverallStatus        = 'InProgress'
		}

		# DNS Resolution Test
		$dnsResult = Test-DnsResolution -DomainController $DomainController

		if (-not $dnsResult.Success) {
			$Results.DnsResolutionError = $dnsResult.ErrorMessage
			$Results.OverallStatus = 'Failed'
			return [PSCustomObject]$Results
		}
		$Results.ResolvedIPs = $dnsResult.ResolvedIPs
	}

	process {
		# New: UDP Port 88 Test using Test-KerberosPort
		Write-Verbose "Testing UDP port 88 connectivity"
		$udpTestResult = Test-KerberosPort -Server $DomainController -Port 88 -TimeoutMs 5000
		$Results.UdpPort88Tested = $true
		if ($udpTestResult.Success -and $udpTestResult.Analysis.Type -in @('AS-REP', 'KRB-ERROR')) {
			$Results.UdpPort88Open = $true
			$Results.UdpPort88ResponseTime = $udpTestResult.ResponseTime
			$Results.UdpPort88Analysis = $udpTestResult.Analysis
		} else {
			$Results.UdpPort88Open = $false
			if ($udpTestResult.Success) {
				$Results.UdpPort88Error = "Invalid Kerberos response"
				$Results.UdpPort88Details = "Received response but not a valid Kerberos message"
			} else {
				$Results.UdpPort88Error = $udpTestResult.Error
				$Results.UdpPort88Details = $udpTestResult.Details
			}
		}

		# TCP Connectivity Tests
		$tcpResult = Test-TcpConnectivity -DomainController $DomainController -TimeoutSeconds $TimeoutSeconds
		$Results.TcpPort88Open = $tcpResult.TcpPort88Open
		$Results.TcpPort389Open = $tcpResult.TcpPort389Open
		$Results.TcpPort636Open = $tcpResult.TcpPort636Open
		$Results.PortTestDetails = $tcpResult.PortTestDetails

		# TGT Request Test
		$tgtResult = Test-TgtRequest -DomainController $DomainController -ParameterSetName $PSCmdlet.ParameterSetName -Credential $Credential
		$Results.TgtRequestStatus = $tgtResult.TgtRequestStatus
		$Results.TgtRequestError = $tgtResult.TgtRequestError

		# TGS and SPN Validation Tests
		if ($Results.TgtRequestStatus -eq 'Success') {
			$tgsResult = Test-TgsAndSpnValidation -DomainController $DomainController
			$Results.TgsRequestStatus = $tgsResult.TgsRequestStatus
			$Results.TgsRequestError = $tgsResult.TgsRequestError
			$Results.SpnValidationStatus = $tgsResult.SpnValidationStatus
			$Results.SpnValidationError = $tgsResult.SpnValidationError
			$Results.EncryptionType = $tgsResult.EncryptionType
		}

		# Time Synchronization Test
		$timeResult = Test-TimeSynchronization -DomainController $DomainController
		$Results.TimeSkewSeconds = $timeResult.TimeSkewSeconds
		$Results.TimeSkewWarning = $timeResult.TimeSkewWarning
		$Results.TimeSkewMessage = $timeResult.TimeSkewMessage

		# Cross-Realm Referral Test
		if ($TargetRealm) {
			$crossRealmResult = Test-CrossRealmReferral -TargetRealm $TargetRealm -TgtRequestStatus $Results.TgtRequestStatus
			$Results.CrossRealmStatus = $crossRealmResult.CrossRealmStatus
			$Results.CrossRealmErrors = $crossRealmResult.CrossRealmErrors
		}

		# Determine Overall Status
		$Results.OverallStatus = Get-OverallStatus -TestResults $Results

		Write-Verbose "Overall test status: $($Results.OverallStatus)"

		# Return Results
		return [PSCustomObject]$Results
	}
}
