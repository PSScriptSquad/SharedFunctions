function Convert-DeviceRedirection {
    <#
        .SYNOPSIS
            Converts a 32-bit unsigned integer representing RDG device redirection settings to a human-readable format and vice versa.

        .DESCRIPTION
            This function allows conversion between a 32-bit unsigned integer (representing RDG device redirection settings) 
            and a set of flags indicating which redirection features are enabled or disabled. It supports two parameter sets:
            one for converting from an integer to a textual description, and another for converting from a set of switches 
            to an integer.

        .PARAMETER Value
            A 32-bit unsigned integer that represents the RDG device redirection settings in network-byte order. 
            This parameter is used in the "ToText" parameter set.

        .PARAMETER DrivesEnabled
            Indicates whether drives redirection is enabled. This parameter is used in the "ToInt" parameter set.

        .PARAMETER PrintersEnabled
            Indicates whether printers redirection is enabled. This parameter is used in the "ToInt" parameter set.

        .PARAMETER SerialPortsEnabled
            Indicates whether serial ports redirection is enabled. This parameter is used in the "ToInt" parameter set.

        .PARAMETER ClipboardEnabled
            Indicates whether clipboard redirection is enabled. This parameter is used in the "ToInt" parameter set.

        .PARAMETER PlugAndPlayEnabled
            Indicates whether plug-and-play devices redirection is enabled. This parameter is used in the "ToInt" parameter set.

        .PARAMETER DisableAll
            Disables redirection for all devices. If set, the states of other flags are ignored. This parameter is used in the "ToInt" parameter set.

        .PARAMETER EnableAll
            Enables redirection for all devices. If set, the states of other flags are ignored. This parameter is used in the "ToInt" parameter set.

        .EXAMPLE
            # Example 1: Convert an integer to a textual description
            Convert-DeviceRedirection -Value 1073741824

            # Example 2: Convert flags to an integer with all redirections enabled
            Convert-DeviceRedirection -DrivesEnabled -PrintersEnabled -ClipboardEnabled -SerialPortsEnabled -PlugAndPlayEnabled

            # Example 3: Convert flags to an integer with all redirections disabled
            Convert-DeviceRedirection -DisableAll

            # Example 4: Convert flags to an integer with only drives and printers redirection enabled
            Convert-DeviceRedirection -DrivesEnabled -PrintersEnabled

        .NOTES
            When either the DisableAll or EnableAll flag is set, the individual feature flags (DrivesEnabled, PrintersEnabled, 
            SerialPortsEnabled, ClipboardEnabled, PlugAndPlayEnabled) are ignored.

            Author: Ryan Whitlock
            Date: 07.30.2024
            Version: 1.0
            Changes: Initial release
    #>
    [CmdletBinding(DefaultParameterSetName = "ToText")]
    param (
        [Parameter(Position = 0, Mandatory = $true, ParameterSetName = "ToText")]
        [ValidateRange(0,[uint32]::MaxValue)]
        [UInt32]
        $Value,

        [Parameter(Position = 0, ParameterSetName = "ToInt")]
        [Switch]
        $DrivesEnabled,

        [Parameter(Position = 1, ParameterSetName = "ToInt")]
        [Switch]
        $PrintersEnabled,

        [Parameter(Position = 2, ParameterSetName = "ToInt")]
        [Switch]
        $SerialPortsEnabled,

        [Parameter(Position = 3, ParameterSetName = "ToInt")]
        [Switch]
        $ClipboardEnabled,

        [Parameter(Position = 4, ParameterSetName = "ToInt")]
        [Switch]
        $PlugAndPlayEnabled,

        [Parameter(Position = 5, ParameterSetName = "ToInt")]
        [Switch]
        $DisableAll,

        [Parameter(Position = 6, ParameterSetName = "ToInt")]
        [Switch]
        $EnableAll
    )

    begin {
        # Define bit masks for each setting
        $BitMasks = @{
            DrivesEnabled     = 0x1
            PrintersEnabled   = 0x2
            SerialPortsEnabled= 0x4
            ClipboardEnabled  = 0x8
            PlugAndPlayEnabled= 0x10
            DisableAll        = 0x20000000
            EnableAll         = 0x40000000
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq "ToText") {
            $Flags = @{
                DrivesEnabled     = -not [bool]($Value -band $BitMasks['DrivesEnabled'])
                PrintersEnabled   = -not [bool]($Value -band $BitMasks['PrintersEnabled'])
                SerialPortsEnabled= -not [bool]($Value -band $BitMasks['SerialPortsEnabled'])
                ClipboardEnabled  = -not [bool]($Value -band $BitMasks['ClipboardEnabled'])
                PlugAndPlayEnabled= -not [bool]($Value -band $BitMasks['PlugAndPlayEnabled'])
                DisableAll        = [bool]($Value -band $BitMasks['DisableAll'])
                EnableAll         = [bool]($Value -band $BitMasks['EnableAll'])
            }

            if ($Flags.EnableAll) {
                "All devices redirection is enabled"
            }
            elseif ($Flags.DisableAll) {
                "All devices redirection is disabled"
            }
            else {
                if ($Flags.DrivesEnabled) {
                    "Drives redirection: Enabled"
                } else {
                    "Drives redirection: Disabled"
                }

                if ($Flags.PrintersEnabled) {
                    "Printers redirection: Enabled"
                } else {
                    "Printers redirection: Disabled"
                }

                if ($Flags.SerialPortsEnabled) {
                    "Serial ports redirection: Enabled"
                } else {
                    "Serial ports redirection: Disabled"
                }

                if ($Flags.ClipboardEnabled) {
                    "Clipboard redirection: Enabled"
                } else {
                    "Clipboard redirection: Disabled"
                }

                if ($Flags.PlugAndPlayEnabled) {
                    "Plug and play devices redirection: Enabled"
                } else {
                    "Plug and play devices redirection: Disabled"
                }
            }
        }
        else {
            $Value = 0

            if ($EnableAll) {
                $Value = $Value -bor $BitMasks['EnableAll']
            }
            elseif ($DisableAll) {
                $Value = $Value -bor $BitMasks['DisableAll']
            }
            else {
                if ($DrivesEnabled) {
                    $Value = $Value -bor $BitMasks['DrivesEnabled']
                }
                if ($PrintersEnabled) {
                    $Value = $Value -bor $BitMasks['PrintersEnabled']
                }
                if ($SerialPortsEnabled) {
                    $Value = $Value -bor $BitMasks['SerialPortsEnabled']
                }
                if ($ClipboardEnabled) {
                    $Value = $Value -bor $BitMasks['ClipboardEnabled']
                }
                if ($PlugAndPlayEnabled) {
                    $Value = $Value -bor $BitMasks['PlugAndPlayEnabled']
                }
            }

            Write-Output $Value
        }
    }
}
