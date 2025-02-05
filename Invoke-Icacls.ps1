function Invoke-Icacls {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$User,

        # Allow an array so multiple rights can be specified.
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemRights[]]$Rights,

        # Allow an array so multiple inheritance options can be specified.
        [Parameter(Mandatory = $false)]

        [System.Security.AccessControl.InheritanceFlags[]]$Inheritance = @([System.Security.AccessControl.InheritanceFlags]::None),

        [Parameter(Mandatory = $false)]
        [System.Security.AccessControl.PropagationFlags]$Propagation = [System.Security.AccessControl.PropagationFlags]::None,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.AccessControlType]$ControlType,

        [Parameter(Mandatory = $false)]
        [Switch]$Recurse,

        [Parameter(Mandatory = $false)]
        [Switch]$ContinueOnError
    )

    begin {
        # Helper function to convert combined FileSystemRights to icacls flag(s).
        function Convert-FileSystemRightsToIcacls {
            [CmdletBinding()]
            param(
                [Parameter(Mandatory = $true, Position = 0)]
                [ValidateScript({
                    # Ensure the value is a nonnegative integer.
                    if ([int]$_ -lt 0) {
                        throw "FileSystemRights value must be greater than or equal to 0. Current value: $($_)"
                    }

                    if ($_ -isnot [System.Security.AccessControl.FileSystemRights]) {
                        throw "Input must be a valid [System.Security.AccessControl.FileSystemRights] enum value."
                    }

                    # Manually defined allowed maximum (mask). Adjust as needed.
                    $allowedMask = 2032127
                    if ([int]$_ -gt $allowedMask) {
                        throw "FileSystemRights value ($_) is greater than the allowed maximum ($allowedMask)."
                    }

                    $true
                })]
                [System.Security.AccessControl.FileSystemRights]$CombinedRights
            )

            Write-Verbose "Raw input: $CombinedRights"

            # Remove Synchronize (not mapped)
            $CombinedRights = $CombinedRights -band (-bnot [System.Security.AccessControl.FileSystemRights]::Synchronize)
            Write-Verbose "After removing Synchronize: $CombinedRights"

            # ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
            # Validate that no unknown bits are set.
            # (Because many FileSystemRights values are composite, we build a mask from the fundamental flags we allow.)
            $allowedBits = @(
                [System.Security.AccessControl.FileSystemRights]::Delete,
                [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles,
                [System.Security.AccessControl.FileSystemRights]::Modify,
                [System.Security.AccessControl.FileSystemRights]::ReadAndExecute,
                [System.Security.AccessControl.FileSystemRights]::Read,
                [System.Security.AccessControl.FileSystemRights]::Write,
                [System.Security.AccessControl.FileSystemRights]::ReadPermissions,
                [System.Security.AccessControl.FileSystemRights]::ChangePermissions,
                [System.Security.AccessControl.FileSystemRights]::TakeOwnership,
                [System.Security.AccessControl.FileSystemRights]::Traverse,
                [System.Security.AccessControl.FileSystemRights]::ExecuteFile,
                [System.Security.AccessControl.FileSystemRights]::ListDirectory,
                [System.Security.AccessControl.FileSystemRights]::ReadData,
                [System.Security.AccessControl.FileSystemRights]::ReadAttributes,
                [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes,
                [System.Security.AccessControl.FileSystemRights]::WriteData,
                [System.Security.AccessControl.FileSystemRights]::AppendData,
                [System.Security.AccessControl.FileSystemRights]::WriteAttributes,
                [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes,
                [System.Security.AccessControl.FileSystemRights]::CreateFiles,
                [System.Security.AccessControl.FileSystemRights]::CreateDirectories,
                [System.Security.AccessControl.FileSystemRights]::FullControl
            )
            $validMask = 0
            foreach ($bit in $allowedBits) {
                $validMask = $validMask -bor $bit
            }
            if (($CombinedRights -band (-bnot $validMask)) -ne 0) {
                throw "Invalid FileSystemRights value detected. Ensure only valid permissions are used."
            }
            Write-Verbose "Validation passed. (validMask = $validMask)"

            # ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
            # For certain single‐value inputs (that are “ambiguous” because their underlying bit
            # is shared) we use the caller’s literal name. For example, if the input is exactly
            # "ListDirectory" we want to return (L) rather than (R).
            $inputName = $PSBoundParameters["CombinedRights"].ToString()
            Write-Verbose "Input name string: $inputName"

            if ($CombinedRights -eq [System.Security.AccessControl.FileSystemRights]::ListDirectory -and $inputName -eq "ListDirectory") {
                Write-Verbose "Detected singular ListDirectory input."
                return "(R)"
            }
            if ($CombinedRights -eq [System.Security.AccessControl.FileSystemRights]::ReadData -and $inputName -eq "ReadData") {
                Write-Verbose "Detected singular ReadData input."
                return "(R)"
            }
            if ($CombinedRights -eq [System.Security.AccessControl.FileSystemRights]::Read -and $inputName -eq "Read") {
                Write-Verbose "Detected singular Read input."
                return "(R)"
            }

            # ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
            # If FullControl is explicitly set OR if a complete set of “sub‐rights” is present, return F immediately.
            if (($CombinedRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl) {
                Write-Verbose "FullControl explicitly detected."
                return "(F)"
            }
            # Also, if Modify, DeleteSubdirectoriesAndFiles, ChangePermissions and TakeOwnership are all set,
            # then treat that grouping as FullControl.
            $fcGroup = [System.Security.AccessControl.FileSystemRights]::Modify -bor
                       [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                       [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                       [System.Security.AccessControl.FileSystemRights]::TakeOwnership
            if (( $CombinedRights -band $fcGroup ) -eq $fcGroup) {
                Write-Verbose "FullControl grouping (via sub-rights) detected."
                return "(F)"
            }

            # ––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––––
            # Now “peel off” known bits, grouping where complete.
            $resultFlags = @()
            $remaining = $CombinedRights
            Write-Verbose "Begin processing remaining bits: $remaining"

            # ----- Grouping for Modify (M) -----
            # Two ways: either the explicit Modify flag is set OR the combination of Read, Write and ExecuteFile is present.
            $explicitModify = [System.Security.AccessControl.FileSystemRights]::Modify
            $modifyGroup = [System.Security.AccessControl.FileSystemRights]::Read -bor
                           [System.Security.AccessControl.FileSystemRights]::Write -bor
                           [System.Security.AccessControl.FileSystemRights]::ExecuteFile
            if (( $remaining -band $explicitModify ) -eq $explicitModify) {
                Write-Verbose "Explicit Modify detected."
                $resultFlags += "M"
                $remaining = $remaining -band (-bnot $explicitModify)
            }
            # Only group as Modify if the caller did not explicitly include ReadAndExecute in their input.
            elseif (($inputName -notmatch "ReadAndExecute") -and (( $remaining -band $modifyGroup ) -eq $modifyGroup)) {
                Write-Verbose "Modify grouping (Read, Write, ExecuteFile) detected."
                $resultFlags += "M"
                $remaining = $remaining -band (-bnot $modifyGroup)
            }

            # ----- Grouping for Read & Execute (RX) -----
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ReadAndExecute ) -eq [System.Security.AccessControl.FileSystemRights]::ReadAndExecute) {
                Write-Verbose "ReadAndExecute flag detected."
                $resultFlags += "RX"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ReadAndExecute)
            }
            else {
                $readGroup = [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                             [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                             [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor
                             [System.Security.AccessControl.FileSystemRights]::ExecuteFile
                if (( $remaining -band $readGroup ) -eq $readGroup) {
                    Write-Verbose "Granular Read grouping (ReadData, ReadAttributes, ReadExtendedAttributes, ExecuteFile) detected."
                    $resultFlags += "RX"
                    $remaining = $remaining -band (-bnot $readGroup)
                }
            }

            # ----- Grouping for Write (W) -----
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::Write ) -eq [System.Security.AccessControl.FileSystemRights]::Write) {
                Write-Verbose "Write flag detected."
                $resultFlags += "W"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::Write)
            }
            else {
                $writeGroup = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                              [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                              [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                              [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
                if (( $remaining -band $writeGroup ) -eq $writeGroup) {
                    Write-Verbose "Granular Write grouping (WriteData, AppendData, WriteAttributes, WriteExtendedAttributes) detected."
                    $resultFlags += "W"
                    $remaining = $remaining -band (-bnot $writeGroup)
                }
            }

            # ----- Grouping for Delete -----
            $hasDelete = (( $remaining -band [System.Security.AccessControl.FileSystemRights]::Delete ) -eq [System.Security.AccessControl.FileSystemRights]::Delete)
            $hasDeleteSub = (( $remaining -band [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles ) -eq [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
            if ($hasDelete -and $hasDeleteSub) {
                Write-Verbose "Both Delete and DeleteSubdirectoriesAndFiles detected; merging as Delete."
                $resultFlags += "D"
                $remaining = $remaining -band (-bnot ([System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles))
            }
            elseif ($hasDelete) {
                Write-Verbose "Delete detected."
                $resultFlags += "D"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::Delete)
            }
            elseif ($hasDeleteSub) {
                Write-Verbose "DeleteSubdirectoriesAndFiles detected."
                $resultFlags += "DC"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles)
            }

            # ----- Advanced rights: ChangePermissions, ReadPermissions, TakeOwnership -----
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ReadPermissions ) -eq [System.Security.AccessControl.FileSystemRights]::ReadPermissions) {
                Write-Verbose "ReadPermissions detected."
                $resultFlags += "P"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ReadPermissions)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ChangePermissions ) -eq [System.Security.AccessControl.FileSystemRights]::ChangePermissions) {
                Write-Verbose "ChangePermissions detected."
                $resultFlags += "P"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ChangePermissions)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::TakeOwnership ) -eq [System.Security.AccessControl.FileSystemRights]::TakeOwnership) {
                Write-Verbose "TakeOwnership detected."
                $resultFlags += "O"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::TakeOwnership)
            }

            # ----- Granular rights not yet grouped -----
            # For execute/traverse, map both to "X"
            if ((( $remaining -band [System.Security.AccessControl.FileSystemRights]::Traverse ) -eq [System.Security.AccessControl.FileSystemRights]::Traverse) -or 
                (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ExecuteFile ) -eq [System.Security.AccessControl.FileSystemRights]::ExecuteFile)) {
                Write-Verbose "Traverse/ExecuteFile detected."
                $resultFlags += "X"
                $remaining = $remaining -band (-bnot ([System.Security.AccessControl.FileSystemRights]::Traverse -bor [System.Security.AccessControl.FileSystemRights]::ExecuteFile))
            }
            # For the ambiguous ReadData/ListDirectory bit: in composite contexts default to "R"
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ListDirectory ) -eq [System.Security.AccessControl.FileSystemRights]::ListDirectory) {
                Write-Verbose "ListDirectory (or ReadData) detected in composite context – mapping as R."
                $resultFlags += "R"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ListDirectory)
            }
            # Additional granular mappings:
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::CreateFiles ) -eq [System.Security.AccessControl.FileSystemRights]::CreateFiles) {
                Write-Verbose "CreateFiles detected."
                $resultFlags += "WD"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::CreateFiles)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::CreateDirectories ) -eq [System.Security.AccessControl.FileSystemRights]::CreateDirectories) {
                Write-Verbose "CreateDirectories detected."
                $resultFlags += "AD"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::CreateDirectories)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::WriteData ) -eq [System.Security.AccessControl.FileSystemRights]::WriteData) {
                Write-Verbose "WriteData detected."
                $resultFlags += "WD"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::WriteData)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::AppendData ) -eq [System.Security.AccessControl.FileSystemRights]::AppendData) {
                Write-Verbose "AppendData detected."
                $resultFlags += "AD"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::AppendData)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::WriteAttributes ) -eq [System.Security.AccessControl.FileSystemRights]::WriteAttributes) {
                Write-Verbose "WriteAttributes detected."
                $resultFlags += "WA"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::WriteAttributes)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes ) -eq [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes) {
                Write-Verbose "WriteExtendedAttributes detected."
                $resultFlags += "WEA"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ReadAttributes ) -eq [System.Security.AccessControl.FileSystemRights]::ReadAttributes) {
                Write-Verbose "ReadAttributes detected."
                $resultFlags += "RA"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ReadAttributes)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes ) -eq [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes) {
                Write-Verbose "ReadExtendedAttributes detected."
                $resultFlags += "REA"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes)
            }
            if (( $remaining -band [System.Security.AccessControl.FileSystemRights]::ReadData ) -eq [System.Security.AccessControl.FileSystemRights]::ReadData) {
                Write-Verbose "ReadData detected."
                $resultFlags += "R"
                $remaining = $remaining -band (-bnot [System.Security.AccessControl.FileSystemRights]::ReadData)
            }

            if ($remaining -ne 0) {
                throw "Unknown FileSystemRights bits detected in remaining value: $remaining"
            }
    
            # ----- Ordering the flags -----
            # (Using a custom order so that, for example, R comes before W, and M comes before D.)
            $order = @{
                "F"   =  0;
                "M"   =  1;
                "RX"  =  2;
                "R"   =  3;
                "W"   =  4;
                "WD"  =  5;
                "AD"  =  6;
                "RA"  =  7;
                "REA" =  8;
                "WA"  =  9;
                "WEA" = 10;
                "D"   = 11;
                "DC"  = 12;
                "P"   = 13;
                "O"   = 14;
                "X"   = 15;
                "L"   = 16
            }
            $resultFlags = $resultFlags | Sort-Object { $order[$_] } | Select-Object -Unique

            $final = "(" + ($resultFlags -join ",") + ")"
            Write-Verbose "Final result: $final"
            return $final
        }

        # Helper function to convert combined InheritanceFlags to icacls syntax.
        function Convert-InheritanceAndPropagationToIcacls {
            param(
                [System.Security.AccessControl.InheritanceFlags]$CombinedInheritance,
                [System.Security.AccessControl.PropagationFlags]$Propagation
            )
            $flag = ""
            if ($CombinedInheritance -band [System.Security.AccessControl.InheritanceFlags]::ContainerInherit) {
                $flag += "(CI)"
            }
            if ($CombinedInheritance -band [System.Security.AccessControl.InheritanceFlags]::ObjectInherit) {
                $flag += "(OI)"
            }
            if ($Propagation -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) {
                $flag += "(IO)"
            }

            return $flag
        }
    }

    process {
        # Combine the array of Rights using bitwise OR.
        $combinedRights = 0
        foreach ($r in $Rights) {
            $combinedRights = $combinedRights -bor $r
        }

        # Combine the array of Inheritance flags using bitwise OR.
        $combinedInheritance = 0
        foreach ($i in $Inheritance) {
            $combinedInheritance = $combinedInheritance -bor $i
        }

        # Convert the combined values to the strings required by icacls.
        $icaclsRightsFlag = Convert-FileSystemRightsToIcacls -CombinedRights $combinedRights
        $icaclsInheritanceFlag = Convert-InheritanceAndPropagationToIcacls -CombinedInheritance $combinedInheritance -Propagation $Propagation

        # Build the permission string in the format "User:(CI)(OI)F"
        $permissionString = "$($User):$icaclsInheritanceFlag$icaclsRightsFlag"

        # Determine the icacls action based on the AccessControlType.
        switch -Exact ($ControlType) {
            { $_ -eq [System.Security.AccessControl.AccessControlType]::Allow } { $icaclsAction = "/grant" }
            { $_ -eq [System.Security.AccessControl.AccessControlType]::Deny }  { $icaclsAction = "/deny" }
            default { throw "Unsupported AccessControlType: $ControlType" }
        }

        # Build the full icacls command.
        $icaclsCmd = @($Path, $icaclsAction, $permissionString)
        if ($Recurse)         { $icaclsCmd += "/t" }
        if ($ContinueOnError) { $icaclsCmd += "/c" }

        Write-Verbose "Executing: icacls.exe $($icaclsCmd -join ' ')"

        $result = Invoke-ExternalCommand -commandPath "icacls.exe" -Arguments $icaclsCmd -TimeoutMilliseconds 30000000
        if ($result.ExitCode -eq 0) {
            Write-Verbose "Successfully executed: $($icaclsCmd -join ' ')"
        }
        else {
            Write-Error "Failed to execute icacls. Error: $($result.StdErr)"
        }
    }
}
