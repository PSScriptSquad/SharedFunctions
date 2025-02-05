function Test-ConvertFileSystemRightsToIcacls {
    param (
        [scriptblock]$FunctionToTest
    )

    $testCases = @(
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ListDirectory; Expected = "(R)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadData; Expected = "(R)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::CreateFiles; Expected = "(WD)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::WriteData; Expected = "(WD)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::AppendData; Expected = "(AD)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::CreateDirectories; Expected = "(AD)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes; Expected = "(REA)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes; Expected = "(WEA)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ExecuteFile; Expected = "(X)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::Traverse; Expected = "(X)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles; Expected = "(DC)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadAttributes; Expected = "(RA)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::WriteAttributes; Expected = "(WA)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::Delete; Expected = "(D)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadPermissions; Expected = "(P)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ChangePermissions; Expected = "(P)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::TakeOwnership; Expected = "(O)" }

        # Grouped Permissions
        @{ Input = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
                    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
                    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                    [System.Security.AccessControl.FileSystemRights]::WriteAttributes
           Expected = "(W)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadData -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
                    [System.Security.AccessControl.FileSystemRights]::ExecuteFile
           Expected = "(RX)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Delete -bor
                    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
           Expected = "(D)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
           Expected = "(P,O)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Read -bor
                    [System.Security.AccessControl.FileSystemRights]::Write -bor
                    [System.Security.AccessControl.FileSystemRights]::ExecuteFile
           Expected = "(RX,W)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Modify -bor
                    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
           Expected = "(F)" }
        
        @{ Input = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                    [System.Security.AccessControl.FileSystemRights]::Write -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
           Expected = "(RX,W,DC)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                    [System.Security.AccessControl.FileSystemRights]::Modify
           Expected = "(M,DC)" }

        # Special Cases
        @{ Input = [System.Security.AccessControl.FileSystemRights]::FullControl; Expected = "(F)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::FullControl -bor
                    [System.Security.AccessControl.FileSystemRights]::Write
           Expected = "(F)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Modify -bor
                    [System.Security.AccessControl.FileSystemRights]::Write
           Expected = "(M)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Read -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
           Expected = "(RX)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Write -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadData
           Expected = "(R,W)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::ExecuteFile -bor
                    [System.Security.AccessControl.FileSystemRights]::Traverse
           Expected = "(X)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Delete -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                    [System.Security.AccessControl.FileSystemRights]::Modify
           Expected = "(M)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Write -bor
                    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor
                    [System.Security.AccessControl.FileSystemRights]::Delete
           Expected = "(M)" }

        @{ Input = [System.Security.AccessControl.FileSystemRights]::Synchronize; Expected = "()" }

        # Edge Cases (should throw)
        @{ Input = 2032127; Expected = "(F)" }
        @{ Input = "FullControl"; Expected = "(F)" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor 999999; Expected = "ERROR" }
        @{ Input = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor -1; Expected = "ERROR" }
    )

    $passed = 0
    $failed = 0

    foreach ($test in $testCases) {
        try {
            $actualOutput = & $FunctionToTest $test["Input"]
            if ($actualOutput -eq $test["Expected"]) {
                Write-Host "✅ Test Passed: $($test["Input"]) → $actualOutput" -ForegroundColor Green
                $passed++
            } else {
                Write-Host "❌ Test Failed: $($test["Input"]) → Expected: $($test["Expected"]), Got: $actualOutput" -ForegroundColor Red
                $failed++
            }
        }
        catch {
            if ($test["Expected"] -eq "ERROR") {
                Write-Host "✅ Test Passed (Error Expected): $($test["Input"]) threw an error" -ForegroundColor Green
                $passed++
            } else {
                Write-Host "❌ Test Failed: $($test["Input"]) → Expected: $($test["Expected"]), Got: ERROR ($_)" -ForegroundColor Red
                $failed++
            }
        }
    }

    Write-Host "`nSummary: $passed passed, $failed failed." -ForegroundColor Cyan
    if ($failed -gt 0) {
        throw "$failed test(s) failed. Please review errors."
    }
}

# Run the test suite:
Test-ConvertFileSystemRightsToIcacls -FunctionToTest { param($rights) Convert-FileSystemRightsToIcacls -CombinedRights $rights }
