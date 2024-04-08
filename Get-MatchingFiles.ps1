Function Get-MatchingFiles {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({
            if (-not ($_ | Test-Path)) {
                throw "File or folder does not exist"
            }
            return $true
        })]
        [System.IO.FileInfo]$PathA,

        [Parameter(Mandatory=$true, Position=1)]
        [ValidateScript({
            if (-not ($_ | Test-Path)) {
                throw "File or folder does not exist"
            }
            return $true
        })]
        [System.IO.FileInfo]$PathB
    ) 

    # Adding the required assembly for using System.Core
    Add-Type -AssemblyName System.Core

    # Defining a class to compare files
    class FileCompare : System.Collections.Generic.IEqualityComparer[object] {
        [bool] Equals([object]$fA, [object]$fB) { 
            # Comparing file names and lengths
            return $fA.Name -eq $fB.Name -and $fA.Length -eq $fB.Length 
        } 
        
        [int] GetHashCode($fA) { 
            # Generating hash code based on file name
            return $fA.Name.GetHashCode()
        }
    }

    # Creating DirectoryInfo objects for the specified paths
    [System.IO.DirectoryInfo]$DirA = [System.IO.DirectoryInfo]::new($PathA)
    [System.IO.DirectoryInfo]$DirB = [System.IO.DirectoryInfo]::new($PathB)

    # Enumerating files in the directories
    $FilesA = $DirA.EnumerateFileSystemInfos('*', [System.IO.SearchOption]::AllDirectories)
    $FilesB = $DirB.EnumerateFileSystemInfos('*', [System.IO.SearchOption]::AllDirectories)

    # Creating an instance of the FileCompare class
    [FileCompare]$FileCompare = [FileCompare]::new()

    # Finding matching files using LINQ's Intersect method
    $MatchingFiles = [Linq.Enumerable]::Intersect(
        [System.Collections.Generic.IEnumerable[object]]$FilesA,
        [System.Collections.Generic.IEnumerable[object]]$FilesB,
        [FileCompare]$FileCompare
    )

    # Returning the matching files
    Return $MatchingFiles
}
