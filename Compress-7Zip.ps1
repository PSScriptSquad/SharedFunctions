function Compress-7Zip {
    <#
    .SYNOPSIS
        Create a compressed archive of a file or folder.

    .DESCRIPTION
        Use Compress-7Zip to create a 7z, gzip, zip, bzip2, or tar archive.

    .PARAMETER FullName
        The full path of the file or folder you would like to turn into a compressed archive.

    .PARAMETER OutputFile
        The full path of the file to be created. Defaults to archive.zip in the current working directory.

    .PARAMETER ArchiveType
        The type of archive you would like. Valid types: 7Z, GZIP, ZIP, BZIP2, TAR. Defaults to ZIP.

    .PARAMETER Remove
        If $True, this will remove the uncompressed version of the file or folder, leaving only the compressed archive.

    .EXAMPLE
        Compress-7Zip -FullName 'C:\example\folder' -OutputFile 'C:\backup\folder.zip' -ArchiveType ZIP -Remove

    .NOTES
        Name: Compress-7Zip
        Author: Ryan Whitlock
        Date: 02.02.2020
        Version: 1.1
        Changes: Improved error handling and code simplification.
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0, ValueFromPipelineByPropertyName=$True)]
        [ValidateScript({Test-Path $_})]
        [string]$FullName,

        [Parameter()]
        [string]$OutputFile,

        [Parameter()]
        [ValidateSet("7Z", "GZIP", "ZIP", "BZIP2", "TAR")]
        [string]$ArchiveType = "ZIP",

        [Parameter()]
        [switch]$Remove
    )
    
    Begin {
        $7ZipPath = "C:\Program Files\7-Zip\7z.exe"

        if (-not (Test-Path -Path $7ZipPath)) {
            throw "7-Zip executable not found at $7ZipPath. Please install 7-Zip or adjust the path in the script."
        }

        $archiveSettings = @{
            "7Z" = @('-t7z', '.7z')
            "GZIP" = @('-tgzip', '.gz')
            "ZIP" = @('-tzip', '.zip')
            "BZIP2" = @('-tbzip2', '.bzip2')
            "TAR" = @('-ttar', '.tar')
        }

        $selectedArchive = $archiveSettings[$ArchiveType]
        $7zaArchiveType = $selectedArchive[0]
        $ArchiveExt = $selectedArchive[1]

        if (-not $PSBoundParameters.ContainsKey('OutputFile')) {
            $OutputFile = ".\archive$ArchiveExt"
        }
    }
    
    Process {
        Write-Verbose -Message 'Creating compressed archive file'
        try {
            & "$7ZipPath" a $7zaArchiveType $OutputFile $FullName -y
        } catch {
            throw "Failed to compress the file or folder: $_"
        }

        if ($Remove) {
            Write-Verbose -Message 'Removing original files/folders'
            try {
                Remove-Item -Path $FullName -Recurse -Force -ErrorAction Stop
            } catch {
                throw "Failed to remove the original files/folders: $_"
            }
        }
    }
    
    End {}
}
