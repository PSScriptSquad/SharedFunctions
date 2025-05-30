function Generate-RandomPassword {
    <#
        .SYNOPSIS
            Generates a random password or passphrase with specified length and complexity.

        .DESCRIPTION
            This function generates a random password of a given length or a passphrase composed of random words.
            It provides options to generate complex passwords or customize complexity by including letters, digits, 
            and/or symbols. For passphrases, it can use online word lists or fall back to a built-in list.
            
            For CustomComplexity parameter set, at least one of -Letters, -Digits, or -Symbols must be specified.

        .PARAMETER Length
            The length of the generated password (minimum 8 characters for security).

        .PARAMETER Complex
            Switch to generate a complex password that includes letters, digits, and symbols.

        .PARAMETER Letters
            Switch to include letters in the password. Required when using CustomComplexity (at least one of Letters, Digits, or Symbols must be specified).

        .PARAMETER Digits
            Switch to include digits in the password. Required when using CustomComplexity (at least one of Letters, Digits, or Symbols must be specified).

        .PARAMETER Symbols
            Switch to include symbols in the password. Required when using CustomComplexity (at least one of Letters, Digits, or Symbols must be specified).

        .PARAMETER Passphrase
            Switch to generate a passphrase instead of a traditional password.

        .PARAMETER WordCount
            Number of words to include in the passphrase (3-8 words, default is 4).

        .PARAMETER Delimiter
            Character(s) to separate words in the passphrase (default is '-').

        .PARAMETER IncludeNumbers
            Switch to append random numbers to passphrase words for additional security.

        .PARAMETER Capitalize
            Switch to capitalize the first letter of each word in the passphrase.

        .PARAMETER UseLocalDict
            Switch to use local system dictionary (/usr/share/dict/words) if available.

        .PARAMETER CustomWordList
            Array of custom words to use for passphrase generation, or path to a text file containing words (one per line).

        .PARAMETER MinWordLength
            Minimum word length for passphrase words (default is 3).

        .PARAMETER MaxWordLength
            Maximum word length for passphrase words (default is 12).

        .PARAMETER DisableOnlineWordList
            Switch to disable online word list fetching. Forces use of local dictionary, custom word list, or fallback list only.

        .PARAMETER AsSecureString
            Return the password as a SecureString object instead of plain text.

        .OUTPUTS
            System.String or System.Security.SecureString

        .EXAMPLE
            Generate a complex password of length 12:
            PS C:\> Generate-RandomPassword -Length 12 -Complex

        .EXAMPLE
            Generate a custom password of length 10 with letters and digits:
            PS C:\> Generate-RandomPassword -Length 10 -Letters -Digits

        .EXAMPLE
            Generate a 4-word passphrase:
            PS C:\> Generate-RandomPassword -Passphrase

        .EXAMPLE
            Generate a 5-word passphrase with numbers and capitalization:
            PS C:\> Generate-RandomPassword -Passphrase -WordCount 5 -IncludeNumbers -Capitalize

        .EXAMPLE
            Generate a passphrase using custom word list:
            PS C:\> Generate-RandomPassword -Passphrase -CustomWordList @('apple', 'banana', 'cherry', 'dog', 'elephant')

        .EXAMPLE
            Generate a password as SecureString for piping to other cmdlets:
            PS C:\> Generate-RandomPassword -Length 16 -Complex -AsSecureString

        .EXAMPLE
            Generate a passphrase for offline use (no online word list):
            PS C:\> Generate-RandomPassword -Passphrase -DisableOnlineWordList

        .NOTES
            Name: Generate-RandomPassword 
            Author: Ryan Whitlock
            Date: 06.25.2024
            Version: 4.3
            Changes: Enhanced security validation, uniform character coverage, updated RNG provider,
                    consistent secure random generation, configurable word lists, entropy calculation for passwords,
                    RNG reuse optimization, bias removal, improved error handling, 
                    added DisableOnlineWordList parameter for offline use, added warning for small word lists
    #>
    [CmdletBinding(DefaultParameterSetName='Complex')]
    param (
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "Complex")]
        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = "CustomComplexity")]
        [ValidateRange(8, [int]::MaxValue)]
        [int]$Length,

        [Parameter(Mandatory = $false, ParameterSetName = "Complex")]
        [switch]$Complex,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Letters,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Digits,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Symbols,

        [Parameter(Mandatory = $true, ParameterSetName = "Passphrase")]
        [switch]$Passphrase,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [ValidateRange(3, 8)]
        [int]$WordCount = 4,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [string]$Delimiter = '-',

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [switch]$IncludeNumbers,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [switch]$Capitalize,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [switch]$UseLocalDict,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [object]$CustomWordList,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [ValidateRange(1, 50)]
        [int]$MinWordLength = 3,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [ValidateRange(1, 50)]
        [int]$MaxWordLength = 12,

        [Parameter(Mandatory = $false, ParameterSetName = "Passphrase")]
        [switch]$DisableOnlineWordList,

        [Parameter(Mandatory = $false)]
        [switch]$AsSecureString
    )

    begin {
        # Validate mutual dependencies
        if ($PSCmdlet.ParameterSetName -eq 'Passphrase' -and $MinWordLength -gt $MaxWordLength) {
            throw [System.ArgumentException]"MinWordLength must be <= MaxWordLength"
        }

        # Single RNG instance for the entire operation
        $Rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()

        function Get-WordList {
            [CmdletBinding()]
            param(
                [switch]$UseLocalDict,
                [object]$CustomWordList,
                [int]$MinLength = 3,
                [int]$MaxLength = 12,
                [switch]$DisableOnlineWordList
            )

            $WordList = @()

            # Try custom word list first if provided
            if ($CustomWordList) {
                if ($CustomWordList -is [string]) {
                    # Treat as file path
                    if (Test-Path $CustomWordList) {
                        Write-Verbose "Loading custom word list from file: $CustomWordList"
                        $WordList = Get-Content $CustomWordList | Where-Object { 
                            $_.Length -ge $MinLength -and 
                            $_.Length -le $MaxLength -and 
                            $_ -match '^[a-zA-Z]+$'
                        }
                        Write-Verbose "Loaded $($WordList.Count) words from custom file"
                    }
                    else {
                        # Improved error handling for missing custom word list files
                        if ($CustomWordList -match '\.(txt|dic|dict|words)$') {
                            throw "Custom word list file not found: $CustomWordList"
                        }
                        else {
                            Write-Warning "Custom word list file not found: $CustomWordList"
                        }
                    }
                }
                elseif ($CustomWordList -is [array]) {
                    # Treat as array of words
                    Write-Verbose "Using provided custom word list array"
                    $WordList = $CustomWordList | Where-Object { 
                        $_ -and
                        $_.Length -ge $MinLength -and 
                        $_.Length -le $MaxLength -and 
                        $_ -match '^[a-zA-Z]+$'
                    }
                    Write-Verbose "Filtered to $($WordList.Count) words from custom array"
                }
                
                # Check for small custom word list and warn
                if ($WordList.Count -gt 0 -and $WordList.Count -lt 10) {
                    Write-Warning "Custom word list contains only $($WordList.Count) words. This may result in low entropy and weaker passphrase security. Consider using a larger word list or the built-in fallback list."
                }
            }

            # Try local dictionary if no custom list or if custom list failed
            if ($WordList.Count -eq 0 -and $UseLocalDict) {
                $LocalPaths = @('/usr/share/dict/words', '/usr/dict/words', 'C:\Windows\System32\drivers\etc\words')
                foreach ($Path in $LocalPaths) {
                    if (Test-Path $Path) {
                        Write-Verbose "Loading local dictionary from: $Path"
                        $WordList = Get-Content $Path | Where-Object { 
                            $_.Length -ge $MinLength -and 
                            $_.Length -le $MaxLength -and 
                            $_ -match '^[a-zA-Z]+$'
                        }
                        Write-Verbose "Loaded $($WordList.Count) words from local dictionary"
                        break
                    }
                }
            }

            # Try online word list if no local dictionary found and online is not disabled
            if ($WordList.Count -eq 0 -and -not $DisableOnlineWordList) {
                try {
                    Write-Verbose "Downloading word list from online source"
                    
                    $Response = Invoke-RestMethod -Uri "https://random-word-api.vercel.app/api?words=500" -Method GET -TimeoutSec 30
                    
                    if ($Response -is [array]) {
                        $WordList = $Response | Where-Object { 
                            $_ -and 
                            $_.Length -ge $MinLength -and 
                            $_.Length -le $MaxLength -and 
                            $_ -match '^[a-zA-Z]+$'
                        }
                        Write-Verbose "Downloaded and filtered $($WordList.Count) words"
                    }
                }
                catch {
                    Write-Warning "Failed to download word list: $($_.Exception.Message)"
                }
            }
            elseif ($WordList.Count -eq 0 -and $DisableOnlineWordList) {
                Write-Verbose "Online word list fetching is disabled"
            }

            # Fall back to built-in list if nothing else worked
            if ($WordList.Count -eq 0) {
                Write-Verbose "Using fallback word list"
                $FallbackList = @(
                    'able', 'about', 'above', 'across', 'action', 'active', 'after', 'again', 'against', 'age',
                    'almost', 'alone', 'along', 'also', 'always', 'among', 'another', 'answer', 'appear', 'around',
                    'back', 'beach', 'become', 'been', 'before', 'begin', 'being', 'below', 'best', 'better',
                    'between', 'blue', 'book', 'both', 'bring', 'build', 'came', 'change', 'city', 'close',
                    'come', 'could', 'country', 'course', 'different', 'door', 'down', 'during', 'each', 'early',
                    'earth', 'easy', 'enough', 'even', 'every', 'example', 'face', 'fact', 'family', 'feel',
                    'field', 'find', 'fire', 'first', 'follow', 'food', 'form', 'found', 'four', 'from',
                    'game', 'give', 'good', 'great', 'green', 'group', 'grow', 'hand', 'hard', 'have',
                    'head', 'help', 'here', 'high', 'home', 'house', 'idea', 'important', 'into', 'just',
                    'keep', 'kind', 'know', 'land', 'large', 'last', 'late', 'learn', 'leave', 'left',
                    'life', 'light', 'like', 'line', 'little', 'live', 'local', 'long', 'look', 'love',
                    'made', 'make', 'many', 'mean', 'might', 'more', 'most', 'move', 'much', 'music',
                    'must', 'name', 'need', 'never', 'next', 'night', 'number', 'often', 'only', 'open',
                    'order', 'other', 'over', 'part', 'people', 'place', 'play', 'point', 'power', 'program',
                    'public', 'question', 'read', 'real', 'right', 'room', 'same', 'school', 'seem', 'service',
                    'several', 'should', 'show', 'side', 'since', 'small', 'social', 'some', 'state', 'still',
                    'story', 'student', 'study', 'system', 'take', 'tell', 'than', 'that', 'their', 'them',
                    'then', 'there', 'these', 'they', 'thing', 'think', 'this', 'those', 'three', 'through',
                    'time', 'today', 'together', 'turn', 'under', 'until', 'used', 'using', 'very', 'want',
                    'water', 'well', 'were', 'what', 'when', 'where', 'which', 'while', 'will', 'with',
                    'within', 'without', 'word', 'work', 'world', 'would', 'write', 'year', 'young', 'your'
                )
                
                $WordList = $FallbackList | Where-Object { 
                    $_.Length -ge $MinLength -and 
                    $_.Length -le $MaxLength 
                }
            }
            
            # Check for small word list after all processing and warn if too small
            if ($WordList.Count -gt 0 -and $WordList.Count -lt 50) {
                Write-Warning "Final word list contains only $($WordList.Count) words. This may result in low entropy and weaker passphrase security. Consider adjusting MinWordLength/MaxWordLength parameters or using a larger custom word list."
            }

            return $WordList
        }

        function Get-SecureRandomBytes {
            param([int]$Count)
            $Bytes = [byte[]]::new($Count)
            $Rng.GetBytes($Bytes)
            return $Bytes
        }

        function Get-UnbiasedRandomIndex {
            param([int]$MaxValue)

            if ($MaxValue -le 1) { return 0 }
            
            # Use rejection sampling to eliminate modulo bias
            $MaxValidValue = ([uint32]::MaxValue / $MaxValue) * $MaxValue - 1
            
            do {
                $RandomBytes = Get-SecureRandomBytes -Count 4
                $RandomValue = [System.BitConverter]::ToUInt32($RandomBytes, 0)
            } while ($RandomValue -gt $MaxValidValue)
            
            return $RandomValue % $MaxValue
        }

        function Get-SecureRandomNumber {
            param(
                [int]$Minimum = 0,
                [int]$Maximum = 1000
            )
            $Range = $Maximum - $Minimum
            $RandomIndex = Get-UnbiasedRandomIndex -MaxValue $Range
            return $RandomIndex + $Minimum
        }

        function Invoke-FisherYatesShuffle {
            param([char[]]$Array)
            for ($i = $Array.Length - 1; $i -gt 0; $i--) {
                $j = Get-UnbiasedRandomIndex -MaxValue ($i + 1)
                $Temp = $Array[$i]
                $Array[$i] = $Array[$j]
                $Array[$j] = $Temp
            }
            return $Array
        }

        # Define character sets for traditional passwords
        $LetterChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $DigitChars = '0123456789'
        $SymbolChars = '!@#$%^&*()-_=+[]{}|;:,.<>?'
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'Passphrase') {
                # Generate passphrase
                # Get word list
                $WordList = Get-WordList -UseLocalDict:$UseLocalDict -CustomWordList $CustomWordList -MinLength $MinWordLength -MaxLength $MaxWordLength -DisableOnlineWordList:$DisableOnlineWordList
                
                if ($WordList.Count -eq 0) {
                    throw "Unable to retrieve any words for passphrase generation."
                }

                Write-Verbose "Using word list with $($WordList.Count) words"
                
                $SelectedWords = @()
                
                # Select random words
                for ($i = 0; $i -lt $WordCount; $i++) {
                    $RandomIndex = Get-UnbiasedRandomIndex -MaxValue $WordList.Count
                    
                    $Word = $WordList[$RandomIndex]
                    
                    # Apply capitalization if requested
                    if ($Capitalize) {
                        $Word = $Word.Substring(0,1).ToUpper() + $Word.Substring(1)
                    }
                    
                    # Add numbers if requested using secure random generation
                    if ($IncludeNumbers) {
                        $RandomNumber = Get-SecureRandomNumber -Minimum 0 -Maximum 1000
                        $Word += $RandomNumber.ToString()
                    }
                    
                    $SelectedWords += $Word
                }
                
                # Calculate and display entropy information
                $Entropy = [Math]::Log($WordList.Count, 2) * $WordCount
                if ($IncludeNumbers) {
                    $Entropy += [Math]::Log(1000, 2) * $WordCount  # ~10 bits per number
                }
                
                Write-Verbose "Passphrase entropy: approximately $([Math]::Round($Entropy, 1)) bits"
                
                # Join words with delimiter
                $Result = ($SelectedWords -join $Delimiter)
            }
            else {
                # Generate traditional password with uniform character coverage
                $RequiredSets = @()
                $CharPool = ""
                
                # Check if any custom complexity parameters are provided
                $CustomComplexityProvided = $PSBoundParameters.ContainsKey('Letters') -or $PSBoundParameters.ContainsKey('Digits') -or $PSBoundParameters.ContainsKey('Symbols')

                if ($Complex -or -not $CustomComplexityProvided) {
                    # If Complex switch is used or no custom complexity parameters are provided, include all character sets
                    $RequiredSets += @{chars = $LetterChars; name = "Letters"}
                    $RequiredSets += @{chars = $DigitChars; name = "Digits"}  
                    $RequiredSets += @{chars = $SymbolChars; name = "Symbols"}
                    $CharPool = $LetterChars + $DigitChars + $SymbolChars
                }
                elseif ($PSCmdlet.ParameterSetName -eq 'CustomComplexity') {
                    # Use custom complexity options
                    if ($Letters) { 
                        $RequiredSets += @{chars = $LetterChars; name = "Letters"}
                        $CharPool += $LetterChars 
                    }
                    if ($Digits) { 
                        $RequiredSets += @{chars = $DigitChars; name = "Digits"}
                        $CharPool += $DigitChars 
                    }
                    if ($Symbols) { 
                        $RequiredSets += @{chars = $SymbolChars; name = "Symbols"}
                        $CharPool += $SymbolChars 
                    }

                    if ($CharPool -eq "") {
                        throw "At least one of the complexity options (Letters, Digits, Symbols) must be specified."
                    }
                }

                # Ensure we have enough length for required character sets
                if ($Length -lt $RequiredSets.Count) {
                    throw "Password length ($Length) must be at least $($RequiredSets.Count) to include all required character types."
                }

                # Generate password with guaranteed character coverage
                $Result = [char[]]::new($Length)
                $CharPoolArray = $CharPool.ToCharArray()
                
                # Step 1: Place one character from each required set
                for ($i = 0; $i -lt $RequiredSets.Count; $i++) {
                    $SetChars = $RequiredSets[$i].chars.ToCharArray()
                    $RandomIndex = Get-UnbiasedRandomIndex -MaxValue $SetChars.Length
                    $Result[$i] = $SetChars[$RandomIndex]
                }
                
                # Step 2: Fill remaining positions from the full character pool
                for ($i = $RequiredSets.Count; $i -lt $Length; $i++) {
                    $RandomIndex = Get-UnbiasedRandomIndex -MaxValue $CharPoolArray.Length
                    $Result[$i] = $CharPoolArray[$RandomIndex]
                }
                
                # Step 3: Fisher-Yates shuffle to eliminate positional bias
                $Result = Invoke-FisherYatesShuffle -Array $Result
                
                # Calculate entropy for traditional passwords
                # More accurate calculation accounting for guaranteed character sets
                $PoolSize = $CharPool.Length
                $BaseEntropy = [Math]::Log($PoolSize, 2) * $Length
                
                # Subtract entropy loss from guaranteed character placement
                $EntropyAdjustment = 0
                foreach ($Set in $RequiredSets) {
                    $SetSize = $Set.chars.Length
                    $EntropyAdjustment += [Math]::Log($PoolSize / $SetSize, 2)
                }
                
                $AdjustedEntropy = $BaseEntropy - $EntropyAdjustment
                Write-Verbose "Password entropy: approximately $([Math]::Round($AdjustedEntropy, 1)) bits (adjusted for guaranteed character sets)"
                
                $Result = -join $Result
            }

            # Return as SecureString if requested
            if ($AsSecureString) {
                return (ConvertTo-SecureString $Result -AsPlainText -Force)
            }
            else {
                return $Result
            }
        }
        finally {
            # Ensure RNG is properly disposed
            if ($Rng) {
                $Rng.Dispose()
            }
        }
    }

    end {
        # Additional cleanup in case of early termination
        if ($Rng) {
            $Rng.Dispose()
        }
    }
}
