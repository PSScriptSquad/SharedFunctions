function Generate-RandomPassword {
    <#
        .SYNOPSIS
            Generates a random password with specified length and complexity.

        .DESCRIPTION
            This function generates a random password of a given length. It provides an option to generate a complex password
            or customize the complexity by including letters, digits, and/or symbols. If no complexity parameters (Letters, 
            Digits, Symbols) are defined, the function will generate a complex password by default.

        .PARAMETER Length
            The length of the generated password.

        .PARAMETER Complex
            Switch to generate a complex password that includes letters, digits, and symbols.

        .PARAMETER Letters
            Switch to include letters in the password.

        .PARAMETER Digits
            Switch to include digits in the password.

        .PARAMETER Symbols
            Switch to include symbols in the password.

        .EXAMPLE
            Generate a complex password of length 12:
            PS C:\> Generate-RandomPassword -Length 12 -Complex

        .EXAMPLE
            Generate a custom password of length 10 with letters and digits:
            PS C:\> Generate-RandomPassword -Length 10 -Letters -Digits

        .NOTES
            Name: Generate-RandomPassword 
            Author: Ryan Whitlock
            Date: 06.25.2024
            Version: 1.0
            Changes: Initial release           
    #>
    [CmdletBinding(DefaultParameterSetName='Complex')]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateRange(1, [int]::MaxValue)]
        [int]$Length,

        [Parameter(Mandatory = $false, ParameterSetName = "Complex")]
        [switch]$Complex,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Letters,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Digits,

        [Parameter(Mandatory = $false, ParameterSetName = "CustomComplexity")]
        [switch]$Symbols
    )

    begin {
        # Define character sets
        $letterChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
        $digitChars = '0123456789'
        $symbolChars = '!@#$%^&*()-_=+[]{}|;:,.<>?/'
        
        # Initialize the character pool
        $charPool = ""
    }

    process {
        # Check if any custom complexity parameters are provided
        $customComplexityProvided = $PSBoundParameters.ContainsKey('Letters') -or $PSBoundParameters.ContainsKey('Digits') -or $PSBoundParameters.ContainsKey('Symbols')

        if ($Complex -or -not $customComplexityProvided) {
            # If Complex switch is used or no custom complexity parameters are provided, include all character sets
            $charPool += $letterChars
            $charPool += $digitChars
            $charPool += $symbolChars
        } elseif ($PSCmdlet.ParameterSetName -eq 'CustomComplexity') {
            # Use switch statement to handle custom complexity
            switch ($PSBoundParameters.Keys) {
                'Letters' { $charPool += $letterChars }
                'Digits' { $charPool += $digitChars }
                'Symbols' { $charPool += $symbolChars }
            }

            # Ensure at least one character set is included
            if ($charPool -eq "") {
                throw "At least one of the complexity options (Letters, Digits, Symbols) must be specified."
            }
        }

        # Convert character pool to a char array
        $charSet = $charPool.ToCharArray()

        # Create RNGCryptoServiceProvider instance for secure random number generation
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::new()

        # Create a byte array to hold random bytes
        $bytes = [byte[]]::new($Length)

        # Fill the byte array with random bytes
        $rng.GetBytes($bytes)

        # Initialize an array to hold the resulting password characters
        $result = [char[]]::new($Length)

        # Generate the password by mapping random bytes to characters in the character set
        for ($i = 0; $i -lt $Length; $i++) {
            $result[$i] = $charSet[$bytes[$i] % $charSet.Length]
        }
    }

    end {
        # Return the generated password
        return -join $result
    }
}
