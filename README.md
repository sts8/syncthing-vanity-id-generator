# Syncthing Vanity ID Generator

Implements a vanity ID generator for Syncthing Device IDs.

## Usage

Set the regex_pattern in the main function and run it.

### Regex pattern examples

    regex_pattern = r"(.)\1{5}"  # 6 repeating characters
    regex_pattern = r"(.)\1{4}"  # 5 repeating characters
    regex_pattern = r"(.)\1{3}"  # 4 repeating characters
    regex_pattern = r"(.)\1{2}"  # 3 repeating characters
    regex_pattern = "HEY"
    regex_pattern = "ABCD"
    regex_pattern = "AA"
