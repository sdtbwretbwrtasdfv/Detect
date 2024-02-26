rule Detect_5pdr {
    meta:
        description = "Detects files containing the string '5pdr'"
        author = "sdtbwretbwrtasdfv"
        date = "2024-02-26"
    strings:
        $a = "5pdr" ascii
    condition:
        $a
}
