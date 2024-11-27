import "pe"
rule MAL_concatenated_files {
        meta:
                description = "Detect exe files that are concatenated together"
        strings:
                $text = "This program cannot be run in DOS mode" ascii
        condition:
                uint16be(0) == 0x4d5a
                and
                #text > 2  //setting >1 will create a few false positives with sysinternals and MS bins, and may detect more
                and
                pe.version_info["OriginalFilename"] endswith "exe"
}
