import "pe"
rule TTP_concatenated_files {
        meta:
                description = "This signature will detect the presence of exe files that are concatenated together."
                author = "Raresteak"
        strings:
                $text = "This program cannot be run in DOS mode" ascii
        condition:
                uint16be(0) == 0x4d5a
                and
                #text > 2  //setting >1 will create a few false positives with sysinternals and MS bins, and may detect more badness
                and
                pe.version_info["OriginalFilename"] endswith "exe"
}
