rule sus_keywords {
meta:
	author = "Raresteak"
	description = "a list of suspicious keywords"
strings:
	$s01 = "-ep remotesigned " wide ascii nocase
	$s02 = "-ep unrestricted " wide ascii nocase
condition:
	uint16(0) == 0x5a4d and any of ($s*)
}
