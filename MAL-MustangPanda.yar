import "pe"
//objective
//Compose one rule that is specific or precise, with a lot of high-quality strings that catch this exact sample.
//Compose another rule that is “broader” or “looser” or less specific, that will catch this and other samples of the same malware.
//Experiment with a third rule that makes use of the PE module to look for unique or interesting features

rule MAL_MustangPanda_strings {
meta:
	hash="1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
strings:
	$s1="https://45.154.14.235/2022/COVID-19 travel restrictions EU reviews list of third countries.doc" wide
	$s2="/c ping 8.8.8.8 -n 70&&\"%temp%\\PotPlayer.exe" wide
	$s3="https://45.154.14.235/2022/PotPlayer.exe" wide
	$s4="https://45.154.14.235/2022/PotPlayer.dll" wide
	$s5="https://45.154.14.235/2022/PotPlayerDB.dat" wide
condition:
	all of them
}

rule MAL_MustangPanda_strings_looser {
meta:
	hash="1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
strings:
	$s1="https://" nocase wide
	$s2="200 ok" nocase wide
	$s3="/c ping" nocase wide
	$s4="@abcdefghijklmnopqrstuvwxyz"
condition:
	all of them
}

rule MAL_MustangPanda_strings_pe_features {
meta:
	hash="1b520e4dea36830a94a0c4ff92568ff8a9f2fbe70a7cedc79e01cea5ba0145b0"
condition:
	pe.number_of_resources==25 and pe.number_of_imports==3 and filesize > 284000
}