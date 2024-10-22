import "pe"
rule MAL_EDRSilencer {
	meta:
		author = "raresteak"
		description = "EDRSilencer detections"
	strings:
		$s1 = "LookupPrivilegeValueA"
		$s2 = "OpenProcessToken"
		$s3 = "GetSidSubAuthorityCount"
		$s4 = "AdjustTokenPrivileges"
		$s5 = "CreateToolhelp32Snapshot"
		$m1 = "Detected running EDR process"
		$m2 = "SeDebugPrivilege"
		$m3 = "Custom Outbound Filter" wide
	condition:
		pe.is_pe and 
    ( ( all of ($s*) ) or ( all of ($m*) ) )
}
