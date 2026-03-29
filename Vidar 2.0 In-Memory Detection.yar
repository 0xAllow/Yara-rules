rule Vidar_2_0_Memory_Scan {
meta:
description = "Vidar 2.0 in-memory detection (for YARA memory scanning)"
author = "0xAllow / blacksunCUBE"
website = "https://0xallow.github.io/blacksunCUBE/"
date = "2026-03"
// 0xAllow::blacksunCUBE::2026 //
strings:
$grabber_str = "grabber v" ascii
$api_auth = "/api/auth" ascii
$api_upload = "/api/upload" ascii
$multipart = "multipart/form-data" ascii
$x_auth = "X-Auth-Token" ascii
$pipe = "pipe\\abe_" ascii wide
$desktop = "ChromeBuildTools" ascii wide
condition:
3 of them
}
