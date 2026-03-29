rule Vidar_2_0_CFF_Infostealer {
meta:
description = "Vidar Infostealer 2.0 - CFF obfuscated PE with dynamic API resolution"
author = "0xAllow / blacksunCUBE"
website = "https://0xallow.github.io/blacksunCUBE/"
date = "2026-03"
tlp = "clear"
hash = "bcf8a6911bf4033cf4d55caf22d7da9d97275bbb3b0f8fefd1129e86bd4b49f8"
// 0xAllow::blacksunCUBE::2026 //
strings:
// CFF dispatcher pattern: cmp reg, imm32; je; cmp reg, imm32; je
$cff_dispatch = { 81 (F8|F9|FA|FB|FC|FD|FE|FF) ?? ?? ?? ?? 0F 84 ?? ?? ?? ??
81 (F8|F9|FA|FB|FC|FD|FE|FF) ?? ?? ?? ?? 0F 84 }
// CFF state update: mov [rbp+var], imm32; jmp dispatcher
$cff_update = { C7 45 ?? ?? ?? ?? ?? E9 ?? ?? ?? ?? }
// PEB walk (x64): gs:[0x60] -> Ldr -> InMemoryOrderModuleList
$peb_x64 = { 65 48 8B 04 25 60 00 00 00 48 8B 40 18 }
// BCrypt for Chrome v20 decryption
$bcrypt_open = "BCryptOpenAlgorithmProvider" ascii
$bcrypt_decrypt = "BCryptDecrypt" ascii
$gcm_mode = "ChainingModeGCM" wide
// Named pipe for AppBound bypass
$pipe_abe = "\\\\.\\pipe\\abe_" ascii wide
$pipe_test = "\\\\.\\pipe\\test" ascii wide
// Browser targeting
$chrome = "\\Google\\Chrome\\User Data\\" ascii wide
$edge = "\\Microsoft\\Edge\\User Data\\" ascii wide
$firefox = "\\Mozilla\\Firefox\\Profiles\\" ascii wide
// Azure / Cloud
$msal = "msal_token_cache" ascii wide
$azure = "accessTokens.json" ascii wide
$aws = ".aws/credentials" ascii wide
// Crypto wallets
$metamask = "nkbihfbeogaeaoehlefnkodbefgpgknn" ascii
$phantom = "bfnaelmomeimhlpmgjnjophhpkkoljpa" ascii
// Exfil pattern
$exfil_token = "name=\"token\"" ascii
$exfil_message = "name=\"message\"" ascii
// Desktop creation for hidden browser
$hidden_desktop = "ChromeBuildTools" ascii wide
condition:
uint16(0) == 0x5A4D and filesize < 3MB and
(
// CFF + PEB walk = strong indicator
(2 of ($cff_*) and $peb_x64) or
// Browser injection indicators
(1 of ($pipe_*) and $hidden_desktop and 1 of ($bcrypt_*)) or
// Broad stealer fingerprint
(3 of ($chrome,$edge,$firefox,$metamask,$phantom) and
$exfil_token and $exfil_message) or
// Cloud targeting combo
($msal and $azure and 1 of ($bcrypt_*))
)
}
