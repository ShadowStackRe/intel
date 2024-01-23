rule CactusRansomware {
meta:
    description = "rule to detect Cactus Ransomware"
    author = "ShadowStackRe.com"
    date = "2024-01-18"
    Rule_Version = "v1"
    malware_type = "ransomware"
    malware_family = "Cactus"
    License = "MIT License, https://opensource.org/license/mit/"
    Hash = "9ec6d3bc07743d96b723174379620dd56c167c58a1e04dbfb7a392319647441a,c49b4faa6ac7b5c207410ed1e86d0f21c00f47a78c531a0a736266c436cc1c0a"
strings:
    $strReadMe = "cAcTuS.readme.txt" wide
    $strLockExt = ".cts" wide
    $strTskName = "Updates Check Task" wide
    $strTskName2 = "Google Service Update"
    $strNTUSer = "ntuser.dat" wide
    $strNTUSer2 = "ntuser.log" wide
    $strBuilderName = "cactusbuilder"
condition:
    uint16(0) == 0x5A4D and ($strReadMe and $strLockExt) and
    (1 of ($strTskName*)) and (1 of ($strNTUSer*)) or ($strBuilderName)
}