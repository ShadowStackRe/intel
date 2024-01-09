rule LostTrust {

meta:
      description = "rule to detect LostTrust ransomware"
      author = "ShadowStackRe.com"
      date = "2023-11-26"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "LostTrust"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
    $strOption1 = "--onlypath" ascii wide
    $strOption2 = "--enable-shares" ascii wide
    $strEncodedLog = "ENCODED : %ws (total files : %d)" ascii
    $strExt = ".losttrustencoded" ascii wide
    $strDecryptLog = "decrypt file %ws, %ws" ascii
    $strReadMe1 = "So we decided to change our business model." ascii
    $strReadMe2 = "This is serious business for us" ascii
condition:
        all of them
}