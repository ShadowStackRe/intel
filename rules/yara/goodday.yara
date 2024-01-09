rule goodday {
    
meta:
      description = "rule to detect Goodday Ransomware"
      author = "ShadowStackRe.com"
      date = "2023-10-12"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Gooday"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
    $strFile_A = "crYptA" ascii wide    
    $strFile_B = "crYptB" ascii wide
    $strFile_C = "crYptC" ascii wide
    $strFile_D = "crYptD" ascii wide
    $strFile_E = "crYptE" ascii wide
    $strFile_F = "crYptF" ascii wide
    $strTorInfo = "Download & Install TOR browser" ascii wide
    $strReadmeNote = "readme_for_unlock.txt" ascii wide
    $strAttention = "ATTENTION" ascii wide
    $strHacked = "Your network is hacked and files are encrypted." ascii wide

condition:
    all of them
}