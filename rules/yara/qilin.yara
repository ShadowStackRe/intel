rule QilinRansomware {
meta:
      description = "rule to detect Qilin Ransomware"
      author = "ShadowStackRe.com"
      date = "2023-12-06"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Qilin"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
      $strMotd = "/etc/motd"
      $strEncryptQuestion = "Are you sure to start encryption"
      $strConfigStart = "--- Configuration start ---"
      $strEsxiUsage = "esxcli"
      $strEncryptRenameFail = "Failed to rename encrypted file to"
      $strStartJob = "Started job..."
      $strBug = "\x1B[%uG 100%%"
condition:
      all of them
}