rule RhysidaRansomware {
meta:
      description = "rule to detect Rhysida Ransomware"
      author = "ShadowStackRe.com"
      date = "2023-12-12"
      Rule_Version = "v1"
      malware_type = "ransomware"
      malware_family = "Rhysida"
      License = "MIT License, https://opensource.org/license/mit/"

strings:
      $strShadowCopy = " vssadmin.exe Delete Shadows"
      $strRhsyida01 = "Rhysida-0.1"
      $strRhysida = "rhysida"
      $strRegKey1 = "cmd.exe /c reg delete \"HKCU\\Contol Panel\\Desktop"
      $strRegKey2 = "Policies\\ActiveDesktop\" /v NoChangingWallPaper"
      $strRunDll32 = "rundll32.exe user32.dll,UpdatePerUserSystemParameters"
      $strPDF = "CriticalBreachDetected.pdf"
condition:
      all of them
}