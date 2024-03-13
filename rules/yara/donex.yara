rule DoNex_Ransomware {
    meta:
        description = "Rule to detect DoNex ransomware"
        author = "ShadowStackRe.com"
        date = "2024-03-12"
        Rule_Version = "v1"
        malware_type = "ransomware"
        malware_family = "DoNex"
        License = "MIT License, https://opensource.org/license/mit/"
        Hash = "0adde4246aaa9fb3964d1d6cf3c29b1b13074015b250eb8e5591339f92e1e3ca"
    strings:
        $strBat = "C:\\ProgramData\\1.bat"
        $strCheckMutex = "CheckMutex"
        $strEncThread = "encryption_thread"
        $strReadMe = "Readme.%ls.txt"
        $strWalkThread = "walk_thread"
        $strWhiteExt = "white_extens"
        $strWhiteFolders = "white_folders"
        $strLocalDisks = "local_disks"
        $strIcon = "C:\\ProgramData\\icon.ico"
        $strTaskKill = "cmd /c \"taskkill /f /im cmd.exe & taskkill /f /im conhost.exe\""
    condition:
        uint16(0) == 0x5A4D and
        all of them
}
